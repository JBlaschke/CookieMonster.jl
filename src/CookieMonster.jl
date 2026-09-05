"""
    CookieMonster

Read and decrypt cookies from Chromium-based browsers (Chrome, Chromium, Brave)
on macOS and Linux.

The browser stores its cookies in an SQLite database, with each cookie value
encrypted using AES-128-CBC. The encryption key is derived (via PBKDF2-HMAC-SHA1)
from a per-browser "Safe Storage" password held in the OS keyring — the macOS
Keychain, or a Linux Secret Service keyring — with a well-known fallback on Linux.

The single exported entry point is `read_cookies`.
"""
module CookieMonster

using SQLite, DBInterface, Nettle, Dates

const IV16 = fill(0x20, 16)  # 16 space bytes, NOT zeros
const SALT = Vector{UInt8}("saltysalt")

#______________________________________________________________________________
"""
    pbkdf2_hmac_sha1(pw, salt, iters, dklen) -> Vector{UInt8}

Derive a `dklen`-byte key from password `pw` and `salt` using PBKDF2 with
HMAC-SHA1 as the pseudo-random function and `iters` iterations.

Only a single output block is supported, so `dklen` must be `<= 20` (the SHA-1
digest length); this is sufficient for the 16-byte AES keys used here.

# Arguments
- `pw::Vector{UInt8}`: the password / master key bytes.
- `salt::Vector{UInt8}`: the salt bytes.
- `iters::Integer`: the number of PBKDF2 iterations.
- `dklen::Integer`: the desired key length in bytes (`<= 20`).
"""
function pbkdf2_hmac_sha1(
            pw::Vector{UInt8},
            salt::Vector{UInt8},
            iters::Integer,
            dklen::Integer
        )

    @assert dklen <= 20 "single-block only"

    hmac1(msg) = (
        h = HMACState("sha1", pw);
        Nettle.update!(h, msg);
        Nettle.digest!(h)
    )

    U = hmac1(vcat(salt, UInt8[0x00, 0x00, 0x00, 0x01]))
    T = copy(U)
    for _ in 2:iters
        U = hmac1(U)
        T .⊻= U
    end

    return T[1:dklen]
end

#______________________________________________________________________________
# Per-platform key derivation, keyring service names, and cookie DB locations.
#

h = homedir()

if Sys.isapple()
    const SERVICE_TYPE = Dict(
        "chrome"   => "Chrome Safe Storage",
        "chromium" => "Chromium Safe Storage",
        "brave"    => "Brave Safe Storage"
    )

    const DB_PATH = Dict(
        "chrome"   => "$h/Library/Application Support/Google/Chrome",
        "chromium" => "$h/Library/Application Support/Chromium",
        "brave"    => "$h/Library/Application Support/BraveSoftware/Brave-Browser"
    )
else
    const SERVICE_TYPE = Dict(
        "chrome"   => "chrome",
        "chromium" => "chromium",
        "brave"    => "brave"
    )

    const DB_PATH = Dict(
        "chrome"   => "$h/.config/google-chrome",
        "chromium" => "$h/.config/chromium",
        "brave"    => "$h/.config/BraveSoftware/Brave-Browser"
    )
end

const LINUX_V10_PW = Vector{UInt8}("peanuts")

"""
    derive_keys(browser) -> NamedTuple

Derive the AES-128 keys used to decrypt `browser`'s cookies, returned as a named
tuple `(v10 = ..., v11 = ...)`. Each field is a 16-byte key, or `nothing` when
that key scheme is unavailable on the current platform.

On macOS, the browser's "Safe Storage" password is read from the login Keychain
(prompting the user once) and stretched with 1003 PBKDF2 iterations into the
`v10` key; `v11` is unused (`nothing`).

On Linux, `v10` is derived from the well-known fallback password `"peanuts"`
(1 iteration), and `v11` is derived from the Secret Service password looked up
via `secret-tool`, or `nothing` when no keyring / `secret-tool` is available.

`browser` must be one of `"chrome"`, `"chromium"`, or `"brave"`.
"""
function derive_keys(browser::AbstractString)
    if Sys.isapple()
        service = SERVICE_TYPE[browser]
        # prompts Keychain once
        pw = readchomp(`security find-generic-password -w -s $service`)  

        return (
            v10 = pbkdf2_hmac_sha1(Vector{UInt8}(pw), SALT, 1003, 16),
            v11 = nothing
        )
    else
        v10 = pbkdf2_hmac_sha1(LINUX_V10_PW, SALT, 1, 16)
        app = SERVICE_TYPE[browser]
        v11 = try
            pw = readchomp(`secret-tool lookup application $app`)
            isempty(pw) ? nothing : pbkdf2_hmac_sha1(Vector{UInt8}(pw), SALT, 1, 16)
        catch
            nothing  # no keyring / secret-tool not installed
        end
        return (v10 = v10, v11 = v11)
    end
end

"""
    cookie_db_path(browser; profile = "Default", base = nothing) -> String

Return the path to the Cookies SQLite database for `browser` and `profile`.

`base` overrides the default per-browser data directory. Recent Chromium
versions store the database at `<profile>/Network/Cookies`, older ones at
`<profile>/Cookies`; both locations are checked, in that order. Throws an error
if neither exists.
"""
function cookie_db_path(browser::AbstractString; profile = "Default", base = nothing)
    base = base === nothing ? DB_PATH[browser] : base
    for cand in ("$base/$profile/Network/Cookies", "$base/$profile/Cookies")
        isfile(cand) && return cand
    end
    error("No Cookies DB under $base/$profile")
end

#------------------------------------------------------------------------------


#______________________________________________________________________________
# Decrypt Cookies
#

"""
    snapshot(dbpath) -> String

Copy the cookie database at `dbpath`, together with its `-wal` and `-shm`
sidecar files if present, into a fresh temporary directory and return the path
to the copy.

Copying the write-ahead log alongside the database ensures cookies that have not
yet been checkpointed are still read, and avoids touching (or locking) the live
database the browser is using.
"""
function snapshot(dbpath::AbstractString)
    dest = joinpath(mktempdir(), "Cookies")
    cp(dbpath, dest; force = true)
    for suf in ("-wal", "-shm")
        isfile(dbpath * suf) && cp(dbpath * suf, dest * suf; force = true)
    end
    return dest
end

"""
    strip_pkcs7(d)

Remove PKCS#7 padding from the decrypted byte vector `d`, returning `d`
unchanged if the trailing padding length is not a valid value in `1:16`.
"""
strip_pkcs7(d) = (isempty(d) ? d : (p = Int(d[end]); (1 <= p <= 16 && p <= length(d)) ? d[1:end-p] : d))

"""
    tobool(x) -> Bool

Coerce a SQLite column value to `Bool`, treating a `missing` (NULL) value as
`false`.
"""
tobool(x) = x === missing ? false : Bool(x)  # some columns can be NULL

"""
    sha256_bytes(data) -> Vector{UInt8}

Return the raw SHA-256 digest of `data` as bytes.
"""
sha256_bytes(data) = (h = Hasher("sha256"); update!(h, data); digest!(h)) # Alternatively: `using SHA`

"""
    decrypt_value(enc, plainval, host_key, keys) -> String

Decrypt a single cookie's stored value.

`enc` is the raw `encrypted_value` blob and `plainval` the legacy plaintext
`value` column; `host_key` is the cookie's host, and `keys` the named tuple of
derivation keys from `derive_keys`.

When `enc` is empty the plaintext `plainval` is returned. Otherwise the leading
version tag (`v10` or `v11`) selects the key, and the remaining bytes are
decrypted with AES-128-CBC and PKCS#7-unpadded. Chromium (v104+) prefixes the
plaintext with the SHA-256 of the host key; that prefix is stripped when present.
Returns an empty string if the required key is unavailable or the ciphertext is
malformed.
"""
function decrypt_value(enc, plainval, host_key, keys)
    (enc === missing || isempty(enc)) && return plainval === missing ? "" : String(plainval)
    enc = Vector{UInt8}(enc)
    prefix = length(enc) >= 3 ? String(enc[1:3]) : ""
    key = prefix == "v10" ? keys.v10 :
          prefix == "v11" ? keys.v11 : nothing
    key === nothing && return prefix in ("v10", "v11") ? "" :
                             (plainval === missing ? "" : String(plainval))
    ct = enc[4:end]
    (isempty(ct) || length(ct) % 16 != 0) && return ""
    pt = strip_pkcs7(decrypt(Decryptor("AES128", key), :CBC, IV16, ct))
    hk = Vector{UInt8}(host_key === missing ? "" : host_key)
    (length(pt) >= 32 && pt[1:32] == sha256_bytes(hk)) && (pt = pt[33:end])  # strip domain prefix if present
    return String(pt)
end


"""
    chrome_time(x) -> Union{DateTime, Nothing}

Convert a Chromium timestamp `x` (microseconds since 1601-01-01 UTC) to a
`DateTime`, returning `nothing` for a `missing` or zero value (e.g. a session
cookie with no expiry).
"""
chrome_time(x) = (x === missing || x == 0) ? nothing : Dates.unix2datetime(x / 1_000_000 - 11_644_473_600)

"""
    read_cookies(browser = "chrome"; profile = "Default", domain = nothing,
                 base = nothing, keys = nothing) -> Vector{NamedTuple}

Read and decrypt the cookies stored by `browser` (`"chrome"`, `"chromium"`, or
`"brave"`, case-insensitive).

Each returned element is a named tuple with fields `host`, `name`, `path`,
`value` (decrypted), `expires` (a `DateTime` or `nothing`), `secure`, and
`httponly`.

# Keyword arguments
- `profile`: the browser profile to read (default `"Default"`).
- `domain`: if given, only cookies whose host contains this substring are
  returned.
- `base`: override for the browser's data directory (see `cookie_db_path`).
- `keys`: precomputed decryption keys (see `derive_keys`); derived automatically
  when omitted, which may prompt for keyring access.

The live database is snapshotted before reading (see `snapshot`), so the browser
need not be closed.
"""
function read_cookies(browser::AbstractString = "chrome"; profile = "Default",
                      domain = nothing, base = nothing, keys = nothing)
    browser = lowercase(browser)
    keys = keys === nothing ? derive_keys(browser) : keys
    db = SQLite.DB(snapshot(cookie_db_path(browser; profile = profile, base = base)))
    sql = "SELECT host_key, name, path, value, encrypted_value, expires_utc, is_secure, is_httponly FROM cookies"
    q = domain === nothing ?
        DBInterface.execute(db, sql) :
        DBInterface.execute(db, sql * " WHERE host_key LIKE ?", ("%$domain%",))
    out = NamedTuple[]
    for r in q
        push!(out, (host = r.host_key, name = r.name, path = r.path,
                    value = decrypt_value(r.encrypted_value, r.value, r.host_key, keys),
                    expires = chrome_time(r.expires_utc),
                    secure = tobool(r.is_secure), httponly = tobool(r.is_httponly)))
    end
    return out
end

#------------------------------------------------------------------------------

export read_cookies


end
