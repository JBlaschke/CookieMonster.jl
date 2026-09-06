"""
    CookieMonster

Read, decrypt, and write cookies for Chromium-based browsers (Chrome, Chromium,
Brave) on macOS and Linux.

The browser stores its cookies in an SQLite database, with each cookie value
encrypted using AES-128-CBC. The encryption key is derived (via
PBKDF2-HMAC-SHA1) from a per-browser "Safe Storage" password held in the OS
keyring — the macOS Keychain, or a Linux Secret Service keyring — with a
well-known fallback on Linux.

The exported entry points are `read_cookies` and `write_cookie`; the latter
encrypts a value the same way the browser does and inserts it into the store.
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

Copying the write-ahead log alongside the database ensures cookies that have
not yet been checkpointed are still read, and avoids touching (or locking) the
live database the browser is using.
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
plaintext with the SHA-256 of the host key; that prefix is stripped when
present. Returns an empty string if the required key is unavailable or the
ciphertext is malformed.
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
- `keys`: precomputed decryption keys (see `derive_keys`); derived
  automatically when omitted, which may prompt for keyring access.

The live database is snapshotted before reading (see `snapshot`), so the
browser need not be closed.
"""
function read_cookies(
            browser::AbstractString = "chrome";
            profile = "Default", domain = nothing, base = nothing,
            keys = nothing
        )
    browser = lowercase(browser)
    keys = keys === nothing ? derive_keys(browser) : keys
    db = SQLite.DB(snapshot(cookie_db_path(browser; profile = profile, base = base)))
    sql = "SELECT host_key, name, path, value, encrypted_value, expires_utc, is_secure, is_httponly FROM cookies"
    q = domain === nothing ? DBInterface.execute(db, sql) :
        DBInterface.execute(db, sql * " WHERE host_key LIKE ?", ("%$domain%",))
    out = NamedTuple[]
    for r in q
        push!(out, (
            host = r.host_key, name = r.name, path = r.path,
            value = decrypt_value(r.encrypted_value, r.value, r.host_key, keys),
            expires = chrome_time(r.expires_utc),
            secure = tobool(r.is_secure), httponly = tobool(r.is_httponly)
        ))
    end
    return out
end

#------------------------------------------------------------------------------


#______________________________________________________________________________
# Encrypt & write cookies
#
# The inverse of the read pipeline above: encrypt a value exactly the way the
# browser does, then write a fully-formed row into the Cookies database. Two
# things differ from reading. First, the write must target the real on-disk
# database, not a snapshot. Second, it is only safe while the browser is not
# running: Chromium keeps its cookies in an in-memory store and flushes through
# to SQLite, so a direct write under a live browser can be lost or clobbered
# (see `write_cookie`).

"""
    pkcs7pad(data, blocksize = 16) -> Vector{UInt8}

Append PKCS#7 padding to `data` so its length becomes a multiple of
`blocksize`. When the length is already a multiple, a whole block of
`blocksize` padding bytes is added; this is the inverse of `strip_pkcs7`, which
removes such a block.
"""
function pkcs7pad(data::Vector{UInt8}, blocksize::Integer = 16)
    pad = blocksize - (length(data) % blocksize)  # always in 1:blocksize
    return vcat(data, fill(UInt8(pad), pad))
end

"""
    datetime2chrome(dt) -> Int

Convert a `DateTime` (UTC) to a Chromium timestamp (microseconds since
1601-01-01 UTC). `nothing` maps to `0`, matching how `chrome_time` reads a zero
timestamp back as `nothing` (a session cookie with no expiry). Inverse of
`chrome_time`.
"""
datetime2chrome(::Nothing) = 0
datetime2chrome(dt::DateTime) = round(
    Int, (Dates.datetime2unix(dt) + 11_644_473_600) * 1_000_000
)

"""
    encrypt_value(plaintext, host_key, keys; scheme = :v10, host_prefix = true)
        -> Vector{UInt8}

Produce an `encrypted_value` blob in the exact format `decrypt_value` reads:
the 3-byte version tag (`"v10"` or `"v11"`, chosen by `scheme`) followed by
AES-128-CBC(IV = 16 spaces, key, PKCS#7(`[sha256(host_key)]` * `plaintext`)).

The 32-byte host digest is prepended to the plaintext when `host_prefix` is
`true` (the default), matching Chromium v104+; `decrypt_value` strips it back
off when it matches the cookie's host. Set `host_prefix = false` only for
browsers old enough to predate domain-bound cookie values.

Throws if the key for `scheme` is unavailable — `:v11` on macOS, or either
scheme when the corresponding key could not be derived.
"""
function encrypt_value(
            plaintext::AbstractString, host_key::AbstractString, keys;
            scheme::Symbol = :v10, host_prefix::Bool = true
        )
    key = scheme === :v10 ? keys.v10 :
          scheme === :v11 ? keys.v11 :
          error("unknown scheme $(repr(scheme)); use :v10 or :v11")
    key === nothing && error(
        "no $scheme key available on this platform/keyring"
    )
    pt = Vector{UInt8}(plaintext)
    host_prefix && (pt = vcat(sha256_bytes(Vector{UInt8}(host_key)), pt))
    ct = encrypt(Encryptor("AES128", key), :CBC, IV16, pkcs7pad(pt))
    return vcat(Vector{UInt8}(String(scheme)), ct)
end

"""
    samesite_code(s) -> Int

Map a SameSite value to the integer Chromium stores in the `samesite` column:
`:unspecified => -1`, `:none => 0`, `:lax => 1`, `:strict => 2`. An integer is
passed through unchanged.
"""
samesite_code(n::Integer) = Int(n)
samesite_code(s::Symbol) =
    s === :unspecified ? -1 : s === :none ? 0 :
    s === :lax ? 1 : s === :strict ? 2 :
    error("bad samesite $(repr(s)); use :unspecified/:none/:lax/:strict")

"""
    browser_running(browser; base = nothing) -> Bool

Heuristically report whether `browser` currently holds the profile open, by
testing for the `SingletonLock` marker Chromium keeps in its user-data
directory while running. A `true` result is reliable; a `false` result is not a
guarantee (the marker can linger after a crash, or be briefly absent), so it is
used only to steer `write_cookie` away from the common footgun of writing under
a live browser.
"""
function browser_running(browser::AbstractString; base = nothing)
    base = base === nothing ? DB_PATH[lowercase(browser)] : base
    lock = joinpath(base, "SingletonLock")
    return ispath(lock) || islink(lock)  # the marker is a (sometimes dangling) symlink
end

"""
    zero_for(sqltype) -> Union{Int, String, Vector{UInt8}}

A type-appropriate zero for an SQLite column declared with type `sqltype`: `0`
for an integer affinity, an empty `Vector{UInt8}` for `BLOB`, and `""`
otherwise. Used to satisfy `NOT NULL` columns that `write_cookie` does not set
itself.
"""
zero_for(t::AbstractString) = (
    T = uppercase(t); occursin("INT", T) ? 0 : occursin("BLOB", T) ? UInt8[] : ""
)

"""
    build_row(db; provided...) -> Vector{Pair{String, Any}}

Assemble the column/value pairs for an `INSERT` into the `cookies` table of
`db`, resilient to the schema differences between Chromium versions.

The table is introspected with `PRAGMA table_info`. For each column: if a value
was `provided`, it is used; otherwise, if the column is `NOT NULL` with no
default, a `zero_for` value is supplied so the insert cannot fail on a column
we did not anticipate. Nullable or defaulted columns we do not set are omitted
and left to SQLite. `provided` values whose column does not exist in this
schema are dropped, so the same call works across versions.
"""
function build_row(db; provided...)
    want = Dict{String,Any}(String(k) => v for (k, v) in provided)
    row = Pair{String,Any}[]
    for c in DBInterface.execute(db, "PRAGMA table_info(cookies)")
        if haskey(want, c.name)
            push!(row, c.name => want[c.name])
        elseif c.notnull == 1 && c.dflt_value === missing
            push!(row, c.name => zero_for(c.type))
        end
    end
    return row
end

"""
    write_cookie(browser = "chrome"; host, name, value, kwargs...) -> Nothing
    write_cookie(browser, cookie::NamedTuple; kwargs...) -> Nothing

Encrypt `value` and write a cookie into `browser`'s on-disk cookie store — the
inverse of [`read_cookies`](@ref). The second form takes a `NamedTuple` shaped
like an element returned by `read_cookies` (fields `host`, `name`, `value`,
`path`, `expires`, `secure`, `httponly`), so a cookie can be read, modified,
and written back; any keyword argument overrides the matching tuple field.

Any existing cookie with the same `(host, name, path)` is replaced, so repeated
writes are idempotent and never leave duplicates.

# Required keyword arguments
- `host`: the cookie host / domain, stored in `host_key` (e.g. `".github.com"`).
- `name`: the cookie name.
- `value`: the plaintext value (encrypted before storage).

# Optional keyword arguments
- `path` (`"/"`): the path scope.
- `expires` (`nothing`): a `DateTime` (UTC) expiry, or `nothing` for a session
  cookie. Browsers usually discard persisted session cookies on restart, so
  pass an expiry for a cookie that should survive one.
- `secure` (`false`), `httponly` (`false`): the corresponding attributes. When
  `secure` is set, the row's `source_scheme`/`source_port` are written as
  https/443 rather than http/80.
- `samesite` (`:lax`): one of `:unspecified`, `:none`, `:lax`, `:strict`.
- `profile` (`"Default"`), `base` (`nothing`): select the profile / data
  directory, exactly as in `read_cookies` and `cookie_db_path`.
- `keys` (`nothing`): precomputed keys from `derive_keys`; derived
  automatically when omitted, which may prompt for keyring access.
- `scheme` (`nothing`): `:v10` or `:v11`; when omitted, `:v11` is used if that
  key is available (a Linux keyring) and `:v10` otherwise (always on macOS).
- `host_prefix` (`true`): prepend the host digest to the value (Chromium
  v104+); see [`encrypt_value`](@ref).
- `allow_running` (`false`): by default the write is refused when `browser`
  looks like it is running (see [`browser_running`](@ref)), because the
  browser's in-memory cookie store would overwrite a direct database write. Set
  `true` to override the check.
- `backup` (`true`): copy the database to `<Cookies>.cmbak` before writing.

!!! warning "Quit the browser first"
    Writing to the live database while the browser is open is unreliable and
    can lose the write or disturb the store. The `allow_running` guard is a
    convenience, not a guarantee.
"""
function write_cookie(
            browser::AbstractString = "chrome";
            host, name, value, path = "/", expires = nothing, secure = false,
            httponly = false, samesite = :lax, profile = "Default",
            base = nothing, keys = nothing, scheme = nothing,
            host_prefix = true, allow_running = false, backup = true
        )
    browser = lowercase(browser)
    keys = keys === nothing ? derive_keys(browser) : keys
    scheme = scheme === nothing ? (keys.v11 !== nothing ? :v11 : :v10) : scheme

    if !allow_running && browser_running(browser; base = base)
        error(
            "$browser appears to be running; its in-memory cookie store will " *
            "overwrite a direct database write. Quit $browser, or pass " *
            "allow_running = true to override."
        )
    end

    dbpath = cookie_db_path(browser; profile = profile, base = base)
    backup && cp(dbpath, dbpath * ".cmbak"; force = true)

    enc = encrypt_value(
        value, host, keys; scheme = scheme, host_prefix = host_prefix
    )
    now = datetime2chrome(Dates.now(Dates.UTC))
    persistent = expires !== nothing

    db = SQLite.DB(dbpath)  # the live database, NOT a snapshot
    try
        row = build_row(db;
            host_key = host, name = name, value = "", encrypted_value = enc,
            path = path, expires_utc = datetime2chrome(expires),
            is_secure = Int(secure), is_httponly = Int(httponly),
            samesite = samesite_code(samesite), priority = 1,
            has_expires = Int(persistent), is_persistent = Int(persistent),
            creation_utc = now, last_access_utc = now, last_update_utc = now,
            source_scheme = secure ? 2 : 1, source_port = secure ? 443 : 80
        )
        isempty(row) && error(
            "no `cookies` table in $dbpath; has $browser created this profile yet?"
        )

        cols = join(first.(row), ", ")
        qs   = join(fill("?", length(row)), ", ")
        DBInterface.execute(db, "BEGIN")
        DBInterface.execute(db,
            "DELETE FROM cookies WHERE host_key = ? AND name = ? AND path = ?",
            (host, name, path)
        )
        DBInterface.execute(db,
            "INSERT INTO cookies ($cols) VALUES ($qs)", last.(row)
        )
        DBInterface.execute(db, "COMMIT")
    catch
        try; DBInterface.execute(db, "ROLLBACK"); catch; end
        rethrow()
    finally
        DBInterface.close!(db)
    end
    return nothing
end

function write_cookie(browser::AbstractString, c::NamedTuple; kwargs...)
    fields = (
        host = c.host, name = c.name, value = c.value, path = c.path,
        expires = c.expires, secure = c.secure, httponly = c.httponly
    )
    return write_cookie(browser; merge(fields, values(kwargs))...)
end

#------------------------------------------------------------------------------

export read_cookies, write_cookie


end
