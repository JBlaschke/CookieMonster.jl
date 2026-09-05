module CookieMonster

using SQLite, DBInterface, Nettle, Dates

const IV16 = fill(0x20, 16)  # 16 space bytes, NOT zeros
const SALT = Vector{UInt8}("saltysalt")

#______________________________________________________________________________
# PBKDF2-HMAC-SHA1, single block (dklen 16 <= 20, so one block suffices)
#

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
# Per-platform key derivation.
# Returns (v10=..., v11=...) ; nothing = unavailable
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

# Copy DB + WAL/SHM so an un-checkpointed WAL is still read consistently
function snapshot(dbpath::AbstractString)
    dest = joinpath(mktempdir(), "Cookies")
    cp(dbpath, dest; force = true)
    for suf in ("-wal", "-shm")
        isfile(dbpath * suf) && cp(dbpath * suf, dest * suf; force = true)
    end
    return dest
end

strip_pkcs7(d) = (isempty(d) ? d : (p = Int(d[end]); (1 <= p <= 16 && p <= length(d)) ? d[1:end-p] : d))
tobool(x) = x === missing ? false : Bool(x)  # some columns can be NULL
sha256_bytes(data) = (h = Hasher("sha256"); update!(h, data); digest!(h)) # Alternatively: `using SHA`

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


chrome_time(x) = (x === missing || x == 0) ? nothing : Dates.unix2datetime(x / 1_000_000 - 11_644_473_600)

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
