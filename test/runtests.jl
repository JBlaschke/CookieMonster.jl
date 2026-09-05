using CookieMonster
using Test
using Nettle, SQLite, DBInterface, Dates

const CM = CookieMonster

# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------

# PKCS#7 pad to the AES block size, mirroring what Chrome does before encrypting.
function pkcs7pad(data::Vector{UInt8}, blocksize::Int = 16)
    pad = blocksize - (length(data) % blocksize)
    return vcat(data, fill(UInt8(pad), pad))
end

# Build an encrypted cookie blob exactly the way Chrome stores it:
#   "v10" | AES-128-CBC( IV = 16 spaces, key, PKCS7( [sha256(host)] * plaintext ) )
# When `with_host_prefix` is true the 32-byte host digest is prepended to the
# plaintext (newer Chrome), which `decrypt_value` is expected to strip back off.
function make_encrypted(key::Vector{UInt8}, plaintext::AbstractString;
                        prefix::AbstractString = "v10",
                        host::AbstractString = "",
                        with_host_prefix::Bool = false)
    pt = Vector{UInt8}(plaintext)
    if with_host_prefix
        pt = vcat(CM.sha256_bytes(Vector{UInt8}(host)), pt)
    end
    ct = encrypt(Encryptor("AES128", key), :CBC, CM.IV16, pkcs7pad(pt))
    return vcat(Vector{UInt8}(prefix), ct)
end

# A fixed 16-byte AES key used throughout the decryption tests.
const TESTKEY = Vector{UInt8}(collect(0x01:0x10))
const TESTKEYS = (v10 = TESTKEY, v11 = nothing)

@testset "CookieMonster.jl" begin

    @testset "pbkdf2_hmac_sha1" begin
        # RFC 6070 test vectors for PBKDF2-HMAC-SHA1 (P = "password", S = "salt").
        pw = Vector{UInt8}("password")
        salt = Vector{UInt8}("salt")

        @test CM.pbkdf2_hmac_sha1(pw, salt, 1, 20) ==
            hex2bytes("0c60c80f961f0e71f3a9b524af6012062fe037a6")
        @test CM.pbkdf2_hmac_sha1(pw, salt, 2, 20) ==
            hex2bytes("ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957")
        @test CM.pbkdf2_hmac_sha1(pw, salt, 4096, 20) ==
            hex2bytes("4b007901b765489abead49d926f721d065a429c1")

        # dklen shorter than the 20-byte SHA1 output is a prefix truncation.
        @test CM.pbkdf2_hmac_sha1(pw, salt, 1, 16) ==
            hex2bytes("0c60c80f961f0e71f3a9b524af601206")
        @test length(CM.pbkdf2_hmac_sha1(pw, salt, 1, 16)) == 16

        # The Chrome/macOS key derivation uses 1003 iterations, dklen 16.
        @test length(CM.pbkdf2_hmac_sha1(pw, CM.SALT, 1003, 16)) == 16

        # Single-block implementation only: dklen may not exceed 20.
        @test_throws AssertionError CM.pbkdf2_hmac_sha1(pw, salt, 1, 21)
    end

    @testset "strip_pkcs7" begin
        @test CM.strip_pkcs7(UInt8[1, 2, 3, 0x03, 0x03, 0x03]) == UInt8[1, 2, 3]
        @test CM.strip_pkcs7(UInt8[0x2a, 0x01]) == UInt8[0x2a]        # one pad byte
        @test CM.strip_pkcs7(fill(0x10, 16)) == UInt8[]              # full block of padding
        @test CM.strip_pkcs7(UInt8[]) == UInt8[]                     # empty stays empty

        # Invalid pad lengths are left untouched (not stripped).
        @test CM.strip_pkcs7(UInt8[1, 2, 0x00]) == UInt8[1, 2, 0x00] # pad byte 0
        @test CM.strip_pkcs7(UInt8[1, 2, 0xff]) == UInt8[1, 2, 0xff] # pad byte > 16
        @test CM.strip_pkcs7(UInt8[0x05]) == UInt8[0x05]            # pad longer than data
    end

    @testset "tobool" begin
        @test CM.tobool(missing) === false   # NULL columns default to false
        @test CM.tobool(0) === false
        @test CM.tobool(1) === true
        @test CM.tobool(true) === true
        @test CM.tobool(false) === false
    end

    @testset "sha256_bytes" begin
        @test CM.sha256_bytes(Vector{UInt8}("abc")) ==
            hex2bytes("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        @test CM.sha256_bytes(UInt8[]) ==
            hex2bytes("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        @test length(CM.sha256_bytes(Vector{UInt8}("anything"))) == 32
    end

    @testset "chrome_time" begin
        # Chrome timestamps are microseconds since 1601-01-01 (WebKit epoch).
        @test CM.chrome_time(0) === nothing
        @test CM.chrome_time(missing) === nothing
        # 11_644_473_600 s is the 1601->1970 offset; that many microseconds is the Unix epoch.
        @test CM.chrome_time(11_644_473_600_000_000) == DateTime(1970, 1, 1)
        @test CM.chrome_time(13_253_932_800_000_000) == DateTime(2021, 1, 1)
        @test CM.chrome_time(11_644_473_600_000_000) isa DateTime
    end

    @testset "decrypt_value" begin
        host = "example.com"

        @testset "unencrypted / passthrough" begin
            # No encrypted blob -> fall back to the plaintext value column.
            @test CM.decrypt_value(missing, "plainval", host, TESTKEYS) == "plainval"
            @test CM.decrypt_value(UInt8[], "plainval", host, TESTKEYS) == "plainval"
            # Both columns empty -> empty string, never `missing`.
            @test CM.decrypt_value(missing, missing, host, TESTKEYS) == ""
            @test CM.decrypt_value(UInt8[], missing, host, TESTKEYS) == ""
        end

        @testset "v10 roundtrip" begin
            enc = make_encrypted(TESTKEY, "hello world")
            @test CM.decrypt_value(enc, missing, host, TESTKEYS) == "hello world"

            # Empty plaintext encrypts to a single padding block and decrypts back to "".
            enc_empty = make_encrypted(TESTKEY, "")
            @test CM.decrypt_value(enc_empty, missing, host, TESTKEYS) == ""
        end

        @testset "v10 with host digest prefix" begin
            # Newer Chrome prepends sha256(host_key); decrypt_value must strip it.
            enc = make_encrypted(TESTKEY, "topsecret"; host = host, with_host_prefix = true)
            @test CM.decrypt_value(enc, missing, host, TESTKEYS) == "topsecret"

            # A wrong host means the digest doesn't match, so the 32 bytes are NOT
            # stripped and leak into the (binary) result -> it is not the clean value.
            @test CM.decrypt_value(enc, missing, "wrong.host", TESTKEYS) != "topsecret"
        end

        @testset "unknown / unavailable keys" begin
            # Prefix that isn't v10/v11 -> treat as unencrypted, return plaintext column.
            @test CM.decrypt_value(Vector{UInt8}("abcdef"), "plainval", host, TESTKEYS) == "plainval"
            # v11 requested but no v11 key on this platform (macOS) -> empty string.
            v11blob = vcat(Vector{UInt8}("v11"), fill(0x00, 16))
            @test CM.decrypt_value(v11blob, "plainval", host, TESTKEYS) == ""
        end

        @testset "malformed ciphertext" begin
            # Ciphertext length not a multiple of the 16-byte block size.
            @test CM.decrypt_value(vcat(Vector{UInt8}("v10"), fill(0x00, 5)), "x", host, TESTKEYS) == ""
            # Prefix present but no ciphertext at all.
            @test CM.decrypt_value(Vector{UInt8}("v10"), "x", host, TESTKEYS) == ""
        end
    end

    @testset "snapshot" begin
        dir = mktempdir()
        src = joinpath(dir, "Cookies")
        write(src, "DBDATA")

        # Without WAL/SHM sidecars, only the main file is copied.
        snap = CM.snapshot(src)
        @test isfile(snap)
        @test read(snap, String) == "DBDATA"
        @test !isfile(snap * "-wal")
        @test !isfile(snap * "-shm")
        @test snap != src   # snapshot lives in a fresh temp dir

        # With WAL/SHM sidecars present, they are copied alongside.
        write(src * "-wal", "WALDATA")
        write(src * "-shm", "SHMDATA")
        snap2 = CM.snapshot(src)
        @test read(snap2, String) == "DBDATA"
        @test read(snap2 * "-wal", String) == "WALDATA"
        @test read(snap2 * "-shm", String) == "SHMDATA"
    end

    @testset "cookie_db_path" begin
        # Unknown browser key -> KeyError from the DB_PATH lookup.
        @test_throws KeyError CM.cookie_db_path("firefox")
        # Known browser but a profile that cannot exist -> descriptive error.
        @test_throws ErrorException CM.cookie_db_path("chrome"; profile = "__cookiemonster_no_such_profile__")
    end

    # Integration: exercise the DB-read + decrypt pipeline the way read_cookies
    # does, but with an injected key (read_cookies itself derives keys from the
    # system keychain, which is not available in a unit-test environment).
    @testset "integration: decrypt from a synthetic Cookies DB" begin
        db = SQLite.DB()  # in-memory
        DBInterface.execute(db, """
            CREATE TABLE cookies (
                host_key TEXT, name TEXT, path TEXT, value TEXT,
                encrypted_value BLOB, expires_utc INTEGER,
                is_secure INTEGER, is_httponly INTEGER)""")
        ins = "INSERT INTO cookies VALUES (?,?,?,?,?,?,?,?)"

        # Encrypted cookie, Chrome-style with host digest prefix + NULL is_httponly.
        DBInterface.execute(db, ins,
            ("example.com", "sid", "/", "",
             make_encrypted(TESTKEY, "topsecret"; host = "example.com", with_host_prefix = true),
             13_253_932_800_000_000, 1, missing))
        # Plaintext cookie, no encrypted blob, non-expiring.
        DBInterface.execute(db, ins,
            ("plain.com", "pref", "/app", "lightmode", UInt8[], 0, 0, 1))

        sql = "SELECT host_key, name, path, value, encrypted_value, expires_utc, is_secure, is_httponly FROM cookies"
        rows = [(host = r.host_key, name = r.name, path = r.path,
                 value = CM.decrypt_value(r.encrypted_value, r.value, r.host_key, TESTKEYS),
                 expires = CM.chrome_time(r.expires_utc),
                 secure = CM.tobool(r.is_secure), httponly = CM.tobool(r.is_httponly))
                for r in DBInterface.execute(db, sql)]

        @test length(rows) == 2

        enc_row = rows[1]
        @test enc_row.host == "example.com"
        @test enc_row.name == "sid"
        @test enc_row.value == "topsecret"        # decrypted + host prefix stripped
        @test enc_row.expires == DateTime(2021, 1, 1)
        @test enc_row.secure === true
        @test enc_row.httponly === false          # NULL -> false

        plain_row = rows[2]
        @test plain_row.host == "plain.com"
        @test plain_row.value == "lightmode"      # plaintext passthrough
        @test plain_row.expires === nothing       # expires_utc == 0
        @test plain_row.secure === false
        @test plain_row.httponly === true
    end

end
