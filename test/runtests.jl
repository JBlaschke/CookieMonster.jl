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
        # Unknown browser key -> KeyError from the db_path lookup.
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

    # Drive the real read_cookies function end to end, but inject the key and
    # point `base` at a throwaway profile on disk, so no OS keychain or real
    # browser install is needed. This exercises snapshot + cookie_db_path (the
    # Network/Cookies layout) + the SQL query + domain filter + decryption.
    @testset "read_cookies (injected keys + base)" begin
        base = mktempdir()
        profdir = joinpath(base, "Default", "Network")
        mkpath(profdir)
        db = SQLite.DB(joinpath(profdir, "Cookies"))
        DBInterface.execute(db, """
            CREATE TABLE cookies (
                host_key TEXT, name TEXT, path TEXT, value TEXT,
                encrypted_value BLOB, expires_utc INTEGER,
                is_secure INTEGER, is_httponly INTEGER)""")
        ins = "INSERT INTO cookies VALUES (?,?,?,?,?,?,?,?)"
        DBInterface.execute(db, ins,
            ("example.com", "sid", "/", "",
             make_encrypted(TESTKEY, "topsecret"; host = "example.com", with_host_prefix = true),
             13_253_932_800_000_000, 1, missing))
        DBInterface.execute(db, ins,
            ("plain.com", "pref", "/app", "lightmode", UInt8[], 0, 0, 1))
        DBInterface.close!(db)  # flush to disk before reading

        all = read_cookies("chrome"; base = base, keys = TESTKEYS)
        @test length(all) == 2

        enc = only(filter(c -> c.name == "sid", all))
        @test enc.host == "example.com"
        @test enc.value == "topsecret"          # decrypted + host prefix stripped
        @test enc.expires == DateTime(2021, 1, 1)
        @test enc.secure === true
        @test enc.httponly === false            # NULL -> false

        plain = only(filter(c -> c.name == "pref", all))
        @test plain.value == "lightmode"        # plaintext passthrough
        @test plain.expires === nothing

        # The domain filter narrows the SQL query (host_key LIKE %domain%).
        just_example = read_cookies("chrome"; base = base, keys = TESTKEYS, domain = "example.com")
        @test length(just_example) == 1
        @test only(just_example).host == "example.com"
    end

    # -----------------------------------------------------------------------
    # Write side: each helper is the inverse of a read-side helper, so the
    # strongest tests round-trip through the pair.
    # -----------------------------------------------------------------------

    @testset "datetime2chrome" begin
        @test CM.datetime2chrome(nothing) == 0
        @test CM.datetime2chrome(DateTime(1970, 1, 1)) == 11_644_473_600_000_000
        @test CM.datetime2chrome(DateTime(2021, 1, 1)) == 13_253_932_800_000_000
        # Inverse of chrome_time, at second precision.
        for dt in (DateTime(1970, 1, 1), DateTime(2021, 1, 1),
                   DateTime(2035, 6, 15, 12, 30, 45))
            @test CM.chrome_time(CM.datetime2chrome(dt)) == dt
        end
        @test CM.chrome_time(CM.datetime2chrome(nothing)) === nothing
    end

    @testset "pkcs7pad" begin
        @test CM.pkcs7pad(UInt8[1, 2, 3]) == vcat(UInt8[1, 2, 3], fill(0x0d, 13))
        @test length(CM.pkcs7pad(UInt8[])) == 16                    # empty -> full pad block
        @test length(CM.pkcs7pad(collect(0x01:0x10))) == 32         # exact multiple -> +full block
        # Inverse of strip_pkcs7 for every length across a block boundary.
        for n in 0:33
            data = rand(UInt8, n)
            padded = CM.pkcs7pad(data)
            @test length(padded) % 16 == 0
            @test CM.strip_pkcs7(padded) == data
        end
    end

    @testset "encrypt_value" begin
        host = "example.com"
        # Inverse of decrypt_value across empty, block-aligned, unicode, and
        # control-character payloads.
        for pt in ("", "hello world", "a"^16, "unicode: café ☕", "with\0control")
            enc = CM.encrypt_value(pt, host, TESTKEYS)             # :v10, host_prefix = true
            @test CM.decrypt_value(enc, missing, host, TESTKEYS) == pt
        end
        # host_prefix = false also round-trips (decrypt strips only a matching digest).
        noprefix = CM.encrypt_value("plain", host, TESTKEYS; host_prefix = false)
        @test CM.decrypt_value(noprefix, missing, host, TESTKEYS) == "plain"
        @test length(noprefix) < length(CM.encrypt_value("plain", host, TESTKEYS))
        # The blob carries the scheme's 3-byte version tag.
        @test String(CM.encrypt_value("x", host, TESTKEYS)[1:3]) == "v10"
        # Unavailable / unknown key -> a clear error, never a silent bad blob.
        @test_throws ErrorException CM.encrypt_value("x", host, TESTKEYS; scheme = :v11)
        @test_throws ErrorException CM.encrypt_value("x", host, TESTKEYS; scheme = :bogus)
    end

    @testset "samesite_code" begin
        @test CM.samesite_code(:unspecified) == -1
        @test CM.samesite_code(:none) == 0
        @test CM.samesite_code(:lax) == 1
        @test CM.samesite_code(:strict) == 2
        @test CM.samesite_code(2) == 2                              # integer passthrough
        @test_throws ErrorException CM.samesite_code(:bogus)
    end

    @testset "zero_for" begin
        @test CM.zero_for("INTEGER") === 0
        @test CM.zero_for("BLOB") == UInt8[]
        @test CM.zero_for("TEXT") == ""
        @test CM.zero_for("") == ""
    end

    @testset "browser_running" begin
        base = mktempdir()
        @test CM.browser_running("chrome"; base = base) == false
        touch(joinpath(base, "SingletonLock"))                     # real marker is a symlink; a file also trips ispath
        @test CM.browser_running("chrome"; base = base) == true
    end

    # build_row is what makes writing robust to schema drift: it must fill an
    # unexpected NOT NULL column, skip nullable/defaulted ones, and drop provided
    # values that have no column in this schema.
    @testset "build_row schema resilience" begin
        db = SQLite.DB()
        DBInterface.execute(db, """
            CREATE TABLE cookies (
                host_key TEXT NOT NULL, name TEXT NOT NULL, value TEXT NOT NULL,
                encrypted_value BLOB NOT NULL, path TEXT NOT NULL,
                mystery_flag INTEGER NOT NULL,      -- unexpected, no default
                optional_note TEXT,                 -- nullable, we don't set it
                prio INTEGER DEFAULT 1)""")         # defaulted, we don't set it
        row = CM.build_row(db; host_key = "h", name = "n", value = "",
                           encrypted_value = UInt8[1, 2], path = "/",
                           nonexistent_col = 999)   # not a real column -> dropped
        d = Dict(row)
        @test d["host_key"] == "h"
        @test d["encrypted_value"] == UInt8[1, 2]
        @test d["mystery_flag"] == 0                # NOT NULL, no default -> zero_for
        @test !haskey(d, "optional_note")           # nullable -> left to SQLite
        @test !haskey(d, "prio")                    # has a default -> left to SQLite
        @test !haskey(d, "nonexistent_col")         # no such column -> dropped
    end

    # Full write path against a realistic multi-column schema (extra NOT NULL
    # columns and the real UNIQUE constraint), read back through read_cookies.
    @testset "write_cookie (round-trip on a synthetic DB)" begin
        base = mktempdir()
        profdir = joinpath(base, "Default", "Network")
        mkpath(profdir)
        dbpath = joinpath(profdir, "Cookies")
        db = SQLite.DB(dbpath)
        DBInterface.execute(db, """
            CREATE TABLE cookies (
                creation_utc INTEGER NOT NULL,
                host_key TEXT NOT NULL,
                top_frame_site_key TEXT NOT NULL,
                name TEXT NOT NULL, value TEXT NOT NULL,
                encrypted_value BLOB NOT NULL, path TEXT NOT NULL,
                expires_utc INTEGER NOT NULL,
                is_secure INTEGER NOT NULL, is_httponly INTEGER NOT NULL,
                last_access_utc INTEGER NOT NULL, has_expires INTEGER NOT NULL,
                is_persistent INTEGER NOT NULL, priority INTEGER NOT NULL,
                samesite INTEGER NOT NULL, source_scheme INTEGER NOT NULL,
                source_port INTEGER NOT NULL, last_update_utc INTEGER NOT NULL,
                source_type INTEGER NOT NULL, has_cross_site_ancestor INTEGER NOT NULL,
                UNIQUE (host_key, top_frame_site_key, name, path, source_scheme, source_port))""")
        DBInterface.close!(db)

        exp = DateTime(2030, 1, 2, 3, 4, 5)
        write_cookie("chrome"; base = base, keys = TESTKEYS,
            host = "example.com", name = "sid", value = "s3cr3t",
            path = "/", expires = exp, secure = true, httponly = true)

        @test isfile(dbpath * ".cmbak")             # backup taken by default

        got = only(filter(c -> c.name == "sid",
                          read_cookies("chrome"; base = base, keys = TESTKEYS)))
        @test got.host == "example.com"
        @test got.value == "s3cr3t"                 # decrypted, host prefix stripped
        @test got.expires == exp
        @test got.secure === true
        @test got.httponly === true

        # Re-writing the same (host, name, path) replaces in place: no duplicates.
        write_cookie("chrome"; base = base, keys = TESTKEYS, backup = false,
            host = "example.com", name = "sid", value = "updated",
            path = "/", expires = exp, secure = true)
        dup = filter(c -> c.name == "sid",
                     read_cookies("chrome"; base = base, keys = TESTKEYS))
        @test length(dup) == 1
        @test only(dup).value == "updated"

        # NamedTuple form: read a cookie, change its value, write it back.
        orig = only(filter(c -> c.name == "sid",
                           read_cookies("chrome"; base = base, keys = TESTKEYS)))
        write_cookie("chrome", merge(orig, (value = "roundtrip",));
                     base = base, keys = TESTKEYS, backup = false)
        back = only(filter(c -> c.name == "sid",
                           read_cookies("chrome"; base = base, keys = TESTKEYS)))
        @test back.value == "roundtrip"
        @test back.expires == exp                   # other fields carried through

        # A session cookie (no expiry) reads back with expires === nothing.
        write_cookie("chrome"; base = base, keys = TESTKEYS, backup = false,
            host = "session.test", name = "tmp", value = "ephemeral")
        s = only(filter(c -> c.name == "tmp",
                        read_cookies("chrome"; base = base, keys = TESTKEYS)))
        @test s.value == "ephemeral"
        @test s.expires === nothing

        # Refuses to write under a "running" browser unless allowed.
        touch(joinpath(base, "SingletonLock"))
        @test_throws ErrorException write_cookie("chrome"; base = base,
            keys = TESTKEYS, host = "x.test", name = "n", value = "v")
        write_cookie("chrome"; base = base, keys = TESTKEYS, backup = false,
            allow_running = true, host = "x.test", name = "n", value = "v")
        @test only(filter(c -> c.name == "n",
                          read_cookies("chrome"; base = base, keys = TESTKEYS))).value == "v"
    end

    # Batch writes: mixed item shapes, one backup, one atomic transaction.
    @testset "write_cookies (batch, one transaction)" begin
        # A realistic multi-column schema, created fresh per profile directory.
        schema = """
            CREATE TABLE cookies (
                creation_utc INTEGER NOT NULL, host_key TEXT NOT NULL,
                top_frame_site_key TEXT NOT NULL, name TEXT NOT NULL,
                value TEXT NOT NULL, encrypted_value BLOB NOT NULL,
                path TEXT NOT NULL, expires_utc INTEGER NOT NULL,
                is_secure INTEGER NOT NULL, is_httponly INTEGER NOT NULL,
                last_access_utc INTEGER NOT NULL, has_expires INTEGER NOT NULL,
                is_persistent INTEGER NOT NULL, priority INTEGER NOT NULL,
                samesite INTEGER NOT NULL, source_scheme INTEGER NOT NULL,
                source_port INTEGER NOT NULL, last_update_utc INTEGER NOT NULL,
                source_type INTEGER NOT NULL, has_cross_site_ancestor INTEGER NOT NULL,
                UNIQUE (host_key, top_frame_site_key, name, path, source_scheme, source_port))"""
        function fresh_base()
            base = mktempdir()
            profdir = joinpath(base, "Default", "Network")
            mkpath(profdir)
            db = SQLite.DB(joinpath(profdir, "Cookies"))
            DBInterface.execute(db, schema)
            DBInterface.close!(db)
            return base
        end

        base = fresh_base()
        dbpath = joinpath(base, "Default", "Network", "Cookies")

        # Mixed item shapes: a full tuple and a bare (host, name, value).
        batch = [
            (host = "a.test", name = "one", value = "v1", path = "/",
             expires = DateTime(2031, 1, 1), secure = true, httponly = false),
            (host = "b.test", name = "two", value = "v2"),   # bare -> defaults apply
        ]
        n = write_cookies("chrome", batch; base = base, keys = TESTKEYS)
        @test n == 2
        @test isfile(dbpath * ".cmbak")            # a single backup for the batch

        got = read_cookies("chrome"; base = base, keys = TESTKEYS)
        @test length(got) == 2
        one = only(filter(c -> c.name == "one", got))
        @test one.value == "v1"
        @test one.expires == DateTime(2031, 1, 1)
        @test one.secure === true
        two = only(filter(c -> c.name == "two", got))
        @test two.value == "v2"
        @test two.expires === nothing              # bare item -> session cookie
        @test two.secure === false                 # bare item -> default attributes

        # The tuples from read_cookies round-trip straight back through the batch API.
        n2 = write_cookies("chrome", got; base = base, keys = TESTKEYS, backup = false)
        @test n2 == 2
        @test length(read_cookies("chrome"; base = base, keys = TESTKEYS)) == 2  # replaced, not duplicated

        # Atomicity: a failure partway through rolls back the whole batch, so the
        # cookie inserted before the bad one does not survive.
        base2 = fresh_base()
        @test_throws ErrorException write_cookies("chrome",
            [(host = "ok.test",  name = "k1", value = "v1"),
             (host = "bad.test", name = "k2", value = "v2", samesite = :bogus)];
            base = base2, keys = TESTKEYS, backup = false)
        @test isempty(read_cookies("chrome"; base = base2, keys = TESTKEYS))
    end

end

# Opt-in, Linux-only end-to-end tests against a real browser (see test/e2e.jl):
# the browser->CookieMonster read path and the CookieMonster->browser write path.
# Skipped unless COOKIEMONSTER_E2E=1, so a plain `Pkg.test()` needs no browser.
include("e2e.jl")
