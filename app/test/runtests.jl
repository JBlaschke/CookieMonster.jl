# Tests for the CLI layer that do not need a browser or the OS keyring: the
# hand-rolled JSON codec (the genuinely new, security-relevant code, since cookie
# values are arbitrary) and the `write` dispatch glue's pre-key decision points.
# The actual encrypt-and-write path is covered by the library test suite and the
# real-browser E2E; here we only need the pieces that run before key derivation.
#
# Run with:  julia --project=app app/test/runtests.jl

using Test
using Dates

include(joinpath(@__DIR__, "..", "src", "Cookie.jl"))
using .Cookie

@testset "Cookie CLI" begin

    @testset "parse_json: values" begin
        @test Cookie.parse_json("  true ")  === true
        @test Cookie.parse_json("false")    === false
        @test Cookie.parse_json("null")     === nothing
        @test Cookie.parse_json("42")       === 42
        @test Cookie.parse_json("-3.5")     === -3.5
        @test Cookie.parse_json("1e3")      == 1000.0
        @test Cookie.parse_json("\"hi\"")   == "hi"
        @test Cookie.parse_json("[1, 2, 3]") == Any[1, 2, 3]
        @test Cookie.parse_json("[]")       == Any[]
        @test Cookie.parse_json("{}")       == Dict{String,Any}()
        obj = Cookie.parse_json("""{ "a": 1, "b": [true, null], "c": "x" }""")
        @test obj["a"] == 1
        @test obj["b"] == Any[true, nothing]
        @test obj["c"] == "x"
    end

    @testset "parse_json: string escapes" begin
        # Round-trip each string through the (correct) encoder, which exercises
        # every escape the decoder must reverse without hand-writing tricky
        # literals (Julia raw strings mangle an embedded \").
        rt(s) = (io = IOBuffer(); Cookie.json_scalar(io, s); Cookie.parse_json(String(take!(io))))
        for s in ("a\"b\\c/d", "tab\tnl\ncr\r", "\b\f", "Aé", "🍪",
                  "café ☕", "", "controlx")
            @test rt(s) == s
        end
        # Decode \u escapes directly (no embedded quotes, so raw is safe here):
        # Decode \u escapes directly. Build the input from char codes so the
        # source carries no backslash/quote literals to be re-interpreted.
        bs = Char(0x5c); q = Char(0x22)   # '\' and '"'
        @test Cookie.parse_json(string(q, bs, "u0041", bs, "u00e9", q)) == "Aé"   # BMP
        @test Cookie.parse_json(string(q, bs, "ud83c", bs, "udf6a", q)) == "🍪"   # surrogate pair
    end

    @testset "parse_json: errors" begin
        @test_throws Cookie.JSONError Cookie.parse_json("")
        @test_throws Cookie.JSONError Cookie.parse_json("[1, 2")         # unterminated array
        @test_throws Cookie.JSONError Cookie.parse_json("{\"a\": }")     # missing value
        @test_throws Cookie.JSONError Cookie.parse_json("\"abc")         # unterminated string
        @test_throws Cookie.JSONError Cookie.parse_json("tru")           # bad literal
        @test_throws Cookie.JSONError Cookie.parse_json("[1] junk")      # trailing junk
        @test_throws Cookie.JSONError Cookie.parse_json(raw""" "\x" """) # invalid escape
    end

    @testset "parse_expires_field" begin
        @test Cookie.parse_expires_field(nothing) === nothing
        @test Cookie.parse_expires_field("") === nothing
        @test Cookie.parse_expires_field("2030-01-01T00:00:00Z") == DateTime(2030, 1, 1)
        @test Cookie.parse_expires_field("2030-01-01T00:00:00")  == DateTime(2030, 1, 1)
        @test Cookie.parse_expires_field(0) === nothing                  # non-positive -> session
        @test Cookie.parse_expires_field(1_600_000_000) == unix2datetime(1_600_000_000)
        @test_throws Cookie.JSONError Cookie.parse_expires_field("not-a-date")
    end

    @testset "parse_expires_opt" begin
        @test Cookie.parse_expires_opt("") === nothing
        @test Cookie.parse_expires_opt("session") === nothing
        @test Cookie.parse_expires_opt("SESSION") === nothing
        @test Cookie.parse_expires_opt("2030-06-15T12:00:00") == DateTime(2030, 6, 15, 12)
    end

    @testset "cookies_from_json" begin
        json = """
        [
          {"host": ".x.com", "name": "sid", "path": "/", "value": "abc",
           "expires": "2030-01-01T00:00:00Z", "secure": true, "httponly": true},
          {"host": "y.com", "name": "p", "value": "v"}
        ]
        """
        cs = Cookie.cookies_from_json(json)
        @test length(cs) == 2
        @test cs[1].host == ".x.com"
        @test cs[1].value == "abc"
        @test cs[1].expires == DateTime(2030, 1, 1)
        @test cs[1].secure && cs[1].httponly
        @test cs[2].path == "/"             # default
        @test cs[2].expires === nothing     # default (session)
        @test cs[2].secure === false        # default

        # Errors: not an array, element not an object, missing required field.
        @test_throws Cookie.JSONError Cookie.cookies_from_json("{}")
        @test_throws Cookie.JSONError Cookie.cookies_from_json("[1]")
        @test_throws Cookie.JSONError Cookie.cookies_from_json("""[{"name":"n","value":"v"}]""")
    end

    # The encoder and decoder are exact inverses: this is the read-on-A /
    # write-on-B migration path, so it must survive arbitrary cookie values.
    @testset "print_json / cookies_from_json round-trip" begin
        cookies = [
            (host = ".a.com", name = "one", path = "/", value = "plain",
             expires = DateTime(2031, 2, 3, 4, 5, 6), secure = true, httponly = false),
            (host = "b.org", name = "two", path = "/app",
             value = "quote\" back\\slash\ttab\nnl \u2615 café", expires = nothing,
             secure = false, httponly = true),
        ]
        io = IOBuffer(); Cookie.print_json(io, cookies)
        back = Cookie.cookies_from_json(String(take!(io)))
        @test length(back) == 2
        for (a, b) in zip(cookies, back)
            @test a.host == b.host && a.name == b.name && a.path == b.path
            @test a.value == b.value          # every escape survives
            @test a.expires == b.expires
            @test a.secure == b.secure && a.httponly == b.httponly
        end
    end

    # `write` dispatch glue: the branches that run before key derivation, so no
    # keyring/Keychain access is triggered.
    @testset "write dispatch (pre-key paths)" begin
        # Single-cookie mode without --host is rejected early.
        @test_throws ErrorException Cookie.write("chrome"; name = "x", value = "v")

        # JSON mode with nothing to write returns 0 without deriving keys.
        empty_file = joinpath(mktempdir(), "empty.json")
        write(empty_file, "[]")
        @test Cookie.write("chrome"; input = empty_file) == 0

        # A domain filter that excludes everything is likewise a no-op.
        some_file = joinpath(mktempdir(), "cookies.json")
        write(some_file, """[{"host":"keep.com","name":"n","value":"v"}]""")
        @test Cookie.write("chrome"; input = some_file, domain = "nomatch.example") == 0
    end

end
