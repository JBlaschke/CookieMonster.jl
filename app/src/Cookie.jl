module Cookie

using CookieMonster
using Comonicon
using Dates

#______________________________________________________________________________
# Minimal JSON encoding.
#
# The `--json` output is a flat array of objects with string, bool, and
# nullable-timestamp fields, so a tiny hand-rolled encoder keeps the compiled
# app free of a JSON dependency. The only real subtlety is string escaping:
# decrypted cookie values are arbitrary and may contain quotes, backslashes, or
# control characters, all of which must be escaped per RFC 8259.

"""
    json_escape(io, s)

Write `s` to `io` with the characters that are illegal inside a JSON string
literal escaped: `"`, `\\`, and every control character `U+0000`–`U+001F` (the
five with short forms as `\\b`/`\\t`/`\\n`/`\\f`/`\\r`, the rest as `\\uXXXX`).
Everything else, including non-ASCII UTF-8, is emitted verbatim.
"""
function json_escape(io::IO, s::AbstractString)
    for c in s
        if c == '"'
            print(io, "\\\"")
        elseif c == '\\'
            print(io, "\\\\")
        elseif c == '\b'
            print(io, "\\b")
        elseif c == '\t'
            print(io, "\\t")
        elseif c == '\n'
            print(io, "\\n")
        elseif c == '\f'
            print(io, "\\f")
        elseif c == '\r'
            print(io, "\\r")
        elseif c < '\x20'
            print(io, "\\u", lpad(string(codepoint(c), base = 16), 4, '0'))
        else
            print(io, c)
        end
    end
end

# JSON scalar for each field type present in a cookie NamedTuple. Timestamps are
# UTC (see `chrome_time`), so the `Z` suffix makes that explicit and ISO 8601.
json_scalar(io::IO, s::AbstractString) = (print(io, '"'); json_escape(io, s); print(io, '"'))
json_scalar(io::IO, b::Bool)          = print(io, b ? "true" : "false")
json_scalar(io::IO, ::Nothing)        = print(io, "null")
json_scalar(io::IO, ::Missing)        = print(io, "null")  # a NULL column, in a malformed DB
json_scalar(io::IO, t::DateTime)      = (print(io, '"'); print(io, t); print(io, "Z\""))

"""
    print_json(io, cookies)

Write `cookies` (as returned by `read_cookies`) to `io` as a JSON array, one
object per line, with the fields `host`, `name`, `path`, `value`, `expires`
(an ISO 8601 UTC string, or `null` for a session cookie), `secure`, and
`httponly`.
"""
function print_json(io::IO, cookies)
    println(io, "[")
    n = length(cookies)
    for (i, c) in enumerate(cookies)
        print(io, "  {")
        for (key, val) in (
                    ("host", c.host), ("name", c.name), ("path", c.path),
                    ("value", c.value), ("expires", c.expires),
                    ("secure", c.secure), ("httponly", c.httponly)
                )
            print(io, '"', key, "\": ")
            json_scalar(io, val)
            key == "httponly" || print(io, ", ")
        end
        println(io, i < n ? "}," : "}")
    end
    println(io, "]")
end

"""
Read and decrypt cookies from a Chromium-based browser.

# Arguments

- `browser`: which browser to read — chrome, chromium, or brave.

# Options

- `-p, --profile <name>`: browser profile to read.
- `-d, --domain <substr>`: only cookies whose host contains this substring.
- `--base <dir>`: override the browser's data directory.

# Flags

- `--json`: emit a JSON array (host, name, path, value, expires, secure,
  httponly) instead of the default tab-separated host/name/value.
"""
Comonicon.@main function cookie(
            browser::String = "chrome";
            profile::String = "Default", domain::String = "", base::String = "",
            json::Bool = false
        )
    cookies = read_cookies(browser;
        profile = profile,
        domain  = isempty(domain) ? nothing : domain,
        base    = isempty(base)   ? nothing : base,
    )
    if json
        print_json(stdout, cookies)
    else
        for c in cookies
            println(c.host, "\t", c.name, "\t", c.value)
        end
    end
    return 0
end

# # Fallback for PackageCompiler.jl
# function julia_main()::Cint
#     try
#         args    = copy(ARGS)
#         browser = isempty(args) ? "chrome" : popfirst!(args)
#         i       = findfirst(==("--domain"), args)
#         domain  = i === nothing ? nothing : args[i + 1]
#         for c in read_cookies(browser; domain = domain)
#             println(c.host, "\t", c.name, "\t", c.value)
#         end
#     catch
#         Base.invokelatest(Base.display_error, Base.catch_stack())
#         return 1
#     end
#     return 0
# end

end # module Cookie
