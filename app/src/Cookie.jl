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

#______________________________________________________________________________
# Minimal JSON decoding.
#
# The inverse of the encoder above, for `cookie write`. A small recursive-descent
# parser keeps the app dependency-free while still handling the full JSON value
# grammar for what we consume (arrays of flat objects with string, number, bool
# and null values, including every string escape). It is not a general-purpose
# library, but it round-trips `cookie read --json` exactly and tolerates cookie
# dumps from other tools whose field names line up.

struct JSONError <: Exception
    msg::String
end
Base.showerror(io::IO, e::JSONError) = print(io, "JSON parse error: ", e.msg)

mutable struct JParser
    c::Vector{Char}
    i::Int
end
JParser(s::AbstractString) = JParser(collect(s), 1)

_done(p::JParser) = p.i > length(p.c)
_peek(p::JParser) = _done(p) ? '\0' : p.c[p.i]
_advance!(p::JParser) = (ch = p.c[p.i]; p.i += 1; ch)

function _skipws!(p::JParser)
    while !_done(p) && _peek(p) in (' ', '\t', '\n', '\r')
        p.i += 1
    end
end

function _expect!(p::JParser, ch::Char)
    (_done(p) || _advance!(p) != ch) && throw(JSONError("expected '$ch'"))
end

"""
    parse_json(s) -> Any

Parse a JSON document into Julia values: `Dict{String,Any}` for objects,
`Vector{Any}` for arrays, `String`, `Int`/`Float64`, `Bool`, and `nothing` for
`null`. Throws `JSONError` on malformed input.
"""
function parse_json(s::AbstractString)
    p = JParser(s)
    _skipws!(p)
    v = _parse_value!(p)
    _skipws!(p)
    _done(p) || throw(JSONError("trailing characters after JSON value"))
    return v
end

function _parse_value!(p::JParser)
    _skipws!(p)
    _done(p) && throw(JSONError("unexpected end of input"))
    ch = _peek(p)
    ch == '{' && return _parse_object!(p)
    ch == '[' && return _parse_array!(p)
    ch == '"' && return _parse_string!(p)
    (ch == 't' || ch == 'f') && return _parse_bool!(p)
    ch == 'n' && return _parse_null!(p)
    return _parse_number!(p)
end

function _parse_object!(p::JParser)
    _expect!(p, '{')
    obj = Dict{String,Any}()
    _skipws!(p)
    if _peek(p) == '}'
        _advance!(p); return obj
    end
    while true
        _skipws!(p)
        _peek(p) == '"' || throw(JSONError("expected string key"))
        key = _parse_string!(p)
        _skipws!(p)
        _expect!(p, ':')
        obj[key] = _parse_value!(p)
        _skipws!(p)
        _done(p) && throw(JSONError("unterminated object"))
        ch = _advance!(p)
        ch == ',' && continue
        ch == '}' && break
        throw(JSONError("expected ',' or '}' in object"))
    end
    return obj
end

function _parse_array!(p::JParser)
    _expect!(p, '[')
    arr = Any[]
    _skipws!(p)
    if _peek(p) == ']'
        _advance!(p); return arr
    end
    while true
        push!(arr, _parse_value!(p))
        _skipws!(p)
        _done(p) && throw(JSONError("unterminated array"))
        ch = _advance!(p)
        ch == ',' && continue
        ch == ']' && break
        throw(JSONError("expected ',' or ']' in array"))
    end
    return arr
end

_hexval(c::Char) =
    '0' <= c <= '9' ? Int(c - '0') :
    'a' <= c <= 'f' ? Int(c - 'a') + 10 :
    'A' <= c <= 'F' ? Int(c - 'A') + 10 :
    throw(JSONError("invalid hex digit '$c'"))

function _parse_hex4!(p::JParser)
    v = 0
    for _ in 1:4
        _done(p) && throw(JSONError("truncated \\u escape"))
        v = v * 16 + _hexval(_advance!(p))
    end
    return v
end

function _parse_string!(p::JParser)
    _expect!(p, '"')
    io = IOBuffer()
    while true
        _done(p) && throw(JSONError("unterminated string"))
        ch = _advance!(p)
        if ch == '"'
            break
        elseif ch == '\\'
            _done(p) && throw(JSONError("unterminated escape"))
            esc = _advance!(p)
            if     esc == '"';  print(io, '"')
            elseif esc == '\\'; print(io, '\\')
            elseif esc == '/';  print(io, '/')
            elseif esc == 'b';  print(io, '\b')
            elseif esc == 'f';  print(io, '\f')
            elseif esc == 'n';  print(io, '\n')
            elseif esc == 'r';  print(io, '\r')
            elseif esc == 't';  print(io, '\t')
            elseif esc == 'u'
                cp = _parse_hex4!(p)
                if 0xD800 <= cp <= 0xDBFF          # high surrogate -> need the low one
                    (_advance!(p) == '\\' && _advance!(p) == 'u') ||
                        throw(JSONError("expected low surrogate"))
                    lo = _parse_hex4!(p)
                    (0xDC00 <= lo <= 0xDFFF) || throw(JSONError("invalid low surrogate"))
                    cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00)
                end
                print(io, Char(cp))
            else
                throw(JSONError("invalid escape \\$esc"))
            end
        else
            print(io, ch)
        end
    end
    return String(take!(io))
end

function _parse_bool!(p::JParser)
    if _peek(p) == 't'
        _matchlit!(p, "true"); return true
    else
        _matchlit!(p, "false"); return false
    end
end

_parse_null!(p::JParser) = (_matchlit!(p, "null"); nothing)

function _matchlit!(p::JParser, lit::AbstractString)
    for ch in lit
        (_done(p) || _advance!(p) != ch) &&
            throw(JSONError("invalid literal, expected '$lit'"))
    end
end

function _parse_number!(p::JParser)
    start = p.i
    while !_done(p) && (_peek(p) in ('-', '+', '.', 'e', 'E') || isdigit(_peek(p)))
        p.i += 1
    end
    str = String(p.c[start:p.i-1])
    isempty(str) && throw(JSONError("expected a JSON value"))
    v = tryparse(Int, str)
    v !== nothing && return v
    f = tryparse(Float64, str)
    f !== nothing && return f
    throw(JSONError("invalid number '$str'"))
end

#______________________________________________________________________________
# Mapping parsed JSON to cookies.
#

"""
    parse_expires_field(x) -> Union{DateTime, Nothing}

Interpret a JSON `expires` value: `null`/`""` -> `nothing` (session cookie); an
ISO 8601 string (with or without a trailing `Z`, as the encoder emits) -> the
corresponding `DateTime`; a number -> Unix seconds since 1970 (as browser and
extension dumps often store it).
"""
function parse_expires_field(x)
    x === nothing && return nothing
    if x isa AbstractString
        isempty(x) && return nothing
        s = endswith(x, "Z") ? x[1:end-1] : x
        dt = tryparse(DateTime, s)
        dt === nothing && throw(JSONError("could not parse expires \"$x\""))
        return dt
    elseif x isa Real
        return x <= 0 ? nothing : unix2datetime(x)
    end
    throw(JSONError("invalid expires value $(repr(x))"))
end

"""
    cookies_from_json(text) -> Vector{NamedTuple}

Parse `text` (a JSON array of cookie objects, as produced by `cookie read
--json`) into cookie NamedTuples suitable for `write_cookies`. Requires `host`,
`name`, and `value` on each object; `path`, `expires`, `secure`, and `httponly`
default when absent.
"""
function cookies_from_json(text::AbstractString)
    v = parse_json(text)
    v isa AbstractVector || throw(JSONError("expected a JSON array of cookie objects"))
    out = NamedTuple[]
    for (k, item) in enumerate(v)
        item isa AbstractDict || throw(JSONError("array element $k is not an object"))
        req(key) = haskey(item, key) ? item[key] :
                   throw(JSONError("cookie $k is missing \"$key\""))
        push!(out, (
            host     = String(req("host")),
            name     = String(req("name")),
            path     = String(get(item, "path", "/")),
            value    = String(req("value")),
            expires  = parse_expires_field(get(item, "expires", nothing)),
            secure   = get(item, "secure", false) === true,
            httponly = get(item, "httponly", false) === true,
        ))
    end
    return out
end

# Parse the CLI `--expires` option: "" or "session" -> nothing; otherwise an
# ISO 8601 timestamp or a Unix epoch (seconds).
function parse_expires_opt(s::AbstractString)
    (isempty(s) || lowercase(s) == "session") && return nothing
    return parse_expires_field(s)
end

#______________________________________________________________________________
# CLI: `cookie read` and `cookie write`.
#

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
@cast function read(
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

"""
Write cookies into a Chromium-based browser's cookie store, from a JSON array
(as produced by `cookie read --json`, via `--input` or stdin) or a single
`--host`/`--name`/`--value`. Replaces any cookie with the same host/name/path.
Quit the browser first (see `--allow-running`); the database is backed up to
`<Cookies>.cmbak` beforehand.

# Arguments

- `browser`: which browser to write to — chrome, chromium, or brave.

# Options

- `-i, --input <file>`: JSON file to read (default: standard input).
- `-p, --profile <name>`: browser profile to write to.
- `-d, --domain <substr>`: with JSON input, only write cookies whose host
  contains this substring.
- `--base <dir>`: override the browser's data directory.
- `--host <h>`: single-cookie mode — the cookie host (e.g. `.example.com`).
- `--name <n>`: single-cookie mode — the cookie name (selects this mode).
- `--value <v>`: single-cookie mode — the cookie value.
- `--path <p>`: single-cookie mode — the path scope (default `/`).
- `--expires <t>`: single-cookie mode — ISO 8601 UTC (e.g.
  `2030-01-01T00:00:00`), a Unix timestamp, or `session` (default).
- `--samesite <s>`: single-cookie mode — unspecified, none, lax, or strict
  (default lax).

# Flags

- `--secure`: single-cookie mode — set the Secure attribute.
- `--httponly`: single-cookie mode — set the HttpOnly attribute.
- `--allow-running`: write even if the browser appears to be running (unsafe).
- `--no-backup`: do not back up the database before writing.
"""
@cast function write(
            browser::String = "chrome";
            input::String = "", profile::String = "Default",
            domain::String = "", base::String = "",
            host::String = "", name::String = "", value::String = "",
            path::String = "/", expires::String = "", samesite::String = "lax",
            secure::Bool = false, httponly::Bool = false,
            allow_running::Bool = false, no_backup::Bool = false
        )
    base_opt = isempty(base) ? nothing : base

    if !isempty(name)
        # Single-cookie mode.
        isempty(host) && error("single-cookie mode (--name) also needs --host")
        write_cookie(browser;
            host = host, name = name, value = value, path = path,
            expires = parse_expires_opt(expires), secure = secure,
            httponly = httponly, samesite = Symbol(lowercase(samesite)),
            profile = profile, base = base_opt,
            allow_running = allow_running, backup = !no_backup,
        )
        println(stderr, "Wrote 1 cookie to $browser ($host / $name).")
        return 0
    end

    # JSON mode: from --input, or standard input.
    text = isempty(input) ? Base.read(stdin, String) : Base.read(input, String)
    cookies = cookies_from_json(text)
    isempty(domain) || filter!(c -> occursin(domain, c.host), cookies)
    if isempty(cookies)
        println(stderr, "No cookies to write.")
        return 0
    end
    n = write_cookies(browser, cookies;
        profile = profile, base = base_opt,
        allow_running = allow_running, backup = !no_backup,
    )
    println(stderr, "Wrote $n cookie(s) to $browser.")
    return 0
end

"""
Read, decrypt, and write cookies for Chromium-based browsers (Chrome, Chromium,
Brave) on macOS and Linux.
"""
Comonicon.@main

end # module Cookie
