```@meta
CurrentModule = CookieMonster
```

# CookieMonster.jl

Read, decrypt, and write cookies for Chromium-based browsers — Google Chrome,
Chromium, and Brave — on macOS and Linux, directly from the browser's on-disk
cookie store.

Each browser keeps its cookies in an SQLite database whose values are encrypted
with AES-128-CBC. The key is derived (via PBKDF2-HMAC-SHA1) from a per-browser
"Safe Storage" password held in the operating-system keyring: the login Keychain
on macOS, or a Secret Service keyring on Linux (with a well-known fallback key
when no keyring is available). CookieMonster reproduces that scheme and hands you
the decrypted cookies as plain Julia values.

!!! warning "`read_cookies` decrypts your real browser secrets"
    The values returned by [`read_cookies`](@ref) include live session tokens,
    authentication cookies, and other credentials belonging to the browser's
    signed-in user. On macOS the first call prompts for Keychain access. Treat
    the results as sensitive data: do not log them, print them in shared
    terminals, or transmit them to third parties.

## Installation

CookieMonster is not registered, so install it directly from GitHub:

```julia
using Pkg
Pkg.add(url = "https://github.com/JBlaschke/CookieMonster.jl")
```

## Quick start

```julia
using CookieMonster

# All cookies from Chrome's default profile
cookies = read_cookies("chrome")

# Just the cookies for one domain
gh = read_cookies("chrome"; domain = "github.com")

for c in gh
    println(c.name, " = ", c.value, "   (expires ", c.expires, ")")
end
```

Each element is a `NamedTuple` with the following fields:

| Field      | Type                      | Description                                   |
|:-----------|:--------------------------|:----------------------------------------------|
| `host`     | `String`                  | Cookie host / domain (the `host_key` column). |
| `name`     | `String`                  | Cookie name.                                  |
| `path`     | `String`                  | Path scope of the cookie.                     |
| `value`    | `String`                  | Decrypted cookie value.                       |
| `expires`  | `DateTime` or `nothing`   | Expiry, or `nothing` for a session cookie.    |
| `secure`   | `Bool`                    | `Secure` attribute.                           |
| `httponly` | `Bool`                    | `HttpOnly` attribute.                         |

## Writing cookies

[`write_cookie`](@ref) is the inverse of `read_cookies`: it encrypts a value
exactly the way the browser does and inserts a fully-formed row into the cookie
store.

```julia
using CookieMonster, Dates

write_cookie("chrome";
    host     = ".example.com",
    name     = "session",
    value    = "s3cr3t-token",
    expires  = now(UTC) + Year(1),   # omit for a session cookie
    secure   = true,
    httponly = true,
)
```

Because `read_cookies` returns `NamedTuple`s, a cookie can be read, modified, and
written back — the second form of `write_cookie` takes such a tuple, and keyword
arguments override its fields:

```julia
c = only(read_cookies("chrome"; domain = "example.com"))
write_cookie("chrome", c; value = "rotated-token")
```

!!! warning "Quit the browser before writing"
    Chromium keeps its cookies in an in-memory store and flushes them through to
    SQLite, so writing to the live database while the browser is open is
    unreliable — the write can be lost or clobbered. By default `write_cookie`
    refuses when it detects the browser running (see [`browser_running`](@ref));
    it also backs the database up to `<Cookies>.cmbak` first. An existing cookie
    with the same `(host, name, path)` is replaced.

The `cookies` table must already exist, so the target profile must have been
created by at least one prior browser run. See [`write_cookie`](@ref) for the
full list of keyword arguments (`path`, `samesite`, `scheme`, `host_prefix`,
`profile`, `base`, `keys`, …).

## Supported browsers and platforms

| Browser  | `browser` argument | macOS | Linux |
|:---------|:-------------------|:-----:|:-----:|
| Chrome   | `"chrome"`         |   ✅   |   ✅   |
| Chromium | `"chromium"`       |   ✅   |   ✅   |
| Brave    | `"brave"`          |   ✅   |   ✅   |

On macOS the decryption password is read from the login Keychain (`v10` keys).
On Linux the value is decrypted with the `v11` key from the Secret Service
keyring when available, falling back to the `v10` "peanuts" key otherwise.

## Selecting a profile or database

By default CookieMonster reads the `Default` profile from the browser's standard
data directory. Pass `profile` to pick a different profile, or `base` to point at
a data directory in a non-standard location:

```julia
read_cookies("chrome"; profile = "Profile 1")
read_cookies("chromium"; base = "/path/to/chromium/User Data")
```

See [`cookie_db_path`](@ref) for how the database file is located.

## Next steps

The complete list of exported and internal functions, with signatures and
argument descriptions, is on the [API reference](@ref) page.
