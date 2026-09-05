```@meta
CurrentModule = CookieMonster
```

# CookieMonster.jl

Read and decrypt cookies from Chromium-based browsers — Google Chrome, Chromium,
and Brave — on macOS and Linux, directly from the browser's on-disk cookie store.

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
