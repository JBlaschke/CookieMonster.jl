# CookieMonster

[![Dev](https://img.shields.io/badge/docs-dev-blue.svg)](https://JBlaschke.github.io/CookieMonster.jl/dev/)
[![Build Status](https://github.com/JBlaschke/CookieMonster.jl/actions/workflows/CI.yml/badge.svg?branch=main)](https://github.com/JBlaschke/CookieMonster.jl/actions/workflows/CI.yml?query=branch%3Amain)

CookieMonster reads and decrypts the cookies stored by Chromium-based browsers
— Chrome, Chromium, and Brave — on **macOS** and **Linux**.

Those browsers keep their cookies in an SQLite database, with each cookie value
encrypted using AES-128-CBC. The key is derived (PBKDF2-HMAC-SHA1) from a
per-browser "Safe Storage" password held in the OS keyring: the macOS Keychain,
or a Linux Secret Service keyring, with a well-known fallback on Linux.
CookieMonster locates the database, obtains the key, and hands you back the
decrypted cookies — without needing to close the running browser (it reads a
snapshot, write-ahead log included).

The package exposes a single function, `read_cookies`.

>[!WARNING]
> Reading the key may prompt for keyring access (a Keychain dialog on
> macOS) the first time. CookieMonster only decrypts cookies belonging to the
> current user; use it on your own machine and profiles.

## Documentation

- [**Stable docs**](https://JBlaschke.github.io/CookieMonster.jl/stable/) — for the
  latest tagged release.
- [**Dev docs**](https://JBlaschke.github.io/CookieMonster.jl/dev/) — built from `main`.

The [API reference](https://JBlaschke.github.io/CookieMonster.jl/dev/api/) documents
`read_cookies` and the internal helpers in full.

## Usage

```julia
using CookieMonster

# Read (and decrypt) every cookie from the default Chrome profile.
cookies = read_cookies("chrome")

# Each cookie is a NamedTuple:
c = first(cookies)
c.host      # e.g. ".github.com"
c.name      # cookie name
c.path      # e.g. "/"
c.value     # decrypted value (String)
c.expires   # DateTime, or nothing for a session cookie
c.secure    # Bool
c.httponly  # Bool
```

`read_cookies` takes the browser name as its first argument (`"chrome"`,
`"chromium"`, or `"brave"`, case-insensitive; defaults to `"chrome"`) plus a few
keyword arguments:

```julia
# Only cookies whose host contains a substring.
gh = read_cookies("chrome"; domain = "github.com")

# Read a non-default profile.
work = read_cookies("brave"; profile = "Profile 1")

# Point at a data directory in a non-standard location.
read_cookies("chromium"; base = "/path/to/user-data-dir")
```

| Keyword   | Default     | Description                                                        |
|-----------|-------------|--------------------------------------------------------------------|
| `profile` | `"Default"` | Which browser profile to read.                                     |
| `domain`  | `nothing`   | If set, keep only cookies whose host contains this substring.      |
| `base`    | `nothing`   | Override the browser's data directory (else a per-OS default).     |
| `keys`    | `nothing`   | Precomputed decryption keys; derived automatically when omitted.   |

For example, to grab a session token for use with `HTTP.jl`:

```julia
token = only(c.value for c in read_cookies("chrome"; domain = "example.com")
             if c.name == "session")
```

## Testing

Run the unit tests with:

```julia
using Pkg; Pkg.test()
```

The suite also includes an opt-in, Linux-only end-to-end test (`test/e2e.jl`)
that drives a real headless Chromium to write a cookie and checks that
CookieMonster reads it back and decrypts it. It is skipped unless
`COOKIEMONSTER_E2E=1` is set.

### Running the end-to-end test in a container

Because that test relies on Chromium's Linux "peanuts" key store, a reproducible
Docker/Podman environment is provided so it can be run cleanly on any host
(including macOS):

```bash
./docker/run-e2e.sh
```

See [`docker/README.md`](docker/README.md) for details.
