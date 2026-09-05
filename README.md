# CookieMonster

[![Build Status](https://github.com/JBlaschke/CookieMonster.jl/actions/workflows/CI.yml/badge.svg?branch=main)](https://github.com/JBlaschke/CookieMonster.jl/actions/workflows/CI.yml?query=branch%3Amain)

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
