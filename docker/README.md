# Containerised end-to-end test

CookieMonster's browser end-to-end test (`test/e2e.jl`) is **Linux-only**: it
relies on Chromium's keyring-free "peanuts" cookie store (v10,
`--password-store=basic`), which does not apply on macOS (random Keychain key)
or Windows (app-bound "v20"). This directory packages a reproducible environment
— Julia + Python + Playwright + Chromium — so the test can be run cleanly on any
host with Docker or Podman.

## Quick start

From the repository root:

```bash
./docker/run-e2e.sh
```

This builds the image and runs the **full test suite** (unit + E2E) inside it,
printing a summary like:

```
Test Summary:    | Pass  Total  Time
CookieMonster.jl |   71     71
Test Summary:               | Pass  Total  Time
e2e: real browser roundtrip |    5      5
```

## Options

- **Engine:** auto-detects `docker`, else `podman`. Force one with
  `CONTAINER_ENGINE=podman ./docker/run-e2e.sh`.
- **Julia version:** `JULIA_VERSION=1.12 ./docker/run-e2e.sh` (default `1.10`).
- **Debug shell:** `./docker/run-e2e.sh bash` drops you into the image at `/pkg`.

## What's inside

- [`Dockerfile`](Dockerfile) — a `julia:$JULIA_VERSION` base with Python,
  Playwright and Chromium installed and the Julia dependencies precompiled.
- [`entrypoint.sh`](entrypoint.sh) — runs `Pkg.test()` with
  `COOKIEMONSTER_E2E=1`, or any command you pass.
- [`run-e2e.sh`](run-e2e.sh) — auto-detects the engine, builds the image, runs it.

The source is copied into the image at build time, so the container runs entirely
self-contained and nothing is written to your working copy. Re-running the script
after editing code rebuilds only the cheap source layer (the browser and
dependency layers stay cached).

## Notes

- **Podman on macOS** needs its VM running first: `podman machine start`.
- CI runs the same test natively (see `.github/workflows/CI.yml`), installing
  Playwright directly on the runner; this container is for local reproducibility.
- If Chromium ever crashes with a `/dev/shm` error, raise the shared-memory size.
  `run-e2e.sh` already passes `--shm-size=1g`.
