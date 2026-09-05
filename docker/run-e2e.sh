#!/usr/bin/env bash
# Build the containerised E2E environment and run CookieMonster.jl's full test
# suite (including the real-browser E2E test) inside it. Works with Docker or
# Podman, on Linux or macOS.
#
# Usage:
#   ./docker/run-e2e.sh                          # build + run the full suite
#   JULIA_VERSION=1.12 ./docker/run-e2e.sh       # pick the Julia version (default 1.10)
#   CONTAINER_ENGINE=podman ./docker/run-e2e.sh  # force an engine (default: auto)
#   ./docker/run-e2e.sh bash                     # drop into a shell in the image
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

engine="${CONTAINER_ENGINE:-}"
if [ -z "$engine" ]; then
    if command -v docker >/dev/null 2>&1; then engine=docker
    elif command -v podman >/dev/null 2>&1; then engine=podman
    else
        echo "error: need docker or podman on PATH (or set CONTAINER_ENGINE)" >&2
        exit 1
    fi
fi

julia_version="${JULIA_VERSION:-1.10}"
image="cookiemonster-e2e:julia-${julia_version}"

echo ">> Building ${image} with ${engine}"
"$engine" build \
    --build-arg "JULIA_VERSION=${julia_version}" \
    -f "${ROOT}/docker/Dockerfile" \
    -t "${image}" \
    "${ROOT}"

echo ">> Running E2E suite (${engine})"
exec "$engine" run --rm --shm-size=1g "${image}" "$@"
