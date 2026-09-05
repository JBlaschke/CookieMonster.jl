# syntax=docker/dockerfile:1
#
# Reproducible environment for CookieMonster.jl's browser end-to-end test
# (test/e2e.jl). It bakes in Julia, Python, Playwright and Chromium so the
# Linux-only "peanuts" cookie path (v10, --password-store=basic) -- which cannot
# run on macOS -- can be exercised identically on any host with Docker or Podman.
#
# Build from the repository root. Easiest is the wrapper:  ./docker/run-e2e.sh
# Manual:
#   docker build -f docker/Dockerfile -t cookiemonster-e2e .
#   docker run --rm --shm-size=1g cookiemonster-e2e

ARG JULIA_VERSION=1.10
FROM julia:${JULIA_VERSION}

ENV DEBIAN_FRONTEND=noninteractive \
    PIP_NO_CACHE_DIR=1 \
    PIP_BREAK_SYSTEM_PACKAGES=1

# Python + Playwright + Chromium (and the system libraries Chromium needs).
# This is the heavy, slow-changing layer, so it comes first for cache reuse.
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 python3-pip ca-certificates \
 && pip3 install playwright \
 && python3 -m playwright install --with-deps chromium \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /pkg

# Dependency layer: cached until Project.toml changes. Download the Julia deps
# without precompiling (the package source is not present in this layer yet).
COPY Project.toml ./
RUN JULIA_PKG_PRECOMPILE_AUTO=0 julia -e 'using Pkg; Pkg.activate("."); Pkg.instantiate()'

# Package source + full precompile, baked into the image so runs start fast.
COPY src ./src
COPY test ./test
RUN julia --project=. -e 'using Pkg; Pkg.precompile()'

COPY docker/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
