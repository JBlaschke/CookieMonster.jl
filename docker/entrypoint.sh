#!/usr/bin/env bash
# Default: run the full test suite with the browser E2E test enabled. Passing a
# command (e.g. `... bash`) runs that instead, for debugging inside the image.
set -euo pipefail

cd /pkg

if [ "$#" -gt 0 ]; then
    exec "$@"
fi

export COOKIEMONSTER_E2E=1
exec julia --project=. --color=yes -e 'using Pkg; Pkg.test()'
