# End-to-end test: a real headless browser writes a known cookie to a real
# profile, then CookieMonster reads it back and decrypts it through the full
# pipeline (derive_keys -> snapshot -> SQLite -> decrypt_value).
#
# Why this can run without a keychain: on Linux with no desktop keyring (the
# case on a CI runner), Chromium encrypts cookies with the hardcoded password
# "peanuts" under the v10 scheme when launched with --password-store=basic.
# That is exactly CookieMonster's Linux v10 path, so derive_keys("chromium")
# reproduces the key deterministically. macOS (random Keychain key) and Windows
# (app-bound "v20") are intentionally out of scope here.
#
# This test is opt-in. Enable it with:
#     export COOKIEMONSTER_E2E=1
#     pip install playwright && python -m playwright install chromium
# Without COOKIEMONSTER_E2E=1 (or off Linux) it is skipped, so a plain
# `Pkg.test()` never needs a browser.

using Test

# Playwright driver: open a persistent Chromium profile, set one known cookie,
# and close so the encrypted cookie is flushed to the on-disk Cookies DB.
const E2E_PYSCRIPT = raw"""
import sys, time
from playwright.sync_api import sync_playwright

user_data_dir = sys.argv[1]
with sync_playwright() as p:
    ctx = p.chromium.launch_persistent_context(
        user_data_dir,
        headless=True,
        # --password-store=basic forces the hardcoded "peanuts" v10 key store
        # (no keyring); --no-sandbox is required when running as root in CI;
        # --disable-dev-shm-usage avoids crashes where /dev/shm is small.
        args=["--password-store=basic", "--no-sandbox", "--disable-dev-shm-usage"],
    )
    ctx.add_cookies([{
        "name": "cm_e2e",
        "value": "monster_nomnom_42",
        "domain": "cookiemonster.test",
        "path": "/",
        "expires": time.time() + 31_536_000,  # +1y: a session cookie would not persist
        "httpOnly": True,
        "secure": True,
        "sameSite": "Lax",
    }])
    ctx.close()
"""

@testset "e2e: real browser roundtrip" begin
    if get(ENV, "COOKIEMONSTER_E2E", "") != "1"
        @info "e2e test skipped (set COOKIEMONSTER_E2E=1 to enable)"
    elseif !Sys.islinux()
        @info "e2e test skipped: only supported on Linux (peanuts/basic key store)"
    else
        py = Sys.which("python3")
        py === nothing && (py = Sys.which("python"))
        py === nothing && error(
            "COOKIEMONSTER_E2E=1 but neither python3 nor python is on PATH"
        )

        user_data_dir = mktempdir()
        script = joinpath(mktempdir(), "set_cookie.py")
        write(script, E2E_PYSCRIPT)

        # Run the browser driver; surface stderr if it fails (e.g. Playwright
        # or Chromium not installed) instead of a cryptic nonzero-exit error.
        err = IOBuffer()
        proc = run(
            pipeline(
                ignorestatus(`$py $script $user_data_dir`);
                stdout = devnull,
                stderr = err
            )
        )
        proc.exitcode == 0 ||
            error("Playwright driver failed (exit $(proc.exitcode)):\n" * String(take!(err)))

        # Real key derivation (Linux peanuts v10) + real on-disk profile.
        cookies = read_cookies(
            "chromium";
            base = user_data_dir,
            profile = "Default",
            domain = "cookiemonster"
        )
        matches = filter(c -> c.name == "cm_e2e", cookies)
        @test length(matches) == 1
        c = only(matches)
        @test c.value == "monster_nomnom_42"  # decrypted through the full real pipeline
        @test occursin("cookiemonster.test", c.host)
        @test c.secure === true
        @test c.httponly === true
    end
end
