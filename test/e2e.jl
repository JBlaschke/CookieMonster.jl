# End-to-end tests against a real headless browser. Two directions:
#
#   1. read : the browser writes a known cookie, CookieMonster reads it back and
#             decrypts it through the full pipeline (derive_keys -> snapshot ->
#             SQLite -> decrypt_value).
#   2. write: CookieMonster writes an encrypted cookie into a real profile, then
#             the browser is relaunched and asked for its cookies — proving the
#             row we wrote is well-formed and decrypts under the browser's own
#             key (encrypt_value + build_row + the real schema).
#
# Why this can run without a keychain: on Linux with no desktop keyring (the
# case on a CI runner), Chromium encrypts cookies with the hardcoded password
# "peanuts" under the v10 scheme when launched with --password-store=basic.
# That is exactly CookieMonster's Linux v10 path, so derive_keys("chromium")
# reproduces the key deterministically. macOS (random Keychain key) and Windows
# (app-bound "v20") are intentionally out of scope here.
#
# These tests are opt-in. Enable them with:
#     export COOKIEMONSTER_E2E=1
#     pip install playwright && python -m playwright install chromium
# Without COOKIEMONSTER_E2E=1 (or off Linux) they are skipped, so a plain
# `Pkg.test()` never needs a browser.

using Test
using Dates

# Playwright driver: open a persistent Chromium profile, set one known cookie,
# and close so the encrypted cookie is flushed to the on-disk Cookies DB. This
# both seeds the read test and creates the profile/DB the write test needs.
const E2E_SET_PYSCRIPT = raw"""
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

# Playwright driver: open the same persistent profile and print every cookie the
# browser loaded, one per line, tab-separated and prefixed so the Julia side can
# pick them out of stdout. A cookie only appears here if the browser accepted the
# on-disk row and decrypted its value with its own key.
const E2E_DUMP_PYSCRIPT = raw"""
import sys
from playwright.sync_api import sync_playwright

user_data_dir = sys.argv[1]
with sync_playwright() as p:
    ctx = p.chromium.launch_persistent_context(
        user_data_dir,
        headless=True,
        args=["--password-store=basic", "--no-sandbox", "--disable-dev-shm-usage"],
    )
    for c in ctx.cookies():
        print("COOKIE\t%s\t%s\t%s\t%s\t%s\t%s" % (
            c["name"], c["value"], c["domain"],
            c.get("secure", False), c.get("httpOnly", False),
            c.get("sameSite", "")))
    ctx.close()
"""

# Locate a Python interpreter, or fail the (already-enabled) test loudly.
function e2e_python()
    py = Sys.which("python3")
    py === nothing && (py = Sys.which("python"))
    py === nothing &&
        error("COOKIEMONSTER_E2E=1 but neither python3 nor python is on PATH")
    return py
end

# Run a Playwright script, returning its stdout. Surfaces stderr on failure
# (e.g. Playwright or Chromium not installed) instead of a cryptic exit code.
function e2e_run(py, script_body, args...)
    script = joinpath(mktempdir(), "driver.py")
    write(script, script_body)
    out, err = IOBuffer(), IOBuffer()
    proc = run(pipeline(ignorestatus(`$py $script $(collect(args))`);
                        stdout = out, stderr = err))
    proc.exitcode == 0 || error(
        "Playwright driver failed (exit $(proc.exitcode)):\n" * String(take!(err))
    )
    return String(take!(out))
end

# Parse the "COOKIE\t..." lines emitted by E2E_DUMP_PYSCRIPT into NamedTuples.
function e2e_parse(dump)
    cookies = NamedTuple[]
    for line in split(dump, '\n')
        startswith(line, "COOKIE\t") || continue
        _, name, value, domain, secure, httponly, samesite = split(line, '\t')
        push!(cookies, (name = name, value = value, domain = domain,
                        secure = secure == "True", httponly = httponly == "True",
                        samesite = samesite))
    end
    return cookies
end

# Decide once whether to run, so the "skipped" note is printed only once.
run_e2e = get(ENV, "COOKIEMONSTER_E2E", "") == "1"
if run_e2e && !Sys.islinux()
    @info "e2e tests skipped: only supported on Linux (peanuts/basic key store)"
    global run_e2e = false
elseif !run_e2e
    @info "e2e tests skipped (set COOKIEMONSTER_E2E=1 to enable)"
end

@testset "e2e: real browser roundtrip (read)" begin
    if run_e2e
        py = e2e_python()
        user_data_dir = mktempdir()
        e2e_run(py, E2E_SET_PYSCRIPT, user_data_dir)   # browser writes cm_e2e

        # Real key derivation (Linux peanuts v10) + real on-disk profile.
        cookies = read_cookies("chromium"; base = user_data_dir,
                               profile = "Default", domain = "cookiemonster")
        matches = filter(c -> c.name == "cm_e2e", cookies)
        @test length(matches) == 1
        c = only(matches)
        @test c.value == "monster_nomnom_42"   # decrypted through the full real pipeline
        @test occursin("cookiemonster.test", c.host)
        @test c.secure === true
        @test c.httponly === true
        @test c.samesite == "lax"              # the browser set SameSite=Lax; read it back
    end
end

@testset "e2e: CookieMonster writes, real browser reads" begin
    if run_e2e
        py = e2e_python()
        user_data_dir = mktempdir()
        # 1. Seed the profile so the Cookies DB + table exist (and leave cm_e2e
        #    in place, to prove our write coexists with a browser-written cookie).
        e2e_run(py, E2E_SET_PYSCRIPT, user_data_dir)

        # 2. CookieMonster encrypts and writes a cookie into the closed profile.
        #    scheme/keys auto-derive to the Linux v10 "peanuts" store, matching
        #    what the browser itself uses under --password-store=basic.
        write_cookie("chromium"; base = user_data_dir, profile = "Default",
            host = "cookiemonster.test", name = "cm_write",
            value = "written_by_cm_99",
            expires = Dates.now(Dates.UTC) + Dates.Year(1),
            # SameSite=None (needs Secure) is the case that matters for cross-site
            # SSO replay and the one a Lax-downgrade bug would break; prove the
            # real browser accepts and reports it as None.
            secure = true, httponly = true, samesite = :none,
            allow_running = true,   # profile is closed; skip the lingering-lock heuristic
            backup = false)

        # 3. The browser reloads the profile and returns the cookies it accepted.
        dumped = e2e_parse(e2e_run(py, E2E_DUMP_PYSCRIPT, user_data_dir))

        written = filter(c -> c.name == "cm_write", dumped)
        @test length(written) == 1                 # browser accepted & decrypted our row
        w = only(written)
        @test w.value == "written_by_cm_99"        # our value, via the browser's own key
        @test occursin("cookiemonster.test", w.domain)
        @test w.secure === true
        @test w.httponly === true
        @test w.samesite == "None"                 # SameSite=None survived CM -> browser

        # The browser-written cookie is still there: our write replaced nothing else.
        seeded = filter(c -> c.name == "cm_e2e", dumped)
        @test length(seeded) == 1
        @test only(seeded).value == "monster_nomnom_42"
    end
end
