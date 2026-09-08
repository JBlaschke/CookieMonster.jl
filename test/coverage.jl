#!/usr/bin/env julia
# Local test-coverage report via LocalCoverage.jl
# (https://github.com/JuliaCI/LocalCoverage.jl).
#
# Usage:
#     julia test/coverage.jl          # run the tests, print a per-file summary
#     julia test/coverage.jl --html   # ... then build and open an HTML report
#
# LocalCoverage is installed into a throwaway environment, so it never touches
# the package's Project.toml. The lcov trace lands in coverage/lcov.info
# (gitignored). The HTML report needs `genhtml` from the lcov package
# (brew install lcov / apt install lcov).

using Pkg

repo = dirname(@__DIR__)

Pkg.activate(; temp = true)
Pkg.develop(path = repo)
Pkg.add("LocalCoverage")

using LocalCoverage

cov = generate_coverage("CookieMonster")
display(cov)
println()

if "--html" in ARGS
    try
        html_coverage(cov; open = true, dir = joinpath(repo, "coverage", "html"))
    catch
        @error "Building the HTML report failed — is `genhtml` installed? " *
               "(brew install lcov / apt install lcov)"
        rethrow()
    end
end
