#!/usr/bin/env julia
# Parse an lcov tracefile, print a per-file coverage table (appending it to the
# GitHub Actions job summary when running in CI), and exit nonzero when total
# line coverage falls below the floor. Stdlib only — no packages needed.
#
# Usage: julia .github/coverage_gate.jl <lcov.info> <floor-percent>

length(ARGS) == 2 || (println(stderr, "usage: coverage_gate.jl <lcov.info> <floor-percent>"); exit(2))
tracefile, floor_arg = ARGS
floor_pct = parse(Float64, floor_arg)

# Each record: SF:<file>, one DA:<line>,<count>[,...] per tracked line, end_of_record.
files = Vector{NamedTuple{(:file, :tracked, :hit), Tuple{String, Int, Int}}}()
let file = "", tracked = 0, hit = 0
    for line in eachline(tracefile)
        if startswith(line, "SF:")
            file, tracked, hit = chopprefix(line, "SF:"), 0, 0
        elseif startswith(line, "DA:")
            tracked += 1
            hit += parse(Int, split(chopprefix(line, "DA:"), ',')[2]) > 0
        elseif line == "end_of_record"
            push!(files, (; file, tracked, hit))
        end
    end
end
isempty(files) && (println(stderr, "no coverage records in $tracefile"); exit(2))

pct(hit, tracked) = tracked == 0 ? 100.0 : 100 * hit / tracked
fmt(x) = string(round(x; digits = 1), "%")
total_tracked = sum(f.tracked for f in files)
total_hit = sum(f.hit for f in files)
total = pct(total_hit, total_tracked)

rows = ["| File | Lines | Hit | Coverage |", "|---|---:|---:|---:|"]
for f in files
    push!(rows, "| `$(f.file)` | $(f.tracked) | $(f.hit) | $(fmt(pct(f.hit, f.tracked))) |")
end
push!(rows, "| **Total** | **$total_tracked** | **$total_hit** | **$(fmt(total))** |")

verdict = total >= floor_pct ? "meets" : "is below"
report = """
    ### Test coverage

    Total line coverage **$(fmt(total))** $verdict the $(fmt(floor_pct)) floor.

    $(join(rows, '\n'))
    """
println(report)
summary = get(ENV, "GITHUB_STEP_SUMMARY", "")
isempty(summary) || open(io -> println(io, report), summary, "a")

if total < floor_pct
    println("::error::Total line coverage $(fmt(total)) is below the $(fmt(floor_pct)) floor")
    exit(1)
end
