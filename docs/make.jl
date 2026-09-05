using CookieMonster
using Documenter

DocMeta.setdocmeta!(
    CookieMonster, :DocTestSetup, :(using CookieMonster); recursive = true
)

makedocs(;
    modules  = [CookieMonster],
    authors  = "Johannes Blaschke",
    sitename = "CookieMonster.jl",
    format   = Documenter.HTML(;
        canonical = "https://JBlaschke.github.io/CookieMonster.jl",
        edit_link = "main",
        assets    = String[],
    ),
    pages = [
        "Home"          => "index.md",
        "API reference" => "api.md",
    ],
)

deploydocs(;
    repo      = "github.com/JBlaschke/CookieMonster.jl",
    devbranch = "main",
)
