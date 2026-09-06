module Cookie

using CookieMonster
using Comonicon

"""
Read and decrypt cookies from a Chromium-based browser.

# Arguments

- `browser`: which browser to read — chrome, chromium, or brave.

# Options

- `-p, --profile <name>`: browser profile to read.
- `-d, --domain <substr>`: only cookies whose host contains this substring.
- `--base <dir>`: override the browser's data directory.
"""
Comonicon.@main function cookie(
            browser::String = "chrome";
            profile::String = "Default", domain::String = "", base::String = ""
        )
    cookies = read_cookies(browser;
        profile = profile,
        domain  = isempty(domain) ? nothing : domain,
        base    = isempty(base)   ? nothing : base,
    )
    for c in cookies
        println(c.host, "\t", c.name, "\t", c.value)
    end
    return 0
end

# # Fallback for PackageCompiler.jl
# function julia_main()::Cint
#     try
#         args    = copy(ARGS)
#         browser = isempty(args) ? "chrome" : popfirst!(args)
#         i       = findfirst(==("--domain"), args)
#         domain  = i === nothing ? nothing : args[i + 1]
#         for c in read_cookies(browser; domain = domain)
#             println(c.host, "\t", c.name, "\t", c.value)
#         end
#     catch
#         Base.invokelatest(Base.display_error, Base.catch_stack())
#         return 1
#     end
#     return 0
# end

end # module Cookie
