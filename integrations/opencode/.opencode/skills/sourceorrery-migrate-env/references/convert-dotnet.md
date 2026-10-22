# Converting .NET code (C#, F#, VB)

SDK: `dotnet add package SourceOrrery` (.NET 8 or newer; native library for
Windows, macOS and Linux, x64 and arm64, included; trimming and AOT
compatible). On an older runtime, keep the variables and start the
program with `sourceorrery run --`.

## One class for every read

```csharp
// Secrets.cs
using SourceOrrery;

/// <summary>Secrets from the SourceOrrery vault named in sourceorrery.toml.</summary>
public static class Secrets
{
    private static readonly Project LoadedProject = Project.Load(); // nearest sourceorrery.toml

    /// <summary>The value delivered as environment variable <paramref name="name"/>.</summary>
    public static string Get(string name) =>
        LoadedProject.Env(name)?.ExposeText()
        ?? throw new InvalidOperationException($"{name} is not available from sourceorrery.toml");

    public static string? GetOrDefault(string name, string? fallback = null) =>
        LoadedProject.Env(name)?.ExposeText() ?? fallback;
}
```

## Replacements

| Before | After |
|--------|-------|
| `Environment.GetEnvironmentVariable("DATABASE_URL")` | `Secrets.Get("DATABASE_URL")` (or `GetOrDefault` where null was handled) |
| `DotNetEnv.Env.Load()` | delete, once every key is covered |

## ASP.NET Core and the generic host

`IConfiguration` reads environment variables, with `__` meaning `:`
(`ConnectionStrings__Default` is `ConnectionStrings:Default`). Feed the
vault into configuration once at start-up and leave the rest of the code
(`builder.Configuration[...]`, `IOptions<T>`, `GetConnectionString`)
unchanged:

```csharp
using SourceOrrery;

var builder = WebApplication.CreateBuilder(args);
using (var project = Project.Load())
{
    builder.Configuration.AddInMemoryCollection(
        project.Secrets.Select(s => KeyValuePair.Create(s.Env.Replace("__", ":"), (string?)s.Value.ExposeText())));
}
```

Alternatively start the host under `sourceorrery run -- dotnet run`.
Remove `DotNetEnv` from the project file when nothing loads `.env` any
more.

## Tests

`sourceorrery run -- dotnet test`, or let the code load the project.
