using System.Text.Json;
using SourceOrrery.Native;

namespace SourceOrrery;

/// <summary>One secret resolved from <c>sourceorrery.toml</c>.</summary>
public sealed record ProjectSecret
{
    public required string Name { get; init; }
    public required string Env { get; init; }
    public required string Reference { get; init; }
    public required bool Required { get; init; }
    public required SecretProperties Properties { get; init; }
    public required SecretValue Value { get; init; }
}

/// <summary>
/// The secrets a <c>sourceorrery.toml</c> declares, resolved like
/// <c>sourceorrery run</c>: every required secret must resolve or
/// <see cref="Load"/> throws that secret's exception; optional secrets that
/// are missing, refused by policy or whose vault does not exist are left out.
/// </summary>
public sealed unsafe class Project : IDisposable
{
    private Project(string name, string manifestPath, IReadOnlyList<ProjectSecret> secrets)
    {
        Name = name;
        ManifestPath = manifestPath;
        Secrets = secrets;
    }

    /// <summary><c>[project].name</c>.</summary>
    public string Name { get; }

    /// <summary>The manifest file that was loaded.</summary>
    public string ManifestPath { get; }

    /// <summary>Every secret that resolved, in manifest order.</summary>
    public IReadOnlyList<ProjectSecret> Secrets { get; }

    /// <summary>
    /// Load <paramref name="manifest"/> (null: the nearest <c>sourceorrery.toml</c>
    /// above the current directory). <paramref name="options"/> apply to every
    /// vault the manifest names.
    /// </summary>
    public static Project Load(string? manifest = null, OpenOptions? options = null)
    {
        Interop.RequireAbi();
        options ??= new OpenOptions();
        var manifestBytes = NativeLibraryLoader.Utf8(manifest);
        var json = NativeLibraryLoader.Utf8(options.ToJson())!;
        var recoveryKey = NativeLibraryLoader.Utf8(options.RecoveryKey);
        nint handle = nint.Zero;
        try
        {
            fixed (byte* manifestPtr = manifestBytes)
            fixed (byte* jsonPtr = json)
            fixed (byte* keyPtr = recoveryKey)
            {
                Interop.Check(NativeMethods.so_project_load(
                    manifestPtr, (nuint)(manifestBytes?.Length ?? 0),
                    jsonPtr, (nuint)json.Length,
                    keyPtr, (nuint)(recoveryKey?.Length ?? 0),
                    &handle));
            }
        }
        finally
        {
            // The library keeps its own copy; a wrong recovery key must be cleared too.
            Array.Clear(recoveryKey ?? Array.Empty<byte>());
        }
        var secrets = new List<ProjectSecret>();
        try
        {
            SoBytes infoJson = default;
            Interop.Check(NativeMethods.so_project_info(handle, &infoJson));
            var info = JsonSerializer.Deserialize(Interop.TakeString(ref infoJson), SourceOrreryJsonContext.Default.ProjectInfoDto)
                ?? throw new SourceOrreryException("empty project document", "storage");
            var count = checked((int)NativeMethods.so_project_count(handle));
            for (var index = 0; index < count; index++)
            {
                SoBytes entryJson = default;
                SoBytes value = default;
                Interop.Check(NativeMethods.so_project_entry(handle, (nuint)index, &entryJson, &value));
                // Owned before the entry is parsed, so a parse failure still zeroises it.
                var secretValue = new SecretValue(value);
                try
                {
                    var entry = JsonSerializer.Deserialize(Interop.TakeString(ref entryJson), SourceOrreryJsonContext.Default.ProjectEntryDto)
                        ?? throw new SourceOrreryException("empty project entry", "storage");
                    secrets.Add(new ProjectSecret
                    {
                        Name = entry.Name,
                        Env = entry.Env,
                        Reference = entry.Reference,
                        Required = entry.Required,
                        Properties = SecretProperties.FromDto(entry.Properties),
                        Value = secretValue,
                    });
                }
                catch
                {
                    secretValue.Dispose();
                    throw;
                }
            }
            return new Project(info.Name, info.ManifestPath, secrets);
        }
        catch
        {
            // Values already read belong to no project: zeroise them now.
            foreach (var secret in secrets)
            {
                secret.Value.Dispose();
            }
            throw;
        }
        finally
        {
            NativeMethods.so_project_free(handle);
        }
    }

    /// <summary>The entry declared as <c>[secrets.&lt;name&gt;]</c>, if it resolved.</summary>
    public ProjectSecret? Get(string name) => Secrets.FirstOrDefault(s => s.Name == name);

    /// <summary>The value delivered in environment variable <paramref name="variable"/>, if any.</summary>
    public SecretValue? Env(string variable) => Secrets.FirstOrDefault(s => s.Env == variable)?.Value;

    /// <summary>Zeroise every value.</summary>
    public void Dispose()
    {
        foreach (var secret in Secrets)
        {
            secret.Value.Dispose();
        }
    }
}
