using System.Text.Json;
using System.Text.Json.Serialization;

namespace SourceOrrery;

/// <summary>Metadata of one version. Never contains the value.</summary>
public sealed record SecretProperties
{
    public required string Vault { get; init; }
    public required string Name { get; init; }
    public required string Version { get; init; }
    public required bool Enabled { get; init; }
    public string? ContentType { get; init; }
    public IReadOnlyDictionary<string, string> Tags { get; init; } = new Dictionary<string, string>();
    public DateTimeOffset? NotBefore { get; init; }
    public DateTimeOffset? ExpiresOn { get; init; }
    public required DateTimeOffset CreatedOn { get; init; }
    public required DateTimeOffset UpdatedOn { get; init; }
    public string RecoveryLevel { get; init; } = "recoverable";

    /// <summary><c>sourceorrery://vault/name/version</c> for exactly this version.</summary>
    public string Reference => $"sourceorrery://{Vault}/{Name}/{Version}";

    internal static SecretProperties FromDto(SecretPropertiesDto dto) => new()
    {
        Vault = dto.Vault,
        Name = dto.Name,
        Version = dto.Version,
        Enabled = dto.Enabled,
        ContentType = dto.ContentType,
        Tags = dto.Tags ?? new Dictionary<string, string>(),
        NotBefore = dto.NotBefore,
        ExpiresOn = dto.ExpiresOn,
        CreatedOn = dto.CreatedOn,
        UpdatedOn = dto.UpdatedOn,
        RecoveryLevel = dto.RecoveryLevel ?? "recoverable",
    };

    internal static SecretProperties Parse(string json)
    {
        var dto = JsonSerializer.Deserialize(json, SourceOrreryJsonContext.Default.SecretPropertiesDto)
            ?? throw new SourceOrreryException("empty properties document", "storage");
        return FromDto(dto);
    }
}

/// <summary>A version's metadata and its value. Disposing it zeroises the value.</summary>
public sealed class Secret : IDisposable
{
    internal Secret(SecretProperties properties, SecretValue value)
    {
        Properties = properties;
        Value = value;
    }

    public SecretProperties Properties { get; }
    public SecretValue Value { get; }

    public void Dispose() => Value.Dispose();
}

/// <summary>Non-sensitive description of a vault.</summary>
public sealed record VaultDescriptor
{
    public required string Name { get; init; }
    public required string Id { get; init; }
    public required string Backend { get; init; }
    public string? Path { get; init; }
    public DateTimeOffset CreatedOn { get; init; }
    public string RecoveryLevel { get; init; } = "recoverable";
    public uint RetentionDays { get; init; }
    public IReadOnlyList<string> Protectors { get; init; } = Array.Empty<string>();
}

/// <summary>How to find and unlock a vault. Defaults reproduce the CLI.</summary>
public sealed record OpenOptions
{
    /// <summary>Directory holding the <c>vaults/</c> folder; null honours <c>SOURCEORRERY_HOME</c>.</summary>
    public string? Home { get; init; }

    /// <summary>A passphrase tried before the environment sources.</summary>
    public string? Passphrase { get; init; }

    /// <summary>A file holding the passphrase; replaces <c>SOURCEORRERY_PASSPHRASE_FILE</c>.</summary>
    public string? PassphraseFile { get; init; }

    /// <summary>Consult <c>SOURCEORRERY_PASSPHRASE</c> and <c>SOURCEORRERY_PASSPHRASE_FILE</c> (default true).</summary>
    public bool Environment { get; init; } = true;

    /// <summary>
    /// The <c>sourceorrery.toml</c> whose <c>[vaults.&lt;name&gt;]</c> tables say which vaults are
    /// remote and where; null uses the nearest manifest above the current directory. Credentials
    /// for a remote provider come from the provider's own environment, never from the manifest.
    /// </summary>
    public string? Manifest { get; init; }

    internal string ToJson() => JsonSerializer.Serialize(
        new ReaderOptionsDto { Home = Home, PassphraseFile = PassphraseFile, Environment = Environment, Manifest = Manifest },
        SourceOrreryJsonContext.Default.ReaderOptionsDto);
}

internal sealed class SecretPropertiesDto
{
    public required string Vault { get; set; }
    public required string Name { get; set; }
    public required string Version { get; set; }
    public bool Enabled { get; set; }
    public string? ContentType { get; set; }
    public Dictionary<string, string>? Tags { get; set; }
    public DateTimeOffset? NotBefore { get; set; }
    public DateTimeOffset? ExpiresOn { get; set; }
    public DateTimeOffset CreatedOn { get; set; }
    public DateTimeOffset UpdatedOn { get; set; }
    public string? RecoveryLevel { get; set; }
}

internal sealed class ReaderOptionsDto
{
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Home { get; set; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? PassphraseFile { get; set; }

    public bool Environment { get; set; } = true;

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Manifest { get; set; }
}

internal sealed class ProjectInfoDto
{
    public required string Name { get; set; }
    public required string ManifestPath { get; set; }
    public int Count { get; set; }
}

internal sealed class ProjectEntryDto
{
    public required string Name { get; set; }
    public required string Env { get; set; }
    public required string Reference { get; set; }
    public bool Required { get; set; }
    public required SecretPropertiesDto Properties { get; set; }
}

internal sealed class VaultDescriptorDto
{
    public required string Name { get; set; }
    public required string Id { get; set; }
    public required string Backend { get; set; }
    public string? Path { get; set; }
    public DateTimeOffset CreatedOn { get; set; }
    public string? RecoveryLevel { get; set; }
    public uint RetentionDays { get; set; }
    public List<string>? Protectors { get; set; }
}

[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.SnakeCaseLower)]
[JsonSerializable(typeof(SecretPropertiesDto))]
[JsonSerializable(typeof(ReaderOptionsDto))]
[JsonSerializable(typeof(ProjectInfoDto))]
[JsonSerializable(typeof(ProjectEntryDto))]
[JsonSerializable(typeof(VaultDescriptorDto))]
internal partial class SourceOrreryJsonContext : JsonSerializerContext;
