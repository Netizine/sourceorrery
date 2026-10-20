using System.Collections.ObjectModel;
using System.Text.Json.Serialization;

namespace SourceOrrery;

/// <summary>Metadata of one version of a secret. Never contains the value.</summary>
public sealed record SecretProperties
{
    /// <summary>Vault the secret lives in.</summary>
    public required string Vault { get; init; }

    /// <summary>Secret name (letters, digits and hyphens; at most 127 characters).</summary>
    public required string Name { get; init; }

    /// <summary>Opaque version identifier, unique within the secret.</summary>
    public required string Version { get; init; }

    /// <summary>Disabled versions cannot be retrieved.</summary>
    public required bool Enabled { get; init; }

    /// <summary>Free-form content type hint (<c>text/plain</c>, <c>application/json</c>, ...).</summary>
    public string? ContentType { get; init; }

    /// <summary>Caller-defined, non-sensitive tags; empty when the core omitted them.</summary>
    public IReadOnlyDictionary<string, string> Tags
    {
        // The core omits an empty map, and the serializer does not run field
        // initialisers for types with required members, so normalise here.
        get => tags ?? ReadOnlyDictionary<string, string>.Empty;
        init => tags = value;
    }

    private readonly IReadOnlyDictionary<string, string>? tags;

    /// <summary>The version cannot be retrieved before this time.</summary>
    public DateTimeOffset? NotBefore { get; init; }

    /// <summary>The version cannot be retrieved after this time.</summary>
    public DateTimeOffset? ExpiresOn { get; init; }

    /// <summary>When this version was created. Immutable.</summary>
    public required DateTimeOffset CreatedOn { get; init; }

    /// <summary>When this version's metadata last changed.</summary>
    public required DateTimeOffset UpdatedOn { get; init; }

    /// <summary>Deletion behaviour inherited from the vault.</summary>
    public RecoveryLevel RecoveryLevel { get; init; } = RecoveryLevel.Recoverable;

    /// <summary><c>sourceorrery://vault/name/version</c>: a reference to exactly this version. Safe to log and commit.</summary>
    [JsonIgnore]
    public string Reference => $"sourceorrery://{Vault}/{Name}/{Version}";

    /// <summary>Value equality, tags included.</summary>
    public bool Equals(SecretProperties? other)
    {
        return other is not null
            && Vault == other.Vault
            && Name == other.Name
            && Version == other.Version
            && Enabled == other.Enabled
            && ContentType == other.ContentType
            && NotBefore == other.NotBefore
            && ExpiresOn == other.ExpiresOn
            && CreatedOn == other.CreatedOn
            && UpdatedOn == other.UpdatedOn
            && RecoveryLevel == other.RecoveryLevel
            && Collections.TagsEqual(Tags, other.Tags);
    }

    /// <inheritdoc />
    public override int GetHashCode()
    {
        return HashCode.Combine(Vault, Name, Version, Enabled, CreatedOn, UpdatedOn, Tags.Count);
    }
}
