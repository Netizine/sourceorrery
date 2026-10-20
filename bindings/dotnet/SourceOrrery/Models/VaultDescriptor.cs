namespace SourceOrrery;

/// <summary>Non-sensitive description of a vault.</summary>
public sealed record VaultDescriptor
{
    /// <summary>Vault name.</summary>
    public required string Name { get; init; }

    /// <summary>Stable random identifier, bound into every ciphertext.</summary>
    public required string Id { get; init; }

    /// <summary>Backend kind (<c>encrypted-sqlite</c>, ...).</summary>
    public required string Backend { get; init; }

    /// <summary>On-disk location for file-backed vaults.</summary>
    public string? Path { get; init; }

    /// <summary>Creation time.</summary>
    public required DateTimeOffset CreatedOn { get; init; }

    /// <summary>Deletion behaviour for secrets in this vault.</summary>
    public required RecoveryLevel RecoveryLevel { get; init; }

    /// <summary>Soft-delete retention in days.</summary>
    public required int RetentionDays { get; init; }

    /// <summary>Names of the key protectors that can unlock this vault.</summary>
    public IReadOnlyList<string> Protectors
    {
        // Normalised like SecretProperties.Tags: initialisers do not run for
        // deserialised types with required members.
        get => protectors ?? Array.Empty<string>();
        init => protectors = value;
    }

    private readonly IReadOnlyList<string>? protectors;

    /// <summary>Value equality, protectors included.</summary>
    public bool Equals(VaultDescriptor? other)
    {
        return other is not null
            && Name == other.Name
            && Id == other.Id
            && Backend == other.Backend
            && Path == other.Path
            && CreatedOn == other.CreatedOn
            && RecoveryLevel == other.RecoveryLevel
            && RetentionDays == other.RetentionDays
            && Collections.SequenceEqual(Protectors, other.Protectors);
    }

    /// <inheritdoc />
    public override int GetHashCode()
    {
        return HashCode.Combine(Name, Id, Backend, CreatedOn);
    }
}
