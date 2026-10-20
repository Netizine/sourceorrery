namespace SourceOrrery;

/// <summary>A soft-deleted secret awaiting recovery or purge.</summary>
public sealed record DeletedSecret
{
    /// <summary>Properties of the latest version at deletion time.</summary>
    public required SecretProperties Properties { get; init; }

    /// <summary>When the secret was deleted.</summary>
    public required DateTimeOffset DeletedOn { get; init; }

    /// <summary>When the vault will purge it automatically, if retention applies.</summary>
    public DateTimeOffset? ScheduledPurgeOn { get; init; }

    /// <summary>Identifier of the deleted secret (<c>sourceorrery://vault/deletedsecrets/name</c>); empty in a purgeable vault.</summary>
    public required string RecoveryId { get; init; }
}
