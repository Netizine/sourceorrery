namespace SourceOrrery;

/// <summary>Filter for <see cref="SecretClient.GetAuditEvents"/>. Every field is optional.</summary>
public sealed record AuditQuery
{
    /// <summary>Only events about this secret.</summary>
    public string? SecretName { get; init; }

    /// <summary>Only events of this operation.</summary>
    public AuditOperation? Operation { get; init; }

    /// <summary>Only events at or after this time.</summary>
    public DateTimeOffset? Since { get; init; }

    /// <summary>Return at most this many events, newest first (the vault's default is 1000).</summary>
    public int? Limit { get; init; }
}
