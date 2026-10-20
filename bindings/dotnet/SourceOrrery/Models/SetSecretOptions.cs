namespace SourceOrrery;

/// <summary>Options for creating a new secret version.</summary>
public sealed record SetSecretOptions
{
    /// <summary>Content type hint.</summary>
    public string? ContentType { get; init; }

    /// <summary>Non-sensitive tags.</summary>
    public IReadOnlyDictionary<string, string>? Tags { get; init; }

    /// <summary>Whether the new version is immediately usable (default <c>true</c>).</summary>
    public bool Enabled { get; init; } = true;

    /// <summary>Activation time.</summary>
    public DateTimeOffset? NotBefore { get; init; }

    /// <summary>Expiry time.</summary>
    public DateTimeOffset? ExpiresOn { get; init; }
}
