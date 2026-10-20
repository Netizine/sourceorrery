using System.Text.Json.Serialization;

namespace SourceOrrery;

/// <summary>Options for <see cref="SecretClient.CreateVault"/>.</summary>
public sealed record VaultCreateOptions
{
    /// <summary>Deletion behaviour for secrets in the vault (default recoverable).</summary>
    public RecoveryLevel RecoveryLevel { get; init; } = RecoveryLevel.Recoverable;

    /// <summary>Soft-delete retention in days, 7 to 90 (default 90).</summary>
    public int RetentionDays { get; init; } = 90;

    /// <summary>
    /// Argon2id cost of the passphrase protector. Leave unset outside tests:
    /// the vault's defaults are the interactive parameters.
    /// </summary>
    [JsonPropertyName("argon2")]
    public Argon2Parameters? KeyDerivation { get; init; }

    /// <summary>SourceOrrery home directory; null honours <c>SOURCEORRERY_HOME</c> or the platform data directory.</summary>
    [JsonIgnore]
    public string? Home { get; init; }
}

/// <summary>Argon2id key-derivation cost for a passphrase protector.</summary>
public sealed record Argon2Parameters
{
    /// <summary>Memory cost in KiB.</summary>
    public required int MemoryKib { get; init; }

    /// <summary>Number of passes.</summary>
    public required int Iterations { get; init; }

    /// <summary>Degree of parallelism.</summary>
    public required int Parallelism { get; init; }

    /// <summary>Interactive-unlock defaults: 64 MiB, 3 passes, 1 lane.</summary>
    public static Argon2Parameters Interactive { get; } = new() { MemoryKib = 64 * 1024, Iterations = 3, Parallelism = 1 };

    /// <summary>Cheap parameters for tests only (8 MiB, 1 pass, 1 lane). Never use for real vaults.</summary>
    public static Argon2Parameters Testing { get; } = new() { MemoryKib = 8 * 1024, Iterations = 1, Parallelism = 1 };
}

/// <summary>Options for opening a vault with <see cref="SecretClient"/>.</summary>
public sealed record SecretClientOptions
{
    /// <summary>SourceOrrery home directory; null honours <c>SOURCEORRERY_HOME</c> or the platform data directory.</summary>
    public string? Home { get; init; }
}
