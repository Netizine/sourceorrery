using System.Text.Json.Serialization;
using SourceOrrery.Json;

namespace SourceOrrery;

/// <summary>One audit record. Contains no secret material.</summary>
public sealed record AuditEvent
{
    /// <summary>Monotonic identifier assigned by the vault.</summary>
    public required long Id { get; init; }

    /// <summary>When it happened.</summary>
    public required DateTimeOffset OccurredOn { get; init; }

    /// <summary>Who did it.</summary>
    public required Principal Actor { get; init; }

    /// <summary>What they did.</summary>
    public required AuditOperation Operation { get; init; }

    /// <summary>Which secret, if the operation targets one.</summary>
    public string? SecretName { get; init; }

    /// <summary>Which version, if known.</summary>
    public string? Version { get; init; }

    /// <summary>How it ended.</summary>
    public required AuditOutcome Outcome { get; init; }

    /// <summary>Error code or short note. Never a secret value.</summary>
    public string? Detail { get; init; }
}

/// <summary>An identity that performs operations.</summary>
public sealed record Principal
{
    /// <summary>What kind of thing this is.</summary>
    public required PrincipalKind Kind { get; init; }

    /// <summary>Stable identifier within its kind (OS user name, workload id, ...).</summary>
    public required string Id { get; init; }

    /// <inheritdoc />
    public override string ToString()
    {
        return $"{Kind}:{Id}";
    }
}

/// <summary>
/// The operations SourceOrrery audits. An extensible string value: the core's
/// list is append-only, so an operation this assembly does not know is kept
/// as its label rather than rejected.
/// </summary>
[JsonConverter(typeof(AuditOperationJsonConverter))]
public readonly struct AuditOperation : IEquatable<AuditOperation>
{
    private readonly string value;

    /// <summary>Wrap a stable label such as <c>secret_get</c>.</summary>
    public AuditOperation(string value)
    {
        ArgumentException.ThrowIfNullOrEmpty(value);
        this.value = value;
    }

    public static AuditOperation VaultCreate { get; } = new("vault_create");
    public static AuditOperation VaultOpen { get; } = new("vault_open");
    public static AuditOperation ProtectorAdd { get; } = new("protector_add");
    public static AuditOperation ProtectorRemove { get; } = new("protector_remove");
    public static AuditOperation SecretSet { get; } = new("secret_set");
    public static AuditOperation SecretGet { get; } = new("secret_get");
    public static AuditOperation SecretList { get; } = new("secret_list");
    public static AuditOperation SecretUpdate { get; } = new("secret_update");
    public static AuditOperation SecretDelete { get; } = new("secret_delete");
    public static AuditOperation SecretRecover { get; } = new("secret_recover");
    public static AuditOperation SecretPurge { get; } = new("secret_purge");
    public static AuditOperation VaultMigrate { get; } = new("vault_migrate");
    public static AuditOperation AuditVerify { get; } = new("audit_verify");
    public static AuditOperation SecretInspect { get; } = new("secret_inspect");

    public bool Equals(AuditOperation other) => string.Equals(value, other.value, StringComparison.Ordinal);

    public override bool Equals(object? obj) => obj is AuditOperation other && Equals(other);

    public override int GetHashCode() => StringComparer.Ordinal.GetHashCode(value ?? string.Empty);

    public static bool operator ==(AuditOperation left, AuditOperation right) => left.Equals(right);

    public static bool operator !=(AuditOperation left, AuditOperation right) => !left.Equals(right);

    /// <summary>The stable label.</summary>
    public override string ToString() => value ?? string.Empty;
}

/// <summary>How an audited operation ended. Extensible like <see cref="AuditOperation"/>.</summary>
[JsonConverter(typeof(AuditOutcomeJsonConverter))]
public readonly struct AuditOutcome : IEquatable<AuditOutcome>
{
    private readonly string value;

    /// <summary>Wrap a stable label such as <c>denied</c>.</summary>
    public AuditOutcome(string value)
    {
        ArgumentException.ThrowIfNullOrEmpty(value);
        this.value = value;
    }

    /// <summary>The operation completed.</summary>
    public static AuditOutcome Success { get; } = new("success");

    /// <summary>Policy refused the operation (disabled, expired, unauthorised, ...).</summary>
    public static AuditOutcome Denied { get; } = new("denied");

    /// <summary>The operation failed for another reason (not found, storage error).</summary>
    public static AuditOutcome Failure { get; } = new("failure");

    public bool Equals(AuditOutcome other) => string.Equals(value, other.value, StringComparison.Ordinal);

    public override bool Equals(object? obj) => obj is AuditOutcome other && Equals(other);

    public override int GetHashCode() => StringComparer.Ordinal.GetHashCode(value ?? string.Empty);

    public static bool operator ==(AuditOutcome left, AuditOutcome right) => left.Equals(right);

    public static bool operator !=(AuditOutcome left, AuditOutcome right) => !left.Equals(right);

    /// <summary>The stable label.</summary>
    public override string ToString() => value ?? string.Empty;
}

/// <summary>Category of principal. Extensible like <see cref="AuditOperation"/>.</summary>
[JsonConverter(typeof(PrincipalKindJsonConverter))]
public readonly struct PrincipalKind : IEquatable<PrincipalKind>
{
    private readonly string value;

    /// <summary>Wrap a stable label such as <c>user</c>.</summary>
    public PrincipalKind(string value)
    {
        ArgumentException.ThrowIfNullOrEmpty(value);
        this.value = value;
    }

    /// <summary>An interactive human user (the OS account for local vaults).</summary>
    public static PrincipalKind User { get; } = new("user");

    /// <summary>An application or service with its own verified identity.</summary>
    public static PrincipalKind Workload { get; } = new("workload");

    /// <summary>An AI coding agent session.</summary>
    public static PrincipalKind Agent { get; } = new("agent");

    /// <summary>SourceOrrery itself (maintenance, scheduled purge, ...).</summary>
    public static PrincipalKind System { get; } = new("system");

    public bool Equals(PrincipalKind other) => string.Equals(value, other.value, StringComparison.Ordinal);

    public override bool Equals(object? obj) => obj is PrincipalKind other && Equals(other);

    public override int GetHashCode() => StringComparer.Ordinal.GetHashCode(value ?? string.Empty);

    public static bool operator ==(PrincipalKind left, PrincipalKind right) => left.Equals(right);

    public static bool operator !=(PrincipalKind left, PrincipalKind right) => !left.Equals(right);

    /// <summary>The stable label.</summary>
    public override string ToString() => value ?? string.Empty;
}
