namespace SourceOrrery;

/// <summary>
/// A failed read. <see cref="Code"/> is the core's stable, append-only code;
/// <see cref="Detail"/> says what went wrong and <see cref="Hint"/> what to
/// do about it. <see cref="Exception.Message"/> is both joined. None of them
/// ever contains a secret value.
/// </summary>
public class SourceOrreryException : Exception
{
    public SourceOrreryException(string message, string code = "internal", string hint = "")
        : base(string.IsNullOrEmpty(hint) ? message : $"{message}. {hint}")
    {
        Detail = message;
        Code = code;
        Hint = hint;
    }

    /// <summary>Stable code (<c>not_found</c>, <c>locked</c>, ...).</summary>
    public string Code { get; }

    /// <summary>What went wrong, without the hint.</summary>
    public string Detail { get; }

    /// <summary>What to do about it; empty when nothing specific applies.</summary>
    public string Hint { get; }

    /// <summary>True when retrying later could succeed without administrative action.</summary>
    public bool IsTransient => Code is "not_yet_valid" or "provider_unavailable";

    /// <summary>The exception for a stable code. Unknown codes map to this type and keep their code.</summary>
    public static SourceOrreryException ForCode(string code, string message, string hint = "")
    {
        return code switch
        {
            "vault_not_found" => new VaultNotFoundException(message, code, hint),
            "locked" => new VaultLockedException(message, code, hint),
            "migration_required" => new MigrationRequiredException(message, code, hint),
            "vault_mismatch" => new VaultMismatchException(message, code, hint),
            "not_found" => new SecretNotFoundException(message, code, hint),
            "version_not_found" => new VersionNotFoundException(message, code, hint),
            "deleted" => new SecretDeletedException(message, code, hint),
            "disabled" => new SecretDisabledException(message, code, hint),
            "not_yet_valid" => new SecretNotYetValidException(message, code, hint),
            "expired" => new SecretExpiredException(message, code, hint),
            "crypto" => new IntegrityException(message, code, hint),
            "unsupported" => new UnsupportedException(message, code, hint),
            "invalid_argument" => new InvalidArgumentException(message, code, hint),
            "invalid_name" => new InvalidNameException(message, code, hint),
            "manifest" => new ManifestException(message, code, hint),
            "permission_denied" => new PermissionDeniedException(message, code, hint),
            "storage" or "io" => new StorageException(message, code, hint),
            "unauthenticated" => new UnauthenticatedException(message, code, hint),
            "provider_unavailable" => new ProviderUnavailableException(message, code, hint),
            _ => new SourceOrreryException(message, code, hint),
        };
    }
}

/// <summary><c>vault_not_found</c>: no vault file with that name in the home directory.</summary>
public class VaultNotFoundException(string message, string code = "vault_not_found", string hint = "") : SourceOrreryException(message, code, hint);

/// <summary><c>locked</c>: neither this machine's key nor a recovery key could open the vault.</summary>
public class VaultLockedException(string message, string code = "locked", string hint = "") : SourceOrreryException(message, code, hint);

/// <summary>
/// <c>migration_required</c>: the vault was written by an earlier release, which this one
/// cannot read; recreate it with <c>sourceorrery setup</c>.
/// </summary>
public class MigrationRequiredException(string message, string code = "migration_required", string hint = "") : SourceOrreryException(message, code, hint);

/// <summary><c>vault_mismatch</c>: the file found for the vault holds another vault (renamed, copied or swapped in).</summary>
public class VaultMismatchException(string message, string code = "vault_mismatch", string hint = "") : SourceOrreryException(message, code, hint);

/// <summary><c>not_found</c>: no secret with that name.</summary>
public class SecretNotFoundException(string message, string code = "not_found", string hint = "") : SourceOrreryException(message, code, hint);

/// <summary><c>version_not_found</c>: the secret exists but the version does not.</summary>
public class VersionNotFoundException(string message, string code = "version_not_found", string hint = "") : SecretNotFoundException(message, code, hint);

/// <summary><c>deleted</c>: the secret is soft-deleted; recover it before use.</summary>
public class SecretDeletedException(string message, string code = "deleted", string hint = "") : SourceOrreryException(message, code, hint);

/// <summary>A version refused by policy: disabled, not yet valid or expired.</summary>
public class PolicyException(string message, string code, string hint = "") : SourceOrreryException(message, code, hint);

/// <summary><c>disabled</c>: the version is disabled.</summary>
public class SecretDisabledException(string message, string code = "disabled", string hint = "") : PolicyException(message, code, hint);

/// <summary><c>not_yet_valid</c>: the version's activation time has not been reached.</summary>
public class SecretNotYetValidException(string message, string code = "not_yet_valid", string hint = "") : PolicyException(message, code, hint);

/// <summary><c>expired</c>: the version's expiry time has passed.</summary>
public class SecretExpiredException(string message, string code = "expired", string hint = "") : PolicyException(message, code, hint);

/// <summary><c>crypto</c>: the vault file failed an integrity check.</summary>
public class IntegrityException(string message, string code = "crypto", string hint = "") : SourceOrreryException(message, code, hint);

/// <summary><c>unsupported</c>: no OS credential store here (use the vault's recovery key), or a remote provider this build does not include.</summary>
public class UnsupportedException(string message, string code = "unsupported", string hint = "") : SourceOrreryException(message, code, hint);

/// <summary><c>unauthenticated</c>: the remote provider refused the process's credentials; give it the ones its own tools expect.</summary>
public class UnauthenticatedException(string message, string code = "unauthenticated", string hint = "") : SourceOrreryException(message, code, hint);

/// <summary><c>provider_unavailable</c>: the remote provider could not be reached; transient, so the call can be retried.</summary>
public class ProviderUnavailableException(string message, string code = "provider_unavailable", string hint = "") : SourceOrreryException(message, code, hint);

/// <summary><c>invalid_argument</c>: a malformed reference, version or option.</summary>
public class InvalidArgumentException(string message, string code = "invalid_argument", string hint = "") : SourceOrreryException(message, code, hint);

/// <summary><c>invalid_name</c>: a secret or vault name breaks the naming rules.</summary>
public class InvalidNameException(string message, string code = "invalid_name", string hint = "") : InvalidArgumentException(message, code, hint);

/// <summary><c>manifest</c>: sourceorrery.toml is missing or invalid.</summary>
public class ManifestException(string message, string code = "manifest", string hint = "") : SourceOrreryException(message, code, hint);

/// <summary><c>permission_denied</c>: authenticated but not authorised.</summary>
public class PermissionDeniedException(string message, string code = "permission_denied", string hint = "") : SourceOrreryException(message, code, hint);

/// <summary><c>storage</c> / <c>io</c>: the vault file could not be read.</summary>
public class StorageException(string message, string code = "storage", string hint = "") : SourceOrreryException(message, code, hint);
