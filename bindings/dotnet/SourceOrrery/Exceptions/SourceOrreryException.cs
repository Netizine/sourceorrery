namespace SourceOrrery;

/// <summary>
/// A failed SourceOrrery operation. <see cref="Code"/> is the core's stable,
/// append-only error code (<c>not_found</c>, <c>disabled</c>, <c>locked</c>,
/// ...); the message is human-readable and may change between releases.
/// Neither ever contains a secret value.
/// </summary>
public class SourceOrreryException : Exception
{
    public SourceOrreryException(string code, string message)
        : base(message)
    {
        ArgumentNullException.ThrowIfNull(code);
        Code = code;
    }

    public SourceOrreryException(string code, string message, Exception? innerException)
        : base(message, innerException)
    {
        ArgumentNullException.ThrowIfNull(code);
        Code = code;
    }

    /// <summary>Stable error code from <c>SecretError::code()</c>, or <c>internal</c> / <c>abi_mismatch</c> for failures of the binding itself.</summary>
    public string Code { get; }

    /// <summary>True when retrying later could succeed without administrative action.</summary>
    public virtual bool IsTransient => false;

    /// <summary>
    /// The typed exception for a stable code. Codes are append-only, so an
    /// unknown code maps to this base type and is never dropped.
    /// </summary>
    public static SourceOrreryException FromCode(string code, string message)
    {
        ArgumentNullException.ThrowIfNull(code);
        return code switch
        {
            "not_found" or "version_not_found" => new SecretNotFoundException(code, message),
            "disabled" or "expired" or "not_yet_valid" => new SecretPolicyException(code, message),
            "deleted" or "deleted_conflict" or "not_deleted" => new SecretStateException(code, message),
            "invalid_name" or "invalid_argument" => new SourceOrreryArgumentException(code, message),
            "permission_denied" => new SecretAccessDeniedException(code, message),
            "locked" => new VaultLockedException(code, message),
            "vault_not_found" or "vault_exists" => new VaultException(code, message),
            _ => new SourceOrreryException(code, message),
        };
    }
}
