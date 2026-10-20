namespace SourceOrrery;

/// <summary>
/// Policy refused the version: <c>disabled</c>, <c>expired</c>, or
/// <c>not_yet_valid</c>. Only the last is transient: the version becomes
/// readable once its activation time passes.
/// </summary>
public class SecretPolicyException : SourceOrreryException
{
    public SecretPolicyException(string code, string message)
        : base(code, message)
    {
    }

    /// <inheritdoc />
    public override bool IsTransient => Code == "not_yet_valid";
}
