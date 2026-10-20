namespace SourceOrrery;

/// <summary><c>not_found</c>: no secret with that name; <c>version_not_found</c>: the secret exists but the version does not.</summary>
public class SecretNotFoundException : SourceOrreryException
{
    public SecretNotFoundException(string code, string message)
        : base(code, message)
    {
    }

    /// <summary>True when the secret exists but the requested version does not.</summary>
    public bool IsVersionMissing => Code == "version_not_found";
}
