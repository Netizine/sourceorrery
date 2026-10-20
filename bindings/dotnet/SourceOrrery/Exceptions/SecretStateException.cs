namespace SourceOrrery;

/// <summary>
/// The secret is in the wrong lifecycle state for the operation:
/// <c>deleted</c> (soft-deleted; recover it first), <c>deleted_conflict</c>
/// (a deleted secret of that name is awaiting purge, so it cannot be set) or
/// <c>not_deleted</c> (recover or purge of a live secret).
/// </summary>
public class SecretStateException : SourceOrreryException
{
    public SecretStateException(string code, string message)
        : base(code, message)
    {
    }
}
