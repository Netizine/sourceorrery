namespace SourceOrrery;

/// <summary><c>permission_denied</c>: authenticated but not authorised for the operation.</summary>
public class SecretAccessDeniedException : SourceOrreryException
{
    public SecretAccessDeniedException(string code, string message)
        : base(code, message)
    {
    }
}
