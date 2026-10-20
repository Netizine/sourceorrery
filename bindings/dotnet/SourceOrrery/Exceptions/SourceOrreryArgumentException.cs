namespace SourceOrrery;

/// <summary>
/// <c>invalid_name</c>: a secret or vault name breaks the naming rules;
/// <c>invalid_argument</c>: an option, time window, tag, version or JSON
/// document was rejected.
/// </summary>
public class SourceOrreryArgumentException : SourceOrreryException
{
    public SourceOrreryArgumentException(string code, string message)
        : base(code, message)
    {
    }
}
