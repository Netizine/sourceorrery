namespace SourceOrrery;

/// <summary><c>vault_not_found</c>: no vault with that name in the home directory; <c>vault_exists</c>: a vault with that name is already there.</summary>
public class VaultException : SourceOrreryException
{
    public VaultException(string code, string message)
        : base(code, message)
    {
    }
}
