namespace SourceOrrery;

/// <summary><c>locked</c>: neither the OS credential store nor the passphrase could unlock the vault.</summary>
public class VaultLockedException : SourceOrreryException
{
    public VaultLockedException(string code, string message)
        : base(code, message)
    {
    }
}
