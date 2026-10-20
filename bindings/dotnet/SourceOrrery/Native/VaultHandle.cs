using System.Runtime.InteropServices;

namespace SourceOrrery.Native;

/// <summary>
/// An open <c>so_vault*</c>. The <see cref="SafeHandle"/> reference count
/// keeps <c>so_vault_close</c> from racing with a call in progress on
/// another thread, as the ABI requires; the close runs when the last user
/// lets go.
/// </summary>
internal sealed class VaultHandle : SafeHandle
{
    public VaultHandle(nint raw)
        : base(nint.Zero, ownsHandle: true)
    {
        SetHandle(raw);
    }

    public override bool IsInvalid => handle == nint.Zero;

    protected override bool ReleaseHandle()
    {
        NativeMethods.so_vault_close(handle);
        return true;
    }
}
