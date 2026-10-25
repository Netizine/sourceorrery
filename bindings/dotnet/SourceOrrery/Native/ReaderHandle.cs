using System.Runtime.InteropServices;

namespace SourceOrrery.Native;

/// <summary>
/// An <c>so_reader</c> handle. The C ABI requires that it is closed exactly
/// once and never while another thread is using it; the reference count of
/// <see cref="SafeHandle"/> enforces that: every <c>so_reader_*</c> import
/// takes this handle itself, so the marshaller holds a reference for the
/// call's duration, and <see cref="SafeHandle.Dispose()"/> on another thread
/// (or the finalizer) closes the handle only after the last call has ended.
/// </summary>
internal sealed class ReaderHandle : SafeHandle
{
    internal ReaderHandle(nint opened)
        : base(nint.Zero, ownsHandle: true)
    {
        SetHandle(opened);
    }

    public override bool IsInvalid => handle == nint.Zero;

    protected override bool ReleaseHandle()
    {
        NativeMethods.so_reader_close(handle);
        return true;
    }
}
