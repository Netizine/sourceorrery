using System.Runtime.InteropServices;

namespace SourceOrrery.Native;

/// <summary>
/// Mirror of <c>so_bytes</c>: a buffer SourceOrrery allocated and the caller
/// owns. <c>Ptr</c> points at <c>Len</c> bytes plus one trailing <c>0</c>;
/// <c>Ptr == null</c> is the empty buffer, which output slots hold after a
/// failed call and after <see cref="NativeMethods.so_bytes_free"/>.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal unsafe struct SoBytes
{
    public byte* Ptr;
    public nuint Len;

    /// <summary>True for the empty buffer (nothing to read, nothing to free).</summary>
    public readonly bool IsEmpty => Ptr == null;

    /// <summary>The bytes, or an empty span for the empty buffer.</summary>
    public readonly ReadOnlySpan<byte> AsSpan()
    {
        return Ptr == null ? default : new ReadOnlySpan<byte>(Ptr, checked((int)Len));
    }
}
