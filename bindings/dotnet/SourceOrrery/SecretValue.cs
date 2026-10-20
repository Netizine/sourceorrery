using System.Buffers;
using SourceOrrery.Native;

namespace SourceOrrery;

/// <summary>A callback that receives a secret value's bytes for the duration of the call.</summary>
public delegate void SecretBytesAction(ReadOnlySpan<byte> bytes);

/// <summary>
/// A secret value held in native memory until <see cref="Dispose"/> zeroises
/// and frees it. <see cref="Use(SecretBytesAction)"/> hands the bytes to a
/// callback without copying; <see cref="CopyTo"/> is the plain getter. There
/// is deliberately no string getter: a .NET string cannot be wiped. Once a
/// plaintext is in application memory the application can disclose it; keep
/// copies short-lived and clear them. <see cref="ToString"/> returns
/// <c>[REDACTED]</c>.
/// </summary>
public sealed unsafe class SecretValue : IDisposable
{
    private readonly object gate = new();
    private SoBytes bytes;

    internal SecretValue(SoBytes bytes)
    {
        this.bytes = bytes;
    }

    /// <summary>Length in bytes; 0 once disposed.</summary>
    public int Length
    {
        get
        {
            lock (gate)
            {
                return bytes.IsEmpty ? 0 : checked((int)bytes.Len);
            }
        }
    }

    /// <summary>True once <see cref="Dispose"/> has run; the value then reads as empty.</summary>
    public bool IsDisposed
    {
        get
        {
            lock (gate)
            {
                return bytes.IsEmpty;
            }
        }
    }

    /// <summary>Run <paramref name="action"/> over the bytes without copying them. The span is empty after disposal.</summary>
    public void Use(SecretBytesAction action)
    {
        ArgumentNullException.ThrowIfNull(action);
        lock (gate)
        {
            action(bytes.AsSpan());
        }
    }

    /// <summary>Run <paramref name="action"/> over the bytes with a state argument, without copying them.</summary>
    public void Use<TState>(ReadOnlySpanAction<byte, TState> action, TState state)
    {
        ArgumentNullException.ThrowIfNull(action);
        lock (gate)
        {
            action(bytes.AsSpan(), state);
        }
    }

    /// <summary>
    /// Copy the bytes into <paramref name="destination"/> (at least
    /// <see cref="Length"/> long) and return how many were copied. Clear the
    /// destination when you are done with it.
    /// </summary>
    public int CopyTo(Span<byte> destination)
    {
        lock (gate)
        {
            var span = bytes.AsSpan();
            span.CopyTo(destination);
            return span.Length;
        }
    }

    /// <summary>Zeroise and free the native bytes. Idempotent.</summary>
    public void Dispose()
    {
        lock (gate)
        {
            NativeMethods.so_bytes_free(ref bytes);
        }
        GC.SuppressFinalize(this);
    }

    ~SecretValue()
    {
        NativeMethods.so_bytes_free(ref bytes);
    }

    /// <inheritdoc />
    public override string ToString()
    {
        return "[REDACTED]";
    }
}
