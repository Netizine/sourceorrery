using System.Buffers;
using System.Text;
using SourceOrrery.Native;

namespace SourceOrrery;

/// <summary>
/// A secret value kept in native memory until <see cref="Dispose"/> zeroises
/// it. <see cref="Use"/> hands the bytes to a callback without copying;
/// <see cref="Expose"/> and <see cref="ExposeText"/> return copies the
/// application owns (a .NET string cannot be wiped: keep it short-lived).
/// <see cref="ToString"/> prints <c>[REDACTED]</c>.
/// </summary>
public sealed unsafe class SecretValue : IDisposable
{
    private SoBytes bytes;
    private readonly object gate = new();

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
                return bytes.Ptr == null ? 0 : checked((int)bytes.Len);
            }
        }
    }

    /// <summary>True once <see cref="Dispose"/> has run.</summary>
    public bool IsClosed
    {
        get
        {
            lock (gate)
            {
                return bytes.Ptr == null;
            }
        }
    }

    /// <summary>Run <paramref name="action"/> over the bytes without copying them.</summary>
    public void Use(ReadOnlySpanAction<byte, object?> action, object? state = null)
    {
        ArgumentNullException.ThrowIfNull(action);
        lock (gate)
        {
            action(Span(), state);
        }
    }

    /// <summary>A copy of the bytes.</summary>
    public byte[] Expose()
    {
        lock (gate)
        {
            return Span().ToArray();
        }
    }

    /// <summary>The value decoded as UTF-8.</summary>
    public string ExposeText()
    {
        lock (gate)
        {
            return Encoding.UTF8.GetString(Span());
        }
    }

    /// <summary>Zeroise and free the native bytes. Idempotent.</summary>
    public void Dispose()
    {
        lock (gate)
        {
            fixed (SoBytes* slot = &bytes)
            {
                NativeMethods.so_bytes_free(slot);
            }
        }
        GC.SuppressFinalize(this);
    }

    ~SecretValue()
    {
        fixed (SoBytes* slot = &bytes)
        {
            NativeMethods.so_bytes_free(slot);
        }
    }

    /// <inheritdoc />
    public override string ToString() => "[REDACTED]";

    private ReadOnlySpan<byte> Span()
    {
        if (bytes.Ptr == null)
        {
            throw new ObjectDisposedException(nameof(SecretValue), "the value was zeroised");
        }
        return new ReadOnlySpan<byte>(bytes.Ptr, checked((int)bytes.Len));
    }
}
