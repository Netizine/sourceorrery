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
/// <remarks>
/// Disposal is requested, then completed: once <see cref="Dispose"/> has been
/// called (from any thread, or from inside a <see cref="Use"/> callback,
/// directly or by disposing the <see cref="Secret"/> or <see cref="Project"/>
/// that owns the value) every new use throws
/// <see cref="ObjectDisposedException"/> and <see cref="IsClosed"/> is true,
/// but the native bytes are zeroised and freed only when the last callback
/// already running has returned, exactly once. A callback is never handed
/// memory that is freed while it runs, and no lock is held while it runs.
/// </remarks>
public sealed unsafe class SecretValue : IDisposable
{
    /// <summary>Frees a native buffer: <see cref="NativeMethods.so_bytes_free"/>, or a test's.</summary>
    internal delegate void Release(SoBytes* bytes);

    private SoBytes bytes;
    private readonly Release release;
    private readonly object gate = new();
    private int active;
    private bool disposeRequested;
    private bool released;

    internal SecretValue(SoBytes bytes)
        : this(bytes, static slot => NativeMethods.so_bytes_free(slot))
    {
    }

    /// <summary>A value whose buffer <paramref name="release"/> frees (tests).</summary>
    internal SecretValue(SoBytes bytes, Release release)
    {
        this.bytes = bytes;
        this.release = release;
    }

    /// <summary>Length in bytes; 0 once disposal was requested.</summary>
    public int Length
    {
        get
        {
            lock (gate)
            {
                return disposeRequested || bytes.Ptr == null ? 0 : checked((int)bytes.Len);
            }
        }
    }

    /// <summary>True once <see cref="Dispose"/> has been called.</summary>
    public bool IsClosed
    {
        get
        {
            lock (gate)
            {
                return disposeRequested || bytes.Ptr == null;
            }
        }
    }

    /// <summary>
    /// Run <paramref name="action"/> over the bytes without copying them. The
    /// bytes stay allocated until it returns, even if the value is disposed
    /// meanwhile; a call made after disposal was requested throws
    /// <see cref="ObjectDisposedException"/>.
    /// </summary>
    public void Use(ReadOnlySpanAction<byte, object?> action, object? state = null)
    {
        ArgumentNullException.ThrowIfNull(action);
        ReadOnlySpan<byte> span;
        lock (gate)
        {
            span = Span();
            active++;
        }
        try
        {
            action(span, state);
        }
        finally
        {
            EndUse();
            // The span points into native memory that the finalizer frees: keep
            // this object reachable until the callback has finished with it.
            GC.KeepAlive(this);
        }
    }

    /// <summary>A copy of the bytes.</summary>
    public byte[] Expose()
    {
        lock (gate)
        {
            var copy = Span().ToArray();
            GC.KeepAlive(this);
            return copy;
        }
    }

    /// <summary>The value decoded as UTF-8.</summary>
    public string ExposeText()
    {
        lock (gate)
        {
            var text = Encoding.UTF8.GetString(Span());
            GC.KeepAlive(this);
            return text;
        }
    }

    /// <summary>
    /// Zeroise and free the native bytes, once every callback already running
    /// has returned (at once when none is). Idempotent; never waits, so a
    /// callback may dispose the value it is using.
    /// </summary>
    public void Dispose()
    {
        lock (gate)
        {
            disposeRequested = true;
            if (active == 0)
            {
                Free();
            }
        }
        GC.SuppressFinalize(this);
    }

    ~SecretValue()
    {
        // Unreachable, so no callback is running.
        Free();
    }

    /// <inheritdoc />
    public override string ToString() => "[REDACTED]";

    private void EndUse()
    {
        lock (gate)
        {
            active--;
            if (active == 0 && disposeRequested)
            {
                Free();
            }
        }
    }

    /// <summary>Release the buffer, the first time only.</summary>
    private void Free()
    {
        if (released)
        {
            return;
        }
        released = true;
        fixed (SoBytes* slot = &bytes)
        {
            release(slot);
        }
    }

    private ReadOnlySpan<byte> Span()
    {
        if (disposeRequested || bytes.Ptr == null)
        {
            throw new ObjectDisposedException(nameof(SecretValue), "the value was zeroised");
        }
        return new ReadOnlySpan<byte>(bytes.Ptr, checked((int)bytes.Len));
    }
}
