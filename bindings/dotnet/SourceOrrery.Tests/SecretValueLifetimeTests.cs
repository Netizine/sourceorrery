// SR06 of the 2026-10-25 review: a SecretValue's buffer stays allocated until
// every callback using it has returned, and is freed exactly once. The
// buffers here are the test's own, freed through an instrumented release, so
// these tests need neither the native library nor a vault and never read
// freed memory: the probe records when the free happens.
using System.Runtime.InteropServices;
using System.Text;
using SourceOrrery.Native;
using Xunit;

namespace SourceOrrery.Tests;

public sealed class SecretValueLifetimeTests
{
    private const string Text = "lifetime-canary";

    /// <summary>Counts frees, and whether one came while a callback ran.</summary>
    private sealed class Probe
    {
        private int frees;
        private int insideCallback;

        public int Frees => Volatile.Read(ref frees);
        public bool FreedInsideCallback { get; private set; }

        public void Enter() => Interlocked.Increment(ref insideCallback);
        public void Leave() => Interlocked.Decrement(ref insideCallback);

        public void Freed()
        {
            if (Volatile.Read(ref insideCallback) > 0)
            {
                FreedInsideCallback = true;
            }
            Interlocked.Increment(ref frees);
        }
    }

    private static unsafe SecretValue Make(Probe probe, string text = Text)
    {
        var data = Encoding.UTF8.GetBytes(text);
        var ptr = (byte*)NativeMemory.Alloc((nuint)data.Length);
        data.CopyTo(new Span<byte>(ptr, data.Length));
        return new SecretValue(new SoBytes { Ptr = ptr, Len = (nuint)data.Length }, slot =>
        {
            probe.Freed();
            NativeMemory.Clear(slot->Ptr, slot->Len);
            NativeMemory.Free(slot->Ptr);
            slot->Ptr = null;
            slot->Len = 0;
        });
    }

    [Fact]
    public void DisposingInsideTheCallbackFreesOnlyAfterItReturns()
    {
        var probe = new Probe();
        var value = Make(probe);
        string? read = null;
        value.Use((span, _) =>
        {
            probe.Enter();
            value.Dispose();
            Assert.True(value.IsClosed);
            Assert.Equal(0, value.Length);
            Assert.Equal(0, probe.Frees);
            // Still allocated: the callback reads on.
            read = Encoding.UTF8.GetString(span);
            Assert.Throws<ObjectDisposedException>(() => value.Use((_, _) => { }));
            Assert.Throws<ObjectDisposedException>(() => value.Expose());
            Assert.Throws<ObjectDisposedException>(() => value.ExposeText());
            probe.Leave();
        });
        Assert.Equal(Text, read);
        Assert.Equal(1, probe.Frees);
        Assert.False(probe.FreedInsideCallback);
        Assert.Throws<ObjectDisposedException>(() => value.Use((_, _) => { }));
    }

    [Fact]
    public void NestedCallbacksKeepTheBufferUntilTheOutermostReturns()
    {
        var probe = new Probe();
        var value = Make(probe);
        value.Use((outer, _) =>
        {
            probe.Enter();
            value.Use((inner, _) =>
            {
                Assert.Equal(Text.Length, inner.Length);
                value.Dispose();
            });
            Assert.Equal(0, probe.Frees);
            Assert.Equal(Text, Encoding.UTF8.GetString(outer));
            probe.Leave();
        });
        Assert.Equal(1, probe.Frees);
        Assert.False(probe.FreedInsideCallback);
    }

    [Fact]
    public void ACallbackThatThrowsReleasesItsUse()
    {
        var probe = new Probe();
        var value = Make(probe);
        Assert.Throws<InvalidOperationException>(
            () => value.Use((_, _) => throw new InvalidOperationException("from the callback")));
        Assert.Equal(Text, value.ExposeText());
        Assert.Equal(0, probe.Frees);

        // Disposed inside a callback that then throws: freed once, after it.
        Assert.Throws<InvalidOperationException>(() => value.Use((_, _) =>
        {
            value.Dispose();
            Assert.Equal(0, probe.Frees);
            throw new InvalidOperationException("after disposing");
        }));
        Assert.Equal(1, probe.Frees);
    }

    [Fact]
    public async Task ADisposeFromAnotherThreadWaitsForTheCallbackItDoesNotBlock()
    {
        var probe = new Probe();
        var value = Make(probe);
        using var entered = new ManualResetEventSlim();
        using var proceed = new ManualResetEventSlim();
        string? read = null;
        var user = Task.Run(() => value.Use((span, _) =>
        {
            probe.Enter();
            entered.Set();
            proceed.Wait();
            read = Encoding.UTF8.GetString(span);
            probe.Leave();
        }));
        entered.Wait();
        // Disposal is requested at once and does not wait for the callback.
        value.Dispose();
        Assert.True(value.IsClosed);
        Assert.Equal(0, probe.Frees);
        Assert.Throws<ObjectDisposedException>(() => value.Use((_, _) => { }));
        proceed.Set();
        await user;
        Assert.Equal(Text, read);
        Assert.Equal(1, probe.Frees);
        Assert.False(probe.FreedInsideCallback);
    }

    [Fact]
    public void TheOwningSecretDisposedInsideTheCallbackIsDeferredToo()
    {
        var probe = new Probe();
        var now = DateTimeOffset.UtcNow;
        var properties = new SecretProperties
        {
            Vault = "v",
            Name = "n",
            Version = "1",
            Enabled = true,
            CreatedOn = now,
            UpdatedOn = now,
        };
        using var secret = new Secret(properties, Make(probe));
        secret.Value.Use((span, _) =>
        {
            probe.Enter();
            secret.Dispose();
            Assert.Equal(Text, Encoding.UTF8.GetString(span));
            probe.Leave();
        });
        Assert.Equal(1, probe.Frees);
        Assert.False(probe.FreedInsideCallback);
    }

    [Fact]
    public void DisposingTwiceFreesOnce()
    {
        var probe = new Probe();
        var value = Make(probe);
        value.Dispose();
        value.Dispose();
        Assert.Equal(1, probe.Frees);
        Assert.True(value.IsClosed);
        Assert.Equal(0, value.Length);
    }

    [Fact]
    public void TheFinalizerFreesEachUnreachableValueOnceAndNeverOneInUse()
    {
        var probe = new Probe();
        const int Count = 2000;
        Abandon(probe, Count);
        GC.Collect();
        GC.WaitForPendingFinalizers();
        GC.Collect();
        Assert.Equal(Count, probe.Frees);

        // A collection while a callback runs does not finalize its value.
        var held = new Probe();
        UseWhileCollecting(held);
        GC.Collect();
        GC.WaitForPendingFinalizers();
        Assert.Equal(1, held.Frees);
        Assert.False(held.FreedInsideCallback);
    }

    [System.Runtime.CompilerServices.MethodImpl(System.Runtime.CompilerServices.MethodImplOptions.NoInlining)]
    private static void UseWhileCollecting(Probe held)
    {
        Make(held).Use((span, _) =>
        {
            held.Enter();
            GC.Collect();
            GC.WaitForPendingFinalizers();
            Assert.Equal(0, held.Frees);
            Assert.Equal(Text, Encoding.UTF8.GetString(span));
            held.Leave();
        });
    }

    [System.Runtime.CompilerServices.MethodImpl(System.Runtime.CompilerServices.MethodImplOptions.NoInlining)]
    private static void Abandon(Probe probe, int count)
    {
        for (var i = 0; i < count; i++)
        {
            _ = Make(probe, $"value-{i}");
        }
    }
}
