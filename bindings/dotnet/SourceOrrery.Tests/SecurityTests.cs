// Port of the SDK-reachable scenarios of tests/conformance/tests/security.rs
// (what must never happen), plus the guarantees the .NET wrapper adds.

using System.Text;
using System.Text.Json;
using SourceOrrery.Json;
using Xunit;

namespace SourceOrrery.Tests;

public sealed class SecurityTests
{
    private const string Canary = "CANARY-7f3a9c2e-plaintext-must-never-appear";

    [Fact]
    public void VaultFileNeverContainsPlaintextOrPassphrase()
    {
        using var fx = new VaultFixture();
        string path;
        using (var vault = fx.CreateVault("dev"))
        {
            path = vault.GetVaultDescriptor().Path ?? throw new InvalidOperationException("file-backed vaults report a path");
            vault.Set("canary", Canary);
            vault.Set("canary", Canary);
            vault.Read("canary");
            vault.DeleteSecret("canary");
            vault.RecoverDeletedSecret("canary");
        }

        var bytes = File.ReadAllBytes(path);
        Assert.True(bytes.Length > 4096, "vault file should be a populated SQLite database");
        Assert.False(Secrets.ContainsBytes(bytes, Encoding.UTF8.GetBytes(Canary)), "plaintext found in vault file");
        Assert.False(Secrets.ContainsBytes(bytes, Encoding.UTF8.GetBytes(VaultFixture.Passphrase)), "passphrase found in vault file");
        // Also check UTF-16LE, in case a platform API re-encoded the value.
        Assert.False(Secrets.ContainsBytes(bytes, Encoding.Unicode.GetBytes(Canary)), "UTF-16 plaintext found in vault file");
    }

    [Fact]
    public void AuditLogAndErrorsNeverContainValues()
    {
        using var fx = new VaultFixture();
        using var vault = fx.CreateVault("dev");
        vault.Set("canary", Canary);
        vault.Read("canary");

        var version = Assert.Throws<SecretNotFoundException>(() => vault.GetSecret("canary", "deadbeef"));
        Assert.DoesNotContain(Canary, version.ToString(), StringComparison.Ordinal);
        Assert.Contains("canary", version.Message, StringComparison.Ordinal);
        var name = Assert.Throws<SourceOrreryArgumentException>(() => vault.Set("bad_name", Canary));
        Assert.DoesNotContain(Canary, name.ToString(), StringComparison.Ordinal);

        var events = vault.GetAuditEvents();
        var dump = JsonSerializer.Serialize(events.ToList(), SourceOrreryJsonContext.Default.ListAuditEvent);
        Assert.DoesNotContain(Canary, dump, StringComparison.Ordinal);
        Assert.DoesNotContain(VaultFixture.Passphrase, dump, StringComparison.Ordinal);
        Assert.Contains(events, e => e.Operation == AuditOperation.SecretGet && e.Outcome == AuditOutcome.Success);
    }

    [Fact]
    public void ToStringRedactsValues()
    {
        using var fx = new VaultFixture();
        using var vault = fx.CreateVault("dev");
        vault.Set("canary", Canary);

        using var secret = vault.GetSecret("canary");
        Assert.Equal(Canary, secret.Value.Text());
        Assert.Equal("[REDACTED]", secret.Value.ToString());
        Assert.DoesNotContain(Canary, secret.ToString(), StringComparison.Ordinal);
        Assert.Contains("REDACTED", secret.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain(Canary, secret.Properties.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain(Canary, vault.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain(Canary, $"{secret.Value}", StringComparison.Ordinal);

        var err = Assert.Throws<SecretNotFoundException>(() => vault.GetSecret("canary", "deadbeef"));
        Assert.DoesNotContain(Canary, err.ToString(), StringComparison.Ordinal);
        var mapped = SourceOrreryException.FromCode("storage", "disk full");
        Assert.DoesNotContain(Canary, mapped.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public void WrongPassphraseIsRefusedAndRecorded()
    {
        using var fx = new VaultFixture();
        fx.CreateVault("dev").Dispose();

        var locked = Assert.Throws<VaultLockedException>(() => fx.OpenVault("dev", "not-the-passphrase"));
        Assert.Equal("locked", locked.Code);
        Assert.DoesNotContain("not-the-passphrase", locked.ToString(), StringComparison.Ordinal);

        // No keyring protector and no passphrase: locked as well.
        var noPassphrase = Assert.Throws<VaultLockedException>(() => fx.OpenVault("dev", passphrase: null));
        Assert.Equal("locked", noPassphrase.Code);

        using var vault = fx.OpenVault("dev");
        var events = vault.GetAuditEvents();
        Assert.Contains(events, e => e.Operation == AuditOperation.VaultOpen && e.Outcome == AuditOutcome.Denied);
        var opens = vault.GetAuditEvents(new AuditQuery { Operation = AuditOperation.VaultOpen, Limit = 10 });
        Assert.All(opens, e => Assert.Equal(AuditOperation.VaultOpen, e.Operation));
        Assert.Contains(opens, e => e.Outcome == AuditOutcome.Denied);
    }

    [Fact]
    public void DisposedValueIsZeroed()
    {
        using var fx = new VaultFixture();
        using var vault = fx.CreateVault("dev");
        vault.Set("k", Canary);

        var secret = vault.GetSecret("k");
        var value = secret.Value;
        Assert.Equal(Canary.Length, value.Length);
        Assert.False(value.IsDisposed);
        var seen = 0;
        value.Use((span, state) => seen = span.Length + state, 1);
        Assert.Equal(Canary.Length + 1, seen);

        value.Dispose();
        Assert.True(value.IsDisposed);
        Assert.Equal(0, value.Length);
        value.Use(span => Assert.True(span.IsEmpty));
        Assert.Equal(0, value.CopyTo(new byte[4]));
        Assert.Equal("[REDACTED]", value.ToString());

        // Disposing twice, and through the owning Secret, is harmless.
        value.Dispose();
        secret.Dispose();
        Assert.Equal(0, value.Length);
    }

    [Fact]
    public async Task ClientIsThreadSafe()
    {
        using var fx = new VaultFixture();
        using var vault = fx.CreateVault("dev");
        vault.Set("shared", "value");

        var workers = Enumerable.Range(0, 4).Select(i => Task.Run(() =>
        {
            for (var n = 0; n < 5; n++)
            {
                Assert.Equal("value", vault.Read("shared"));
                vault.Set($"worker-{i}", "w");
            }
            // Each thread has its own error state.
            var err = Assert.Throws<SecretNotFoundException>(() => vault.GetSecret("missing"));
            Assert.Equal("not_found", err.Code);
        })).ToArray();
        await Task.WhenAll(workers);

        Assert.Equal(5, vault.ListPropertiesOfSecrets().Count);
    }

    [Fact]
    public void DisposedClientRefusesCalls()
    {
        using var fx = new VaultFixture();
        var vault = fx.CreateVault("dev");
        vault.Set("k", "v");
        vault.Dispose();
        Assert.True(vault.IsClosed);
        Assert.Throws<ObjectDisposedException>(() => vault.GetSecret("k"));
        vault.Dispose(); // idempotent

        using var reopened = fx.OpenVault("dev");
        Assert.Equal("v", reopened.Read("k"));
    }

    [Fact]
    public void ClearingAPassphraseVaultNeverTouchesTheHome()
    {
        // The fixture's temporary home is the only place a test writes to.
        using var fx = new VaultFixture();
        using var vault = fx.CreateVault("dev");
        var path = vault.GetVaultDescriptor().Path;
        Assert.NotNull(path);
        Assert.StartsWith(fx.Home, path, StringComparison.Ordinal);
    }
}
