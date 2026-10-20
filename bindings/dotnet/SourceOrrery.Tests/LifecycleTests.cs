// Port of tests/conformance/tests/lifecycle.rs: the semantics every
// SecretClient must honour, exercised through the .NET SDK.

using System.Text.Json;
using SourceOrrery.Json;
using Xunit;

namespace SourceOrrery.Tests;

public sealed class LifecycleTests
{
    [Fact]
    public void SetCreatesANewImmutableVersionEachTime()
    {
        using var fx = new VaultFixture();
        using var vault = fx.CreateVault("dev");

        var v1 = vault.Set("db-password", "one");
        var v2 = vault.Set("db-password", "two");
        Assert.NotEqual(v1.Version, v2.Version);
        Assert.Equal(32, v1.Version.Length);

        var versions = vault.ListPropertiesOfSecretVersions("db-password");
        Assert.Equal(2, versions.Count);
        Assert.Equal(v2.Version, versions[0].Version);
        Assert.Equal(v1.Version, versions[1].Version);

        using var latest = vault.GetSecret("db-password");
        Assert.Equal(v2.Version, latest.Properties.Version);
        Assert.Equal("two", latest.Value.Text());

        using var old = vault.GetSecret("db-password", v1.Version);
        Assert.Equal("one", old.Value.Text());
    }

    [Fact]
    public void GetReturnsLatestAccessibleVersion()
    {
        using var fx = new VaultFixture();
        using var vault = fx.CreateVault("dev");
        var v1 = vault.Set("api-key", "old");
        var v2 = vault.Set("api-key", "new");

        // Disabling the newest version falls back to the previous one.
        vault.UpdateSecretProperties("api-key", null, new UpdateSecretProperties { Enabled = false });
        using (var got = vault.GetSecret("api-key"))
        {
            Assert.Equal(v1.Version, got.Properties.Version);
            Assert.Equal("old", got.Value.Text());
        }

        // Asking for the disabled version explicitly is refused.
        var err = Assert.Throws<SecretPolicyException>(() => vault.GetSecret("api-key", v2.Version));
        Assert.Equal("disabled", err.Code);
        Assert.False(err.IsTransient);

        // Metadata of the disabled version is still inspectable.
        var props = vault.GetSecretProperties("api-key", v2.Version);
        Assert.False(props.Enabled);

        // Disabling both leaves nothing accessible; the newest failure is reported.
        vault.UpdateSecretProperties("api-key", v1.Version, new UpdateSecretProperties { Enabled = false });
        err = Assert.Throws<SecretPolicyException>(() => vault.GetSecret("api-key"));
        Assert.Equal("disabled", err.Code);
    }

    [Fact]
    public void TimeWindowIsEnforcedOnRetrieval()
    {
        using var fx = new VaultFixture();
        using var vault = fx.CreateVault("dev");
        var now = DateTimeOffset.UtcNow;

        vault.SetSecret("expired", "x", new SetSecretOptions { ExpiresOn = now.AddMinutes(-1) });
        var expired = Assert.Throws<SecretPolicyException>(() => vault.GetSecret("expired"));
        Assert.Equal("expired", expired.Code);
        Assert.False(expired.IsTransient);

        vault.SetSecret("pending", "x", new SetSecretOptions { NotBefore = now.AddHours(1) });
        var pending = Assert.Throws<SecretPolicyException>(() => vault.GetSecret("pending"));
        Assert.Equal("not_yet_valid", pending.Code);
        Assert.True(pending.IsTransient);

        // Clearing the expiry makes the secret readable again.
        vault.UpdateSecretProperties("expired", null, new UpdateSecretProperties { ExpiresOn = Optional<DateTimeOffset>.Clear });
        Assert.Equal("x", vault.Read("expired"));

        // An inverted window is rejected up front.
        var inverted = Assert.Throws<SourceOrreryArgumentException>(() =>
            vault.SetSecret("bad", "x", new SetSecretOptions { NotBefore = now.AddHours(2), ExpiresOn = now.AddHours(1) }));
        Assert.Equal("invalid_argument", inverted.Code);
    }

    [Fact]
    public void UpdateChangesMetadataNeverTheValue()
    {
        using var fx = new VaultFixture();
        using var vault = fx.CreateVault("dev");
        var created = vault.Set("token", "value");

        var updated = vault.UpdateSecretProperties("token", null, new UpdateSecretProperties
        {
            ContentType = "text/plain",
            Tags = new Dictionary<string, string> { ["env"] = "dev" },
        });
        Assert.Equal(created.Version, updated.Version);
        Assert.Equal("text/plain", updated.ContentType);
        Assert.Equal("dev", updated.Tags["env"]);
        Assert.Equal(created.CreatedOn, updated.CreatedOn);
        Assert.True(updated.UpdatedOn >= created.UpdatedOn);

        using var got = vault.GetSecret("token");
        Assert.Equal("value", got.Value.Text());
        Assert.Equal(updated, got.Properties);

        var empty = Assert.Throws<SourceOrreryArgumentException>(() =>
            vault.UpdateSecretProperties("token", null, new UpdateSecretProperties()));
        Assert.Equal("invalid_argument", empty.Code);
    }

    [Fact]
    public void ListReturnsMetadataForLiveSecretsOnly()
    {
        using var fx = new VaultFixture();
        using var vault = fx.CreateVault("dev");
        vault.Set("alpha", "1");
        vault.Set("beta", "2");
        vault.Set("beta", "3");
        vault.Set("gamma", "4");
        vault.DeleteSecret("gamma");

        var listed = vault.ListPropertiesOfSecrets();
        Assert.Equal(new[] { "alpha", "beta" }, listed.Select(p => p.Name).ToArray());
        var beta = listed.Single(p => p.Name == "beta");
        using (var newest = vault.GetSecret("beta"))
        {
            Assert.Equal(newest.Properties.Version, beta.Version);
        }

        var json = JsonSerializer.Serialize(listed.ToList(), SourceOrreryJsonContext.Default.ListSecretProperties);
        foreach (var value in new[] { "\"1\"", "\"2\"", "\"3\"" })
        {
            Assert.DoesNotContain(value, json, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void DeleteRecoverAndPurge()
    {
        using var fx = new VaultFixture();
        using var vault = fx.CreateVault("dev");
        vault.Set("db", "secret");

        var deleted = vault.DeleteSecret("db");
        Assert.Equal("db", deleted.Properties.Name);
        Assert.NotNull(deleted.ScheduledPurgeOn);
        Assert.True(deleted.ScheduledPurgeOn > deleted.DeletedOn);
        Assert.Equal("sourceorrery://dev/deletedsecrets/db", deleted.RecoveryId);

        var state = Assert.Throws<SecretStateException>(() => vault.GetSecret("db"));
        Assert.Equal("deleted", state.Code);
        Assert.Empty(vault.ListPropertiesOfSecrets());
        Assert.Single(vault.ListDeletedSecrets());
        Assert.Equal(deleted, vault.GetDeletedSecret("db"));

        state = Assert.Throws<SecretStateException>(() => vault.Set("db", "again"));
        Assert.Equal("deleted_conflict", state.Code);

        var missing = Assert.Throws<SecretNotFoundException>(() => vault.PurgeDeletedSecret("other"));
        Assert.Equal("not_found", missing.Code);
        missing = Assert.Throws<SecretNotFoundException>(() => vault.RecoverDeletedSecret("other"));
        Assert.Equal("not_found", missing.Code);

        var recovered = vault.RecoverDeletedSecret("db");
        Assert.Equal("db", recovered.Name);
        Assert.Equal("secret", vault.Read("db"));
        state = Assert.Throws<SecretStateException>(() => vault.RecoverDeletedSecret("db"));
        Assert.Equal("not_deleted", state.Code);
        state = Assert.Throws<SecretStateException>(() => vault.PurgeDeletedSecret("db"));
        Assert.Equal("not_deleted", state.Code);

        vault.DeleteSecret("db");
        vault.PurgeDeletedSecret("db");
        missing = Assert.Throws<SecretNotFoundException>(() => vault.GetSecret("db"));
        Assert.Equal("not_found", missing.Code);
        Assert.Empty(vault.ListDeletedSecrets());

        // The name is free again after a purge.
        vault.Set("db", "fresh");
        Assert.Equal("fresh", vault.Read("db"));
    }

    [Fact]
    public void PurgeableVaultsDeleteImmediately()
    {
        using var fx = new VaultFixture();
        using var vault = fx.CreateVault("scratch", RecoveryLevel.Purgeable, retentionDays: 7);
        var props = vault.Set("tmp", "x");
        Assert.Equal(RecoveryLevel.Purgeable, props.RecoveryLevel);
        Assert.Equal(RecoveryLevel.Purgeable, vault.GetVaultDescriptor().RecoveryLevel);

        var deleted = vault.DeleteSecret("tmp");
        Assert.Equal(string.Empty, deleted.RecoveryId);
        var err = Assert.Throws<SecretNotFoundException>(() => vault.GetSecret("tmp"));
        Assert.Equal("not_found", err.Code);
        Assert.Empty(vault.ListDeletedSecrets());
    }

    [Fact]
    public void NamesAndOptionsAreValidated()
    {
        using var fx = new VaultFixture();
        using var vault = fx.CreateVault("dev");
        foreach (var bad in new[] { "", "has_underscore", "has space", "dots.no", new string('x', 128) })
        {
            var err = Assert.Throws<SourceOrreryArgumentException>(() => vault.Set(bad, "v"));
            Assert.Equal("invalid_name", err.Code);
        }
        var missing = Assert.Throws<SecretNotFoundException>(() => vault.GetSecret("missing"));
        Assert.Equal("not_found", missing.Code);
        Assert.False(missing.IsVersionMissing);

        vault.Set("present", "v");
        var version = Assert.Throws<SecretNotFoundException>(() => vault.GetSecret("present", "nope"));
        Assert.Equal("version_not_found", version.Code);
        Assert.True(version.IsVersionMissing);

        var retention = Assert.Throws<SourceOrreryArgumentException>(() => fx.CreateVault("bad-retention", retentionDays: 3));
        Assert.Equal("invalid_argument", retention.Code);
        var absent = Assert.Throws<VaultException>(() => fx.OpenVault("bad-retention"));
        Assert.Equal("vault_not_found", absent.Code);

        var exists = Assert.Throws<VaultException>(() => fx.CreateVault("dev"));
        Assert.Equal("vault_exists", exists.Code);
        var badName = Assert.Throws<SourceOrreryArgumentException>(() => fx.CreateVault("Bad Name"));
        Assert.Equal("invalid_name", badName.Code);
        var emptyPassphrase = Assert.Throws<SourceOrreryArgumentException>(() =>
            SecretClient.CreateVault("empty-pass", string.Empty, new VaultCreateOptions { Home = fx.Home, KeyDerivation = Argon2Parameters.Testing }));
        Assert.Equal("invalid_argument", emptyPassphrase.Code);
    }

    [Fact]
    public void AuditTrailRecordsEveryOperationWithoutValues()
    {
        using var fx = new VaultFixture();
        using var vault = fx.CreateVault("dev");
        var props = vault.Set("k", "plaintext-value-123");
        vault.Read("k");
        vault.UpdateSecretProperties("k", null, new UpdateSecretProperties { Enabled = false });
        Assert.Throws<SecretPolicyException>(() => vault.GetSecret("k"));
        Assert.Throws<SecretNotFoundException>(() => vault.GetSecret("missing"));
        vault.ListPropertiesOfSecrets();

        var events = vault.GetAuditEvents();
        var ops = events.Select(e => (e.Operation, e.Outcome)).ToList();
        Assert.Contains((AuditOperation.VaultCreate, AuditOutcome.Success), ops);
        Assert.Contains((AuditOperation.SecretSet, AuditOutcome.Success), ops);
        Assert.Contains((AuditOperation.SecretGet, AuditOutcome.Success), ops);
        Assert.Contains((AuditOperation.SecretUpdate, AuditOutcome.Success), ops);
        Assert.Contains((AuditOperation.SecretGet, AuditOutcome.Denied), ops);
        Assert.Contains((AuditOperation.SecretGet, AuditOutcome.Failure), ops);
        Assert.Contains((AuditOperation.SecretList, AuditOutcome.Success), ops);

        var denied = events.First(e => e.Operation == AuditOperation.SecretGet && e.Outcome == AuditOutcome.Denied);
        Assert.Equal("disabled", denied.Detail);
        Assert.Equal("k", denied.SecretName);
        Assert.Equal(PrincipalKind.User, denied.Actor.Kind);

        var successfulGet = events.First(e => e.Operation == AuditOperation.SecretGet && e.Outcome == AuditOutcome.Success);
        Assert.Equal(props.Version, successfulGet.Version);

        // Newest first, and filters work.
        for (var i = 1; i < events.Count; i++)
        {
            Assert.True(events[i - 1].Id > events[i].Id, "events must be newest first");
        }
        var onlyGets = vault.GetAuditEvents(new AuditQuery { Operation = AuditOperation.SecretGet });
        Assert.NotEmpty(onlyGets);
        Assert.All(onlyGets, e => Assert.Equal(AuditOperation.SecretGet, e.Operation));
        var onlyK = vault.GetAuditEvents(new AuditQuery { SecretName = "k", Limit = 2 });
        Assert.Equal(2, onlyK.Count);
        Assert.All(onlyK, e => Assert.Equal("k", e.SecretName));
        var since = vault.GetAuditEvents(new AuditQuery { Since = DateTimeOffset.UtcNow.AddDays(1) });
        Assert.Empty(since);

        var dump = JsonSerializer.Serialize(events.ToList(), SourceOrreryJsonContext.Default.ListAuditEvent);
        Assert.DoesNotContain("plaintext-value-123", dump, StringComparison.Ordinal);
    }

    [Fact]
    public void ReopeningPreservesEverything()
    {
        using var fx = new VaultFixture();
        using (var vault = fx.CreateVault("dev"))
        {
            vault.SetSecret("k", "v", new SetSecretOptions
            {
                ContentType = "text/plain",
                Tags = new Dictionary<string, string> { ["team"] = "platform" },
            });
        }

        using var reopened = fx.OpenVault("dev");
        using var secret = reopened.GetSecret("k");
        Assert.Equal("v", secret.Value.Text());
        Assert.Equal("text/plain", secret.Properties.ContentType);
        Assert.Equal("platform", secret.Properties.Tags["team"]);
        Assert.Equal($"sourceorrery://dev/k/{secret.Properties.Version}", secret.Properties.Reference);

        var descriptor = reopened.GetVaultDescriptor();
        Assert.Equal("dev", descriptor.Name);
        Assert.Equal("encrypted-sqlite", descriptor.Backend);
        Assert.Equal(new[] { "passphrase" }, descriptor.Protectors);
        Assert.Equal(RecoveryLevel.Recoverable, descriptor.RecoveryLevel);
        Assert.Equal(90, descriptor.RetentionDays);
        Assert.NotNull(descriptor.Path);
        Assert.True(File.Exists(descriptor.Path));
        Assert.StartsWith(fx.Home, descriptor.Path, StringComparison.Ordinal);
    }
}
