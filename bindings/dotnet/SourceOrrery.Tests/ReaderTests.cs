// The .NET SDK against the vault created by scripts/ci/fixture-vault.sh.
using System.Runtime.InteropServices;
using System.Text.Json;
using Xunit;

// Environment variables are process-wide and the native library reads them: the remote-vault test
// changes VAULT_TOKEN, so no other test may run while it does.
[assembly: CollectionBehavior(DisableTestParallelization = true)]

namespace SourceOrrery.Tests;

/// <summary>
/// Sets an environment variable where the native library reads it. On Unix,
/// <see cref="Environment.SetEnvironmentVariable(string, string?)"/> changes only the runtime's
/// managed copy of the environment, while the C ABI reads the process's with <c>getenv</c>, so
/// both are set; on Windows the managed call writes through to the process block.
/// </summary>
internal static class ProcessEnvironment
{
    public static void Set(string name, string? value)
    {
        Environment.SetEnvironmentVariable(name, value);
        if (OperatingSystem.IsWindows())
        {
            return;
        }
        var result = value is null ? unsetenv(name) : setenv(name, value, 1);
        if (result != 0)
        {
            throw new InvalidOperationException($"could not set {name} in the process environment");
        }
    }

    [DllImport("libc")]
    private static extern int setenv(string name, string value, int overwrite);

    [DllImport("libc")]
    private static extern int unsetenv(string name);
}

public sealed class Fixture
{
    public Fixture()
    {
        Home = Require("SOURCEORRERY_HOME");
        Passphrase = Require("SOURCEORRERY_PASSPHRASE");
        Vault = Require("SOURCEORRERY_TEST_VAULT");
        Manifest = Require("SOURCEORRERY_TEST_MANIFEST");
        OldVersion = Require("SOURCEORRERY_TEST_OLD_VERSION");
    }

    public string Home { get; }
    public string Passphrase { get; }
    public string Vault { get; }
    public string Manifest { get; }
    public string OldVersion { get; }
    public const string Latest = "ci-secret-value";
    public const string First = "first-version";

    private static string Require(string name) =>
        Environment.GetEnvironmentVariable(name)
        ?? throw new InvalidOperationException($"{name} is not set; run scripts/ci/fixture-vault.sh first");

    /// <summary>Unlocks through SOURCEORRERY_PASSPHRASE from the environment, like the CLI.</summary>
    public SecretReader OpenReader() => SecretReader.Open(Vault);
}

public sealed class ReaderTests : IClassFixture<Fixture>
{
    private readonly Fixture fx;

    public ReaderTests(Fixture fixture)
    {
        fx = fixture;
    }

    [Fact]
    public void ContractVersion()
    {
        Assert.Equal("1", SourceOrreryNative.ContractVersion);
        Assert.Equal(1u, SourceOrreryNative.AbiVersion);
    }

    [Fact]
    public void GetReturnsTheNewestAccessibleVersion()
    {
        using var reader = fx.OpenReader();
        using var secret = reader.Get("database-password");
        Assert.Equal(Fixture.Latest, secret.Value.ExposeText());
        Assert.Equal(System.Text.Encoding.UTF8.GetBytes(Fixture.Latest), secret.Value.Expose());
        Assert.Equal(Fixture.Latest.Length, secret.Value.Length);
        var seen = 0;
        secret.Value.Use((span, _) => seen = span.Length);
        Assert.Equal(Fixture.Latest.Length, seen);
        Assert.Equal("database-password", secret.Properties.Name);
        Assert.Equal(fx.Vault, secret.Properties.Vault);
        Assert.True(secret.Properties.Enabled);
        Assert.Equal("text/plain", secret.Properties.ContentType);
        Assert.Equal("ci", secret.Properties.Tags["env"]);
        Assert.True(secret.Properties.CreatedOn <= DateTimeOffset.UtcNow);
        Assert.Equal($"sourceorrery://{fx.Vault}/database-password/{secret.Properties.Version}", secret.Properties.Reference);
    }

    [Fact]
    public void ExplicitVersionsAndProperties()
    {
        using var reader = fx.OpenReader();
        using var old = reader.Get("database-password", fx.OldVersion);
        Assert.Equal(Fixture.First, old.Value.ExposeText());
        Assert.Equal(fx.OldVersion, old.Properties.Version);
        Assert.Equal(fx.OldVersion, reader.GetProperties("database-password", fx.OldVersion).Version);
        Assert.NotEqual(fx.OldVersion, reader.GetProperties("database-password").Version);
    }

    [Fact]
    public void ReferencesResolveWithinTheVault()
    {
        using var reader = fx.OpenReader();
        using var latest = reader.Resolve($"sourceorrery://{fx.Vault}/database-password");
        Assert.Equal(Fixture.Latest, latest.Value.ExposeText());
        using var pinned = reader.Resolve($"sourceorrery://{fx.Vault}/database-password/{fx.OldVersion}");
        Assert.Equal(Fixture.First, pinned.Value.ExposeText());
        var err = Assert.Throws<InvalidArgumentException>(() => reader.Resolve("sourceorrery://other-vault/database-password"));
        Assert.Equal("invalid_argument", err.Code);
        Assert.Throws<InvalidArgumentException>(() => reader.Resolve("not-a-reference"));
    }

    [Fact]
    public void DisabledNewestVersionFallsBack()
    {
        using var reader = fx.OpenReader();
        using var current = reader.Get("rotated-key");
        Assert.Equal("old", current.Value.ExposeText());
        var newest = reader.GetProperties("rotated-key");
        Assert.False(newest.Enabled);
        var err = Assert.Throws<SecretDisabledException>(() => reader.Get("rotated-key", newest.Version));
        Assert.IsAssignableFrom<PolicyException>(err);
        Assert.Equal("disabled", err.Code);
        Assert.Contains("--enable", err.Hint);
    }

    [Fact]
    public void PolicyErrorsExplainThemselves()
    {
        using var reader = fx.OpenReader();
        var expired = Assert.Throws<SecretExpiredException>(() => reader.Get("expired-token"));
        Assert.StartsWith("Policy", expired.Hint);
        Assert.False(expired.IsTransient);
        var pending = Assert.Throws<SecretNotYetValidException>(() => reader.Get("future-token"));
        Assert.True(pending.IsTransient);
        var deleted = Assert.Throws<SecretDeletedException>(() => reader.Get("deleted-secret"));
        Assert.Contains("secret recover deleted-secret", deleted.Hint);
    }

    [Fact]
    public void MissingSecretsSayHowToStoreThem()
    {
        using var reader = fx.OpenReader();
        var err = Assert.Throws<SecretNotFoundException>(() => reader.Get("missing"));
        Assert.Equal("not_found", err.Code);
        Assert.Equal("secret 'missing' was not found", err.Detail);
        Assert.Contains($"sourceorrery secret set missing --vault {fx.Vault}", err.Hint);
        Assert.StartsWith(err.Detail + ". ", err.Message);
        var version = Assert.Throws<VersionNotFoundException>(() => reader.Get("database-password", "deadbeef"));
        Assert.IsAssignableFrom<SecretNotFoundException>(version);
        Assert.Throws<InvalidNameException>(() => reader.Get("bad_name"));
    }

    [Fact]
    public void VaultErrorsSayHowToFixThem()
    {
        var missing = Assert.Throws<VaultNotFoundException>(() => SecretReader.Open("no-such-vault"));
        Assert.Contains("sourceorrery vault create no-such-vault", missing.Hint);
        Assert.Contains(fx.Home, missing.Hint);

        var locked = Assert.Throws<VaultLockedException>(() =>
            SecretReader.Open(fx.Vault, new OpenOptions { Passphrase = "wrong-passphrase", Environment = false }));
        Assert.Contains("passphrase option: tried", locked.Hint);
        Assert.Contains("SOURCEORRERY_PASSPHRASE: not set", locked.Hint);
        Assert.Contains($"--vault {fx.Vault}", locked.Hint);
        Assert.DoesNotContain("wrong-passphrase", locked.Message);

        using var reader = SecretReader.Open(fx.Vault, new OpenOptions { Home = fx.Home, Passphrase = fx.Passphrase, Environment = false });
        Assert.Equal(fx.Vault, reader.VaultName);
        var descriptor = reader.GetDescriptor();
        Assert.Equal(fx.Vault, descriptor.Name);
        Assert.Contains("passphrase", descriptor.Protectors);
        reader.Dispose();
        Assert.True(reader.IsClosed);
        Assert.Throws<ObjectDisposedException>(() => reader.Get("database-password"));
        reader.Dispose();
    }

    [Fact]
    public void SecretValuesDoNotLeak()
    {
        using var reader = fx.OpenReader();
        var secret = reader.Get("database-password");
        Assert.Equal("[REDACTED]", secret.Value.ToString());
        Assert.DoesNotContain(Fixture.Latest, JsonSerializer.Serialize(secret.Properties));
        Assert.DoesNotContain(Fixture.Latest, JsonSerializer.Serialize(new { secret.Value.Length, secret.Value.IsClosed }));
        secret.Value.Dispose();
        Assert.True(secret.Value.IsClosed);
        Assert.Equal(0, secret.Value.Length);
        Assert.Throws<ObjectDisposedException>(() => secret.Value.Expose());
        secret.Value.Dispose();
    }

    [Fact]
    public void ReaderIsThreadSafe()
    {
        using var reader = fx.OpenReader();
        Parallel.For(0, 4, _ =>
        {
            for (var i = 0; i < 5; i++)
            {
                using var secret = reader.Get("database-password");
                Assert.Equal(Fixture.Latest, secret.Value.ExposeText());
            }
            Assert.Throws<SecretNotFoundException>(() => reader.Get("missing"));
        });
    }

    [Fact]
    public void ProjectLoadMirrorsRun()
    {
        using (var project = Project.Load(fx.Manifest))
        {
            Assert.Equal("ci-project", project.Name);
            Assert.EndsWith("sourceorrery.toml", project.ManifestPath);
            Assert.Equal(new[] { "database-password", "rotated-key" }, project.Secrets.Select(s => s.Name).OrderBy(n => n));
            Assert.Equal(Fixture.Latest, project.Env("DATABASE_PASSWORD")!.ExposeText());
            Assert.Equal("old", project.Env("ROTATED")!.ExposeText());
            Assert.Null(project.Get("missing-optional"));
            Assert.Null(project.Get("expired-token"));
            var entry = project.Get("rotated-key")!;
            Assert.True(entry.Required);
            Assert.Equal("ROTATED", entry.Env);
            Assert.Equal($"sourceorrery://{fx.Vault}/rotated-key", entry.Reference);
            Assert.Equal(2, project.Secrets.Count);
        }
        Assert.Throws<ManifestException>(() => Project.Load(fx.Manifest + ".missing"));
        Assert.Throws<VaultLockedException>(() => Project.Load(fx.Manifest, new OpenOptions { Passphrase = "wrong", Environment = false }));
    }

    /// <summary>
    /// A vault the manifest declares in [vaults.name] goes to its provider, whose credential comes
    /// from the environment, never the manifest.
    /// </summary>
    [Fact]
    public void ManifestDeclaresRemoteVaults()
    {
        var dir = Path.Combine(Path.GetTempPath(), "sourceorrery-dotnet-" + Path.GetRandomFileName());
        Directory.CreateDirectory(dir);
        try
        {
            var remoteManifest = Path.Combine(dir, "sourceorrery.toml");
            File.WriteAllText(remoteManifest, string.Join("\n",
                "[project]",
                "name = \"demo\"",
                $"vault = \"{fx.Vault}\"",
                "",
                "[vaults.remote-x]",
                "provider = \"hashicorp-vault\"",
                "address = \"http://127.0.0.1:1\"",
                "mount = \"secret\"",
                ""));
            var options = new OpenOptions { Manifest = remoteManifest };
            Assert.Contains("\"manifest\":", options.ToJson());

            var previousToken = Environment.GetEnvironmentVariable("VAULT_TOKEN");
            try
            {
                // With a credential the provider connects, and nothing listens on port 1: transient.
                // The value is not a secret; the connection fails before it is ever sent.
                ProcessEnvironment.Set("VAULT_TOKEN", "not-a-real-token");
                var unavailable = Assert.Throws<ProviderUnavailableException>(() => SecretReader.Open("remote-x", options));
                Assert.Equal("provider_unavailable", unavailable.Code);
                Assert.True(unavailable.IsTransient);
                Assert.Contains("hashicorp-vault is unavailable", unavailable.Detail);
                Assert.Contains("[vaults.remote-x]", unavailable.Hint);

                // Without VAULT_TOKEN the provider refuses before any request, unless the developer running
                // this has another credential (~/.vault-token, AppRole, ...), in which case it connects again.
                ProcessEnvironment.Set("VAULT_TOKEN", null);
                var err = Assert.ThrowsAny<SourceOrreryException>(() => SecretReader.Open("remote-x", options));
                Assert.Contains("hashicorp-vault", err.Detail);
                switch (err)
                {
                    case UnauthenticatedException:
                        Assert.Equal("unauthenticated", err.Code);
                        Assert.False(err.IsTransient);
                        Assert.Contains("not authenticated to hashicorp-vault", err.Detail);
                        Assert.Contains("VAULT_TOKEN", err.Hint);
                        break;
                    case ProviderUnavailableException:
                        Assert.Equal("provider_unavailable", err.Code);
                        Assert.True(err.IsTransient);
                        Assert.Contains("[vaults.remote-x]", err.Hint);
                        break;
                    default:
                        Assert.Fail($"expected UnauthenticatedException or ProviderUnavailableException, got {err.GetType().Name} ({err.Code}): {err.Message}");
                        break;
                }
            }
            finally
            {
                ProcessEnvironment.Set("VAULT_TOKEN", previousToken);
            }

            // A vault without a table is still the local file.
            using var reader = SecretReader.Open(fx.Vault, options);
            using var secret = reader.Get("database-password");
            Assert.Equal(fx.Vault, reader.VaultName);
            Assert.Equal(Fixture.Latest, secret.Value.ExposeText());
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public void RemoteCodesMapToTheirExceptions()
    {
        var unauthenticated = SourceOrreryException.ForCode("unauthenticated", "m", "h");
        Assert.IsType<UnauthenticatedException>(unauthenticated);
        Assert.Equal("unauthenticated", unauthenticated.Code);
        Assert.False(unauthenticated.IsTransient);
        var unavailable = SourceOrreryException.ForCode("provider_unavailable", "m", "h");
        Assert.IsType<ProviderUnavailableException>(unavailable);
        Assert.Equal("provider_unavailable", unavailable.Code);
        Assert.True(unavailable.IsTransient);
    }

    [Fact]
    public void UnknownCodesKeepTheirCode()
    {
        var err = SourceOrreryException.ForCode("brand_new_code", "m", "h");
        Assert.Equal(typeof(SourceOrreryException), err.GetType());
        Assert.Equal("brand_new_code", err.Code);
        Assert.Equal("m. h", err.Message);
    }
}

/// <summary>An SDK refuses a library built for another C ABI version with a typed exception (ADR 0007).</summary>
public sealed class AbiTests
{
    [Fact]
    public void AbiMismatchIsATypedException()
    {
        Assert.Equal(Interop.AbiVersion, SourceOrreryNative.AbiVersion);
        Assert.Null(Interop.AbiMismatch(Interop.AbiVersion));
        var err = Interop.AbiMismatch(Interop.AbiVersion + 1)!;
        Assert.Equal("abi_mismatch", err.Code);
        Assert.Contains((Interop.AbiVersion + 1).ToString(), err.Message);
        Assert.Contains("sourceorrery-ffi", err.Message + err.Hint);
    }
}
