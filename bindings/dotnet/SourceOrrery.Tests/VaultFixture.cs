using System.Text;

namespace SourceOrrery.Tests;

/// <summary>
/// A temporary SourceOrrery home with passphrase vaults at the cheap Argon2
/// cost, the .NET twin of the Rust conformance <c>Fixture</c>. Nothing here
/// touches the real <c>SOURCEORRERY_HOME</c> or the OS credential store.
/// </summary>
public sealed class VaultFixture : IDisposable
{
    /// <summary>Passphrase of every fixture vault (<c>FIXTURE_PASSPHRASE</c>).</summary>
    public const string Passphrase = "conformance-passphrase";

    public VaultFixture()
    {
        Home = Path.Combine(Path.GetTempPath(), "sourceorrery-dotnet-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(Home);
    }

    /// <summary>The temporary home directory.</summary>
    public string Home { get; }

    /// <summary>Create a passphrase-protected vault with <see cref="Argon2Parameters.Testing"/>.</summary>
    public SecretClient CreateVault(string name, RecoveryLevel recoveryLevel = RecoveryLevel.Recoverable, int retentionDays = 90)
    {
        return SecretClient.CreateVault(name, Passphrase, new VaultCreateOptions
        {
            Home = Home,
            RecoveryLevel = recoveryLevel,
            RetentionDays = retentionDays,
            KeyDerivation = Argon2Parameters.Testing,
        });
    }

    /// <summary>Re-open a fixture vault.</summary>
    public SecretClient OpenVault(string name, string? passphrase = Passphrase)
    {
        return new SecretClient(name, passphrase, new SecretClientOptions { Home = Home });
    }

    public void Dispose()
    {
        try
        {
            Directory.Delete(Home, recursive: true);
        }
        catch (IOException)
        {
            // A handle may still be closing; the OS temp directory is cleaned eventually.
        }
        catch (UnauthorizedAccessException)
        {
        }
    }
}

/// <summary>Shorthands shared by the test classes.</summary>
internal static class Secrets
{
    /// <summary>Store a UTF-8 value with default options.</summary>
    public static SecretProperties Set(this SecretClient client, string name, string value)
    {
        return client.SetSecret(name, value);
    }

    /// <summary>The value as text (test-only: a copy in managed memory is fine here).</summary>
    public static string Text(this SecretValue value)
    {
        var buffer = new byte[value.Length];
        var copied = value.CopyTo(buffer);
        return Encoding.UTF8.GetString(buffer, 0, copied);
    }

    /// <summary>Read the newest accessible (or the given) version as text.</summary>
    public static string Read(this SecretClient client, string name, string? version = null)
    {
        using var secret = client.GetSecret(name, version);
        return secret.Value.Text();
    }

    /// <summary>True when <paramref name="needle"/> occurs in <paramref name="haystack"/>.</summary>
    public static bool ContainsBytes(ReadOnlySpan<byte> haystack, ReadOnlySpan<byte> needle)
    {
        return haystack.IndexOf(needle) >= 0;
    }
}
