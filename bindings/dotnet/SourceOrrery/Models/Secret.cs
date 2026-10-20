namespace SourceOrrery;

/// <summary>
/// A secret version together with its value. Disposing the secret disposes
/// (zeroises) the value. <see cref="ToString"/> redacts the value.
/// </summary>
public sealed class Secret : IDisposable
{
    internal Secret(SecretProperties properties, SecretValue value)
    {
        Properties = properties;
        Value = value;
    }

    /// <summary>Metadata of the version.</summary>
    public SecretProperties Properties { get; }

    /// <summary>The plaintext, in native memory until disposed.</summary>
    public SecretValue Value { get; }

    /// <summary>Zeroise and free the value. Idempotent.</summary>
    public void Dispose()
    {
        Value.Dispose();
    }

    /// <inheritdoc />
    public override string ToString()
    {
        return $"Secret(name='{Properties.Name}', version='{Properties.Version}', value=[REDACTED])";
    }
}
