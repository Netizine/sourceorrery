// Behaviour the .NET wrapper adds on top of the ABI: library versions, the
// request documents it writes, and the exception mapping.

using System.Text.Json;
using SourceOrrery.Json;
using Xunit;

namespace SourceOrrery.Tests;

public sealed class SdkTests
{
    [Fact]
    public void VersionsAreReported()
    {
        Assert.Equal(1u, SourceOrreryLibrary.ExpectedAbiVersion);
        Assert.Equal(SourceOrreryLibrary.ExpectedAbiVersion, SourceOrreryLibrary.AbiVersion);
        Assert.Equal("1", SourceOrreryLibrary.ContractVersion);
        SourceOrreryLibrary.EnsureCompatible();
    }

    [Fact]
    public void UpdateDocumentCarriesTheTriState()
    {
        static string Json(UpdateSecretProperties update) =>
            JsonSerializer.Serialize(update, SourceOrreryJsonContext.Default.UpdateSecretProperties);

        Assert.Equal("{}", Json(new UpdateSecretProperties()));
        Assert.True(new UpdateSecretProperties().IsEmpty);
        Assert.Equal(
            "{\"content_type\":null,\"expires_on\":null}",
            Json(new UpdateSecretProperties { ContentType = Optional<string>.Clear, ExpiresOn = Optional<DateTimeOffset>.Clear }));
        Assert.Equal(
            "{\"enabled\":false,\"content_type\":\"text/plain\",\"tags\":{\"env\":\"dev\"}}",
            Json(new UpdateSecretProperties
            {
                Enabled = false,
                ContentType = "text/plain",
                Tags = new Dictionary<string, string> { ["env"] = "dev" },
            }));
        Assert.Equal(
            "{\"not_before\":\"2026-10-20T10:30:00Z\"}",
            Json(new UpdateSecretProperties { NotBefore = new DateTimeOffset(2026, 10, 20, 12, 30, 0, TimeSpan.FromHours(2)) }));
        Assert.Equal("{\"content_type\":null}", Json(new UpdateSecretProperties { ContentType = null }));

        Assert.Equal(Optional<string>.Unchanged, default);
        Assert.True(Optional<string>.Clear.IsClear);
        Assert.Equal("v", Optional<string>.Set("v").Value);
        Assert.Throws<InvalidOperationException>(() => Optional<string>.Clear.Value);
        Assert.Throws<ArgumentNullException>(() => Optional<string>.Set(null!));
    }

    [Fact]
    public void RequestDocumentsMatchTheAbi()
    {
        var create = JsonSerializer.Serialize(
            new VaultCreateOptions { RecoveryLevel = RecoveryLevel.Purgeable, RetentionDays = 7, KeyDerivation = Argon2Parameters.Testing, Home = "ignored" },
            SourceOrreryJsonContext.Default.VaultCreateOptions);
        Assert.Equal(
            "{\"recovery_level\":\"purgeable\",\"retention_days\":7,\"argon2\":{\"memory_kib\":8192,\"iterations\":1,\"parallelism\":1}}",
            create);

        var set = JsonSerializer.Serialize(
            new SetSecretOptions { ContentType = "text/plain", Tags = new Dictionary<string, string> { ["a"] = "b" }, Enabled = false, ExpiresOn = new DateTimeOffset(2030, 1, 1, 0, 0, 0, 500, TimeSpan.Zero) },
            SourceOrreryJsonContext.Default.SetSecretOptions);
        Assert.Equal(
            "{\"content_type\":\"text/plain\",\"tags\":{\"a\":\"b\"},\"enabled\":false,\"expires_on\":\"2030-01-01T00:00:00.5Z\"}",
            set);

        var query = JsonSerializer.Serialize(
            new AuditQuery { Operation = AuditOperation.SecretGet, Limit = 3 },
            SourceOrreryJsonContext.Default.AuditQuery);
        Assert.Equal("{\"operation\":\"secret_get\",\"limit\":3}", query);
        Assert.Equal("{}", JsonSerializer.Serialize(new AuditQuery(), SourceOrreryJsonContext.Default.AuditQuery));
    }

    [Fact]
    public void ResponseDocumentsAreReadInTheCoresShape()
    {
        const string json = """
            {"vault":"dev","name":"k","version":"0123456789abcdef0123456789abcdef","enabled":true,
             "content_type":"text/plain","tags":{"env":"dev"},
             "not_before":"2026-10-20T00:00:00Z","created_on":"2026-10-20T10:21:33.123456789Z",
             "updated_on":"2026-10-20T10:21:33.123456789Z","recovery_level":"purgeable"}
            """;
        var props = JsonSerializer.Deserialize(json, SourceOrreryJsonContext.Default.SecretProperties)!;
        Assert.Equal("dev", props.Vault);
        Assert.Equal("dev", props.Tags["env"]);
        Assert.Equal(RecoveryLevel.Purgeable, props.RecoveryLevel);
        Assert.Null(props.ExpiresOn);
        Assert.Equal(new DateTimeOffset(2026, 10, 20, 0, 0, 0, TimeSpan.Zero), props.NotBefore);
        Assert.Equal(2026, props.CreatedOn.Year);
        Assert.Equal("sourceorrery://dev/k/0123456789abcdef0123456789abcdef", props.Reference);

        // Absent optional fields take their defaults; an unknown operation label survives.
        const string minimal = """
            {"vault":"dev","name":"k","version":"v","enabled":false,"created_on":"2026-10-20T00:00:00Z","updated_on":"2026-10-20T00:00:00Z"}
            """;
        var bare = JsonSerializer.Deserialize(minimal, SourceOrreryJsonContext.Default.SecretProperties)!;
        Assert.Empty(bare.Tags);
        Assert.Equal(RecoveryLevel.Recoverable, bare.RecoveryLevel);
        Assert.Null(bare.ContentType);

        const string eventJson = """
            {"id":7,"occurred_on":"2026-10-20T00:00:00Z","actor":{"kind":"user","id":"james"},
             "operation":"some_future_operation","outcome":"success"}
            """;
        var evt = JsonSerializer.Deserialize(eventJson, SourceOrreryJsonContext.Default.AuditEvent)!;
        Assert.Equal(7, evt.Id);
        Assert.Equal(new AuditOperation("some_future_operation"), evt.Operation);
        Assert.Equal(AuditOutcome.Success, evt.Outcome);
        Assert.Equal("user:james", evt.Actor.ToString());
        Assert.Null(evt.SecretName);
    }

    [Theory]
    [InlineData("not_found", typeof(SecretNotFoundException))]
    [InlineData("version_not_found", typeof(SecretNotFoundException))]
    [InlineData("disabled", typeof(SecretPolicyException))]
    [InlineData("expired", typeof(SecretPolicyException))]
    [InlineData("not_yet_valid", typeof(SecretPolicyException))]
    [InlineData("deleted", typeof(SecretStateException))]
    [InlineData("deleted_conflict", typeof(SecretStateException))]
    [InlineData("not_deleted", typeof(SecretStateException))]
    [InlineData("invalid_name", typeof(SourceOrreryArgumentException))]
    [InlineData("invalid_argument", typeof(SourceOrreryArgumentException))]
    [InlineData("permission_denied", typeof(SecretAccessDeniedException))]
    [InlineData("locked", typeof(VaultLockedException))]
    [InlineData("vault_not_found", typeof(VaultException))]
    [InlineData("vault_exists", typeof(VaultException))]
    [InlineData("crypto", typeof(SourceOrreryException))]
    [InlineData("storage", typeof(SourceOrreryException))]
    [InlineData("io", typeof(SourceOrreryException))]
    [InlineData("manifest", typeof(SourceOrreryException))]
    [InlineData("unsupported", typeof(SourceOrreryException))]
    [InlineData("internal", typeof(SourceOrreryException))]
    [InlineData("migration_required", typeof(SourceOrreryException))]
    [InlineData("some_code_added_later", typeof(SourceOrreryException))]
    public void ExceptionsPreserveTheirCodes(string code, Type expected)
    {
        var exception = SourceOrreryException.FromCode(code, "message");
        Assert.IsType(expected, exception);
        Assert.Equal(code, exception.Code);
        Assert.Equal("message", exception.Message);
        Assert.Equal(code == "not_yet_valid", exception.IsTransient);
    }
}
