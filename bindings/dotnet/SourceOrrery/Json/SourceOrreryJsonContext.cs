using System.Text.Json.Serialization;

namespace SourceOrrery.Json;

/// <summary>
/// Source-generated serialisation of the documents that cross the C ABI, in
/// the core's serde shape: <c>snake_case</c> keys, RFC 3339 timestamps,
/// absent optional fields omitted.
/// </summary>
[JsonSourceGenerationOptions(
    PropertyNamingPolicy = JsonKnownNamingPolicy.SnakeCaseLower,
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    Converters = new[] { typeof(Rfc3339DateTimeOffsetJsonConverter) })]
[JsonSerializable(typeof(SecretProperties))]
[JsonSerializable(typeof(List<SecretProperties>))]
[JsonSerializable(typeof(DeletedSecret))]
[JsonSerializable(typeof(List<DeletedSecret>))]
[JsonSerializable(typeof(AuditEvent))]
[JsonSerializable(typeof(List<AuditEvent>))]
[JsonSerializable(typeof(VaultDescriptor))]
[JsonSerializable(typeof(SetSecretOptions))]
[JsonSerializable(typeof(UpdateSecretProperties))]
[JsonSerializable(typeof(AuditQuery))]
[JsonSerializable(typeof(VaultCreateOptions))]
internal sealed partial class SourceOrreryJsonContext : JsonSerializerContext
{
}
