using System.Text.Json.Serialization;
using SourceOrrery.Json;

namespace SourceOrrery;

/// <summary>
/// A partial update to a version's metadata. A property left at its default
/// is not part of the update; <see cref="Optional{T}.Clear"/> removes a
/// clearable field. An update that changes nothing is rejected by the vault
/// with <c>invalid_argument</c>.
/// </summary>
public sealed record UpdateSecretProperties
{
    /// <summary>Enable or disable the version.</summary>
    public bool? Enabled { get; init; }

    /// <summary>Replace or clear the content type.</summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    [JsonConverter(typeof(OptionalStringJsonConverter))]
    public Optional<string> ContentType { get; init; }

    /// <summary>Replace the whole tag set; an empty dictionary clears all tags.</summary>
    public IReadOnlyDictionary<string, string>? Tags { get; init; }

    /// <summary>Replace or clear the activation time.</summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    [JsonConverter(typeof(OptionalDateTimeOffsetJsonConverter))]
    public Optional<DateTimeOffset> NotBefore { get; init; }

    /// <summary>Replace or clear the expiry time.</summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    [JsonConverter(typeof(OptionalDateTimeOffsetJsonConverter))]
    public Optional<DateTimeOffset> ExpiresOn { get; init; }

    /// <summary>True when the update changes nothing.</summary>
    [JsonIgnore]
    public bool IsEmpty =>
        Enabled is null && ContentType.IsUnchanged && Tags is null && NotBefore.IsUnchanged && ExpiresOn.IsUnchanged;
}
