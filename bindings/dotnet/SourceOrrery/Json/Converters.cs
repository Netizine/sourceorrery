using System.Globalization;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace SourceOrrery.Json;

/// <summary>
/// RFC 3339 timestamps. Incoming values are whatever the core emitted;
/// outgoing values are normalised to UTC with a <c>Z</c> suffix and no
/// trailing fractional zeros, so requests read the same as the core's own
/// output.
/// </summary>
internal sealed class Rfc3339DateTimeOffsetJsonConverter : JsonConverter<DateTimeOffset>
{
    public override DateTimeOffset Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        return reader.GetDateTimeOffset();
    }

    public override void Write(Utf8JsonWriter writer, DateTimeOffset value, JsonSerializerOptions options)
    {
        writer.WriteStringValue(Format(value));
    }

    internal static string Format(DateTimeOffset value)
    {
        var utc = value.ToUniversalTime();
        var text = utc.ToString("yyyy-MM-dd'T'HH:mm:ss.fffffff", CultureInfo.InvariantCulture);
        text = text.TrimEnd('0').TrimEnd('.');
        return text + "Z";
    }
}

/// <summary>Reads <c>"recoverable"</c> / <c>"purgeable"</c>, the core's serde labels.</summary>
internal sealed class RecoveryLevelJsonConverter : JsonConverter<RecoveryLevel>
{
    public override RecoveryLevel Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        if (reader.TokenType != JsonTokenType.String)
        {
            throw new JsonException("recovery_level must be a string");
        }
        if (reader.ValueTextEquals("recoverable"u8))
        {
            return RecoveryLevel.Recoverable;
        }
        if (reader.ValueTextEquals("purgeable"u8))
        {
            return RecoveryLevel.Purgeable;
        }
        throw new JsonException($"unknown recovery level '{reader.GetString()}'");
    }

    public override void Write(Utf8JsonWriter writer, RecoveryLevel value, JsonSerializerOptions options)
    {
        writer.WriteStringValue(value == RecoveryLevel.Purgeable ? "purgeable"u8 : "recoverable"u8);
    }
}

/// <summary>A struct that wraps one stable string label.</summary>
internal abstract class LabelJsonConverter<T> : JsonConverter<T>
    where T : struct
{
    protected abstract T Wrap(string label);

    public override T Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        if (reader.TokenType != JsonTokenType.String)
        {
            throw new JsonException($"{typeToConvert.Name} must be a string");
        }
        var label = reader.GetString();
        if (string.IsNullOrEmpty(label))
        {
            throw new JsonException($"{typeToConvert.Name} must not be empty");
        }
        return Wrap(label);
    }

    public override void Write(Utf8JsonWriter writer, T value, JsonSerializerOptions options)
    {
        writer.WriteStringValue(value.ToString());
    }
}

internal sealed class AuditOperationJsonConverter : LabelJsonConverter<AuditOperation>
{
    protected override AuditOperation Wrap(string label) => new(label);
}

internal sealed class AuditOutcomeJsonConverter : LabelJsonConverter<AuditOutcome>
{
    protected override AuditOutcome Wrap(string label) => new(label);
}

internal sealed class PrincipalKindJsonConverter : LabelJsonConverter<PrincipalKind>
{
    protected override PrincipalKind Wrap(string label) => new(label);
}

/// <summary>
/// <see cref="Optional{T}"/> of a string: <c>null</c> for
/// <see cref="Optional{T}.Clear"/>, the string otherwise. The property's
/// <c>WhenWritingDefault</c> ignore condition drops <see cref="Optional{T}.Unchanged"/>.
/// </summary>
internal sealed class OptionalStringJsonConverter : JsonConverter<Optional<string>>
{
    public override bool HandleNull => true;

    public override Optional<string> Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        if (reader.TokenType == JsonTokenType.Null)
        {
            return Optional<string>.Clear;
        }
        return Optional<string>.Set(reader.GetString() ?? throw new JsonException("expected a string"));
    }

    public override void Write(Utf8JsonWriter writer, Optional<string> value, JsonSerializerOptions options)
    {
        if (value.HasValue)
        {
            writer.WriteStringValue(value.Value);
        }
        else
        {
            writer.WriteNullValue();
        }
    }
}

/// <summary><see cref="Optional{T}"/> of a timestamp: <c>null</c> for clear, RFC 3339 otherwise.</summary>
internal sealed class OptionalDateTimeOffsetJsonConverter : JsonConverter<Optional<DateTimeOffset>>
{
    public override bool HandleNull => true;

    public override Optional<DateTimeOffset> Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        if (reader.TokenType == JsonTokenType.Null)
        {
            return Optional<DateTimeOffset>.Clear;
        }
        return Optional<DateTimeOffset>.Set(reader.GetDateTimeOffset());
    }

    public override void Write(Utf8JsonWriter writer, Optional<DateTimeOffset> value, JsonSerializerOptions options)
    {
        if (value.HasValue)
        {
            writer.WriteStringValue(Rfc3339DateTimeOffsetJsonConverter.Format(value.Value));
        }
        else
        {
            writer.WriteNullValue();
        }
    }
}
