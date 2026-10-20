namespace SourceOrrery;

/// <summary>
/// A tri-state field of a partial update: <see cref="Unchanged"/> (the
/// default, omitted from the request), <see cref="Clear"/> (sent as JSON
/// <c>null</c>, which removes the field) or a value. A <typeparamref name="T"/>
/// converts implicitly; a <c>null</c> reference converts to <see cref="Clear"/>.
/// </summary>
public readonly struct Optional<T> : IEquatable<Optional<T>>
{
    private const byte UnchangedState = 0;
    private const byte ClearState = 1;
    private const byte SetState = 2;

    private readonly byte state;
    private readonly T? value;

    private Optional(byte state, T? value)
    {
        this.state = state;
        this.value = value;
    }

    /// <summary>Leave the field as it is.</summary>
    public static Optional<T> Unchanged => default;

    /// <summary>Remove the field's current value.</summary>
    public static Optional<T> Clear => new(ClearState, default);

    /// <summary>Replace the field with <paramref name="value"/>.</summary>
    public static Optional<T> Set(T value)
    {
        ArgumentNullException.ThrowIfNull(value);
        return new Optional<T>(SetState, value);
    }

    /// <summary>True for the default: the field is not part of the update.</summary>
    public bool IsUnchanged => state == UnchangedState;

    /// <summary>True when the update clears the field.</summary>
    public bool IsClear => state == ClearState;

    /// <summary>True when the update sets the field to <see cref="Value"/>.</summary>
    public bool HasValue => state == SetState;

    /// <summary>The new value; only valid when <see cref="HasValue"/>.</summary>
    public T Value => HasValue ? value! : throw new InvalidOperationException("this Optional holds no value");

    /// <summary>A value converts to <see cref="Set"/>; a null reference to <see cref="Clear"/>.</summary>
    public static implicit operator Optional<T>(T? value)
    {
        return value is null ? Clear : Set(value);
    }

    /// <summary>Named form of the implicit conversion.</summary>
    public static Optional<T> FromValue(T? value)
    {
        return value;
    }

    public bool Equals(Optional<T> other)
    {
        return state == other.state && (state != SetState || EqualityComparer<T?>.Default.Equals(value, other.value));
    }

    public override bool Equals(object? obj) => obj is Optional<T> other && Equals(other);

    public override int GetHashCode()
    {
        return HasValue ? HashCode.Combine(state, value) : state.GetHashCode();
    }

    public static bool operator ==(Optional<T> left, Optional<T> right) => left.Equals(right);

    public static bool operator !=(Optional<T> left, Optional<T> right) => !left.Equals(right);

    /// <inheritdoc />
    public override string ToString()
    {
        return state switch
        {
            UnchangedState => "unchanged",
            ClearState => "clear",
            _ => value?.ToString() ?? string.Empty,
        };
    }
}
