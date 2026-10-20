namespace SourceOrrery;

/// <summary>Content comparisons for the collection-valued properties of the models.</summary>
internal static class Collections
{
    public static bool TagsEqual(IReadOnlyDictionary<string, string> left, IReadOnlyDictionary<string, string> right)
    {
        if (ReferenceEquals(left, right))
        {
            return true;
        }
        if (left.Count != right.Count)
        {
            return false;
        }
        foreach (var (key, value) in left)
        {
            if (!right.TryGetValue(key, out var other) || !string.Equals(value, other, StringComparison.Ordinal))
            {
                return false;
            }
        }
        return true;
    }

    public static bool SequenceEqual(IReadOnlyList<string> left, IReadOnlyList<string> right)
    {
        return ReferenceEquals(left, right) || left.SequenceEqual(right, StringComparer.Ordinal);
    }
}
