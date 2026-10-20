using System.Text.Json.Serialization;
using SourceOrrery.Json;

namespace SourceOrrery;

/// <summary>What happens to a secret when it is deleted.</summary>
[JsonConverter(typeof(RecoveryLevelJsonConverter))]
public enum RecoveryLevel
{
    /// <summary>Deletion is soft: the secret can be recovered until its retention period ends, and purged early.</summary>
    Recoverable,

    /// <summary>Deletion is immediate and permanent.</summary>
    Purgeable,
}
