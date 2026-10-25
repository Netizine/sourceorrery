// Read one secret and report its size, never its value.
//
//   dotnet add package SourceOrrery
//   export SOURCEORRERY_RECOVERY_KEY=...   # or rely on the OS credential store
//   dotnet run -- development database-password
using SourceOrrery;

var vault = args.Length > 0 ? args[0] : "development";
var name = args.Length > 1 ? args[1] : "database-password";

try
{
    // Unlocked by the OS credential store, then SOURCEORRERY_RECOVERY_KEY,
    // then SOURCEORRERY_RECOVERY_KEY_FILE; never a prompt.
    using var reader = SecretReader.Open(vault);
    using var secret = reader.Get(name); // newest accessible version; disposed = zeroised
    await Console.Out.WriteLineAsync($"{name} version {secret.Properties.Version} from vault {vault}: {secret.Value.Length} bytes");
    return 0;
}
catch (SourceOrreryException err)
{
    // err.Code is stable; err.Message is the detail plus a hint. No values.
    await Console.Error.WriteLineAsync($"error [{err.Code}]: {err.Message}");
    return 1;
}
