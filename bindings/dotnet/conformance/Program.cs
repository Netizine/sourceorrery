// Conformance runner for the .NET SDK (tests/conformance/sdk/README.md).
//
//   dotnet build bindings/dotnet/conformance -c Release
//   dotnet bindings/dotnet/conformance/bin/Release/net10.0/Conformance.dll <op> [key=value ...]
using SourceOrrery;

if (args.Length < 1)
{
    Console.Error.WriteLine("usage: Conformance <op> [key=value ...]");
    return 2;
}
var op = args[0];
var kv = new Dictionary<string, string>();
foreach (var arg in args.Skip(1))
{
    var eq = arg.IndexOf('=');
    if (eq > 0) kv[arg[..eq]] = arg[(eq + 1)..];
}
var vault = kv.GetValueOrDefault("vault") ?? Environment.GetEnvironmentVariable("SOURCEORRERY_TEST_VAULT") ?? "development";
var options = new OpenOptions
{
    Home = kv.GetValueOrDefault("home"),
    RecoveryKey = kv.GetValueOrDefault("recovery_key"),
    RecoveryKeyFile = kv.GetValueOrDefault("recovery_key_file"),
    Environment = kv.GetValueOrDefault("environment") != "false",
};
var lines = new List<(string, string)>();

void Properties(SecretProperties p)
{
    lines.Add(("version", p.Version));
    lines.Add(("enabled", p.Enabled ? "true" : "false"));
    lines.Add(("content_type", p.ContentType ?? ""));
    lines.Add(("reference", p.Reference));
    foreach (var (k, v) in p.Tags) lines.Add(($"tag.{k}", v));
}

void SecretLines(Secret s)
{
    lines.Add(("value", s.Value.ExposeText()));
    Properties(s.Properties);
}

try
{
    if (op == "load")
    {
        using var project = Project.Load(kv.GetValueOrDefault("manifest"), options);
        lines.Add(("outcome", "ok"));
        lines.Add(("project.name", project.Name));
        lines.Add(("project.count", project.Secrets.Count.ToString()));
        lines.Add(("project.names", string.Join(",", project.Secrets.Select(s => s.Name).OrderBy(n => n, StringComparer.Ordinal))));
        foreach (var s in project.Secrets) lines.Add(($"secret.{s.Env}", s.Value.ExposeText()));
    }
    else
    {
        using var reader = SecretReader.Open(vault, options);
        switch (op)
        {
            case "open":
                var d = reader.GetDescriptor();
                lines.Add(("outcome", "ok"));
                lines.Add(("descriptor.name", d.Name));
                lines.Add(("descriptor.protectors", string.Join(",", d.Protectors)));
                break;
            case "get":
                using (var s = reader.Get(kv["name"], kv.GetValueOrDefault("version")))
                {
                    lines.Add(("outcome", "ok"));
                    SecretLines(s);
                }
                break;
            case "get-newest-explicit":
                using (var s = reader.Get(kv["name"], reader.GetProperties(kv["name"]).Version))
                {
                    lines.Add(("outcome", "ok"));
                    SecretLines(s);
                }
                break;
            case "properties":
                lines.Add(("outcome", "ok"));
                Properties(reader.GetProperties(kv["name"], kv.GetValueOrDefault("version")));
                break;
            case "resolve":
                using (var s = reader.Resolve(kv["reference"]))
                {
                    lines.Add(("outcome", "ok"));
                    SecretLines(s);
                }
                break;
            default:
                Console.Error.WriteLine($"unknown scenario op '{op}'");
                return 2;
        }
    }
}
catch (SourceOrreryException e)
{
    lines.Clear();
    lines.Add(("outcome", "error"));
    lines.Add(("code", e.Code));
    lines.Add(("message", e.Detail));
    lines.Add(("hint", e.Hint));
    lines.Add(("transient", e.IsTransient ? "true" : "false"));
    lines.Add(("type", e.GetType().Name));
}
foreach (var (key, value) in lines) Console.Out.Write($"{key}\t{value}\n");
return 0;
