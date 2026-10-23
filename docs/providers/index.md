# Remote providers

A SourceOrrery vault is normally an encrypted file in the home directory.
A **remote vault** is a secrets service of another vendor served behind the
same contract ([ADR 0008](../adr/0008-remote-providers.md)): the CLI, the
Rust client and every SDK read it with the same calls, the same error codes
and the same policy rules as a local vault. There is no SourceOrrery server;
the provider's own service is the remote end.

| Provider | `provider =` | Addressing keys | Status |
|----------|--------------|-----------------|--------|
| HashiCorp Vault, KV v2 | `"hashicorp-vault"` | `address` (`http://` or `https://`), `mount`, optional `namespace` | planned (milestone 4.3) |
| AWS Secrets Manager | `"aws-secrets-manager"` | `region`, optional `prefix` | planned (milestone 4.4) |
| Azure Key Vault | `"azure-key-vault"` | `vault_url` (`https://`) | planned (milestone 4.5) |

The manifest shape, the client option and the error codes below are in
place now; opening a remote vault fails with `unsupported` until its
provider ships, with a message naming the provider.

## Declaring a remote vault

A remote vault is a `[vaults.<name>]` table in `sourceorrery.toml`. The
name is an ordinary vault name and is used everywhere a local vault's would
be: `[project].vault`, `[secrets.<name>].vault`, `--vault`, and
`sourceorrery://<name>/<secret>` references.

```toml
[project]
name = "my-application"
vault = "development"                 # a local vault file, as before

[secrets.payment-api-key]
vault = "production"                  # resolved from the remote vault below

[vaults.production]
provider = "hashicorp-vault"
address = "https://vault.example.com:8200"
mount = "secret"
namespace = "platform"                # Vault Enterprise only

[vaults.aws-shared]
provider = "aws-secrets-manager"
region = "eu-west-1"
prefix = "myapp/"                     # every secret name is placed under it

[vaults.azure-shared]
provider = "azure-key-vault"
vault_url = "https://myapp-kv.vault.azure.net"
```

A vault name without a table is a local vault file, so a manifest written
before remote vaults existed is valid and means what it meant.

**The manifest never holds a credential.** Each provider's table has only
the keys above; any other key (`token`, `access_key_id`, `client_secret`, a
sub-table, a key from another provider) is a parse error that names the key
and never repeats the text. A URL with user information
(`https://user:pass@host`) or a query string is refused, as is `http://` for
Azure Key Vault. Credentials come from where the provider's own tools find
them:

| Provider | Credentials |
|----------|-------------|
| HashiCorp Vault | `VAULT_TOKEN`, or `vault login` for the identity the process runs as |
| AWS Secrets Manager | the AWS default credential chain: `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`, `AWS_PROFILE`, an instance or task role, or a web identity |
| Azure Key Vault | `az login`, a managed identity, or the `AZURE_CLIENT_ID`, `AZURE_TENANT_ID` and `AZURE_FEDERATED_TOKEN_FILE` workload-identity variables |

## Opening a remote vault

* **CLI.** Commands that use the contract (`secret get`, `secret set`,
  `secret list`, `check`, `run`, `import`) work against a remote vault the
  identity may use; `vault list` shows remote vaults with their provider
  and location, and `vault info` shows what the provider reports. Commands
  about the vault file itself (`vault create`, `vault protector`,
  `vault destroy`, `vault migrate`, `audit`, `backup`, `restore`, `ui`)
  refuse a remote vault by name with a message saying they work on local
  vaults only; the provider's own service holds its audit trail.
* **Rust.** `OpenOptions::manifest(path)` names the manifest to resolve
  through; by default `SecretReader::open` uses the nearest
  `sourceorrery.toml` above the current directory, like `sourceorrery run`.
  `Project::load` always resolves through the manifest it loads.
  `SecretReader::provider()` says which provider serves the vault.
* **C ABI and SDKs.** `so_reader_open` takes the same through the
  `"manifest"` key of `options_json`; each SDK exposes it as a `manifest`
  option next to `home` and `passphrase_file`.

## Error codes

Two codes exist for remote providers; both are append-only additions
([ADR 0007](../adr/0007-versioning-and-compatibility.md)) that older SDKs
report as their base error type with the code preserved:

| Code | Meaning | Hint says |
|------|---------|-----------|
| `unauthenticated` | the provider has no credentials for this process, or they expired | where the provider's own tools take credentials from (never the manifest) |
| `provider_unavailable` | the provider could not be reached or answered with a server error; transient | check reachability and the address in the manifest's `[vaults.<name>]` table, then retry |

A provider's "forbidden" is the existing `permission_denied`, a missing
secret `not_found`, and a provider this build does not include
`unsupported`. `audit_events` on a remote vault is `unsupported` too: the
provider's own service keeps the log (Vault audit devices, CloudTrail,
Azure Monitor).
