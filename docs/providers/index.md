# Providers

A SourceOrrery vault is an encrypted file in the home directory. It can
also keep secrets at a secrets service of another vendor, through a
**connection**: HashiCorp Vault, AWS Secrets Manager or Azure Key Vault,
each served behind the same contract as the vault file
([ADR 0008](../adr/0008-remote-providers.md)). The vault is the catalog of
its secrets either way: it records where each one is kept, and the CLI,
the Rust client and every SDK read it with the same calls, the same error
codes and the same policy rules wherever it is kept. There is no
SourceOrrery server; the provider's own service is the remote end.

| Provider | Connection settings | What it cannot express |
|----------|---------------------|------------------------|
| [HashiCorp Vault](hashicorp-vault.md), KV v2 | `address` (`https://`, or `http://` to this machine), `mount` (default `secret`), optional `namespace` | nothing the contract needs |
| [AWS Secrets Manager](aws-secrets-manager.md) | `region`, optional `prefix`, optional `endpoint_url` | properties per version (they are per secret), so no rotation |
| [Azure Key Vault](azure-key-vault.md) | `vault_url` (`https://`) | removing a version's time window |

A build that leaves a provider out (its Cargo feature off) shows it as
unavailable on the setup screens and refuses a connection to it with
`unsupported`, naming the provider.

## Connecting a vault

A vault has at most one connection per provider. It is added on the
[setup screens](../cli.md#setup-a-vault-on-screens) (Storage, then
Connections, with **Test connection**) or with `vault create`'s flags:

```bash
sourceorrery vault create production --recovery-key-out production.recovery-key \
  --hashicorp-vault https://vault.example.com:8200 --hashicorp-vault-namespace platform \
  --aws-secrets-manager eu-west-1 --aws-secrets-manager-prefix myapp/ \
  --azure-key-vault https://myapp-kv.vault.azure.net
```

A secret goes to a provider when it is created there: `secret set NAME
--storage aws-secrets-manager`, `import .env --storage hashicorp-vault`,
or the storage field of a new secret in the `ui` and in `init`'s screens.
Its new versions follow it. The manifest only names the vault and the
secrets; where each is kept is the vault's record, so moving a secret
between storages never touches a project.

**Credentials.** A connection signs in either the way the provider's own
tools do on the machine, or with credentials stored in the vault, sealed
under its key, read from files only (`--hashicorp-vault-token-file`,
`--aws-secret-access-key-file`, `--azure-client-secret-file`) or typed as
dots on the setup screens, never shown again:

| Provider | This machine's sign-in |
|----------|------------------------|
| HashiCorp Vault | `VAULT_TOKEN`, `~/.vault-token` from `vault login`, an AppRole, a JWT or the pod's service account token |
| AWS Secrets Manager | the AWS default credential chain: `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`, `AWS_PROFILE`, an instance or task role, or a web identity |
| Azure Key Vault | the first of: a service principal (`AZURE_CLIENT_SECRET`), workload identity federation (`AZURE_FEDERATED_TOKEN_FILE`), the Azure CLI or Azure Developer CLI, a managed identity |

A connection's settings are checked before it is stored: a URL is
`https://`, or `http://` to this machine; one with user information or a
query string is refused. [enterprise.md](../enterprise.md) covers the
workload identity set-up per platform (GitHub Actions, Kubernetes, VMs),
who decides what, and what a revocation reaches.

## Reading and changing a provider's secrets

* **CLI.** Every `secret` command, `check`, `run`, `import` and the `ui`
  reach a secret wherever it is kept; the vault sends the call through the
  connection and records it in its own audit log, with the provider's
  outcome. `vault export` carries the connections (their credentials still
  sealed) and the catalog; the provider keeps the values.
* **Rust.** `SecretReader::open` and `Project::load` open the vault and
  read through it; no provider is contacted until a secret it keeps is
  read.
* **C ABI and SDKs.** The same, through `so_reader_open` and every SDK's
  open call: nothing changes for an application when a secret moves to a
  provider.

The provider's own service holds its audit trail as well: `sourceorrery
audit` says where it is and the query that shows SourceOrrery's
operations there (each provider page, "Audit trail").

## Error codes

Two codes exist for providers; both are append-only additions
([ADR 0007](../adr/0007-versioning-and-compatibility.md)) that older SDKs
report as their base error type with the code preserved:

| Code | Meaning | Hint says |
|------|---------|-----------|
| `unauthenticated` | the provider has no credentials for this process, or they expired | where the provider's own tools take credentials from, or to store them in the vault's connection |
| `provider_unavailable` | the provider could not be reached or answered with a server error; transient | check reachability and the address in the vault's connection, then retry |

A provider's "forbidden" is the existing `permission_denied`, a missing
secret `not_found`, and a provider this build does not include
`unsupported`, as is something its service cannot express.
