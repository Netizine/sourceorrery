# sourceorrery-provider-azure

[Azure Key Vault](https://learn.microsoft.com/azure/key-vault/secrets/)
behind the [SourceOrrery](https://sourceorrery.ai) secret contract: the
same `get`, `set`, versions, policy, soft delete and recover as a local
vault, served by Key Vault.

**You probably want another crate.** A SourceOrrery vault keeps a
secret at Key Vault through a connection it holds, made with the CLI
(`sourceorrery setup`, or `vault create --azure-key-vault URL`), and
applications read it through
[`sourceorrery`](https://crates.io/crates/sourceorrery) (feature
`provider-azure`, on by default) like any other secret; the manifest never
names the Key Vault.

Use the CLI to create vaults and set secret values; application SDKs are
read-only. See the [CLI installation guide](https://sourceorrery.ai/getting-started/#install).

The connection signs in with a service principal it stores, sealed in the
vault, or else as the first identity the process's environment provides,
through the official Azure SDK (a service principal's
`AZURE_CLIENT_SECRET`, workload identity federation, the Azure CLI or
Azure Developer CLI, a managed identity).

Key Vault keeps metadata per version, like the contract, so versions,
`enabled`, time windows, content types and tags map one to one. A
version's time window can be replaced but not removed, values that are not
UTF-8 are stored as base64, and a version holds at most 12 user tags. The
mapping and every such difference is documented in
the [provider guide](https://sourceorrery.ai/providers/azure-key-vault/).
