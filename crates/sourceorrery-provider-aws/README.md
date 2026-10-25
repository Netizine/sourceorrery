# sourceorrery-provider-aws

[AWS Secrets Manager](https://docs.aws.amazon.com/secretsmanager/) behind
the [SourceOrrery](https://sourceorrery.ai) secret contract: the same
`get`, `set`, versions, policy, soft delete and recover as a local vault,
served by Secrets Manager.

**You probably want another crate.** A SourceOrrery vault keeps a
secret at Secrets Manager through a connection it holds, made with the CLI
(`sourceorrery setup`, or `vault create --aws-secrets-manager REGION`,
optionally with a name prefix), and applications read it through
[`sourceorrery`](https://crates.io/crates/sourceorrery) (feature
`provider-aws`, on by default) like any other secret; the manifest never
names the region.

Use the CLI to create vaults and set secret values; application SDKs are
read-only. See the [CLI installation guide](https://sourceorrery.ai/getting-started/#install).

The connection signs in with an access key it stores, sealed in the
vault, or else through the official AWS SDK's default chain (environment,
shared config and credentials files, SSO, web identity, ECS and EC2
instance roles).

Secrets Manager keeps metadata per secret, not per version, so `enabled`,
`content_type`, `not_before` and `expires_on` apply to the whole secret and
`update_secret_properties` accepts only the newest version. The mapping
and every such difference is documented in
the [provider guide](https://sourceorrery.ai/providers/aws-secrets-manager/).

## Project setup options

1. **Option 1: Set up with the CLI.** Follow the [CLI installation guide](https://sourceorrery.ai/getting-started/#install),
   then create the vault and set its secret values in your own terminal.
2. **Option 2: Set up with an AI coding agent.** Run
   `sourceorrery init --integration all`, then ask your agent to set up
   SourceOrrery for the project without showing values. You keep vault
   keys and new values private. [The agent setup guide](https://sourceorrery.ai/guides/ai-agents/)
   works with an existing CLI installation.
