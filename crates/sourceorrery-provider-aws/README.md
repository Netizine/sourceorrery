# sourceorrery-provider-aws

[AWS Secrets Manager](https://docs.aws.amazon.com/secretsmanager/) behind
the [SourceOrrery](https://sourceorrery.ai) secret contract: the same
`get`, `set`, versions, policy, soft delete and recover as a local vault,
served by Secrets Manager.

**You probably want another crate.** Applications read secrets through
[`sourceorrery`](https://crates.io/crates/sourceorrery) (feature
`provider-aws`, on by default) and name the region in `sourceorrery.toml`:

```toml
[vaults.production]
provider = "aws-secrets-manager"
region = "eu-west-1"
prefix = "myapp/"          # optional: every secret name is placed under it
```

Credentials never live in the manifest: the official AWS SDK's default
chain finds them (environment, shared config and credentials files, SSO,
web identity, ECS and EC2 instance roles).

Secrets Manager keeps metadata per secret, not per version, so `enabled`,
`content_type`, `not_before` and `expires_on` apply to the whole secret and
`update_secret_properties` accepts only the newest version. The mapping
and every such difference is documented in
`docs/providers/aws-secrets-manager.md` of the repository.
