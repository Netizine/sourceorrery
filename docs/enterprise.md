# Enterprise use: identity, policy and revocation

SourceOrrery has no server of its own. A team that needs one identity per
workload, roles, centrally administered policy and revocation gets them
from the secrets service a [remote vault](providers/index.md) points at:
HashiCorp Vault or AWS Secrets Manager. SourceOrrery's part is narrower and
is what this page describes:

* it authenticates with the identity the platform gives the process (a
  CI job's OIDC token, a pod's service account, a VM's instance role) and
  never stores a credential of its own;
* it carries every decision the provider makes through unchanged, as the
  same stable error codes and hints in the CLI, the Rust client and every
  SDK;
* it keeps no copy of a value outside the process that read it, so a
  revocation reaches everything but what a running process already holds.

The `provider-vault` and `provider-aws` CI jobs prove each claim below
against a real Vault server and a Secrets Manager emulator
(`scripts/ci/vault-federation.sh`, `scripts/ci/aws-federation.sh`).

## Who decides what

| | HashiCorp Vault | AWS Secrets Manager | SourceOrrery |
|---|---|---|---|
| **Identity** | an auth method: token, AppRole, JWT/OIDC, Kubernetes | an IAM principal: user, role, web identity, instance or task role | finds the credential where the provider's own tools do; refuses to run without one (`unauthenticated`) |
| **Roles** | the policies attached to the login role | the IAM role the identity assumes | none of its own; the process is whatever the provider says it is |
| **Policy** | ACL policies on `<mount>/data/<name>` and `<mount>/metadata/<name>` | IAM policies on the secret's ARN (`secretsmanager:GetSecretValue`, `DescribeSecret`, `ListSecretVersionIds`, ...) | the `enabled` flag and the time window of each version, evaluated by the core from the properties it stores at the provider; a denied call is `permission_denied` |
| **Revocation** | `vault token revoke`, a lease that expires, a disabled role or auth mount | a revoked session, a removed trust policy, a deny statement | takes effect on the next request (below) |
| **Audit** | the server's audit devices | CloudTrail | `audit_events` on a remote vault is `unsupported`; the CLI's `audit` works on local vaults only |

A **local** vault has no identity beyond the OS account that can unlock
it: anyone who can read the file and reach its protector reads every
secret. Enterprise use means a remote vault.

## Federation: the identity the platform already has

Nothing below goes in `sourceorrery.toml`. The manifest names the
provider, the address and the mount or prefix, and a `token`, `role_id`
or `access_key_id` key in it is a parse error. Credentials come from the
environment of the process, exactly where `vault` and `aws` would find
them.

### HashiCorp Vault

The provider tries, in order: `VAULT_TOKEN`; `~/.vault-token` (what
`vault login` writes); AppRole (`VAULT_ROLE_ID` and `VAULT_SECRET_ID`);
JWT (`VAULT_AUTH_ROLE` with `VAULT_JWT_FILE` or `VAULT_JWT`); Kubernetes
(`VAULT_AUTH_ROLE` in a pod, with the service account token at
`/var/run/secrets/kubernetes.io/serviceaccount/token`). `VAULT_AUTH_MOUNT`
names the auth method's mount when it is not `approle`, `jwt` or
`kubernetes`; `VAULT_NAMESPACE` and `VAULT_CACERT` mean what they mean to
the `vault` CLI. A login happens once, when the vault is opened; the token
it returns is used for the life of the client and is not renewed, so a
process that outlives the role's token TTL gets `unauthenticated` on its
next request and has to open the vault again.

**GitHub Actions.** The job's OIDC token is a JWT Vault can verify against
GitHub's discovery document. Once, as a Vault administrator:

```bash
vault auth enable jwt
vault write auth/jwt/config \
  oidc_discovery_url="https://token.actions.githubusercontent.com" \
  bound_issuer="https://token.actions.githubusercontent.com"
vault policy write ci-read - <<'HCL'
path "secret/data/database-password"     { capabilities = ["read"] }
path "secret/metadata/database-password" { capabilities = ["read"] }
HCL
vault write auth/jwt/role/ci \
  role_type=jwt user_claim=sub bound_audiences=vault token_policies=ci-read \
  bound_claims='{"repository":"example/app"}' token_ttl=10m
```

In the workflow, with `permissions: id-token: write`:

```yaml
- run: |
    curl -sS -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
      "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=vault" \
      | python3 -c 'import json,sys; print(json.load(sys.stdin)["value"], end="")' > "$RUNNER_TEMP/vault.jwt"
    echo "VAULT_JWT_FILE=$RUNNER_TEMP/vault.jwt" >> "$GITHUB_ENV"
    echo "VAULT_AUTH_ROLE=ci" >> "$GITHUB_ENV"
- run: sourceorrery check --access && sourceorrery run -- ./deploy
```

The CI job proves this path with a key pair minted on the runner in place
of GitHub's: a token signed by it logs in and reads, a token for another
audience is `unauthenticated`.

**Kubernetes.** Either the Kubernetes auth method, bound to the service
account and namespace of the workload, or the JWT method with a projected
service account token (its audience and expiry are the cluster's to set):

```yaml
env:
  - { name: VAULT_AUTH_ROLE, value: app }          # auth/kubernetes/role/app
  # or, for a projected token at auth/jwt:
  # - { name: VAULT_JWT_FILE, value: /var/run/secrets/tokens/vault }
```

**VMs and bare metal.** The provider has no cloud auth methods of its own
(Vault's `aws`, `gcp` and `azure` methods). Use AppRole, with the secret
id delivered by the configuration management that places the service, or
log in with the `vault` CLI (`vault login -method=aws`, for instance): the
token it writes to `~/.vault-token` is the second source the provider
tries. In both cases the token's TTL is the policy's lever over a
long-running process.

### AWS Secrets Manager

The official SDK's default credential chain supplies the identity:
environment variables, the shared config with `AWS_PROFILE`, SSO, web
identity (`AWS_WEB_IDENTITY_TOKEN_FILE` and `AWS_ROLE_ARN`), the ECS task
role, the EC2 instance role. Credentials are resolved when the vault is
opened: no identity at all is `unauthenticated` before any request is
made.

**GitHub Actions.** `aws-actions/configure-aws-credentials` with a
`role-to-assume` exchanges the job's OIDC token at STS and exports the
session to the job's environment; nothing else is needed. The same
exchange without the action is the two web identity variables:

```yaml
- run: |
    curl -sS -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
      "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=sts.amazonaws.com" \
      | python3 -c 'import json,sys; print(json.load(sys.stdin)["value"], end="")' > "$RUNNER_TEMP/aws.jwt"
    echo "AWS_WEB_IDENTITY_TOKEN_FILE=$RUNNER_TEMP/aws.jwt" >> "$GITHUB_ENV"
    echo "AWS_ROLE_ARN=arn:aws:iam::123456789012:role/ci-read" >> "$GITHUB_ENV"
- run: sourceorrery check --access && sourceorrery run -- ./deploy
```

The CI job proves the web identity path against the emulator's STS, and
that a process with no credentials (and `AWS_EC2_METADATA_DISABLED=true`)
is refused before it sends a request.

**Kubernetes.** IAM roles for service accounts (IRSA) inject the two web
identity variables into the pod; EKS Pod Identity serves credentials from
the container credential endpoint. Both are part of the default chain, so
a pod needs no configuration beyond its service account annotation.

**VMs and containers.** The EC2 instance profile and the ECS task role
are found through their metadata endpoints with nothing set. Static
access keys in the environment work too, and are the one path on this
page that stores a credential; prefer a role.

## What revocation reaches

A revoked identity is refused the next time the provider is asked
anything. What that means for a process depends on where it is in its
life:

* **A process that has not yet opened the vault** cannot: the login (Vault)
  or the first request (AWS) fails with `unauthenticated`, and
  `sourceorrery run` does not start its child.
* **A process holding an open reader** fails on its next read. The Vault
  provider keeps the token its login returned and does not re-login; the
  AWS provider keeps the session the chain resolved. Neither retries with
  another identity.
* **A value already read** stays with the process that read it until it
  drops it. There is no value cache: nothing is written to disk, nothing is
  shared between processes, and every `get_secret` is a request to the
  provider. The CLI drops a value when the command ends (`run` passes it to
  the child's environment and exits with the child); an SDK reader holds
  it until the application closes it and zeroises it then
  ([threat model](threat-model.md)).

So revocation ends new reads at once and ends what a running process can
read on its next request, but cannot recall a value already in a
process's memory or in a child's environment. Rotating the secret is what
invalidates those (the [rotation workflow](roadmap.md#milestone-4--enterprise-integrations)
is the next milestone item).

## Checking what an identity may read

`sourceorrery check` reads **metadata only**: it says whether every secret
the manifest names resolves to an accessible version, without a value
leaving the provider. A policy can allow that and still deny the value
(Vault's `metadata` path without `data`; IAM `DescribeSecret` without
`GetSecretValue`), which is the right shape for an operator's identity and
the wrong one for the application's. `check --access` adds one read per
secret, discarded at once, so the status is `permission_denied` exactly
where the application's `run` would fail:

```console
$ sourceorrery check --access -o json
{
  "manifest": "/srv/app/sourceorrery.toml",
  "ok": false,
  "secrets": [
    { "name": "database-password", "env": "DATABASE_PASSWORD",
      "reference": "sourceorrery://production/database-password",
      "required": true, "status": "permission_denied", "version": null }
  ]
}
```

The exit status is 1 while a required secret is not readable, so the
command is a pre-flight step a deployment can stop on.

On a local vault the extra read is an audited `secret_get` like any other.

## Error codes and hints

| Code | When | The hint names |
|------|------|----------------|
| `unauthenticated` | no credential found; a token or session the provider refuses; an expired login | the provider's credential sources (`VAULT_TOKEN`, `vault login`, the AWS chain), never the manifest |
| `permission_denied` | the provider's policy denies the call | Vault: the `data` and `metadata` paths to grant with `vault policy write` and `vault read sys/capabilities-self`; AWS: the `secretsmanager:*` actions to allow and `aws sts get-caller-identity` |
| `provider_unavailable` | the provider cannot be reached or fails internally (transient) | reachability and the address in `[vaults.<name>]`; retry |

The codes are the core's and are append-only; an SDK older than a code
reports it as its base error with the code preserved
([ADR 0007](adr/0007-versioning-and-compatibility.md)).
