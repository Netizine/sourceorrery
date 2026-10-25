# Enterprise use: identity, policy and revocation

SourceOrrery has no server of its own. A team that needs one identity per
workload, roles, centrally administered policy and revocation gets them
from the secrets service a vault's [connection](providers/index.md) keeps its secrets at:
HashiCorp Vault, AWS Secrets Manager or Azure Key Vault. SourceOrrery's part is narrower and
is what this page describes:

* it authenticates with the identity the platform gives the process (a
  CI job's OIDC token, a pod's service account, a VM's instance role) and
  never stores a credential of its own;
* it carries every decision the provider makes through unchanged, as the
  same stable error codes and hints in the CLI, the Rust client and every
  SDK;
* it keeps no copy of a value outside the process that read it, so a
  revocation reaches everything but what a running process already holds.

The `provider-vault`, `provider-aws` and `provider-azure` CI jobs prove each
claim below against a real Vault server and Secrets Manager and Key Vault
emulators (`scripts/ci/vault-federation.sh`, `scripts/ci/aws-federation.sh`,
`scripts/ci/azure-federation.sh`), except where a section says otherwise.

## Who decides what

| | HashiCorp Vault | AWS Secrets Manager | Azure Key Vault | SourceOrrery |
|---|---|---|---|---|
| **Identity** | an auth method: token, AppRole, JWT/OIDC, Kubernetes | an IAM principal: user, role, web identity, instance or task role | an Entra ID principal: service principal, workload identity, managed identity, a signed-in user | finds the credential where the provider's own tools do; refuses to run without one (`unauthenticated`) |
| **Roles** | the policies attached to the login role | the IAM role the identity assumes | role assignments on the vault (Key Vault Secrets User, Key Vault Secrets Officer), or the vault's access policies | none of its own; the process is whatever the provider says it is |
| **Policy** | ACL policies on `<mount>/data/<name>` and `<mount>/metadata/<name>`; `update` on `metadata` is policy administration (the version flags and windows live there) | IAM policies on the secret's ARN (`secretsmanager:GetSecretValue`, `DescribeSecret`, `ListSecretVersionIds`, ...); `TagResource` is policy administration (the flags and windows live in tags) | data actions on the vault's secrets; the flags and windows are each version's own attributes, and the one tag SourceOrrery relies on (version order) needs the permission that writes versions | evaluates the flags and windows it reads from the provider; cannot tell a planted one from a set one ([threat model](threat-model.md), gap 14) |
| **Revocation** | `vault token revoke`, a lease that expires, a disabled role or auth mount | a revoked session, a removed trust policy, a deny statement | a removed role assignment, a disabled service principal, a deleted federated credential | takes effect on the next request (below) |
| **Audit** | the server's audit devices | CloudTrail | the vault's diagnostic logs in Azure Monitor | the vault records every call it sends to a provider in its own log, with the provider's outcome; `sourceorrery audit` also prints where the provider's trail is and the query that shows SourceOrrery's operations; the vault's log is exported with `audit export` ([below](#collecting-the-audit-trail)) |

A secret in the **vault file** has no identity beyond the OS account
that can open it: anyone who can read the file and reach this machine's
key, or hold the recovery key, reads every such secret. Enterprise use
means keeping secrets at a provider, through a connection whose
credentials are the workload's own (this machine's sign-in), so the
provider decides who reads what.

## Federation: the identity the platform already has

Nothing below goes in `sourceorrery.toml`. The manifest names the
provider, the address and the mount or prefix, and a `token`, `role_id`,
`access_key_id` or `client_secret` key in it is a parse error. Credentials
come from the environment of the process, exactly where `vault`, `aws` and
`az` would find them.

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

### Azure Key Vault

The provider signs in with the first identity the environment provides: a
service principal (`AZURE_TENANT_ID`, `AZURE_CLIENT_ID` and
`AZURE_CLIENT_SECRET`), workload identity federation
(`AZURE_FEDERATED_TOKEN_FILE` with the tenant and client ids), the Azure CLI
or Azure Developer CLI, or a managed identity
([details](providers/azure-key-vault.md#credentials)). A token is fetched
when the vault is opened: no identity at all is `unauthenticated` before any
request reaches the vault. The identity needs **Key Vault Secrets User** on
the vault to read (**Key Vault Secrets Officer** to write).

**GitHub Actions.** Give the app registration (or a user-assigned managed
identity) a federated credential for the repository and branch (subject
`repo:<owner>/<repo>:ref:refs/heads/main`, audience
`api://AzureADTokenExchange`), assign it the role on the vault, and write
the job's OIDC token to a file:

```yaml
- run: |
    curl -sS -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
      "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=api://AzureADTokenExchange" \
      | python3 -c 'import json,sys; print(json.load(sys.stdin)["value"], end="")' > "$RUNNER_TEMP/azure.jwt"
    echo "AZURE_FEDERATED_TOKEN_FILE=$RUNNER_TEMP/azure.jwt" >> "$GITHUB_ENV"
    echo "AZURE_TENANT_ID=00000000-0000-0000-0000-000000000000" >> "$GITHUB_ENV"
    echo "AZURE_CLIENT_ID=11111111-1111-1111-1111-111111111111" >> "$GITHUB_ENV"
- run: sourceorrery check --access && sourceorrery run -- ./deploy
```

`azure/login` with OIDC signs the Azure CLI in instead, which the provider
finds too. The CI job proves against the emulator that a service principal
from the environment reads, that a principal without a role on the vault is
refused as `permission_denied`, and that a process with no identity is
refused before it sends a request. The emulator does not exchange federated
tokens, so the workload identity path itself is exercised only by the Azure
SDK's own tests.

**Kubernetes.** AKS workload identity injects `AZURE_CLIENT_ID`,
`AZURE_TENANT_ID`, `AZURE_FEDERATED_TOKEN_FILE` and `AZURE_AUTHORITY_HOST`
into a pod whose service account names the identity; nothing else is needed.

**VMs and containers.** A virtual machine's managed identity is found
through the instance metadata endpoint with nothing set (`AZURE_CLIENT_ID`
names a user-assigned one); App Service, Functions and Container Apps
provide `IDENTITY_ENDPOINT`. A client secret in the environment works too,
and is the one path here that stores a credential; prefer a managed identity
or federation.

## What revocation reaches

A revoked identity is refused the next time the provider is asked
anything. What that means for a process depends on where it is in its
life:

* **A process that has not yet opened the vault** cannot: the login (Vault)
  or the first request (AWS) fails with `unauthenticated`, and
  `sourceorrery run` does not start its child.
* **A process holding an open reader** fails on its next read. The Vault
  provider keeps the token its login returned and does not re-login; the
  AWS provider keeps the session the chain resolved; the Azure provider
  keeps signing in as the identity that first gave it a token, and Key
  Vault checks the role on every request, so a removed role assignment
  refuses the next read once it has propagated (within minutes). None
  retries with another identity.
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
invalidates those ([rotation.md](rotation.md): `sourceorrery secret rotate`
issues, validates and activates a new version and retires the previous
credential at the issuer).

## Collecting the audit trail

There is no SourceOrrery server to collect audit logs into, so collection
means getting every trail to the place the organisation already keeps
logs:

* **A local vault** keeps a keyed hash chain of metadata-only events
  ([threat model](threat-model.md)). `sourceorrery audit export` writes it
  oldest first as JSON Lines on stdout, or posts it as OTLP/HTTP log
  records to a collector (`--format otlp --endpoint URL`, or the standard
  `OTEL_EXPORTER_OTLP_*` variables), and ends with the chain verification
  as a trailer, so the collector can tell a complete export from a
  truncated log; `--follow` keeps exporting new events as they are
  recorded. A sidecar that runs `sourceorrery audit export --follow
  --format otlp` next to the application, with the vault's recovery key
  from `SOURCEORRERY_RECOVERY_KEY_FILE` (and its view-check password from
  `SOURCEORRERY_PASSWORD_FILE`, when it has one), is the whole set-up; so is a cron job
  with `--since` and a `file` source on the redirected output
  ([cli.md](cli.md#audit-export-the-log-for-a-collector)).
* **A provider's** trail records SourceOrrery's operations as the
  provider's own API calls, with the identity the process authenticated
  as (Vault's audit devices, CloudTrail, Azure Monitor), besides the
  vault's own record of each call. `sourceorrery audit` prints where the
  trail is and the query that shows those operations; each provider page has the full form under
  "Audit trail" ([HashiCorp Vault](providers/hashicorp-vault.md#audit-trail),
  [AWS Secrets Manager](providers/aws-secrets-manager.md#audit-trail)).
  Route those logs to the same collector and the two trails meet there.

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
| `unauthenticated` | no credential found; a token or session the provider refuses; an expired login | the provider's credential sources (`VAULT_TOKEN`, `vault login`, the AWS chain), or storing credentials in the vault's connection |
| `permission_denied` | the provider's policy denies the call | Vault: the `data` and `metadata` paths to grant with `vault policy write` and `vault read sys/capabilities-self`; AWS: the `secretsmanager:*` actions to allow and `aws sts get-caller-identity` |
| `provider_unavailable` | the provider cannot be reached or fails internally (transient) | reachability and the address in the vault's connection; retry |

The codes are the core's and are append-only; an SDK older than a code
reports it as its base error with the code preserved
([ADR 0007](adr/0007-versioning-and-compatibility.md)).
