# Examples

* [`sourceorrery.toml`](sourceorrery.toml) — a project manifest showing the
  default environment-variable mapping, an optional secret with a custom
  `env`, and a version pinned in another vault.

Try it:

```bash
export SOURCEORRERY_HOME=$(mktemp -d)
sourceorrery vault create development      # prints its recovery key, once
sourceorrery vault create shared-tooling
echo "pg-password" | sourceorrery secret set database-password --vault development
echo "hmac-key"    | sourceorrery secret set signing-key --vault shared-tooling

cd examples
sourceorrery check                # signing-key: version_not_found (pinned id is fictional)
sourceorrery run -- env | grep -E 'DATABASE_PASSWORD|STRIPE_KEY'
```

`check` shows exactly which declared secrets are present, missing or blocked
by policy, without reading a single value. Fix the pinned version (or drop the
`version` line) and `run` will start the child with the secrets injected.
