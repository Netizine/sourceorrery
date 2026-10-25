# Examples

* [`sourceorrery.toml`](sourceorrery.toml) — a project manifest showing the
  default environment-variable mapping, an optional secret with a custom
  `env`, and a version pinned in the project's vault. A secret's provider
  connection belongs to that vault rather than the manifest.

## Setup options

1. **Option 1: Set up with the CLI.** Follow the [CLI installation guide](https://sourceorrery.ai/getting-started/#install),
   then create the vault and set its secret values in your own terminal.
2. **Option 2: Set up with an AI coding agent.** Run
   `sourceorrery init --integration all`, then ask your agent to set up
   SourceOrrery for the project without showing values. You keep vault
   keys and new values private. [The agent setup guide](https://sourceorrery.ai/guides/ai-agents/)
   works with an existing CLI installation.

## Manual example

Try it:

```bash
sourceorrery setup      # choose development; keep its recovery key privately
sourceorrery secret set database-password --vault development   # hidden prompt
sourceorrery secret set signing-key --vault development         # hidden prompt

cd examples
sourceorrery check                # signing-key: version_not_found (pinned id is fictional)
```

`check` shows exactly which declared secrets are present, missing or blocked
by policy, without reading a single value. Fix the pinned version (or drop the
`version` line) and `run` will start the child with the secrets injected.
Start the application with `sourceorrery run -- <your application command>`;
keep values out of terminal output and logs.
