# Installing and setting up SourceOrrery

The CLI creates vaults and sets secret values; application SDKs are
read-only. Start by checking `sourceorrery --version`. If it is installed,
use it as it is. These skills use the 0.3.0 key, view-check and connection
model and do not require rebuilding the CLI to configure a project.

## If the CLI is missing

Follow the [CLI installation guide](https://sourceorrery.ai/getting-started/#install)
for the current platform-specific steps. Prefer a ready-to-run package;
prebuilt binaries do not need Rust. Follow the environment's existing
software-installation approval rules. Verify downloaded archives against
the release's checksums before using them; stop if verification fails.
Then run `sourceorrery --version` again.

## Project setup with an agent

`sourceorrery init --integration <agent>` installs the CLI's bundled
skills for that agent. `--integration all` covers every supported agent;
`--scope user` installs them for the user's projects, and `--skills-dir
DIR` chooses another directory. This installs instructions for an existing
agent, not the agent application. With no secret selection it neither
creates a vault nor writes a project manifest.

The current [repository integration folders](https://github.com/Netizine/sourceorrery/tree/main/integrations)
and Claude Code plugin provide skill text independently of CLI packages.
When refreshing a project from those folders, keep each skill's references
and agent metadata together, review replacements, and preserve unrelated
or user-authored skills. The CLI writes the snapshot bundled with its
installed version; it does not fetch repository updates.

After installation, let the user create or choose the vault. For a new
vault, they run `sourceorrery setup` in their own terminal, keep the
recovery key privately and enter any password/authenticator code there.
Never ask to see those values. The agent can then use metadata commands,
`init`, `import`, SDK setup and launch configuration within the task.

## Headless

Containers, CI runners, WSL and servers without a desktop session have no
credential store. There a vault opens with its **recovery key**, which the
user keeps; never ask for it, invent one or write it into the repository.

- A new vault for CI: the user runs
  `sourceorrery vault create ci --recovery-key-out <file>` and puts that
  file in the CI system's secret store.
- An existing vault on another machine: the user runs
  `sourceorrery vault export --out <file>` where it lives and copies the
  file there (it opens with the recovery key only), or points
  `SOURCEORRERY_HOME` at a shared directory (WSL reading the Windows home).
- Opening: point `SOURCEORRERY_RECOVERY_KEY_FILE` (or `--recovery-key-file`)
  at a file that holds the recovery key and that only that user can read,
  for example a Docker or Kubernetes secret at `/run/secrets/...` or a
  file a CI job writes from its own secret store into a temporary
  directory. `SOURCEORRERY_RECOVERY_KEY` works too but is visible to
  process inspection.
- `SOURCEORRERY_HOME` says where the vault files live, for example a
  mounted volume. Vault files (`*.sorvault`) are never committed.

Docker, Compose and CI examples: https://sourceorrery.ai/guides/headless/
