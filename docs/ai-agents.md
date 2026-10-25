# AI coding agents

> [!NOTE]
> This guide targets the **0.3.0** setup flow. Use your installed CLI;
> `sourceorrery --version` confirms its version. Current repository skills
> can be copied into a project independently of CLI package updates.

This is **option 2** in the setup guides: install the CLI, install the
skills for your agent, then ask it to configure the project. You create
vaults and enter new values privately; the agent handles the manifest,
application code, launch scripts and checks.

SourceOrrery provides two skills for setup and migration while keeping
secret values out of the agent's context:

- **`sourceorrery`**: install the CLI, create a vault, store and check
  secrets, start a program with them, read them from code with an
  [SDK](sdks/index.md), set up CI or a container, and fix errors.
- **`sourceorrery-migrate-env`**: find the project's `.env` files, import
  every value into a vault with `sourceorrery import` (which never shows
  them), declare the keys in `sourceorrery.toml`, find every place the
  code, scripts, Docker and CI files read those variables and convert
  them, then remove the plaintext and report what changed.

They are written in the open [Agent Skills](https://agentskills.io) format
(a folder with a `SKILL.md`), which all twelve agents below read. An agent
loads only the skill's name and description until a request matches, then
the instructions, then the reference for the one language it is
converting.

## Setup choices

1. **Option 1: Set up with the CLI.** Follow the [CLI installation guide](https://sourceorrery.ai/getting-started/#install),
   then create the vault and set its secret values in your own terminal.
2. **Option 2: Set up with an AI coding agent.** Run
   `sourceorrery init --integration all`, then ask your agent to set up
   SourceOrrery for the project without showing values. You keep vault
   keys and new values private. [Current repository skills](#current-repository-skills)
   work with an existing CLI installation.

## Installing the skills

The CLI carries the skills inside the binary and writes them where each
agent looks for them. Nothing is downloaded: the CLI makes no network
requests.

```bash
sourceorrery init --integration claude
```

| Agent | Command | Writes to |
|-------|---------|-----------|
| Claude Code | `sourceorrery init --integration claude` | `.claude/skills/`, and the `sourceorrery-env-migrator` subagent in `.claude/agents/` |
| Gemini CLI | `sourceorrery init --integration gemini` | `.gemini/skills/` |
| GitHub Copilot | `sourceorrery init --integration copilot` | `.github/skills/` |
| Google Antigravity | `sourceorrery init --integration antigravity` | `.agents/skills/` |
| Cline | `sourceorrery init --integration cline` | `.cline/skills/` |
| OpenAI Codex | `sourceorrery init --integration codex` | `.agents/skills/`, with `agents/openai.yaml` per skill |
| Cursor | `sourceorrery init --integration cursor` | `.cursor/skills/` |
| Hermes Agent | `sourceorrery init --integration hermes` | `.hermes/skills/`; run `hermes skills trust` in the project once |
| Kilo Code | `sourceorrery init --integration kilocode` | `.kilo/skills/` |
| Kimi Code CLI | `sourceorrery init --integration kimi` | `.kimi-code/skills/` |
| Kiro | `sourceorrery init --integration kiro` | `.kiro/skills/` |
| OpenCode | `sourceorrery init --integration opencode` | `.opencode/skills/` |

Several at once: `--integration claude,cursor`, or `--integration all`.

- **Before a vault exists** the skills can already be installed. With no
  secret selection, `init --integration` keeps an existing manifest and
  writes no new one. `--all` or `--secret NAME` also writes or extends the
  manifest from the selected vault's catalog.
- **Commit the skill folders** to share them: everyone who clones the
  repository gets them, with their agent.
- **Bundled skills**: running the command again installs the snapshot in
  your CLI. Files SourceOrrery wrote are updated; a skill of the same name
  that someone else wrote is left alone and reported.
- **For every project on this machine**: `--scope user` writes to the
  agent's directory in your home folder instead (`~/.claude/skills`,
  `~/.cursor/skills`, `~/.agents/skills` for Codex and Antigravity,
  `~/.config/opencode/skills`, ...). No manifest is written.
- **Anywhere else**: `--skills-dir DIR`, for example a managed directory
  an organisation deploys to every machine: Claude Code reads
  `.claude/skills/` in its managed settings directory
  (`/etc/claude-code/.claude/skills/` on Linux), Codex reads
  `/etc/codex/skills/`.

### Claude Code plugin

The repository is a Claude Code plugin marketplace. In Claude Code:

```text
/plugin marketplace add Netizine/sourceorrery
/plugin install sourceorrery@sourceorrery
```

The plugin carries the same two skills, as `/sourceorrery:sourceorrery`
and `/sourceorrery:sourceorrery-migrate-env`, and the
`sourceorrery-env-migrator` subagent, and follows the repository as it
changes. An organisation can allow the marketplace through
`strictKnownMarketplaces` in its managed settings.

### Current repository skills

[`integrations/`](https://github.com/Netizine/sourceorrery/tree/main/integrations)
in the repository holds the current skill folders for each agent, ready
to copy into a project. They follow the same layout as `init --integration`
and can be updated independently of CLI packages. A documentation push
updates these files; it does not change a previously installed binary's
bundled snapshot.

Copy the selected agent's two SourceOrrery skill folders, including their
`references/` and agent metadata, into the corresponding project directory
in the table above. For Claude Code, include its migration subagent too.
Review replacements and preserve unrelated or user-authored skills.
The Claude Code plugin is another way to use the repository's skills.

## Using them

Ask in plain words, for example:

- "Set up SourceOrrery for this project."
- "Move our secrets from .env into SourceOrrery and update the code."
- "Why does `sourceorrery run` say the vault is locked?"

Or run a skill directly: `/sourceorrery-migrate-env` in Claude Code,
Cursor, Cline and Kiro, `$sourceorrery-migrate-env` in Codex,
`/skill:sourceorrery-migrate-env` in Kimi. In Claude Code the
`sourceorrery-env-migrator` subagent runs a whole migration in its own
context.

A completed migration should leave `sourceorrery check` passing, the program and its
tests working through the SDK or `sourceorrery run`, the `.env` files
deleted (after the agent asks) and ignored, and a report of the keys
migrated and skipped, the files changed, and what is left for you: for
example rotating credentials that were once committed.

> [!IMPORTANT]
> `sourceorrery import` leaves the original `.env` file in place and reports
> skipped or failed entries. Review that report and test the application
> before approving deletion. Removing a file does not revoke credentials
> or remove copies from Git history, logs or backups.

## What keeps the values away from the agent

- `sourceorrery import` moves values from the `.env` file to the vault
  inside the CLI. Its output, its JSON and its errors carry key names and
  line numbers only; the agent learns the keys from `--dry-run`.
- The CLI has no option that takes a value. When a secret needs a new
  value, the skills tell the agent to ask you to run
  `sourceorrery secret set <name>`, which reads it at a hidden prompt.
- The skills forbid opening `.env` files, `secret get --reveal`, printing
  environment variables and writing values into code, tests or commits,
  and make the agent ask before deleting files, importing production
  values or rewriting history. Making a vault, its recovery key and its
  view check are yours: the skills tell the agent to ask you to run
  `sourceorrery setup`, and never to read a recovery key or a password.

> [!WARNING]
> Skills are instructions, not an access-control boundary. An agent running
> as your user can use the same OS credential store, or a recovery key
> available to it. The view check asks before a value is revealed, and
> `run` does not ask it. Isolating agents from secrets needs the authenticated
> broker and OS isolation on the [roadmap](roadmap.md). The workflow avoids
> exposing values during a cooperative migration; it cannot enforce an
> agent's compliance. See the [threat model](threat-model.md).
