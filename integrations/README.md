# SourceOrrery skills for AI coding agents

Two skills, in the open Agent Skills format (`SKILL.md`) that every agent
below reads:

- **`sourceorrery`**: install the CLI, create a vault, store and check
  secrets, run a program with them, read them from code with an SDK, and
  fix errors.
- **`sourceorrery-migrate-env`**: move a project off `.env` files: import
  every value into a vault without the agent ever seeing it
  (`sourceorrery import`), declare the keys in `sourceorrery.toml`, convert
  the code, scripts, Docker and CI files that read them, and remove the
  plaintext.

Both tell the agent never to read, print or write a secret value. This is
**option 2** in the setup guides: the CLI installs the skills, then the
agent helps configure the project while the user handles keys and values
privately. It installs instructions for your agent, not the agent itself.

## Setup choices

1. **Option 1: Set up with the CLI.** Follow the [CLI installation guide](https://sourceorrery.ai/getting-started/#install),
   then create the vault and set its secret values in your own terminal.
2. **Option 2: Set up with an AI coding agent.** Run
   `sourceorrery init --integration all`, then ask your agent to set up
   SourceOrrery for the project without showing values. You keep vault
   keys and new values private. [The agent setup guide](https://sourceorrery.ai/guides/ai-agents/)
   works with an existing CLI installation.

## Installing them

The `sourceorrery` CLI carries the skills inside the binary and writes them
where each agent looks. Nothing is downloaded:

```bash
sourceorrery init --integration claude      # or gemini, copilot, antigravity, cline, codex,
                                            # cursor, hermes, kilocode, kimi, kiro, opencode, all
sourceorrery init --integration claude,cursor --scope user   # for every project on this machine
```

Without a secret selection, this installs skills before a vault or
manifest exists and keeps an existing manifest. `--all` or `--secret NAME`
also writes or extends the manifest from the selected vault. Running the
command again writes the snapshot bundled with that CLI; user-authored
skills under the same name are preserved.

| Agent | `--integration` | Project directory | `--scope user` directory |
|-------|-----------------|-------------------|--------------------------|
| Claude Code | `claude` | `.claude/skills`, and the `sourceorrery-env-migrator` subagent in `.claude/agents` | `~/.claude/skills`, `~/.claude/agents` |
| Gemini CLI | `gemini` | `.gemini/skills` | `~/.gemini/skills` |
| GitHub Copilot | `copilot` | `.github/skills` | `~/.copilot/skills` |
| Google Antigravity | `antigravity` | `.agents/skills` | `~/.agents/skills` |
| Cline | `cline` | `.cline/skills` | `~/.cline/skills` |
| OpenAI Codex | `codex` | `.agents/skills`, with `agents/openai.yaml` per skill | `~/.agents/skills` |
| Cursor | `cursor` | `.cursor/skills` | `~/.cursor/skills` |
| Hermes Agent | `hermes` | `.hermes/skills` (run `hermes skills trust` once) | `~/.hermes/skills` |
| Kilo Code | `kilocode` | `.kilo/skills` | `~/.kilo/skills` |
| Kimi Code CLI | `kimi` | `.kimi-code/skills` | `$KIMI_CODE_HOME/skills` (`~/.kimi-code/skills`) |
| Kiro | `kiro` | `.kiro/skills` | `~/.kiro/skills` |
| OpenCode | `opencode` | `.opencode/skills` | `$XDG_CONFIG_HOME/opencode/skills` (`~/.config/opencode/skills`) |

`--skills-dir <dir>` writes the skill folders anywhere else, for example a
managed directory an organisation deploys to every machine
(`/etc/claude-code/.claude/skills` for Claude Code, `/etc/codex/skills` for
Codex).

## Current skills without a CLI rebuild

Each directory here holds the current files in the layout that
`sourceorrery init --integration <agent>` writes. Copy them into the
matching project directory to use this repository's skill text with an
existing CLI. Include references and agent metadata, review replacements
and keep unrelated or user-authored files. For a new Cursor skill folder:

```bash
cp -r integrations/cursor/.cursor/skills/* <your project>/.cursor/skills/
```

### Claude Code plugin

This repository is also a Claude Code plugin marketplace:

```text
/plugin marketplace add Netizine/sourceorrery
/plugin install sourceorrery@sourceorrery
```

The plugin (`plugins/sourceorrery`) carries the same two skills, available
as `/sourceorrery:sourceorrery` and `/sourceorrery:sourceorrery-migrate-env`,
and the `sourceorrery-env-migrator` subagent.

## Maintainers

The only source is `crates/sourceorrery-cli/skills/`. Everything under
`integrations/` and `plugins/sourceorrery/skills` and `agents` is
generated, and a test fails when it drifts. After changing a skill:

```bash
SOURCEORRERY_BLESS=1 cargo test -p sourceorrery-cli --test integrations
```

Documentation: https://sourceorrery.ai/guides/ai-agents/
