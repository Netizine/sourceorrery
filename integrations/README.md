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

Both tell the agent never to read, print or write a secret value.

## Installing them

The `sourceorrery` CLI carries the skills inside the binary and writes them
where each agent looks. Nothing is downloaded:

```bash
sourceorrery init --integration claude      # or gemini, copilot, antigravity, cline, codex,
                                            # cursor, hermes, kilocode, kimi, kiro, opencode, all
sourceorrery init --integration claude,cursor --scope user   # for every project on this machine
```

In a project that already has `sourceorrery.toml`, the manifest is kept and
only the skills are installed; run it again after upgrading the CLI to
update them. Skills a user wrote under the same name are never overwritten.

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

## Without the CLI

Each directory here holds exactly what `sourceorrery init --integration
<agent>` writes into a project, so the skills can be copied by hand:

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
