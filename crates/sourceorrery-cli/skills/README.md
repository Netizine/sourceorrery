# Agent skills: the source

`sourceorrery init --integration <agent>` writes these skills, compiled into
the binary by `src/integrations.rs` (`include_str!`), to each agent's skills
directory. This folder is their only source.

The generated repository and plugin folders can be copied into a project
independently of CLI packages. The installed CLI always writes its bundled
snapshot; a documentation push does not alter an existing binary. Setup
guides present manual CLI setup as option 1 and AI-assisted setup as option 2.

- `sourceorrery/`, `sourceorrery-migrate-env/`: each skill's `SKILL.md`.
- `references/`: files a skill links to; `src/integrations.rs` lists which
  skill ships which file (some go into both).
- `agents/claude/`: the Claude Code subagent; `agents/codex/`: each skill's
  `agents/openai.yaml` for Codex.

Rules the unit tests in `src/integrations.rs` enforce: the Agent Skills
frontmatter only (`name` equal to the folder, `description` up to 1024
characters, `license`, `metadata` with `managed-by: sourceorrery`), under 500
lines, and every linked reference shipped. The rule no test can enforce:
nothing here may tell an agent to read, print or write a secret value.

`integrations/` and `plugins/sourceorrery/` at the repository root are
generated from this folder. After a change:

```bash
SOURCEORRERY_BLESS=1 cargo test -p sourceorrery-cli --test integrations
```
