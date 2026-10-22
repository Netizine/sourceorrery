//! The SourceOrrery skills for AI coding agents, embedded in the binary.
//!
//! `skills/` in this crate is their only source. Every file is compiled
//! into the executable with `include_str!`, so `sourceorrery init
//! --integration <agent>` writes them without fetching anything: the CLI
//! makes no network requests. All the supported agents read the same
//! `SKILL.md` format (the Agent Skills standard); what differs is the
//! directory each one scans, and two extras: a `agents/openai.yaml` per
//! skill for Codex and a subagent for Claude Code.
//!
//! A file is replaced only when SourceOrrery wrote it: a skill directory
//! whose `SKILL.md` lacks [`MARKER`] belongs to someone else and is left
//! alone.

use std::path::{Path, PathBuf};

use serde::Serialize;

/// Present in every file SourceOrrery writes for an agent.
pub const MARKER: &str = "managed-by: sourceorrery";

/// One file of a skill, by its path inside the skill directory.
struct SkillFile {
    path: &'static str,
    contents: &'static str,
}

/// A skill directory.
struct Skill {
    name: &'static str,
    files: &'static [SkillFile],
    /// Codex's `agents/openai.yaml` for this skill.
    codex: &'static str,
}

macro_rules! skill_file {
    ($path:literal, $source:literal) => {
        SkillFile {
            path: $path,
            contents: include_str!(concat!("../skills/", $source)),
        }
    };
}

static SKILLS: [Skill; 2] = [
    Skill {
        name: "sourceorrery",
        files: &[
            skill_file!("SKILL.md", "sourceorrery/SKILL.md"),
            skill_file!("references/install.md", "references/install.md"),
            skill_file!("references/sdks.md", "references/sdks.md"),
            skill_file!(
                "references/troubleshooting.md",
                "references/troubleshooting.md"
            ),
        ],
        codex: include_str!("../skills/agents/codex/sourceorrery.yaml"),
    },
    Skill {
        name: "sourceorrery-migrate-env",
        files: &[
            skill_file!("SKILL.md", "sourceorrery-migrate-env/SKILL.md"),
            skill_file!("references/install.md", "references/install.md"),
            skill_file!("references/find-usages.md", "references/find-usages.md"),
            skill_file!(
                "references/convert-python.md",
                "references/convert-python.md"
            ),
            skill_file!(
                "references/convert-javascript.md",
                "references/convert-javascript.md"
            ),
            skill_file!("references/convert-java.md", "references/convert-java.md"),
            skill_file!(
                "references/convert-dotnet.md",
                "references/convert-dotnet.md"
            ),
            skill_file!("references/convert-go.md", "references/convert-go.md"),
            skill_file!("references/convert-rust.md", "references/convert-rust.md"),
            skill_file!("references/convert-php.md", "references/convert-php.md"),
            skill_file!("references/convert-c-cpp.md", "references/convert-c-cpp.md"),
            skill_file!("references/convert-other.md", "references/convert-other.md"),
            skill_file!(
                "references/troubleshooting.md",
                "references/troubleshooting.md"
            ),
        ],
        codex: include_str!("../skills/agents/codex/sourceorrery-migrate-env.yaml"),
    },
];

/// The Claude Code subagent that runs a whole migration. Installed next to
/// the skills, its frontmatter gains a `skills:` line so that it starts with
/// both loaded; the plugin ships this file as it is, because plugin skills
/// are namespaced.
const CLAUDE_SUBAGENT: &str = include_str!("../skills/agents/claude/sourceorrery-env-migrator.md");
const CLAUDE_SUBAGENT_FILE: &str = "sourceorrery-env-migrator.md";

/// An AI coding agent SourceOrrery can install its skills for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Agent {
    Claude,
    Gemini,
    Copilot,
    Antigravity,
    Cline,
    Codex,
    Cursor,
    Hermes,
    Kilocode,
    Kimi,
    Kiro,
    Opencode,
}

impl Agent {
    /// Every supported agent.
    pub const ALL: [Self; 12] = [
        Self::Claude,
        Self::Gemini,
        Self::Copilot,
        Self::Antigravity,
        Self::Cline,
        Self::Codex,
        Self::Cursor,
        Self::Hermes,
        Self::Kilocode,
        Self::Kimi,
        Self::Kiro,
        Self::Opencode,
    ];

    /// The product's name.
    pub fn title(self) -> &'static str {
        match self {
            Self::Claude => "Claude Code",
            Self::Gemini => "Gemini CLI",
            Self::Copilot => "GitHub Copilot",
            Self::Antigravity => "Google Antigravity",
            Self::Cline => "Cline",
            Self::Codex => "OpenAI Codex",
            Self::Cursor => "Cursor",
            Self::Hermes => "Hermes Agent",
            Self::Kilocode => "Kilo Code",
            Self::Kimi => "Kimi Code CLI",
            Self::Kiro => "Kiro",
            Self::Opencode => "OpenCode",
        }
    }

    /// Where the agent looks for a project's skills, relative to its root.
    pub fn project_skills_dir(self) -> &'static str {
        match self {
            Self::Claude => ".claude/skills",
            Self::Gemini => ".gemini/skills",
            Self::Copilot => ".github/skills",
            Self::Antigravity | Self::Codex => ".agents/skills",
            Self::Cline => ".cline/skills",
            Self::Cursor => ".cursor/skills",
            Self::Hermes => ".hermes/skills",
            Self::Kilocode => ".kilo/skills",
            Self::Kimi => ".kimi-code/skills",
            Self::Kiro => ".kiro/skills",
            Self::Opencode => ".opencode/skills",
        }
    }

    /// Where the agent looks for the user's own skills, for every project.
    pub fn user_skills_dir(self, home: &Path) -> PathBuf {
        match self {
            Self::Claude => home.join(".claude/skills"),
            Self::Gemini => home.join(".gemini/skills"),
            Self::Copilot => home.join(".copilot/skills"),
            Self::Antigravity | Self::Codex => home.join(".agents/skills"),
            Self::Cline => home.join(".cline/skills"),
            Self::Cursor => home.join(".cursor/skills"),
            Self::Hermes => home.join(".hermes/skills"),
            Self::Kilocode => home.join(".kilo/skills"),
            Self::Kimi => std::env::var_os("KIMI_CODE_HOME")
                .filter(|v| !v.is_empty())
                .map_or_else(|| home.join(".kimi-code"), PathBuf::from)
                .join("skills"),
            Self::Kiro => home.join(".kiro/skills"),
            Self::Opencode => std::env::var_os("XDG_CONFIG_HOME")
                .filter(|v| !v.is_empty())
                .map_or_else(|| home.join(".config"), PathBuf::from)
                .join("opencode/skills"),
        }
    }

    /// Where Claude Code's subagents go, next to its skills directory.
    fn subagents_dir(self, skills_dir: &Path) -> Option<PathBuf> {
        (self == Self::Claude).then(|| {
            skills_dir
                .parent()
                .map_or_else(PathBuf::new, Path::to_path_buf)
                .join("agents")
        })
    }

    /// What the user does next for this agent to pick the skills up.
    pub fn next_step(self) -> &'static str {
        match self {
            Self::Claude => {
                "Start a new Claude Code session and ask it to migrate this project off .env \
                 (or type /sourceorrery-migrate-env); the sourceorrery-env-migrator subagent \
                 runs the whole migration."
            }
            Self::Gemini => {
                "In Gemini CLI run /skills reload (or start a new session); /skills list shows them."
            }
            Self::Copilot => {
                "Copilot agent mode in VS Code, the Copilot CLI and the cloud agent pick them up; \
                 commit .github/skills to share them."
            }
            Self::Antigravity => {
                "Antigravity loads them when a request matches: ask it to migrate this project \
                 off .env, or mention SourceOrrery."
            }
            Self::Cline => {
                "Cline detects them automatically; type /sourceorrery-migrate-env to run one."
            }
            Self::Codex => {
                "Codex detects new skills automatically (restart it if not); run one with \
                 $sourceorrery-migrate-env or /skills."
            }
            Self::Cursor => {
                "Cursor loads them automatically; type /sourceorrery-migrate-env to run one."
            }
            Self::Hermes => {
                "Hermes loads project skills only in trusted repositories: run `hermes skills trust` \
                 here once, then /sourceorrery-migrate-env."
            }
            Self::Kilocode => "Kilo Code reads skills when a session starts: start a new one.",
            Self::Kimi => {
                "Run one with /skill:sourceorrery-migrate-env, or let Kimi pick it up from your request."
            }
            Self::Kiro => {
                "Kiro activates them when a request matches; type /sourceorrery-migrate-env to run one."
            }
            Self::Opencode => "OpenCode discovers them when it starts: start a new session.",
        }
    }
}

/// One file to write, and the file whose [`MARKER`] decides whether
/// SourceOrrery may replace it.
pub struct Planned {
    pub path: PathBuf,
    pub contents: String,
    owner: PathBuf,
}

/// What [`install`] did with a file.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Outcome {
    /// It did not exist.
    Created,
    /// SourceOrrery wrote it before and its content changed.
    Updated,
    /// Already up to date.
    Unchanged,
    /// Someone else's file under the same name; left as it is.
    Kept,
}

/// Every file `agent` gets when its skill folders go into `skills_dir`.
/// Claude Code's subagent is included when `with_subagent` is set, in the
/// `agents` directory next to `skills_dir`.
pub fn plan(agent: Agent, skills_dir: &Path, with_subagent: bool) -> Vec<Planned> {
    let mut planned = Vec::new();
    for skill in &SKILLS {
        let dir = skills_dir.join(skill.name);
        let owner = dir.join("SKILL.md");
        for file in skill.files {
            planned.push(Planned {
                path: dir.join(file.path),
                contents: file.contents.to_owned(),
                owner: owner.clone(),
            });
        }
        if agent == Agent::Codex {
            planned.push(Planned {
                path: dir.join("agents/openai.yaml"),
                contents: skill.codex.to_owned(),
                owner: owner.clone(),
            });
        }
    }
    if with_subagent && let Some(agents_dir) = agent.subagents_dir(skills_dir) {
        let path = agents_dir.join(CLAUDE_SUBAGENT_FILE);
        planned.push(Planned {
            contents: subagent_with_skills(),
            owner: path.clone(),
            path,
        });
    }
    planned
}

/// The subagent with `skills:` added to its frontmatter.
fn subagent_with_skills() -> String {
    let skills: Vec<&str> = SKILLS.iter().map(|s| s.name).collect();
    let (front, rest) = CLAUDE_SUBAGENT
        .strip_prefix("---\n")
        .and_then(|body| body.split_once("\n---\n"))
        .expect("the subagent starts with YAML frontmatter");
    format!("---\n{front}\nskills: {}\n---\n{rest}", skills.join(", "))
}

/// Write `planned`, leaving files that SourceOrrery did not write alone.
pub fn install(planned: &[Planned]) -> std::io::Result<Vec<(PathBuf, Outcome)>> {
    let mut results = Vec::with_capacity(planned.len());
    for file in planned {
        let owned = match std::fs::read_to_string(&file.owner) {
            Ok(text) => text.contains(MARKER),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => true,
            // Unreadable (binary, permissions): not provably ours.
            Err(_) => false,
        };
        let existing = std::fs::read_to_string(&file.path).ok();
        let outcome = match existing {
            _ if !owned => Outcome::Kept,
            Some(text) if text == file.contents => Outcome::Unchanged,
            Some(_) => Outcome::Updated,
            None => Outcome::Created,
        };
        if matches!(outcome, Outcome::Created | Outcome::Updated) {
            if let Some(parent) = file.path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(&file.path, &file.contents)?;
        }
        results.push((file.path.clone(), outcome));
    }
    Ok(results)
}

/// The names and files of every embedded skill, for tests and checks.
#[cfg(test)]
fn skills() -> impl Iterator<Item = (&'static str, &'static [SkillFile])> {
    SKILLS.iter().map(|s| (s.name, s.files))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The frontmatter of a SKILL.md as (key, raw value) pairs, top level only.
    fn frontmatter(text: &str) -> Vec<(String, String)> {
        let body = text.strip_prefix("---\n").expect("starts with ---");
        let (front, _) = body.split_once("\n---\n").expect("frontmatter is closed");
        front
            .lines()
            .filter(|l| !l.starts_with(' ') && !l.is_empty())
            .map(|l| {
                let (k, v) = l.split_once(':').expect("key: value");
                (k.to_owned(), v.trim().to_owned())
            })
            .collect()
    }

    #[test]
    fn every_skill_follows_the_agent_skills_standard() {
        for (name, files) in skills() {
            let skill_md = files.iter().find(|f| f.path == "SKILL.md").unwrap();
            let fields = frontmatter(skill_md.contents);
            let get = |key: &str| {
                fields
                    .iter()
                    .find(|(k, _)| k == key)
                    .map_or_else(|| panic!("{name}: no {key}"), |(_, v)| v.as_str())
            };
            // name: 1-64 lowercase letters, digits and single hyphens, equal to the directory.
            assert_eq!(get("name"), name);
            assert!(name.len() <= 64);
            assert!(
                name.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            );
            assert!(!name.starts_with('-') && !name.ends_with('-') && !name.contains("--"));
            // description: 1-1024 characters (Kiro and Kilo enforce it).
            let description = get("description");
            assert!(
                !description.is_empty() && description.chars().count() <= 1024,
                "{name}: {}",
                description.len()
            );
            // Only the fields every agent accepts.
            for (key, _) in &fields {
                assert!(
                    ["name", "description", "license", "metadata"].contains(&key.as_str()),
                    "{name}: field {key} is not portable"
                );
            }
            assert!(skill_md.contents.contains(MARKER), "{name}: no marker");
            assert!(
                skill_md.contents.lines().count() < 500,
                "{name}: SKILL.md is too long"
            );
            // Every file the skill links to is shipped with it.
            for target in skill_md
                .contents
                .split("](")
                .skip(1)
                .filter_map(|rest| rest.split(')').next())
                .filter(|link| link.starts_with("references/"))
            {
                let target = target.split('#').next().unwrap();
                assert!(
                    files.iter().any(|f| f.path == target),
                    "{name}: links to missing {target}"
                );
            }
        }
    }

    #[test]
    fn plans_the_same_skills_for_every_agent_in_its_own_directory() {
        let root = Path::new("project");
        for agent in Agent::ALL {
            let dir = root.join(agent.project_skills_dir());
            let planned = plan(agent, &dir, true);
            assert!(planned.iter().all(|p| p.path.starts_with(root)));
            let skill_files = planned.iter().filter(|p| p.path.starts_with(&dir)).count();
            let extra = usize::from(agent == Agent::Codex) * SKILLS.len();
            assert_eq!(
                skill_files,
                SKILLS.iter().map(|s| s.files.len()).sum::<usize>() + extra
            );
            let subagent = planned
                .iter()
                .any(|p| p.path.ends_with(CLAUDE_SUBAGENT_FILE));
            assert_eq!(subagent, agent == Agent::Claude, "{agent:?}");
        }
    }

    #[test]
    fn the_installed_subagent_preloads_both_skills() {
        let text = subagent_with_skills();
        assert!(text.starts_with("---\nname: sourceorrery-env-migrator\n"));
        assert!(text.contains("\nskills: sourceorrery, sourceorrery-migrate-env\n---\n"));
        assert!(text.contains(MARKER));
        assert!(
            !CLAUDE_SUBAGENT.contains("\nskills:"),
            "the plugin ships the file as it is"
        );
    }
}
