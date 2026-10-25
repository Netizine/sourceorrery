//! `sourceorrery init --integration` and `sourceorrery import`, end to end.
//!
//! The per-agent trees committed under `integrations/` and the Claude Code
//! plugin under `plugins/sourceorrery/` must be exactly what the binary
//! writes from its embedded skills. After changing a skill, regenerate them:
//!
//! ```text
//! SOURCEORRERY_BLESS=1 cargo test -p sourceorrery-cli --test integrations
//! ```

use std::collections::BTreeMap;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

const CANARY: &str = "import-canary-7c41";

const AGENTS: [(&str, &str); 12] = [
    ("claude", ".claude/skills"),
    ("gemini", ".gemini/skills"),
    ("copilot", ".github/skills"),
    ("antigravity", ".agents/skills"),
    ("cline", ".cline/skills"),
    ("codex", ".agents/skills"),
    ("cursor", ".cursor/skills"),
    ("hermes", ".hermes/skills"),
    ("kilocode", ".kilo/skills"),
    ("kimi", ".kimi-code/skills"),
    ("kiro", ".kiro/skills"),
    ("opencode", ".opencode/skills"),
];

struct Env {
    home: tempfile::TempDir,
    user: tempfile::TempDir,
    project: tempfile::TempDir,
}

impl Env {
    fn new() -> Self {
        Self {
            home: tempfile::tempdir().unwrap(),
            user: tempfile::tempdir().unwrap(),
            project: tempfile::tempdir().unwrap(),
        }
    }

    fn run(&self, args: &[&str]) -> Output {
        let mut child = Command::new(env!("CARGO_BIN_EXE_sourceorrery"))
            .args(args)
            .current_dir(self.project.path())
            .env("SOURCEORRERY_HOME", self.home.path())
            // Never the real OS credential store: the vault opens with its
            // recovery key, which `create_vault` writes to this file.
            .env("SOURCEORRERY_KEYRING", "off")
            .env("SOURCEORRERY_RECOVERY_KEY_FILE", self.key_file())
            .env_remove("SOURCEORRERY_RECOVERY_KEY")
            .env("HOME", self.user.path())
            .env("USERPROFILE", self.user.path())
            .env_remove("SOURCEORRERY_VAULT")
            .env_remove("KIMI_CODE_HOME")
            .env_remove("XDG_CONFIG_HOME")
            .env("NO_COLOR", "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn sourceorrery");
        child.stdin.take().unwrap().write_all(b"").unwrap();
        child.wait_with_output().unwrap()
    }

    fn ok(&self, args: &[&str]) -> String {
        let out = self.run(args);
        assert!(
            out.status.success(),
            "{args:?} failed:\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8(out.stdout).unwrap() + &String::from_utf8(out.stderr).unwrap()
    }

    fn path(&self, relative: &str) -> PathBuf {
        self.project.path().join(relative)
    }

    /// Where the test vault's recovery key is kept.
    fn key_file(&self) -> PathBuf {
        self.user.path().join("vault.key")
    }

    /// Create the one vault a test uses, opening with its recovery key only.
    fn create_vault(&self, name: &str) {
        let key = self.key_file();
        self.ok(&[
            "vault",
            "create",
            name,
            "--no-keyring",
            "--recovery-key-out",
            key.to_str().unwrap(),
        ]);
    }
}

/// Every file under `dir`, by `/`-separated relative path.
fn tree(dir: &Path) -> BTreeMap<String, Vec<u8>> {
    fn walk(base: &Path, dir: &Path, out: &mut BTreeMap<String, Vec<u8>>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries {
            let path = entry.unwrap().path();
            if path.is_dir() {
                walk(base, &path, out);
            } else {
                let relative = path
                    .strip_prefix(base)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/");
                out.insert(relative, std::fs::read(&path).unwrap());
            }
        }
    }
    let mut out = BTreeMap::new();
    walk(dir, dir, &mut out);
    out
}

fn write_tree(dir: &Path, files: &BTreeMap<String, Vec<u8>>) {
    if dir.exists() {
        std::fs::remove_dir_all(dir).unwrap();
    }
    for (relative, contents) in files {
        let path = dir.join(relative);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, contents).unwrap();
    }
}

fn assert_same_tree(committed: &Path, generated: &BTreeMap<String, Vec<u8>>) {
    let actual = tree(committed);
    let names = |t: &BTreeMap<String, Vec<u8>>| t.keys().cloned().collect::<Vec<_>>();
    assert_eq!(
        names(&actual),
        names(generated),
        "{} does not list the files the CLI writes; regenerate with \
         SOURCEORRERY_BLESS=1 cargo test -p sourceorrery-cli --test integrations",
        committed.display()
    );
    for (name, contents) in generated {
        assert!(
            actual[name] == *contents,
            "{}/{name} differs from what the CLI writes; regenerate with \
             SOURCEORRERY_BLESS=1 cargo test -p sourceorrery-cli --test integrations",
            committed.display()
        );
    }
}

#[test]
fn committed_skills_are_exactly_what_the_cli_writes() {
    let bless = std::env::var_os("SOURCEORRERY_BLESS").is_some();
    let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    // A build from the crates.io package has no repository around it.
    if !bless && !repo.join("integrations").is_dir() {
        return;
    }
    for (agent, _) in AGENTS {
        let env = Env::new();
        env.ok(&["init", "--integration", agent]);
        let mut generated = tree(env.project.path());
        generated.remove("sourceorrery.toml");
        let committed = repo.join("integrations").join(agent);
        if bless {
            write_tree(&committed, &generated);
        } else {
            assert_same_tree(&committed, &generated);
        }
    }

    // The Claude Code plugin: the same skills, and the subagent as written.
    let env = Env::new();
    let skills = env.path("plugin-skills");
    env.ok(&[
        "init",
        "--integration",
        "claude",
        "--skills-dir",
        skills.to_str().unwrap(),
    ]);
    let generated = tree(&skills);
    let plugin = repo.join("plugins/sourceorrery");
    let subagent = std::fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("skills/agents/claude/sourceorrery-env-migrator.md"),
    )
    .unwrap();
    if bless {
        write_tree(&plugin.join("skills"), &generated);
        write_tree(
            &plugin.join("agents"),
            &BTreeMap::from([("sourceorrery-env-migrator.md".to_owned(), subagent)]),
        );
    } else {
        assert_same_tree(&plugin.join("skills"), &generated);
        assert_eq!(
            std::fs::read(plugin.join("agents/sourceorrery-env-migrator.md")).unwrap(),
            subagent,
            "plugins/sourceorrery/agents differs from the crate's subagent; regenerate"
        );
    }
}

#[test]
fn init_installs_every_agent_and_keeps_an_existing_manifest() {
    let env = Env::new();
    let out = env.ok(&["init", "--integration", "all"]);
    // No secrets picked: the skills only, and how to write the manifest.
    assert!(!env.path("sourceorrery.toml").exists());
    assert!(out.contains("init --all"), "{out}");
    for (agent, dir) in AGENTS {
        for skill in ["sourceorrery", "sourceorrery-migrate-env"] {
            let skill_md = env.path(&format!("{dir}/{skill}/SKILL.md"));
            let text = std::fs::read_to_string(&skill_md)
                .unwrap_or_else(|_| panic!("{agent}: no {}", skill_md.display()));
            assert!(
                text.starts_with(&format!("---\nname: {skill}\n")),
                "{agent}"
            );
        }
    }
    assert!(
        env.path(".agents/skills/sourceorrery/agents/openai.yaml")
            .is_file()
    );
    assert!(
        env.path(".claude/agents/sourceorrery-env-migrator.md")
            .is_file()
    );
    assert!(out.contains("hermes skills trust"));

    // A second run changes nothing and keeps the manifest the user edited.
    std::fs::write(
        env.path("sourceorrery.toml"),
        "[project]\nname = \"mine\"\nvault = \"dev\"\n",
    )
    .unwrap();
    let before = tree(env.project.path());
    let out = env.ok(&["init", "--integration", "claude"]);
    assert!(out.contains("kept it"), "{out}");
    assert_eq!(tree(env.project.path()), before);

    // Without --integration, init needs secrets picked and a vault.
    assert!(!env.run(&["init"]).status.success());
}

#[test]
fn init_with_an_integration_writes_the_manifest_when_secrets_are_picked() {
    let env = Env::new();
    env.create_vault("dev");
    env.ok(&[
        "secret",
        "set",
        "api-key",
        "--vault",
        "dev",
        "--allow-empty",
    ]);
    let out = env.ok(&["init", "--integration", "claude", "--all"]);
    assert!(out.contains("Wrote"), "{out}");
    let manifest = std::fs::read_to_string(env.path("sourceorrery.toml")).unwrap();
    assert!(manifest.contains("[secrets.api-key]"), "{manifest}");
    assert!(env.path(".claude/skills/sourceorrery/SKILL.md").is_file());
}

#[test]
fn init_updates_its_own_files_and_leaves_other_skills_alone() {
    let env = Env::new();
    env.ok(&["init", "--integration", "cursor"]);
    let ours = env.path(".cursor/skills/sourceorrery-migrate-env/references/convert-go.md");
    let original = std::fs::read(&ours).unwrap();
    std::fs::write(&ours, "stale").unwrap();
    let theirs = env.path(".cursor/skills/sourceorrery/SKILL.md");
    std::fs::write(
        &theirs,
        "---\nname: sourceorrery\ndescription: a skill of my own\n---\n",
    )
    .unwrap();

    let out = env.ok(&["-o", "json", "init", "--integration", "cursor"]);
    let report: serde_json::Value = serde_json::from_str(&out[..=out.rfind('}').unwrap()]).unwrap();
    let outcome = |suffix: &str| {
        report["integrations"][0]["files"]
            .as_array()
            .unwrap()
            .iter()
            .find(|f| {
                f["path"]
                    .as_str()
                    .unwrap()
                    .replace('\\', "/")
                    .ends_with(suffix)
            })
            .unwrap()["outcome"]
            .clone()
    };
    assert_eq!(
        outcome("sourceorrery-migrate-env/references/convert-go.md"),
        "updated"
    );
    assert_eq!(outcome("sourceorrery/SKILL.md"), "kept");
    assert_eq!(outcome("sourceorrery/references/sdks.md"), "kept");
    assert_eq!(std::fs::read(&ours).unwrap(), original);
    assert!(
        std::fs::read_to_string(&theirs)
            .unwrap()
            .contains("a skill of my own")
    );
}

#[test]
fn user_scope_and_skills_dir_write_no_manifest() {
    let env = Env::new();
    env.ok(&[
        "init",
        "--integration",
        "claude,opencode",
        "--scope",
        "user",
    ]);
    assert!(!env.path("sourceorrery.toml").exists());
    let user = env.user.path();
    assert!(user.join(".claude/skills/sourceorrery/SKILL.md").is_file());
    assert!(
        user.join(".claude/agents/sourceorrery-env-migrator.md")
            .is_file()
    );
    assert!(
        user.join(".config/opencode/skills/sourceorrery-migrate-env/SKILL.md")
            .is_file()
    );

    let managed = env.path("managed");
    env.ok(&[
        "init",
        "--integration",
        "claude",
        "--skills-dir",
        managed.to_str().unwrap(),
    ]);
    assert!(managed.join("sourceorrery/SKILL.md").is_file());
    assert!(
        !env.path("agents").exists(),
        "no subagent outside an agent's own directory"
    );
    assert!(!env.path("sourceorrery.toml").exists());
}

fn env_file(env: &Env) {
    std::fs::write(
        env.path(".env"),
        format!(
            "# settings\nDATABASE_URL=postgres://app:{CANARY}-1@db/app\nexport STRIPE_KEY=\"{CANARY}-2\"\n\
             apiKey='{CANARY}-3'\nEMPTY=\nBAD-NAME={CANARY}-4\n"
        ),
    )
    .unwrap();
}

#[test]
fn import_stores_values_without_ever_showing_them() {
    let env = Env::new();
    env.create_vault("development");
    env_file(&env);

    let dry = env.ok(&["import", ".env", "--dry-run"]);
    assert!(!dry.contains(CANARY), "{dry}");
    assert!(dry.contains("would store"), "{dry}");
    assert!(
        !env.path("sourceorrery.toml").exists(),
        "a dry run writes nothing"
    );

    let out = env.ok(&["import", ".env"]);
    assert!(!out.contains(CANARY), "{out}");
    let manifest = std::fs::read_to_string(env.path("sourceorrery.toml")).unwrap();
    assert!(!manifest.contains(CANARY));
    assert!(manifest.contains("[secrets.database-url]"));
    assert!(manifest.contains("[secrets.apikey]\nenv = \"apiKey\""));
    assert!(!manifest.contains("[secrets.empty]") && !manifest.contains("bad-name"));

    // Values reach the program under their original names.
    let check = env.ok(&["check"]);
    assert!(check.contains("3 secret(s) ready"), "{check}");
    let json = env.ok(&["-o", "json", "secret", "get", "apikey", "--reveal"]);
    assert!(json.contains(&format!("{CANARY}-3")));

    // A second run leaves what is in the vault alone and adds nothing.
    let again = env.ok(&["-o", "json", "import", ".env"]);
    assert!(!again.contains(CANARY));
    assert!(again.contains("already in vault"));
    assert_eq!(
        std::fs::read_to_string(env.path("sourceorrery.toml")).unwrap(),
        manifest
    );
    let versions = env.ok(&["-o", "json", "secret", "versions", "database-url"]);
    assert_eq!(versions.matches("\"version\"").count(), 1, "{versions}");
}

#[test]
fn import_appends_to_an_existing_manifest_and_supports_manifest_only() {
    let env = Env::new();
    let original = "# my project\n[project]\nname = \"demo\"\nvault = \"development\"\n\n[secrets.existing]\npurpose = \"kept\"\n";
    std::fs::write(env.path("sourceorrery.toml"), original).unwrap();
    std::fs::write(
        env.path(".env.example"),
        "DATABASE_URL=\nSTRIPE_KEY=change-me\n",
    )
    .unwrap();

    let out = env.ok(&["import", ".env.example", "--manifest-only"]);
    assert!(!out.contains("change-me"));
    let manifest = std::fs::read_to_string(env.path("sourceorrery.toml")).unwrap();
    assert!(
        manifest.starts_with(original),
        "comments and existing entries are kept"
    );
    assert!(
        manifest.contains("[secrets.database-url]") && manifest.contains("[secrets.stripe-key]")
    );
    assert!(
        !env.home.path().join("vaults").exists(),
        "--manifest-only opens no vault"
    );
}

#[test]
fn import_refuses_ambiguous_files_without_quoting_them() {
    let env = Env::new();
    env.create_vault("development");
    for (text, expected) in [
        (format!("A={CANARY}\nA={CANARY}-again\n"), "A (lines 1, 2)"),
        (format!("OK=1\nBROKEN {CANARY}\n"), "line 2"),
        (
            format!("api_key={CANARY}\nAPI_KEY={CANARY}\n"),
            "would both become the secret 'api-key'",
        ),
    ] {
        std::fs::write(env.path(".env"), &text).unwrap();
        let out = env.run(&["import", ".env"]);
        assert!(!out.status.success());
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(stderr.contains(expected), "{stderr}");
        assert!(!stderr.contains(CANARY), "{stderr}");
    }
    assert!(!env.path("sourceorrery.toml").exists());
}

#[test]
fn import_into_a_missing_vault_says_how_to_create_it() {
    let env = Env::new();
    env_file(&env);
    let out = env.run(&["import", ".env"]);
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("sourceorrery vault create development"),
        "{stderr}"
    );
    assert!(!stderr.contains(CANARY));
    assert!(
        !env.path("sourceorrery.toml").exists(),
        "nothing is written when nothing can be stored"
    );
}
