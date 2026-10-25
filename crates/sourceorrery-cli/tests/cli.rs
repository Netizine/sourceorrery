//! End-to-end tests of the `sourceorrery` binary against a temporary home.

use std::io::Write;
use std::path::Path;
use std::process::{Command, Output, Stdio};

const CANARY: &str = "cli-canary-9b1d-value";
/// A view-check password the strength estimate rates good.
const PASSWORD: &str = "Orbit-Lantern-Copper-Nine-42";

struct Env {
    home: tempfile::TempDir,
    project: tempfile::TempDir,
    /// One `<vault>.key` file per vault the test created: its recovery key.
    keys: tempfile::TempDir,
}

impl Env {
    fn new() -> Self {
        Self {
            home: tempfile::tempdir().unwrap(),
            project: tempfile::tempdir().unwrap(),
            keys: tempfile::tempdir().unwrap(),
        }
    }

    fn cmd(&self, args: &[&str]) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_sourceorrery"));
        cmd.args(args)
            .current_dir(self.project.path())
            .env("SOURCEORRERY_HOME", self.home.path())
            // Never the real OS credential store: every vault opens with its
            // recovery key, from the file the harness keeps for it.
            .env("SOURCEORRERY_KEYRING", "off")
            .env_remove("SOURCEORRERY_VAULT")
            .env_remove("SOURCEORRERY_RECOVERY_KEY")
            .env_remove("SOURCEORRERY_PASSWORD")
            .env_remove("SOURCEORRERY_PASSWORD_FILE")
            .env_remove("SOURCEORRERY_TOTP")
            .env("NO_COLOR", "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        match self.vault_of(args) {
            Some(vault) => cmd.env("SOURCEORRERY_RECOVERY_KEY_FILE", self.key_file(&vault)),
            None => cmd.env_remove("SOURCEORRERY_RECOVERY_KEY_FILE"),
        };
        cmd
    }

    /// The vault a command acts on, as the CLI picks it: `--vault`, else the
    /// project manifest's, else the only vault the test created.
    fn vault_of(&self, args: &[&str]) -> Option<String> {
        if let Some(i) = args.iter().position(|a| *a == "--vault") {
            return args.get(i + 1).map(|v| (*v).to_owned());
        }
        if let Ok(manifest) = std::fs::read_to_string(self.project.path().join("sourceorrery.toml"))
            && let Some(name) = manifest
                .lines()
                .find_map(|l| l.trim().strip_prefix("vault = "))
        {
            return Some(name.trim_matches('"').to_owned());
        }
        let mut keys = std::fs::read_dir(self.keys.path())
            .ok()?
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|x| x == "key"));
        let only = keys.next()?;
        if keys.next().is_some() {
            return None;
        }
        only.file_stem().map(|s| s.to_string_lossy().into_owned())
    }

    /// Where the harness keeps `vault`'s recovery key.
    fn key_file(&self, vault: &str) -> std::path::PathBuf {
        self.keys.path().join(format!("{vault}.key"))
    }

    /// `vault`'s recovery key, as `vault create` wrote it.
    fn recovery_key(&self, vault: &str) -> String {
        std::fs::read_to_string(self.key_file(vault))
            .unwrap()
            .trim()
            .to_owned()
    }

    fn run(&self, args: &[&str]) -> Output {
        self.run_with_stdin(args, "")
    }

    fn run_with_stdin(&self, args: &[&str], stdin: &str) -> Output {
        let mut child = self.cmd(args).spawn().expect("spawn sourceorrery");
        child
            .stdin
            .take()
            .unwrap()
            .write_all(stdin.as_bytes())
            .unwrap();
        child.wait_with_output().unwrap()
    }

    fn ok(&self, args: &[&str]) -> String {
        let out = self.run(args);
        assert!(
            out.status.success(),
            "command {args:?} failed:\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8(out.stdout).unwrap()
    }

    /// Create a vault that opens with its recovery key only; the key goes
    /// to the harness's file for it.
    fn create_vault(&self, name: &str) {
        let key = self.key_file(name);
        self.ok(&[
            "vault",
            "create",
            name,
            "--no-keyring",
            "--recovery-key-out",
            key.to_str().unwrap(),
        ]);
    }

    fn set(&self, vault: &str, name: &str, value: &str) {
        let out = self.run_with_stdin(&["secret", "set", name, "--vault", vault], value);
        assert!(
            out.status.success(),
            "set failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    /// A file in the project directory holding `text`.
    fn file(&self, name: &str, text: &str) -> String {
        let path = self.project.path().join(name);
        std::fs::write(&path, text).unwrap();
        path.to_str().unwrap().to_owned()
    }

    /// `vault` opened in the test itself, with its recovery key, for what the
    /// CLI cannot do yet (add a connection, catalogue a secret at one).
    fn open_vault(&self, vault: &str) -> sourceorrery_storage::SqliteVault {
        sourceorrery_storage::VaultRegistry::with_root(self.home.path())
            .with_store(std::sync::Arc::new(sourceorrery_storage::NoStore))
            .open(
                vault,
                &sourceorrery_storage::StaticRecoveryKey::new(self.recovery_key(vault).as_str()),
            )
            .unwrap()
    }

    /// Add a connection with `settings` to `vault` and catalogue `secret` as
    /// stored through it, as a set there would; returns the connection's id.
    fn store_through(
        &self,
        vault: &str,
        settings: &sourceorrery_core::ConnectionSettings,
        secret: &str,
    ) -> String {
        let opened = self.open_vault(vault);
        let token = sourceorrery_core::Credentials::VaultToken("hvs.cli-test".into());
        let stored = matches!(
            settings,
            sourceorrery_core::ConnectionSettings::HashicorpVault { .. }
        )
        .then_some(&token);
        let id = opened.add_connection(settings, stored).unwrap().id;
        opened
            .record_at_connection(
                &id,
                sourceorrery_core::AuditOperation::SecretSet,
                Some(secret),
                None,
                Ok(()),
                sourceorrery_storage::CatalogChange::Add,
            )
            .unwrap();
        id
    }
}

/// A recovery key that opens nothing: the right shape, wrong letters.
const WRONG_KEY: &str = "AAAAA-AAAAA-AAAAA-AAAAA-AAAAA";

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

#[test]
fn vault_lifecycle_and_metadata_never_reveal_values() {
    let env = Env::new();
    env.create_vault("dev");
    assert!(env.ok(&["vault", "list"]).contains("dev"));

    env.set("dev", "database-password", &format!("{CANARY}\n"));

    let listed = env.ok(&["secret", "list", "--vault", "dev"]);
    assert!(listed.contains("database-password"));
    assert!(listed.contains("enabled"));
    assert!(!listed.contains(CANARY));

    let got = env.run(&["secret", "get", "database-password", "--vault", "dev"]);
    assert!(got.status.success());
    assert!(
        !stdout(&got).contains(CANARY),
        "get without --reveal leaked the value"
    );
    assert!(stderr(&got).contains("--reveal"));

    let json = env.ok(&[
        "secret",
        "get",
        "database-password",
        "--vault",
        "dev",
        "-o",
        "json",
    ]);
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed["name"], "database-password");
    assert!(parsed.get("value").is_none());

    let revealed = env.ok(&[
        "secret",
        "get",
        "database-password",
        "--vault",
        "dev",
        "--reveal",
    ]);
    assert_eq!(
        revealed,
        format!("{CANARY}\n"),
        "trailing newline from stdin is stripped"
    );

    let raw = env.ok(&[
        "secret",
        "get",
        "database-password",
        "--vault",
        "dev",
        "--reveal",
        "--raw",
    ]);
    assert_eq!(raw, CANARY);

    let json = env.ok(&[
        "secret",
        "get",
        "database-password",
        "--vault",
        "dev",
        "--reveal",
        "-o",
        "json",
    ]);
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed["value"], CANARY);

    let versions = env.ok(&["secret", "versions", "database-password", "--vault", "dev"]);
    assert!(versions.contains("newest"));

    let audit = env.ok(&["audit", "--vault", "dev"]);
    assert!(audit.contains("secret_get"));
    assert!(!audit.contains(CANARY));
}

#[test]
fn set_refuses_values_on_the_command_line_and_empty_values() {
    let env = Env::new();
    env.create_vault("dev");

    let out = env.run(&["secret", "set", "db", "--value", "x", "--vault", "dev"]);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("--value"));

    let out = env.run_with_stdin(&["secret", "set", "db", "--vault", "dev"], "");
    assert!(!out.status.success());
    assert!(stderr(&out).contains("empty"));

    let out = env.run_with_stdin(
        &["secret", "set", "db", "--vault", "dev", "--allow-empty"],
        "",
    );
    assert!(out.status.success(), "{}", stderr(&out));
}

#[test]
fn errors_are_structured_in_json_mode() {
    let env = Env::new();
    env.create_vault("dev");
    let out = env.run(&["secret", "get", "missing", "--vault", "dev", "-o", "json"]);
    assert!(!out.status.success());
    let err: serde_json::Value = serde_json::from_str(stderr(&out).trim()).unwrap();
    assert_eq!(err["error"]["code"], "not_found");

    let out = env.run(&["secret", "get", "x", "--vault", "nope"]);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("not found"));
}

#[test]
fn a_wrong_recovery_key_is_locked() {
    let env = Env::new();
    env.create_vault("dev");
    let out = env
        .cmd(&["secret", "list", "--vault", "dev"])
        .env("SOURCEORRERY_RECOVERY_KEY", WRONG_KEY)
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(stderr(&out).contains("locked"));
}

#[test]
fn update_delete_recover_purge() {
    let env = Env::new();
    env.create_vault("dev");
    env.set("dev", "k", "v1");
    env.set("dev", "k", "v2");

    env.ok(&["secret", "update", "k", "--vault", "dev", "--disable"]);
    let revealed = env.ok(&["secret", "get", "k", "--vault", "dev", "--reveal"]);
    assert_eq!(
        revealed.trim(),
        "v1",
        "disabled newest version falls back to previous"
    );

    env.ok(&["secret", "delete", "k", "--vault", "dev"]);
    let out = env.run(&["secret", "get", "k", "--vault", "dev"]);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("deleted"));
    assert!(
        env.ok(&["secret", "list", "--vault", "dev", "--deleted"])
            .contains('k')
    );

    env.ok(&["secret", "recover", "k", "--vault", "dev"]);
    env.ok(&["secret", "delete", "k", "--vault", "dev"]);
    env.ok(&["secret", "purge", "k", "--vault", "dev", "--yes"]);
    let out = env.run(&["secret", "get", "k", "--vault", "dev"]);
    assert!(stderr(&out).contains("not found"));
}

#[test]
fn manifest_driven_check_and_run() {
    let env = Env::new();
    env.create_vault("development");
    env.set("development", "database-password", CANARY);

    let init = env.run(&["init", "--all", "--project-name", "demo"]);
    assert!(init.status.success(), "{}", stderr(&init));
    let manifest_path = env.project.path().join("sourceorrery.toml");
    let manifest = std::fs::read_to_string(&manifest_path).unwrap();
    assert!(manifest.contains("database-password"));
    assert!(!manifest.contains("value ="));
    assert!(!manifest.contains(CANARY));

    // Vault comes from the manifest now: no --vault flag.
    let out = env.run(&["check"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(stdout(&out).contains("ok"));

    // A secret the manifest declares and the vault lacks fails the check.
    std::fs::write(
        &manifest_path,
        format!("{manifest}\n[secrets.missing-one]\n"),
    )
    .unwrap();
    let out = env.run(&["check"]);
    assert!(
        !out.status.success(),
        "check must fail while a secret is missing"
    );
    assert!(stdout(&out).contains("not_found"));
    std::fs::write(&manifest_path, &manifest).unwrap();
    // --access reads the value too (and discards it), which the audit log
    // records as a secret_get; plain check leaves no such row.
    let gets = |label: &str| {
        let out = env.run(&["audit", "--vault", "development", "-o", "json"]);
        assert!(out.status.success(), "{label}: {}", stderr(&out));
        stdout(&out).matches("\"secret_get\"").count()
    };
    let before = gets("before");
    let out = env.run(&["check", "--access"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let text = format!("{}{}", stdout(&out), stderr(&out));
    assert!(text.contains("readable by this identity"), "{text}");
    assert!(!text.contains(CANARY));
    assert_eq!(gets("after"), before + 1);

    let echo: &[&str] = if cfg!(windows) {
        &["run", "--", "cmd", "/C", "echo %DATABASE_PASSWORD%"]
    } else {
        &["run", "--", "sh", "-c", "echo \"$DATABASE_PASSWORD\""]
    };
    let out = env.run(echo);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(stdout(&out).trim(), CANARY);

    // Child exit codes propagate.
    let fail: &[&str] = if cfg!(windows) {
        &["run", "--", "cmd", "/C", "exit 7"]
    } else {
        &["run", "--", "sh", "-c", "exit 7"]
    };
    assert_eq!(env.run(fail).status.code(), Some(7));

    assert!(Path::new(&manifest_path).exists());
}

/// `init` reads the vault, never a value: it declares the secrets picked by
/// name, `purpose` from each description, and records the folder. Run again
/// on the manifest it adds what is missing and leaves the rest byte for
/// byte, under the vault and project name the manifest has.
#[test]
#[allow(clippy::too_many_lines)] // one manifest, written and then added to
fn init_writes_the_manifest_from_the_vault_and_records_the_folder() {
    let env = Env::new();
    let none = env.run(&["init", "--all"]);
    assert!(!none.status.success());
    assert!(stderr(&none).contains("no vault yet"), "{}", stderr(&none));

    env.create_vault("dev");
    let out = env.run_with_stdin(
        &[
            "secret",
            "set",
            "db-password",
            "--vault",
            "dev",
            "--description",
            "Database authentication",
        ],
        CANARY,
    );
    assert!(out.status.success(), "{}", stderr(&out));
    env.set("dev", "api-key", "key");

    for (args, says) in [
        (&["init"][..], "pick the secrets"),
        (
            &["init", "--secret", "missing"][..],
            "has no secret 'missing'",
        ),
    ] {
        let refused = env.run(args);
        assert!(!refused.status.success(), "{args:?}");
        assert!(
            stderr(&refused).contains(says),
            "{args:?}: {}",
            stderr(&refused)
        );
    }
    let manifest_path = env.project.path().join("sourceorrery.toml");
    assert!(!manifest_path.exists(), "a refused init writes nothing");

    let written: serde_json::Value = serde_json::from_str(&env.ok(&[
        "init",
        "--secret",
        "db-password",
        "--project-name",
        "demo",
        "-o",
        "json",
    ]))
    .unwrap();
    assert_eq!(written["created"], true);
    assert_eq!(written["vault"], "dev");
    assert_eq!(written["added"], serde_json::json!(["db-password"]));
    assert_eq!(written["linked"]["name"], "demo");
    let folder = std::fs::canonicalize(env.project.path()).unwrap();
    let recorded = written["linked"]["path"].as_str().unwrap().to_owned();
    assert!(
        folder.to_str().unwrap().ends_with(&recorded) && Path::new(&recorded).is_absolute(),
        "{recorded} is not {}",
        folder.display()
    );
    let manifest = std::fs::read_to_string(&manifest_path).unwrap();
    assert!(
        manifest.contains("name = \"demo\"\nvault = \"dev\""),
        "{manifest}"
    );
    assert!(
        manifest.contains(
            "[secrets.db-password]\nrequired = true\npurpose = \"Database authentication\""
        ),
        "{manifest}"
    );
    assert!(!manifest.contains("api-key") && !manifest.contains(CANARY));
    env.ok(&["check"]);

    // A hand edit stays; the second run adds the rest under the manifest's
    // own vault and name, and the folder keeps its one record.
    let edited = manifest.replace(
        "[secrets.db-password]\n",
        "# the production one\n[secrets.db-password]\nenv = \"DB_PASS\"\n",
    );
    std::fs::write(&manifest_path, &edited).unwrap();
    for (args, says) in [
        (&["init", "other", "--all"][..], "names vault 'dev'"),
        (
            &["init", "--all", "--project-name", "x"][..],
            "names the project 'demo'",
        ),
    ] {
        let refused = env.run(args);
        assert!(!refused.status.success(), "{args:?}");
        assert!(
            stderr(&refused).contains(says),
            "{args:?}: {}",
            stderr(&refused)
        );
    }
    let added: serde_json::Value =
        serde_json::from_str(&env.ok(&["init", "--all", "-o", "json"])).unwrap();
    assert_eq!(added["created"], false);
    assert_eq!(added["added"], serde_json::json!(["api-key"]));
    assert_eq!(added["declared"], serde_json::json!(["db-password"]));
    assert_eq!(added["linked"]["id"], written["linked"]["id"]);
    let manifest = std::fs::read_to_string(&manifest_path).unwrap();
    assert!(manifest.starts_with(&edited), "{manifest}");
    assert!(
        manifest.ends_with("\n[secrets.api-key]\nrequired = true\n"),
        "{manifest}"
    );
    let projects = env.open_vault("dev").projects().unwrap();
    assert_eq!(projects.len(), 1);
    assert_eq!(projects[0].name, "demo");

    // Nothing left to add: the file is not touched.
    let again = env.ok(&["init", "--all"]);
    assert_eq!(std::fs::read_to_string(&manifest_path).unwrap(), manifest);
    drop(again);

    let audit = env.ok(&["audit", "--vault", "dev", "-o", "json"]);
    assert!(audit.contains("project_link"), "{audit}");
    assert!(!audit.contains(CANARY));
}

/// With several vaults init asks which one; the vault a manifest names
/// must be on this machine.
#[test]
fn init_needs_to_know_the_vault() {
    let env = Env::new();
    env.create_vault("dev");
    env.create_vault("prod");
    env.set("prod", "api-key", "key");
    let several = env.run(&["init", "--all"]);
    assert!(!several.status.success());
    assert!(
        stderr(&several).contains("there are 2 vaults (dev, prod)"),
        "{}",
        stderr(&several)
    );
    let out = env
        .cmd(&["init", "prod", "--all"])
        .env("SOURCEORRERY_RECOVERY_KEY_FILE", env.key_file("prod"))
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", stderr(&out));
    let manifest = std::fs::read_to_string(env.project.path().join("sourceorrery.toml")).unwrap();
    assert!(manifest.contains("vault = \"prod\""), "{manifest}");

    std::fs::write(
        env.project.path().join("sourceorrery.toml"),
        "[project]\nname = \"demo\"\nvault = \"elsewhere\"\n",
    )
    .unwrap();
    let missing = env.run(&["init", "--all"]);
    assert!(!missing.status.success());
    assert!(
        stderr(&missing).contains("vault import"),
        "{}",
        stderr(&missing)
    );
}

#[test]
fn completions_generate() {
    let env = Env::new();
    let out = env.ok(&["completions", "bash"]);
    assert!(out.contains("sourceorrery"));
}

/// `ui` needs a terminal and has no JSON output; both are refused before
/// the vault is unlocked, so nothing is prompted for or audited.
#[cfg(feature = "ui")]
#[test]
fn ui_refuses_without_a_terminal_before_unlocking() {
    let env = Env::new();
    env.create_vault("dev");
    let opens = || {
        let json = env.ok(&[
            "audit",
            "--vault",
            "dev",
            "--operation",
            "vault_open",
            "-o",
            "json",
        ]);
        serde_json::from_str::<Vec<serde_json::Value>>(&json)
            .unwrap()
            .len()
    };
    let before = opens();

    let out = env.run(&["ui", "--vault", "dev"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        stderr(&out).contains("needs an interactive terminal"),
        "{}",
        stderr(&out)
    );
    assert_eq!(stdout(&out), "");

    let out = env.run(&["ui", "--vault", "dev", "-o", "json"]);
    assert_eq!(out.status.code(), Some(1));
    let err: serde_json::Value = serde_json::from_str(stderr(&out).trim()).unwrap();
    assert_eq!(err["error"]["code"], "cli");
    assert!(
        err["error"]["message"]
            .as_str()
            .unwrap()
            .contains("no JSON output")
    );

    // Only the second count's own unlock was added.
    assert_eq!(opens(), before + 1);
}

#[test]
fn audit_verify_reports_an_intact_chain() {
    let env = Env::new();
    env.create_vault("dev");
    env.set("dev", "k", "v1");
    env.ok(&["secret", "get", "k", "--vault", "dev"]);

    let table = env.ok(&["audit", "--verify", "--vault", "dev"]);
    assert!(table.contains("intact"), "{table}");
    assert!(!table.contains("BROKEN"));

    let json = env.ok(&["audit", "--verify", "--vault", "dev", "-o", "json"]);
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert!(parsed["first_broken"].is_null());
    assert_eq!(parsed["truncations"], 0);
    assert_eq!(parsed["head_valid"], true);
    assert!(parsed["rows"].as_u64().unwrap() >= 4);

    // --verify is a mode of its own.
    let out = env.run(&["audit", "--verify", "--limit", "3", "--vault", "dev"]);
    assert!(!out.status.success());
}

/// Remove the newest `rows` audit rows from a vault file, as an attacker
/// with write access would.
fn truncate_audit_log(home: &Path, vault: &str, rows: i64) {
    let path = home.join("vaults").join(format!("{vault}.sorvault"));
    let conn = rusqlite::Connection::open(path).unwrap();
    conn.execute(
        "DELETE FROM audit_events WHERE id > (SELECT MAX(id) FROM audit_events) - ?1",
        [rows],
    )
    .unwrap();
}

#[test]
fn truncated_audit_log_blocks_the_vault_until_acknowledged() {
    let env = Env::new();
    env.create_vault("dev");
    env.set("dev", "k", CANARY);
    env.ok(&["secret", "get", "k", "--vault", "dev"]);
    env.ok(&["secret", "get", "k", "--vault", "dev"]);
    truncate_audit_log(env.home.path(), "dev", 2);

    // The first unlock detects the truncation; every later command is
    // refused until it is acknowledged, and none of them shows the value.
    let out = env.run(&["secret", "get", "k", "--vault", "dev", "--reveal"]);
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("rows removed after event"),
        "{}",
        stderr(&out)
    );
    assert!(!stdout(&out).contains(CANARY));
    let out = env.run(&[
        "secret", "get", "k", "--vault", "dev", "--reveal", "-o", "json",
    ]);
    assert!(!out.status.success());
    let err: serde_json::Value = serde_json::from_str(stderr(&out).trim()).unwrap();
    assert_eq!(err["error"]["code"], "crypto");
    let message = err["error"]["message"].as_str().unwrap();
    assert!(message.contains("unacknowledged"), "{message}");
    assert!(message.contains("audit --acknowledge"), "{message}");
    assert!(!stdout(&out).contains(CANARY));
    let out = env.run(&["secret", "list", "--vault", "dev"]);
    assert!(!out.status.success());

    // Inspection still works: the chain report and the log, with a warning.
    let out = env.run(&["audit", "--verify", "--vault", "dev", "-o", "json"]);
    assert!(!out.status.success(), "a truncated chain is not intact");
    let parsed: serde_json::Value = serde_json::from_str(&stdout(&out)).unwrap();
    assert_eq!(parsed["truncations"], 1);
    assert_eq!(parsed["unacknowledged"], 1);
    assert_eq!(parsed["head_valid"], true);
    assert!(stderr(&out).contains("unacknowledged"), "{}", stderr(&out));
    let out = env.run(&["audit", "--vault", "dev"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(stdout(&out).contains("audit_verify"), "{}", stdout(&out));
    assert!(stderr(&out).contains("--acknowledge"), "{}", stderr(&out));

    // Acknowledging needs a confirmation: with no terminal and no --yes it
    // aborts, having shown what would have been acknowledged.
    let out = env.run(&["audit", "--acknowledge", "--vault", "dev"]);
    assert!(!out.status.success());
    assert!(
        stdout(&out).contains("rows removed after event"),
        "{}",
        stdout(&out)
    );
    assert!(stderr(&out).contains("aborted"), "{}", stderr(&out));
    let out = env.run(&["secret", "get", "k", "--vault", "dev"]);
    assert!(!out.status.success(), "still blocked");

    // --yes acknowledges; the vault works again and the truncation stays
    // on record, acknowledged.
    let out = env.run(&[
        "audit",
        "--acknowledge",
        "--yes",
        "--vault",
        "dev",
        "-o",
        "json",
    ]);
    assert!(out.status.success(), "{}", stderr(&out));
    let ack: serde_json::Value = serde_json::from_str(&stdout(&out)).unwrap();
    assert_eq!(ack["truncations"].as_array().unwrap().len(), 1);
    assert!(ack["event_id"].as_u64().unwrap() > 0);
    let revealed = env.ok(&["secret", "get", "k", "--vault", "dev", "--reveal"]);
    assert_eq!(revealed.trim(), CANARY);
    let out = env.run(&["audit", "--verify", "--vault", "dev", "-o", "json"]);
    assert!(!out.status.success());
    let parsed: serde_json::Value = serde_json::from_str(&stdout(&out)).unwrap();
    assert_eq!(parsed["truncations"], 1);
    assert_eq!(parsed["unacknowledged"], 0);
    let listed = env.ok(&["audit", "--operation", "audit_verify", "--vault", "dev"]);
    assert!(listed.contains("truncation acknowledged"), "{listed}");

    // Nothing left to acknowledge is not an error; --yes on its own is a
    // usage error.
    let out = env.run(&["audit", "--acknowledge", "--yes", "--vault", "dev"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(stderr(&out).contains("nothing to do"), "{}", stderr(&out));
    assert_eq!(
        env.run(&["audit", "--yes", "--vault", "dev"]).status.code(),
        Some(2)
    );
}

/// Text a tamperer plants in a free-form field: cursor up and erase line
/// (hides the row above), an OSC 52 clipboard write, a right-to-left
/// override and an 8-bit CSI.
const PLANTED: &str = "planted\x1b[1A\x1b[2K\x1b]52;c;ZXZpbA==\x07\u{202e}\u{9b}2J";

fn open_vault_file(home: &Path, vault: &str) -> rusqlite::Connection {
    rusqlite::Connection::open(home.join("vaults").join(format!("{vault}.sorvault"))).unwrap()
}

/// Output fit for a terminal: no control or bidi character left raw, and
/// the planted text visible in escaped form.
fn assert_escaped(output: &str) {
    let raw = output
        .chars()
        .find(|c| (c.is_control() && *c != '\n') || ('\u{202a}'..='\u{202e}').contains(c));
    assert!(
        raw.is_none(),
        "raw {raw:?} reached the terminal: {output:?}"
    );
    assert!(
        output.contains("planted\\u{1b}[1A\\u{1b}[2K\\u{1b}]52;c;ZXZpbA==\\u{7}\\u{202e}\\u{9b}2J"),
        "{output:?}"
    );
}

#[test]
fn planted_keyring_accounts_are_shown_escaped() {
    let env = Env::new();
    env.create_vault("dev");
    // A this-machine wrap names its credential-store account in the file,
    // where nothing proves it; `vault destroy` names the ones it keeps.
    let kind = serde_json::json!({
        "kind": "this-machine",
        "service": "sourceorrery",
        "account": PLANTED,
    })
    .to_string();
    open_vault_file(env.home.path(), "dev")
        .execute(
            "INSERT INTO key_wraps (id, kind_json, wrapped_nonce, wrapped_key, created_on)
             VALUES ('0123456789abcdef', ?1, zeroblob(24), zeroblob(48), 0)",
            [kind],
        )
        .unwrap();
    // The key wraps are part of the authenticated settings record (ADR
    // 0010), so the planted row is refused at open, and named nowhere.
    let out = env.run(&["secret", "list", "--vault", "dev"]);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("key wrap"), "{}", stderr(&out));
    assert!(!stderr(&out).contains("planted"), "{}", stderr(&out));

    // `vault destroy` reads the wraps without opening the vault, and shows
    // the planted account escaped.
    let out = env.run(&["vault", "destroy", "dev", "--yes"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_escaped(&stderr(&out));
}

#[test]
fn forged_audit_rows_are_shown_escaped() {
    let env = Env::new();
    env.create_vault("dev");
    // A failed unlock writes rows chained without the vault key, which a
    // tamperer can rewrite; a later unlock puts keyed rows after them.
    let out = env
        .cmd(&["secret", "list", "--vault", "dev"])
        .env("SOURCEORRERY_RECOVERY_KEY", WRONG_KEY)
        .output()
        .unwrap();
    assert!(!out.status.success());
    env.ok(&["secret", "list", "--vault", "dev"]);
    let forged = open_vault_file(env.home.path(), "dev")
        .execute(
            "UPDATE audit_events SET actor = ?1, secret_name = ?1, version = ?1, detail = ?1 \
             WHERE keyed = 0",
            [PLANTED],
        )
        .unwrap();
    assert!(forged > 0, "no unkeyed rows to forge");

    let listed = env.ok(&["audit", "--vault", "dev"]);
    assert_escaped(&listed);
    // Every field of the row is escaped, not just the last.
    let row = listed.lines().find(|l| l.contains("planted")).unwrap();
    assert!(row.contains("vault_open"), "{row}");
    assert_eq!(row.matches("planted\\u{1b}").count(), 4, "{row}");

    let json = env.ok(&["audit", "--vault", "dev", "-o", "json"]);
    assert!(!json.contains('\x1b'));
    let events: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert!(
        events
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["detail"] == PLANTED)
    );
}

#[test]
fn no_arguments_prints_the_banner_without_touching_a_vault() {
    let env = Env::new();
    // Piped stdout: plain style, no escape sequences, no vault or home needed.
    let out = env.run(&[]);
    assert!(out.status.success(), "{}", stderr(&out));
    let text = stdout(&out);
    assert!(text.contains("SourceOrrery"));
    assert!(text.contains("https://sourceorrery.ai"));
    assert!(text.contains("Quick start"));
    assert!(!text.contains('\x1b'));

    let out = env
        .cmd(&[])
        .env("SOURCEORRERY_BANNER", "unicode")
        .output()
        .unwrap();
    assert!(out.status.success());
    let text = stdout(&out);
    assert!(text.contains('\u{2588}'), "half-block art expected");
    assert!(text.contains("sourceorrery.ai"));
}

#[test]
fn run_does_not_pass_the_unlock_or_view_check_variables_to_the_child() {
    let env = Env::new();
    env.create_vault("development");
    env.set("development", "database-password", "pw");
    let init = env.run(&["init", "--all", "--project-name", "demo"]);
    assert!(init.status.success(), "{}", stderr(&init));

    // The child reports whether any unlock or view-check variable reached it.
    let probe: &[&str] = if cfg!(windows) {
        &[
            "run",
            "--",
            "cmd",
            "/C",
            "if defined SOURCEORRERY_RECOVERY_KEY (echo LEAK) else if defined \
             SOURCEORRERY_RECOVERY_KEY_FILE (echo LEAK) else if defined SOURCEORRERY_PASSWORD \
             (echo LEAK) else if defined SOURCEORRERY_PASSWORD_FILE (echo LEAK) else if defined \
             SOURCEORRERY_TOTP (echo LEAK) else (echo CLEAN)",
        ]
    } else {
        &[
            "run",
            "--",
            "sh",
            "-c",
            "if [ -n \"$SOURCEORRERY_RECOVERY_KEY$SOURCEORRERY_RECOVERY_KEY_FILE\
             $SOURCEORRERY_PASSWORD$SOURCEORRERY_PASSWORD_FILE$SOURCEORRERY_TOTP\" ]; then \
             echo LEAK; else echo CLEAN; fi",
        ]
    };
    let password = env.file("password.txt", PASSWORD);
    let out = env
        .cmd(probe)
        .env("SOURCEORRERY_RECOVERY_KEY", env.recovery_key("development"))
        .env("SOURCEORRERY_PASSWORD", PASSWORD)
        .env("SOURCEORRERY_PASSWORD_FILE", &password)
        .env("SOURCEORRERY_TOTP", "123456")
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(stdout(&out).trim(), "CLEAN");
}

/// The recovery key opens the vault from the environment or a file, however
/// it is typed: case, hyphens and spaces do not matter. Without one, and
/// without a terminal to ask at, the vault stays locked.
#[test]
fn the_recovery_key_opens_from_the_environment_or_a_file_however_it_is_typed() {
    let env = Env::new();
    env.create_vault("dev");
    env.set("dev", "api-key", CANARY);
    let key = env.recovery_key("dev");
    assert_eq!(key.len(), 29, "{key}");
    assert_eq!(key.matches('-').count(), 4, "{key}");

    let list = |extra: &[&str], key: Option<&str>| -> Output {
        let mut args = vec!["secret", "list", "--vault", "dev"];
        args.extend_from_slice(extra);
        let mut cmd = env.cmd(&args);
        cmd.env_remove("SOURCEORRERY_RECOVERY_KEY_FILE");
        if let Some(key) = key {
            cmd.env("SOURCEORRERY_RECOVERY_KEY", key);
        }
        cmd.output().unwrap()
    };
    for typed in [
        key.to_lowercase(),
        key.replace('-', ""),
        key.replace('-', " "),
    ] {
        let out = list(&[], Some(&typed));
        assert!(out.status.success(), "{typed}: {}", stderr(&out));
        assert!(stdout(&out).contains("api-key"));
    }
    let out = list(&[], Some(WRONG_KEY));
    assert!(!out.status.success());
    assert!(stderr(&out).contains("locked"), "{}", stderr(&out));
    assert!(!stdout(&out).contains("api-key"));

    let file = env.file("key.txt", &format!("{}\n", key.to_lowercase()));
    let out = list(&["--recovery-key-file", &file], None);
    assert!(out.status.success(), "{}", stderr(&out));

    let out = list(&[], None);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("locked"), "{}", stderr(&out));
}

/// Tags under SourceOrrery's own prefix record rotation and restore state;
/// a hand-set one would be taken for theirs.
#[test]
fn reserved_tag_keys_are_refused() {
    let env = Env::new();
    env.create_vault("dev");
    let out = env.run_with_stdin(
        &[
            "secret",
            "set",
            "api-key",
            "--vault",
            "dev",
            "--tag",
            "sourceorrery.rotation.state=validated",
        ],
        "v",
    );
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("SourceOrrery's own"),
        "{}",
        stderr(&out)
    );
    assert!(
        env.ok(&["secret", "list", "--vault", "dev"])
            .trim()
            .is_empty()
            || !env
                .ok(&["secret", "list", "--vault", "dev"])
                .contains("api-key")
    );
}

/// `vault export` writes a copy that opens with the recovery key only: the
/// user's alone, no value in clear, the view check left behind, and never
/// over a file. `vault import` registers it under its own name or `--name`,
/// never over a vault, opens it with the recovery key alone, and sets the
/// check again from `--password-file`.
#[test]
fn vault_export_and_import_move_a_vault_with_its_recovery_key() {
    let env = Env::new();
    let password = env.file("password.txt", PASSWORD);
    env.ok(&[
        "vault",
        "create",
        "dev",
        "--no-keyring",
        "--recovery-key-out",
        env.key_file("dev").to_str().unwrap(),
        "--password-file",
        &password,
    ]);
    env.set("dev", "api-key", CANARY);

    let copy = env.project.path().join("dev.export");
    let copy_arg = copy.to_str().unwrap();
    let exported: serde_json::Value =
        serde_json::from_str(&env.ok(&["vault", "export", "dev", "--out", copy_arg, "-o", "json"]))
            .unwrap();
    assert_eq!(exported["vault"], "dev");
    assert_eq!(exported["left_out"], serde_json::json!(["the password"]));
    let bytes = std::fs::read(&copy).unwrap();
    assert!(!bytes.windows(CANARY.len()).any(|w| w == CANARY.as_bytes()));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(&copy).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "the copy is the user's alone");
    }
    let again = env.run(&["vault", "export", "dev", "--out", copy_arg]);
    assert!(!again.status.success());
    assert!(
        stderr(&again).contains("never replaces"),
        "{}",
        stderr(&again)
    );
    assert_eq!(std::fs::read(&copy).unwrap(), bytes);

    // Its own name is taken in this home, and a wrong key imports nothing.
    let taken = env.run(&["vault", "import", copy_arg]);
    assert!(!taken.status.success());
    assert!(
        stderr(&taken).contains("already exists"),
        "{}",
        stderr(&taken)
    );
    let wrong = env
        .cmd(&["vault", "import", copy_arg, "--name", "moved"])
        .env_remove("SOURCEORRERY_RECOVERY_KEY_FILE")
        .env("SOURCEORRERY_RECOVERY_KEY", WRONG_KEY)
        .output()
        .unwrap();
    assert!(!wrong.status.success());
    assert!(stderr(&wrong).contains("locked"), "{}", stderr(&wrong));
    assert!(!env.ok(&["vault", "list"]).contains("moved"));

    // Under another name, with the copy's recovery key and a password.
    let imported: serde_json::Value = serde_json::from_str(&env.ok(&[
        "vault",
        "import",
        copy_arg,
        "--name",
        "moved",
        "--password-file",
        &password,
        "-o",
        "json",
    ]))
    .unwrap();
    assert_eq!(imported["vault"]["name"], "moved");
    assert_eq!(imported["renamed_from"], "dev");
    assert_eq!(imported["this_machine"], false, "no credential store here");
    assert_eq!(imported["view_check"]["password"], true);
    std::fs::copy(env.key_file("dev"), env.key_file("moved")).unwrap();
    let revealed = env.ok(&[
        "secret", "get", "api-key", "--vault", "moved", "--reveal", "--raw",
    ]);
    assert_eq!(revealed.trim(), CANARY);
    let audit = env.ok(&["audit", "--vault", "moved", "-o", "json"]);
    assert!(audit.contains("vault_export"), "{audit}");
    assert!(audit.contains("vault_import"), "{audit}");
    assert!(!audit.contains(CANARY));

    // Without --password-file the vault comes with no view check.
    let plain = env
        .cmd(&["vault", "import", copy_arg, "--name", "plain"])
        .env("SOURCEORRERY_RECOVERY_KEY_FILE", env.key_file("dev"))
        .output()
        .unwrap();
    assert!(plain.status.success(), "{}", stderr(&plain));
    assert!(
        stderr(&plain).contains("no view check"),
        "{}",
        stderr(&plain)
    );
    assert!(
        stderr(&plain).contains("sourceorrery vault create plain"),
        "{}",
        stderr(&plain)
    );
    assert_eq!(
        std::fs::read(&copy).unwrap(),
        bytes,
        "the copy is only read"
    );
}

#[test]
fn an_optional_secret_the_vault_lacks_does_not_block_run() {
    let env = Env::new();
    env.create_vault("development");
    env.set("development", "database-password", "pw");
    std::fs::write(
        env.project.path().join("sourceorrery.toml"),
        "[project]\nname = \"demo\"\nvault = \"development\"\n\n\
         [secrets.database-password]\n\n\
         [secrets.extra-key]\nrequired = false\n",
    )
    .unwrap();
    let out = env.run(&["check"]);
    assert!(out.status.success(), "{}", stderr(&out));

    let echo: &[&str] = if cfg!(windows) {
        &["run", "--", "cmd", "/C", "echo %DATABASE_PASSWORD%"]
    } else {
        &["run", "--", "sh", "-c", "echo \"$DATABASE_PASSWORD\""]
    };
    let out = env.run(echo);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(stdout(&out).trim(), "pw");

    // A required secret the vault lacks still refuses to start.
    std::fs::write(
        env.project.path().join("sourceorrery.toml"),
        "[project]\nname = \"demo\"\nvault = \"development\"\n\n\
         [secrets.extra-key]\nrequired = true\n",
    )
    .unwrap();
    let out = env.run(echo);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("not_found"), "{}", stderr(&out));
}

#[test]
fn manifest_errors_do_not_echo_rejected_values() {
    const CANARY: &str = "REJECTED_VALUE_CANARY_cli";
    let env = Env::new();
    std::fs::write(
        env.project.path().join("sourceorrery.toml"),
        format!("[project]\nname = \"demo\"\nvault = \"development\"\n\n[secrets.db]\nvalue = \"{CANARY}\"\n"),
    )
    .unwrap();
    for format in [&["check"][..], &["check", "-o", "json"][..]] {
        let out = env.run(format);
        assert!(!out.status.success());
        let text = stderr(&out) + &stdout(&out);
        assert!(
            !text.contains(CANARY),
            "diagnostic echoed the value: {text}"
        );
        assert!(
            text.contains("value"),
            "diagnostic should still name the key: {text}"
        );
    }
}

/// `run` reports the child's status whole: a Windows code above 255 (3010,
/// "reboot required") must not collapse to 1, and a Unix child killed by a
/// signal reports the shell's `128 + signal`.
#[test]
fn run_passes_the_child_exit_status_through_whole() {
    let env = Env::new();
    env.create_vault("development");
    env.set("development", "database-password", "pw");
    let init = env.run(&["init", "--all", "--project-name", "demo"]);
    assert!(init.status.success(), "{}", stderr(&init));

    let small: &[&str] = if cfg!(windows) {
        &["run", "--", "cmd", "/C", "exit 7"]
    } else {
        &["run", "--", "sh", "-c", "exit 7"]
    };
    let out = env.run(small);
    assert_eq!(out.status.code(), Some(7), "{}", stderr(&out));

    if cfg!(windows) {
        let out = env.run(&["run", "--", "cmd", "/C", "exit 3010"]);
        assert_eq!(out.status.code(), Some(3010), "{}", stderr(&out));
    } else {
        let out = env.run(&["run", "--", "sh", "-c", "exit 200"]);
        assert_eq!(out.status.code(), Some(200), "{}", stderr(&out));
        let out = env.run(&["run", "--", "sh", "-c", "kill -9 $$"]);
        assert_eq!(out.status.code(), Some(137), "{}", stderr(&out));
    }
}

#[test]
fn a_secret_a_connection_stores_is_read_at_its_provider() {
    let env = Env::new();
    env.create_vault("development");
    env.set("development", "database-password", CANARY);
    // A HashiCorp Vault connection where nothing listens, with a token
    // stored in it, so the environment's own does not matter.
    let connection = env.store_through(
        "development",
        &sourceorrery_core::ConnectionSettings::HashicorpVault {
            address: "http://127.0.0.1:1".to_owned(),
            mount: "secret".to_owned(),
            namespace: None,
        },
        "api-key",
    );
    std::fs::write(
        env.project.path().join("sourceorrery.toml"),
        "[project]\nname = \"demo\"\nvault = \"development\"\n\n\
         [secrets.database-password]\n\n[secrets.api-key]\n",
    )
    .unwrap();

    let out = env.run(&[
        "secret",
        "get",
        "api-key",
        "--vault",
        "development",
        "-o",
        "json",
    ]);
    assert!(!out.status.success());
    let err: serde_json::Value = serde_json::from_str(stderr(&out).trim()).unwrap();
    assert_eq!(err["error"]["code"], "provider_unavailable", "{err}");
    assert!(
        err["error"]["message"]
            .as_str()
            .unwrap()
            .contains("hashicorp-vault is unavailable"),
        "{err}"
    );
    let out = env.run(&["check"]);
    assert!(!out.status.success());
    assert!(
        stdout(&out).contains("provider_unavailable"),
        "{}",
        stdout(&out)
    );
    // The vault file's own secret is read as before.
    assert!(stdout(&out).contains("ok"), "{}", stdout(&out));

    // The vault's log has the attempts, and the provider's own trail is
    // pointed at, without touching the network.
    let out = env.run(&["audit", "--vault", "development"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(
        stdout(&out).contains(&format!("at connection {connection}")),
        "{}",
        stdout(&out)
    );
    assert!(stderr(&out).contains("audit devices"), "{}", stderr(&out));
    assert!(!stdout(&out).contains(CANARY) && !stderr(&out).contains(CANARY));
}

#[test]
fn vault_create_adds_a_connection_per_provider_and_never_shows_a_credential() {
    const AWS_SECRET: &str = "aws-secret-from-a-file";
    const AZURE_SECRET: &str = "azure-secret-from-a-file";
    let env = Env::new();
    let aws = env.file("aws.txt", AWS_SECRET);
    let azure = env.file("azure.txt", AZURE_SECRET);
    let key = env.key_file("linked");
    let out = env.run(&[
        "vault",
        "create",
        "linked",
        "--no-keyring",
        "--recovery-key-out",
        key.to_str().unwrap(),
        "--hashicorp-vault",
        "https://vault.example.com:8200",
        "--hashicorp-vault-mount",
        "kv",
        "--aws-secrets-manager",
        "eu-west-1",
        "--aws-secrets-manager-prefix",
        "app/",
        "--aws-access-key-id",
        "AKIAEXAMPLE",
        "--aws-secret-access-key-file",
        &aws,
        "--azure-key-vault",
        "https://myapp-kv.vault.azure.net",
        "--azure-tenant-id",
        "00000000-0000-0000-0000-000000000001",
        "--azure-client-id",
        "00000000-0000-0000-0000-000000000002",
        "--azure-client-secret-file",
        &azure,
        "-o",
        "json",
    ]);
    assert!(out.status.success(), "{}", stderr(&out));
    let created: serde_json::Value = serde_json::from_str(&stdout(&out)).unwrap();
    let connections = created["connections"].as_array().unwrap();
    assert_eq!(connections.len(), 3);

    let mut seen: Vec<(String, String)> = connections
        .iter()
        .map(|c| {
            (
                c["settings"]["provider"].as_str().unwrap().to_owned(),
                c["credentials"].as_str().unwrap().to_owned(),
            )
        })
        .collect();
    seen.sort();
    assert_eq!(
        seen,
        [
            ("aws-secrets-manager".to_owned(), "stored".to_owned()),
            ("azure-key-vault".to_owned(), "stored".to_owned()),
            ("hashicorp-vault".to_owned(), "ambient".to_owned()),
        ]
    );
    for shown in [stdout(&out), stderr(&out)] {
        for secret in [AWS_SECRET, AZURE_SECRET] {
            assert!(!shown.contains(secret), "a credential was shown: {shown}");
        }
    }
}

#[test]
fn vault_create_refuses_a_wrong_connection_before_creating_anything() {
    let env = Env::new();
    let key = env.key_file("nothing");
    let refused: [&[&str]; 3] = [
        // A credential sent in clear text off this machine.
        &["--hashicorp-vault", "http://vault.example.com"],
        // Half a stored access key.
        &[
            "--aws-secrets-manager",
            "eu-west-1",
            "--aws-access-key-id",
            "AKIA",
        ],
        // A provider flag without its provider.
        &["--azure-client-id", "client"],
    ];
    for flags in refused {
        let mut args = vec![
            "vault",
            "create",
            "nothing",
            "--no-keyring",
            "--recovery-key-out",
            key.to_str().unwrap(),
        ];
        args.extend_from_slice(flags);
        let out = env.run(&args);
        assert!(!out.status.success(), "{flags:?}");
        assert!(!key.exists(), "{flags:?}: a recovery key was written");
        let list = env.ok(&["vault", "list", "-o", "json"]);
        assert_eq!(list.trim(), "[]", "{flags:?}: {list}");
    }
}

/// `secret set --description` keeps one line in the vault's catalog; one
/// that breaks the rule is refused before the value is read, so nothing
/// is stored.
#[test]
fn secret_set_takes_a_description_for_the_catalog() {
    let env = Env::new();
    env.create_vault("dev");
    let set: serde_json::Value = serde_json::from_str(&stdout(&env.run_with_stdin(
        &[
            "secret",
            "set",
            "db-password",
            "--vault",
            "dev",
            "--description",
            "Database authentication",
            "-o",
            "json",
        ],
        "pw",
    )))
    .unwrap();
    assert_eq!(set["description"], "Database authentication");
    assert_eq!(
        env.open_vault("dev")
            .description_of("db-password")
            .unwrap()
            .as_deref(),
        Some("Database authentication")
    );

    let long = "d".repeat(sourceorrery_storage::MAX_DESCRIPTION_LEN + 1);
    let refused = env.run_with_stdin(
        &[
            "secret",
            "set",
            "api-key",
            "--vault",
            "dev",
            "--description",
            &long,
        ],
        "key",
    );
    assert!(!refused.status.success());
    assert!(stderr(&refused).contains("at most"), "{}", stderr(&refused));
    assert!(
        !env.ok(&["secret", "list", "--vault", "dev"])
            .contains("api-key")
    );
}

#[test]
fn secret_set_and_import_take_a_storage() {
    let env = Env::new();
    let key = env.key_file("development");
    let token = env.file("token.txt", "hvs.storage-test");
    // Nothing listens on port 1: the provider cannot be reached.
    env.ok(&[
        "vault",
        "create",
        "development",
        "--no-keyring",
        "--recovery-key-out",
        key.to_str().unwrap(),
        "--hashicorp-vault",
        "http://127.0.0.1:1",
        "--hashicorp-vault-token-file",
        &token,
    ]);
    let set = |args: &[&str], value: &str| {
        let mut all = vec!["secret", "set"];
        all.extend_from_slice(args);
        all.extend_from_slice(&["--vault", "development", "-o", "json"]);
        env.run_with_stdin(&all, value)
    };

    // The vault file is a storage like any other, and the default.
    let out = set(&["in-file", "--storage", "sourceorrery"], "v1");
    assert!(out.status.success(), "{}", stderr(&out));
    // An unknown storage is refused, naming what the vault has.
    let out = set(&["x", "--storage", "aws-secrets-manager"], "v");
    assert!(!out.status.success());
    let text = stderr(&out);
    assert!(
        text.contains("has no storage 'aws-secrets-manager'")
            && text.contains("sourceorrery, hashicorp-vault"),
        "{text}"
    );
    // At the provider: unreachable, so nothing is catalogued.
    let out = set(&["at-vault", "--storage", "hashicorp-vault"], "v");
    assert!(!out.status.success());
    let err: serde_json::Value = serde_json::from_str(stderr(&out).trim()).unwrap();
    assert_eq!(err["error"]["code"], "provider_unavailable", "{err}");
    let out = env.run(&[
        "secret",
        "get",
        "at-vault",
        "--vault",
        "development",
        "-o",
        "json",
    ]);
    let err: serde_json::Value = serde_json::from_str(stderr(&out).trim()).unwrap();
    assert_eq!(err["error"]["code"], "not_found", "{err}");
    // A new version of a secret goes where the secret is.
    let out = set(&["in-file", "--storage", "hashicorp-vault"], "v2");
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("kept in the vault file"),
        "{}",
        stderr(&out)
    );

    // `import --storage` sends each new secret there.
    let dotenv = env.file(".env", "API_TOKEN=abc\n");
    let out = env.run(&[
        "import",
        &dotenv,
        "--vault",
        "development",
        "--no-manifest",
        "--storage",
        "hashicorp-vault",
        "-o",
        "json",
    ]);
    assert!(!out.status.success());
    assert!(
        stdout(&out).contains("provider_unavailable"),
        "{}",
        stdout(&out)
    );
}

#[test]
fn a_manifest_that_names_remote_vaults_is_refused_with_what_replaced_them() {
    let env = Env::new();
    env.create_vault("development");
    // Even with a credential in it: a parse error that never echoes it.
    std::fs::write(
        env.project.path().join("sourceorrery.toml"),
        "[project]\nname = \"demo\"\nvault = \"development\"\n\n\
         [vaults.prod]\nprovider = \"hashicorp-vault\"\n\
         address = \"http://127.0.0.1:1\"\nmount = \"secret\"\n\
         token = \"hvs.SMUGGLED-TOKEN-CANARY\"\n",
    )
    .unwrap();
    let out = env.run(&["check"]);
    assert!(!out.status.success());
    let text = stderr(&out) + &stdout(&out);
    assert!(
        text.contains("[vaults.*] tables are no longer read"),
        "{text}"
    );
    assert!(!text.contains("SMUGGLED"), "{text}");
}

/// Hook scripts for `secret rotate`: the issuer mints `next-<current>`, the
/// validator compares the candidate with `EXPECTED` (or fails on
/// `FAIL_VALIDATE`), and the retire hook records which version it was told
/// to revoke. Written per platform; the manifest names them as argv.
fn write_rotation_hooks(project: &Path) -> String {
    let dir = project.join("hooks");
    std::fs::create_dir_all(&dir).unwrap();
    if cfg!(windows) {
        std::fs::write(
            dir.join("issue.cmd"),
            "@echo off\r\necho next-%DATABASE_PASSWORD%\r\n",
        )
        .unwrap();
        std::fs::write(
            dir.join("validate.cmd"),
            "@echo off\r\nif defined FAIL_VALIDATE exit /b 3\r\n\
             if not \"%DATABASE_PASSWORD%\"==\"%EXPECTED%\" exit /b 4\r\nexit /b 0\r\n",
        )
        .unwrap();
        std::fs::write(
            dir.join("retire.cmd"),
            "@echo off\r\nif not defined SOURCEORRERY_RETIRED_VERSION exit /b 5\r\n\
             echo %SOURCEORRERY_RETIRED_VERSION%> retired.txt\r\n",
        )
        .unwrap();
        "[rotation.database-password]\n\
         issue = ['cmd', '/C', 'hooks\\issue.cmd']\n\
         validate = ['cmd', '/C', 'hooks\\validate.cmd']\n\
         retire = ['cmd', '/C', 'hooks\\retire.cmd']\n\
         retire_after = \"7d\"\n"
            .to_owned()
    } else {
        std::fs::write(
            dir.join("issue.sh"),
            "printf 'next-%s\\n' \"$DATABASE_PASSWORD\"\n",
        )
        .unwrap();
        std::fs::write(
            dir.join("validate.sh"),
            "[ -n \"$FAIL_VALIDATE\" ] && exit 3\n\
             [ \"$DATABASE_PASSWORD\" = \"$EXPECTED\" ] || exit 4\nexit 0\n",
        )
        .unwrap();
        std::fs::write(
            dir.join("retire.sh"),
            "[ -n \"$SOURCEORRERY_RETIRED_VERSION\" ] || exit 5\n\
             printf '%s' \"$SOURCEORRERY_RETIRED_VERSION\" > retired.txt\n",
        )
        .unwrap();
        "[rotation.database-password]\n\
         issue = ['sh', 'hooks/issue.sh']\n\
         validate = ['sh', 'hooks/validate.sh']\n\
         retire = ['sh', 'hooks/retire.sh']\n\
         retire_after = \"7d\"\n"
            .to_owned()
    }
}

/// A project whose manifest declares the rotation hooks for
/// `database-password`, holding `first-value`.
fn rotation_project() -> Env {
    let env = Env::new();
    env.create_vault("development");
    env.set("development", "database-password", "first-value");
    env.ok(&["init", "--all", "--project-name", "demo"]);
    let manifest_path = env.project.path().join("sourceorrery.toml");
    let mut manifest = std::fs::read_to_string(&manifest_path).unwrap();
    manifest.push('\n');
    manifest.push_str(&write_rotation_hooks(env.project.path()));
    std::fs::write(&manifest_path, manifest).unwrap();
    env
}

/// The versions of `database-password` as JSON, asserting how many.
fn rotation_versions(env: &Env, expect: usize) -> Vec<serde_json::Value> {
    let text = env.ok(&[
        "secret",
        "versions",
        "database-password",
        "--vault",
        "development",
        "-o",
        "json",
    ]);
    let list: Vec<serde_json::Value> = serde_json::from_str(&text).unwrap();
    assert_eq!(list.len(), expect, "{text}");
    list
}

fn rotation_tag(v: &serde_json::Value, key: &str) -> String {
    v["tags"][key].as_str().unwrap_or("").to_owned()
}

#[test]
fn rotation_runs_the_hooks_and_never_prints_a_value() {
    let env = rotation_project();

    // Issue → validate → activate, with a grace period before retirement.
    let out = env
        .cmd(&["secret", "rotate", "database-password"])
        .env("EXPECTED", "next-first-value")
        .output()
        .unwrap();
    let text = format!("{}{}", stdout(&out), stderr(&out));
    assert!(out.status.success(), "{text}");
    assert!(text.contains("Activated version"), "{text}");
    assert!(text.contains("retired after"), "{text}");
    assert!(!text.contains("first-value"), "a value leaked: {text}");
    let revealed = env.ok(&[
        "secret",
        "get",
        "database-password",
        "--vault",
        "development",
        "--reveal",
    ]);
    assert_eq!(revealed.trim(), "next-first-value");
    let list = rotation_versions(&env, 2);
    let (new, old) = (&list[0], &list[1]);
    assert_eq!(new["enabled"], true);
    assert_eq!(rotation_tag(new, "sourceorrery.rotation.state"), "active");
    assert_eq!(
        rotation_tag(new, "sourceorrery.rotation.previous"),
        old["version"].as_str().unwrap()
    );
    assert_ne!(rotation_tag(new, "sourceorrery.rotation.retire-on"), "");
    assert_eq!(old["enabled"], false);
    assert_eq!(
        rotation_tag(old, "sourceorrery.rotation.state"),
        "superseded"
    );
    let old_version = old["version"].as_str().unwrap().to_owned();

    // Retirement waits for the grace period unless forced; the hook learns
    // which version it is revoking.
    let out = env.run(&[
        "secret",
        "rotate",
        "database-password",
        "--step",
        "retire",
        "-o",
        "json",
    ]);
    assert!(!out.status.success());
    let text = format!("{}{}", stdout(&out), stderr(&out));
    assert!(
        text.contains("\"rotation\"") && text.contains("grace"),
        "{text}"
    );
    assert!(!env.project.path().join("retired.txt").exists());
    let out = env.run(&[
        "secret",
        "rotate",
        "database-password",
        "--step",
        "retire",
        "--now",
    ]);
    assert!(out.status.success(), "{}", stderr(&out));
    let retired = std::fs::read_to_string(env.project.path().join("retired.txt")).unwrap();
    assert_eq!(retired.trim(), old_version);
    let list = rotation_versions(&env, 2);
    assert_eq!(
        rotation_tag(&list[0], "sourceorrery.rotation.state"),
        "complete"
    );
    assert_eq!(
        rotation_tag(&list[1], "sourceorrery.rotation.state"),
        "retired"
    );
}

#[test]
fn a_failing_validator_leaves_the_current_version_in_place() {
    let env = rotation_project();
    // A failing validator leaves the candidate disabled and the current
    // version current; nothing printed names either value.
    let out = env
        .cmd(&["secret", "rotate", "database-password"])
        .env("FAIL_VALIDATE", "1")
        .output()
        .unwrap();
    let text = format!("{}{}", stdout(&out), stderr(&out));
    assert!(!out.status.success(), "{text}");
    assert!(
        text.contains("validate command exited with status 3"),
        "{text}"
    );
    assert!(text.contains("stays current"), "{text}");
    assert!(!text.contains("first-value"), "a value leaked: {text}");
    let revealed = env.ok(&[
        "secret",
        "get",
        "database-password",
        "--vault",
        "development",
        "--reveal",
    ]);
    assert_eq!(revealed.trim(), "first-value");
    let list = rotation_versions(&env, 2);
    assert_eq!(list[0]["enabled"], false);
    assert_eq!(
        rotation_tag(&list[0], "sourceorrery.rotation.state"),
        "failed"
    );

    // Status, as JSON.
    let text = env.ok(&[
        "secret",
        "rotate",
        "database-password",
        "--step",
        "status",
        "-o",
        "json",
    ]);
    let status: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert!(status["current"].is_null(), "nothing was activated: {text}");
    assert!(
        status["candidate"].is_null(),
        "a failed candidate is not waiting"
    );
    assert_eq!(status["grace"], "7d");
    assert_eq!(status["versions"][0]["state"], "failed");
    assert!(!text.contains("first-value"));
}

#[test]
fn rotation_without_hooks_reads_stdin_and_activates_on_demand() {
    let env = Env::new();
    env.create_vault("development");
    env.set("development", "api-key", "k1");
    env.ok(&["init", "--all", "--project-name", "demo"]);

    // Without hooks the value comes from stdin, and without a grace period
    // the previous version is retired in the same run.
    let out = env.run_with_stdin(&["secret", "rotate", "api-key", "-o", "json"], "k2\n");
    assert!(out.status.success(), "{}", stderr(&out));
    let report: serde_json::Value = serde_json::from_str(&stdout(&out)).unwrap();
    assert_eq!(report["activated"], true);
    assert_eq!(report["retired"], true);
    assert!(report["retire_on"].is_null());
    let revealed = env.ok(&[
        "secret",
        "get",
        "api-key",
        "--vault",
        "development",
        "--reveal",
    ]);
    assert_eq!(revealed.trim(), "k2");

    // --no-activate leaves a validated candidate that --step activate enables.
    let out = env.run_with_stdin(&["secret", "rotate", "api-key", "--no-activate"], "k3\n");
    assert!(out.status.success(), "{}", stderr(&out));
    let revealed = env.ok(&[
        "secret",
        "get",
        "api-key",
        "--vault",
        "development",
        "--reveal",
    ]);
    assert_eq!(revealed.trim(), "k2", "a validated candidate is not served");
    let out = env.run_with_stdin(&["secret", "rotate", "api-key"], "k4\n");
    assert!(
        !out.status.success(),
        "a waiting candidate blocks a new rotation"
    );
    assert!(
        stderr(&out).contains("waiting for activation"),
        "{}",
        stderr(&out)
    );
    env.ok(&["secret", "rotate", "api-key", "--step", "activate"]);
    let revealed = env.ok(&[
        "secret",
        "get",
        "api-key",
        "--vault",
        "development",
        "--reveal",
    ]);
    assert_eq!(revealed.trim(), "k3");
}

/// What a fake collector saw per request: the path, the `X-Token` header
/// and the body.
type CollectedRequests = Vec<(String, Option<String>, serde_json::Value)>;

/// Accept OTLP/HTTP posts on a local port, answering `status`, and record
/// each request's path, one header and the body it carried.
fn otlp_collector(
    status: u16,
    requests: usize,
) -> (String, std::thread::JoinHandle<CollectedRequests>) {
    use std::io::{BufRead, BufReader, Read};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = format!("http://{}/v1/logs", listener.local_addr().unwrap());
    let handle = std::thread::spawn(move || {
        let mut seen = Vec::new();
        for _ in 0..requests {
            let (stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream);
            let mut request_line = String::new();
            reader.read_line(&mut request_line).unwrap();
            let path = request_line.split_whitespace().nth(1).unwrap().to_owned();
            let mut length = 0;
            let mut token = None;
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                let line = line.trim_end();
                if line.is_empty() {
                    break;
                }
                if let Some((name, value)) = line.split_once(':') {
                    match name.to_ascii_lowercase().as_str() {
                        "content-length" => length = value.trim().parse().unwrap(),
                        "x-token" => token = Some(value.trim().to_owned()),
                        _ => {}
                    }
                }
            }
            let mut body = vec![0; length];
            reader.read_exact(&mut body).unwrap();
            let records: serde_json::Value = serde_json::from_slice(&body).unwrap();
            let reply = format!(
                "HTTP/1.1 {status} {}\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{{}}",
                if status == 200 { "OK" } else { "Error" }
            );
            reader.get_mut().write_all(reply.as_bytes()).unwrap();
            seen.push((path, token, records));
        }
        seen
    });
    (endpoint, handle)
}

#[test]
fn audit_export_writes_json_lines_with_a_verification_trailer() {
    let env = Env::new();
    env.create_vault("dev");
    env.set("dev", "k", CANARY);
    env.ok(&["secret", "get", "k", "--vault", "dev", "--reveal"]);

    let text = env.ok(&["audit", "export", "--vault", "dev"]);
    assert!(!text.contains(CANARY), "a value leaked: {text}");
    let lines: Vec<serde_json::Value> = text
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    let (trailer, events) = lines.split_last().unwrap();
    assert!(events.len() >= 4, "{text}");
    let ids: Vec<u64> = events.iter().map(|e| e["id"].as_u64().unwrap()).collect();
    assert!(ids.windows(2).all(|w| w[0] < w[1]), "oldest first: {ids:?}");
    assert!(events.iter().all(|e| e["vault"] == "dev"));
    assert!(
        events
            .iter()
            .any(|e| e["operation"] == "secret_get" && e["outcome"] == "success")
    );
    assert_eq!(trailer["vault"], "dev");
    assert_eq!(trailer["events"], events.len());
    assert_eq!(trailer["last_id"], *ids.last().unwrap());
    assert_eq!(trailer["intact"], true);
    assert_eq!(trailer["verification"]["truncations"], 0);

    // --since cuts the backlog; the trailer still comes.
    let text = env.ok(&[
        "audit",
        "export",
        "--vault",
        "dev",
        "--since",
        "2099-01-01T00:00:00Z",
    ]);
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 1, "{text}");
    let trailer: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
    assert_eq!(trailer["events"], 0);
    assert!(trailer["last_id"].is_null());

    // A truncated log exports with a trailer that says so.
    truncate_audit_log(env.home.path(), "dev", 1);
    let out = env.run(&["secret", "get", "k", "--vault", "dev"]);
    assert!(
        !out.status.success(),
        "the truncation is detected and blocks"
    );
    let text = env.ok(&["audit", "export", "--vault", "dev"]);
    let trailer: serde_json::Value = serde_json::from_str(text.lines().last().unwrap()).unwrap();
    assert_eq!(trailer["intact"], false);
    assert_eq!(trailer["verification"]["truncations"], 1);
    assert_eq!(trailer["verification"]["unacknowledged"], 1);
}

#[test]
fn audit_export_follow_streams_new_events() {
    use std::io::{BufRead, BufReader};
    let env = Env::new();
    env.create_vault("dev");
    env.set("dev", "k", "v1");

    let mut child = env
        .cmd(&[
            "audit",
            "export",
            "--vault",
            "dev",
            "--follow",
            "--interval",
            "1",
        ])
        .spawn()
        .unwrap();
    drop(child.stdin.take());
    let stdout = child.stdout.take().unwrap();
    let (tx, rx) = std::sync::mpsc::channel::<String>();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            let Ok(line) = line else { break };
            if tx.send(line).is_err() {
                break;
            }
        }
    });
    let wait = std::time::Duration::from_secs(30);
    // The backlog ends with the trailer.
    loop {
        let line = rx.recv_timeout(wait).expect("the backlog and its trailer");
        if line.contains("\"verification\"") {
            break;
        }
    }
    // A new event appears without restarting the export.
    env.set("dev", "k", "v2");
    let line = loop {
        let line = rx.recv_timeout(wait).expect("the new event");
        if line.contains("\"secret_set\"") {
            break line;
        }
    };
    let event: serde_json::Value = serde_json::from_str(&line).unwrap();
    assert_eq!(event["secret_name"], "k");
    assert!(!line.contains("v2"));
    child.kill().unwrap();
    child.wait().unwrap();
}

#[test]
fn audit_export_posts_otlp_log_records() {
    let env = Env::new();
    env.create_vault("dev");
    env.set("dev", "k", CANARY);

    // Every event plus the verification record, in batches of two, with the
    // header the collector asked for. The vault has create, open, set and
    // the export's own open: four events, so two batches of two carry the
    // events and a third the verification.
    let (endpoint, collector) = otlp_collector(200, 3);
    let out = env
        .cmd(&[
            "audit",
            "export",
            "--vault",
            "dev",
            "--format",
            "otlp",
            "--endpoint",
            &endpoint,
            "--header",
            "X-Token=secret-token",
            "--batch",
            "2",
        ])
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", stderr(&out));
    let requests = collector.join().unwrap();
    assert_eq!(requests.len(), 3);
    let mut records = Vec::new();
    for (path, token, body) in &requests {
        assert_eq!(path, "/v1/logs");
        assert_eq!(token.as_deref(), Some("secret-token"));
        let resource = &body["resourceLogs"][0];
        assert!(
            resource["resource"]["attributes"]
                .as_array()
                .unwrap()
                .iter()
                .any(|a| a["key"] == "service.name" && a["value"]["stringValue"] == "sourceorrery")
        );
        records.extend(
            resource["scopeLogs"][0]["logRecords"]
                .as_array()
                .unwrap()
                .iter()
                .cloned(),
        );
    }
    assert_eq!(records.len(), 5, "{records:?}");
    assert!(!serde_json::to_string(&records).unwrap().contains(CANARY));
    let last = records.last().unwrap();
    assert_eq!(
        last["body"]["stringValue"],
        "audit chain verification: intact"
    );
    assert_eq!(last["severityText"], "INFO");
    let set = records
        .iter()
        .find(|r| {
            r["body"]["stringValue"]
                .as_str()
                .unwrap()
                .starts_with("secret_set success")
        })
        .expect("the set event");
    assert!(set["timeUnixNano"].as_str().unwrap().len() > 10);
    assert!(
        set["attributes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|a| a["key"] == "sourceorrery.secret" && a["value"]["stringValue"] == "k")
    );

    // A collector that refuses fails the export, with the status in the error.
    let (endpoint, collector) = otlp_collector(503, 1);
    let out = env.run(&[
        "audit",
        "export",
        "--vault",
        "dev",
        "--format",
        "otlp",
        "--endpoint",
        &endpoint,
    ]);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("503"), "{}", stderr(&out));
    collector.join().unwrap();

    // No endpoint anywhere is an error.
    let out = env
        .cmd(&["audit", "export", "--vault", "dev", "--format", "otlp"])
        .env_remove("OTEL_EXPORTER_OTLP_ENDPOINT")
        .env_remove("OTEL_EXPORTER_OTLP_LOGS_ENDPOINT")
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(stderr(&out).contains("--endpoint"), "{}", stderr(&out));
}

#[test]
fn audit_points_at_the_trail_of_each_provider_that_stores_a_secret() {
    let env = Env::new();
    env.create_vault("dev");
    env.store_through(
        "dev",
        &sourceorrery_core::ConnectionSettings::AwsSecretsManager {
            region: "eu-west-1".to_owned(),
            prefix: Some("myapp/".to_owned()),
            endpoint_url: None,
        },
        "aws-held",
    );
    env.store_through(
        "dev",
        &sourceorrery_core::ConnectionSettings::AzureKeyVault {
            vault_url: "https://myapp-kv.vault.azure.net".to_owned(),
        },
        "azure-held",
    );
    let out = env.run(&["audit", "--vault", "dev"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let notes = stderr(&out);
    assert!(notes.contains("CloudTrail"), "{notes}");
    assert!(notes.contains("myapp/"), "{notes}");
    assert!(notes.contains("Azure Monitor"), "{notes}");
    // Diagnostic logs name the vault resource in capitals.
    assert!(notes.contains("Resource == 'MYAPP-KV'"), "{notes}");
    assert!(notes.contains("MICROSOFT.KEYVAULT"), "{notes}");
    assert!(
        notes.contains("/providers/azure-key-vault/#audit-trail"),
        "{notes}"
    );
    // The JSON form is the vault's own log, unchanged.
    let events: serde_json::Value =
        serde_json::from_str(&env.ok(&["audit", "--vault", "dev", "-o", "json"])).unwrap();
    assert!(events.is_array());
}

#[test]
fn a_weak_password_from_a_file_is_warned_about_not_refused() {
    let env = Env::new();
    let create = |name: &str, password: &str| {
        env.run(&[
            "vault",
            "create",
            name,
            "--no-keyring",
            "--recovery-key-out",
            env.key_file(name).to_str().unwrap(),
            "--password-file",
            password,
        ])
    };
    let weak = env.file("weak.txt", "dev-only\n");
    let out = create("weak", &weak);
    assert!(out.status.success(), "{}", stderr(&out));
    let err = stderr(&out);
    assert!(
        err.contains("rates fair") || err.contains("rates weak"),
        "{err}"
    );
    assert!(err.contains("the password file"), "{err}");
    assert!(
        !err.contains("dev-only"),
        "the password itself is never printed: {err}"
    );
    // A strong one passes silently.
    let strong = env.file("strong.txt", PASSWORD);
    let out = create("strong", &strong);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(!stderr(&out).contains("rates"), "{}", stderr(&out));
}

// ---------------------------------------------------------------------------
// Part 3: the recovery key and the view check
// ---------------------------------------------------------------------------

#[test]
fn the_recovery_key_is_shown_once_and_never_written_over_a_file() {
    let env = Env::new();
    // Printed on stdout when no file is named, with a note on stderr.
    let out = env.run(&["vault", "create", "shown", "--no-keyring"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let key = stdout(&out).trim().to_owned();
    assert_eq!(key.len(), 29, "{key}");
    assert_eq!(key.matches('-').count(), 4, "{key}");
    assert!(stderr(&out).contains("shown once"), "{}", stderr(&out));
    // In JSON it is a field.
    let json = env.ok(&[
        "vault",
        "create",
        "json-vault",
        "--no-keyring",
        "-o",
        "json",
    ]);
    let json: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(json["recovery_key"].as_str().unwrap().len(), 29);
    assert_eq!(json["this_machine"], false);
    // With no credential store the vault says how it opens.
    let out = env.run(&[
        "vault",
        "create",
        "no-store",
        "--recovery-key-out",
        env.key_file("no-store").to_str().unwrap(),
    ]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("recovery key only"),
        "{}",
        stderr(&out)
    );
    // A recovery-key file is never written over, and nothing is created.
    let existing = env.file("existing.key", "keep");
    let out = env.run(&["vault", "create", "other", "--recovery-key-out", &existing]);
    assert!(!out.status.success());
    assert_eq!(std::fs::read_to_string(&existing).unwrap(), "keep");
    assert!(!env.ok(&["vault", "list"]).contains("other"));
}

/// The guard events whose detail is exactly `detail`.
fn guard_events(env: &Env, vault: &str, detail: &str) -> usize {
    let audit = env.ok(&[
        "audit",
        "--vault",
        vault,
        "--operation",
        "guard",
        "--limit",
        "1000",
        "-o",
        "json",
    ]);
    let events: serde_json::Value = serde_json::from_str(&audit).unwrap();
    events
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["detail"] == detail)
        .count()
}

#[test]
fn the_view_check_is_asked_for_by_viewing_commands_only() {
    const OPENED: &str = "view check passed: opened with the recovery key";
    let env = Env::new();
    let password = env.file("password.txt", &format!("{PASSWORD}\n"));
    env.ok(&[
        "vault",
        "create",
        "development",
        "--no-keyring",
        "--recovery-key-out",
        env.key_file("development").to_str().unwrap(),
        "--password-file",
        &password,
    ]);
    env.set("development", "database-password", CANARY);
    let init = env.run(&["init", "--all", "--project-name", "demo"]);
    assert!(init.status.success(), "{}", stderr(&init));
    let vault = ["--vault", "development"];

    // Every viewing command asks; this vault opens with its recovery key,
    // which passes the check by itself, and the vault records that.
    let before = guard_events(&env, "development", OPENED);
    for args in [
        vec!["secret", "list"],
        vec!["secret", "get", "database-password"],
        vec!["secret", "get", "database-password", "--reveal"],
        vec!["secret", "versions", "database-password"],
        vec!["audit"],
    ] {
        let mut args = args.clone();
        args.extend_from_slice(&vault);
        env.ok(&args);
    }
    // Five commands, and the listing that counts them.
    assert_eq!(guard_events(&env, "development", OPENED), before + 5 + 1);

    // Running the application, checking the manifest and writing a secret
    // ask for nothing.
    let before = guard_events(&env, "development", OPENED);
    let echo: &[&str] = if cfg!(windows) {
        &["run", "--", "cmd", "/C", "echo ran"]
    } else {
        &["run", "--", "sh", "-c", "echo ran"]
    };
    assert!(env.ok(echo).contains("ran"));
    env.ok(&["check"]);
    env.set("development", "database-password", "next");
    assert_eq!(guard_events(&env, "development", OPENED), before + 1);

    // Nothing of the password is in the log.
    let audit = env.ok(&["audit", vault[0], vault[1], "-o", "json"]);
    assert!(audit.contains("password set"), "{audit}");
    assert!(!audit.contains(PASSWORD));
}

#[test]
fn setup_without_a_terminal_prints_the_create_command_and_creates_nothing() {
    let env = Env::new();
    let out = env.run(&["setup"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(stdout(&out), "");
    let guide = stderr(&out);
    for text in [
        "sourceorrery vault create development --recovery-key-out development.recovery-key",
        "--password-file FILE",
        "--hashicorp-vault ADDRESS",
        "--aws-secrets-manager REGION",
        "--azure-key-vault URL",
        "sourceorrery init --vault development",
        "sourceorrery run -- <your command>",
    ] {
        assert!(guide.contains(text), "{text}: {guide}");
    }
    assert_eq!(env.ok(&["vault", "list", "-o", "json"]).trim(), "[]");
    assert!(!env.project.path().join("sourceorrery.toml").exists());

    // --guide asks for the same where a terminal would show the screens.
    let json = env.ok(&["setup", "--guide", "--vault", "staging", "-o", "json"]);
    let json: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(json["vault"], "staging");
    assert_eq!(
        json["command"],
        "sourceorrery vault create staging --recovery-key-out staging.recovery-key"
    );
    assert_eq!(json["options"].as_array().unwrap().len(), 4);
    assert_eq!(
        json["then"][0],
        "sourceorrery secret set NAME --vault staging"
    );
}

/// The non-interactive create `setup --guide` prints: the password from a
/// file and a connection, made with the vault in one transaction; a file
/// that cannot be read creates nothing.
#[test]
fn vault_create_sets_the_password_from_a_file_with_the_vault() {
    let env = Env::new();
    let password = env.file("password.txt", PASSWORD);
    let key = env.key_file("guarded");
    let created: serde_json::Value = serde_json::from_str(&env.ok(&[
        "vault",
        "create",
        "guarded",
        "--no-keyring",
        "--recovery-key-out",
        key.to_str().unwrap(),
        "--password-file",
        &password,
        "--hashicorp-vault",
        "https://vault.example.com:8200",
        "-o",
        "json",
    ]))
    .unwrap();
    assert_eq!(created["view_check"]["password"], true);
    assert_eq!(created["view_check"]["authenticator"], false);
    assert_eq!(created["connections"].as_array().unwrap().len(), 1);
    assert_eq!(created["keys"][0]["kind"], "recovery");
    let audit = env.ok(&["audit", "--vault", "guarded", "-o", "json"]);
    for detail in ["password set", "hashicorp-vault"] {
        assert!(audit.contains(detail), "{detail}: {audit}");
    }
    assert!(!audit.contains(PASSWORD));

    let text = env.run(&[
        "vault",
        "create",
        "plain",
        "--no-keyring",
        "--recovery-key-out",
        env.key_file("plain").to_str().unwrap(),
        "--password-file",
        &password,
        "--hashicorp-vault",
        "https://vault.example.com:8200",
        "--hashicorp-vault-mount",
        "kv",
    ]);
    assert!(text.status.success(), "{}", stderr(&text));
    for line in [
        "view check: password",
        "hashicorp-vault https://vault.example.com:8200 kv (ambient credentials)",
    ] {
        assert!(stderr(&text).contains(line), "{line}: {}", stderr(&text));
    }

    let empty = env.file("empty.txt", "");
    let refused_key = env.key_file("nothing");
    let out = env.run(&[
        "vault",
        "create",
        "nothing",
        "--no-keyring",
        "--recovery-key-out",
        refused_key.to_str().unwrap(),
        "--password-file",
        &empty,
    ]);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("is empty"), "{}", stderr(&out));
    assert!(!refused_key.exists());
    assert!(!env.ok(&["vault", "list"]).contains("nothing"));

    // Without a terminal, a vault to create needs its name.
    let out = env.run(&["vault", "create"]);
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("name the vault to create"),
        "{}",
        stderr(&out)
    );
}
