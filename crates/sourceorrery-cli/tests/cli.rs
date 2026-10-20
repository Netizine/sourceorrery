//! End-to-end tests of the `sourceorrery` binary against a temporary home.

use std::io::Write;
use std::path::Path;
use std::process::{Command, Output, Stdio};

const PASSPHRASE: &str = "cli-test-passphrase";
const CANARY: &str = "cli-canary-9b1d-value";

struct Env {
    home: tempfile::TempDir,
    project: tempfile::TempDir,
}

impl Env {
    fn new() -> Self {
        Self {
            home: tempfile::tempdir().unwrap(),
            project: tempfile::tempdir().unwrap(),
        }
    }

    fn cmd(&self, args: &[&str]) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_sourceorrery"));
        cmd.args(args)
            .current_dir(self.project.path())
            .env("SOURCEORRERY_HOME", self.home.path())
            .env("SOURCEORRERY_PASSPHRASE", PASSPHRASE)
            .env_remove("SOURCEORRERY_VAULT")
            .env("NO_COLOR", "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        cmd
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

    fn create_vault(&self, name: &str) {
        self.ok(&["vault", "create", name, "--protector", "passphrase"]);
    }

    fn set(&self, vault: &str, name: &str, value: &str) {
        let out = self.run_with_stdin(&["secret", "set", name, "--vault", vault], value);
        assert!(
            out.status.success(),
            "set failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

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
fn wrong_passphrase_is_locked() {
    let env = Env::new();
    env.create_vault("dev");
    let out = env
        .cmd(&["secret", "list", "--vault", "dev"])
        .env("SOURCEORRERY_PASSPHRASE", "wrong")
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

    let init = env.run(&["init", "--project-name", "demo"]);
    assert!(init.status.success(), "{}", stderr(&init));
    let manifest_path = env.project.path().join("sourceorrery.toml");
    let manifest = std::fs::read_to_string(&manifest_path).unwrap();
    assert!(manifest.contains("database-password"));
    assert!(!manifest.contains("value ="));

    // Vault comes from the manifest now: no --vault flag.
    let out = env.run(&["check"]);
    assert!(
        !out.status.success(),
        "check must fail while the secret is missing"
    );
    assert!(stdout(&out).contains("not_found"));

    env.set("development", "database-password", CANARY);
    let out = env.run(&["check"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(stdout(&out).contains("ok"));

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

#[test]
fn completions_generate() {
    let env = Env::new();
    let out = env.ok(&["completions", "bash"]);
    assert!(out.contains("sourceorrery"));
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
