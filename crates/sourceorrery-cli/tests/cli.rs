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
    let out = env.run(&["vault", "info", "--vault", "dev"]);
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
fn tampered_protector_labels_are_shown_escaped() {
    let env = Env::new();
    env.create_vault("dev");
    // A label is not part of the key wrapping: the vault still unlocks.
    open_vault_file(env.home.path(), "dev")
        .execute("UPDATE key_protectors SET label = ?1", [PLANTED])
        .unwrap();

    assert_escaped(&env.ok(&["vault", "info", "--vault", "dev"]));
    assert_escaped(&env.ok(&["vault", "protector", "list", "--vault", "dev"]));

    // JSON is left alone: serde escapes the controls, the value round-trips.
    let json = env.ok(&["vault", "protector", "list", "--vault", "dev", "-o", "json"]);
    assert!(!json.contains('\x1b'));
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed[0]["label"], PLANTED);

    // Before unlock: a protector the CLI refuses to try is named, by its
    // unverified label, in the error.
    open_vault_file(env.home.path(), "dev")
        .execute(
            "UPDATE key_protectors SET kind_json = json_set(kind_json, '$.params.iterations', 1000)",
            [],
        )
        .unwrap();
    let out = env.run(&["vault", "info", "--vault", "dev"]);
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("exceed the supported limits"),
        "{}",
        stderr(&out)
    );
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
        .env("SOURCEORRERY_PASSPHRASE", "wrong")
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
fn run_does_not_pass_the_unlock_passphrase_to_the_child() {
    let env = Env::new();
    env.create_vault("development");
    env.set("development", "database-password", "pw");
    let init = env.run(&["init", "--project-name", "demo"]);
    assert!(init.status.success(), "{}", stderr(&init));

    // The child reports whether the unlock variable reached it.
    let probe: &[&str] = if cfg!(windows) {
        &[
            "run",
            "--",
            "cmd",
            "/C",
            "if defined SOURCEORRERY_PASSPHRASE (echo LEAK) else (echo CLEAN)",
        ]
    } else {
        &[
            "run",
            "--",
            "sh",
            "-c",
            "if [ -n \"$SOURCEORRERY_PASSPHRASE\" ]; then echo LEAK; else echo CLEAN; fi",
        ]
    };
    let out = env.run(probe);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(stdout(&out).trim(), "CLEAN");
}

#[test]
fn optional_secret_in_a_missing_vault_does_not_block_run() {
    let env = Env::new();
    env.create_vault("development");
    env.set("development", "database-password", "pw");
    std::fs::write(
        env.project.path().join("sourceorrery.toml"),
        "[project]\nname = \"demo\"\nvault = \"development\"\n\n\
         [secrets.database-password]\n\n\
         [secrets.extra-key]\nrequired = false\nvault = \"nowhere\"\n",
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

    // A required secret in a missing vault still refuses to start.
    std::fs::write(
        env.project.path().join("sourceorrery.toml"),
        "[project]\nname = \"demo\"\nvault = \"development\"\n\n\
         [secrets.extra-key]\nrequired = true\nvault = \"nowhere\"\n",
    )
    .unwrap();
    let out = env.run(echo);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("vault_not_found"), "{}", stderr(&out));
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
    let init = env.run(&["init", "--project-name", "demo"]);
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
