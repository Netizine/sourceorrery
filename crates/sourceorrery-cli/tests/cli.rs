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

#[test]
fn remote_vaults_come_from_the_manifest_and_local_only_commands_refuse_them() {
    let env = Env::new();
    env.create_vault("development");
    env.set("development", "database-password", CANARY);
    std::fs::write(
        env.project.path().join("sourceorrery.toml"),
        "[project]\nname = \"demo\"\nvault = \"development\"\n\n\
         [secrets.database-password]\n\n\
         [secrets.api-key]\nvault = \"prod\"\n\n\
         [vaults.prod]\nprovider = \"hashicorp-vault\"\n\
         address = \"http://127.0.0.1:1\"\nmount = \"secret\"\n",
    )
    .unwrap();

    // The listing shows both kinds.
    let out = env.ok(&["vault", "list"]);
    assert!(
        out.contains("development") && out.contains("local"),
        "{out}"
    );
    assert!(
        out.contains("prod") && out.contains("hashicorp-vault") && out.contains("127.0.0.1:1"),
        "{out}"
    );
    let json: serde_json::Value =
        serde_json::from_str(&env.ok(&["vault", "list", "-o", "json"])).unwrap();
    let rows = json.as_array().unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0]["name"], "development");
    assert_eq!(rows[0]["kind"], "local");
    assert_eq!(rows[1]["name"], "prod");
    assert_eq!(rows[1]["kind"], "remote");
    assert_eq!(rows[1]["provider"], "hashicorp-vault");

    // Contract commands reach the HashiCorp Vault provider. With a token in
    // the environment the provider connects, and nothing listens on port 1,
    // so the outcome is `provider_unavailable`; without one it is
    // `unauthenticated` before any connection (unless the developer running
    // the tests has a ~/.vault-token).
    let remote = |args: &[&str]| {
        let mut cmd = env.cmd(args);
        cmd.env("VAULT_TOKEN", "cli-test-token");
        cmd.output().unwrap()
    };
    let out = remote(&["secret", "get", "api-key", "--vault", "prod", "-o", "json"]);
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
    let out = env.run(&["secret", "get", "api-key", "--vault", "prod", "-o", "json"]);
    assert!(!out.status.success());
    let err: serde_json::Value = serde_json::from_str(stderr(&out).trim()).unwrap();
    assert!(
        err["error"]["code"] == "unauthenticated" || err["error"]["code"] == "provider_unavailable",
        "{err}"
    );
    let out = remote(&["check"]);
    assert!(!out.status.success());
    assert!(
        stdout(&out).contains("provider_unavailable"),
        "{}",
        stdout(&out)
    );
    // The local vault is still read as before.
    assert!(stdout(&out).contains("ok"), "{}", stdout(&out));

    // Local-only commands refuse the remote vault by name, before any
    // network or unlock attempt.
    for args in [
        vec!["vault", "protector", "list", "--vault", "prod"],
        vec!["vault", "destroy", "prod", "--yes"],
        vec!["vault", "migrate", "prod"],
        vec!["audit", "--verify", "--vault", "prod"],
        vec!["audit", "--acknowledge", "--yes", "--vault", "prod"],
        vec!["backup", "--vault", "prod", "--out", "x.sobackup"],
    ] {
        let out = env.run(&args);
        assert!(!out.status.success(), "{args:?}");
        let text = stderr(&out);
        assert!(
            text.contains("remote vault") && text.contains("local vaults only"),
            "{args:?}: {text}"
        );
    }
    assert!(!env.project.path().join("x.sobackup").exists());
    // Listing the audit log of a remote vault points at the provider's own
    // trail instead, without touching the network.
    let out = env.run(&["audit", "--vault", "prod"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(stderr(&out).contains("audit devices"), "{}", stderr(&out));

    // A credential in the manifest is a parse error that never echoes it.
    std::fs::write(
        env.project.path().join("sourceorrery.toml"),
        "[project]\nname = \"demo\"\nvault = \"development\"\n\n\
         [vaults.prod]\nprovider = \"hashicorp-vault\"\n\
         address = \"http://127.0.0.1:1\"\nmount = \"secret\"\n\
         token = \"hvs.SMUGGLED-TOKEN-CANARY\"\n",
    )
    .unwrap();
    let out = env.run(&["vault", "list"]);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("token"), "{}", stderr(&out));
    assert!(!stderr(&out).contains("SMUGGLED"), "{}", stderr(&out));
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
    env.ok(&["init", "--project-name", "demo"]);
    let manifest_path = env.project.path().join("sourceorrery.toml");
    let mut manifest = std::fs::read_to_string(&manifest_path).unwrap();
    manifest.push('\n');
    manifest.push_str(&write_rotation_hooks(env.project.path()));
    std::fs::write(&manifest_path, manifest).unwrap();
    env.set("development", "database-password", "first-value");
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
    env.ok(&["init", "--project-name", "demo"]);

    // Without hooks the value comes from stdin, and without a grace period
    // the previous version is retired in the same run.
    env.set("development", "api-key", "k1");
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
fn audit_on_a_remote_vault_points_at_the_providers_trail() {
    let env = Env::new();
    std::fs::write(
        env.project.path().join("sourceorrery.toml"),
        "[project]\nname = \"x\"\nvault = \"dev\"\n\n[vaults.remote]\n\
         provider = \"aws-secrets-manager\"\nregion = \"eu-west-1\"\nprefix = \"myapp/\"\n",
    )
    .unwrap();
    let text = env.ok(&["audit", "--vault", "remote", "-o", "json"]);
    let pointer: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(pointer["provider"], "aws-secrets-manager");
    assert_eq!(pointer["audit_trail"], "AWS CloudTrail");
    assert!(pointer["query"].as_str().unwrap().contains("myapp/"));
    assert!(pointer["docs"].as_str().unwrap().ends_with("#audit-trail"));
    let out = env.run(&["audit", "--vault", "remote"]);
    assert!(out.status.success());
    assert!(stderr(&out).contains("CloudTrail"), "{}", stderr(&out));

    // An export has nothing of ours to export there.
    let out = env.run(&["audit", "export", "--vault", "remote"]);
    assert!(!out.status.success());
    let err = stderr(&out);
    assert!(
        err.contains("unsupported") && err.contains("CloudTrail"),
        "{err}"
    );
}

#[test]
fn passphrase_generate_and_check_estimate_strength_without_storing_anything() {
    let env = Env::new();
    let text = env.ok(&["vault", "passphrase", "generate"]);
    let generated = text.trim();
    assert_eq!(generated.chars().count(), 20, "{text}");
    assert!(generated.bytes().all(|b| b.is_ascii_graphic()));
    let again = env.ok(&["vault", "passphrase", "generate", "--length", "32"]);
    assert_eq!(again.trim().chars().count(), 32);
    assert_ne!(generated, again.trim());
    let json = env.ok(&["vault", "passphrase", "generate", "-o", "json"]);
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed["length"], 20);
    assert_eq!(parsed["bits"], 125);
    assert_eq!(parsed["passphrase"].as_str().unwrap().len(), 20);
    let out = env.run(&["vault", "passphrase", "generate", "--length", "8"]);
    assert!(!out.status.success());

    // The generated passphrase rates strong; a common one does not, and the
    // estimate never repeats what it was given.
    let out = env.run_with_stdin(&["vault", "passphrase", "check", "-o", "json"], generated);
    assert!(out.status.success(), "{}", stderr(&out));
    let estimate: serde_json::Value = serde_json::from_str(&stdout(&out)).unwrap();
    // Random characters can land in runs the estimate costs as words, so a
    // generated passphrase is asserted acceptable, not a fixed score.
    assert_eq!(estimate["acceptable"], true, "{estimate}");
    assert!(estimate["bits"].as_u64().unwrap() >= 44, "{estimate}");
    let out = env.run_with_stdin(
        &["vault", "passphrase", "check", "-o", "json"],
        "Password1!\n",
    );
    let estimate: serde_json::Value = serde_json::from_str(&stdout(&out)).unwrap();
    assert_eq!(estimate["label"], "guessable", "{estimate}");
    assert_eq!(estimate["acceptable"], false);
    assert!(!stdout(&out).contains("Password1"));
    let out = env.run_with_stdin(&["vault", "passphrase", "check"], "Harbour2024!\n");
    let shown = format!("{}{}", stdout(&out), stderr(&out));
    assert!(shown.contains("a year"), "{shown}");
    assert!(!shown.contains("Harbour"), "{shown}");
}

#[test]
fn a_weak_passphrase_from_the_environment_is_warned_about_not_refused() {
    let env = Env::new();
    let out = env
        .cmd(&["vault", "create", "weakly", "--protector", "passphrase"])
        .env("SOURCEORRERY_PASSPHRASE", "dev-only")
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", stderr(&out));
    let err = stderr(&out);
    assert!(
        err.contains("rates fair") || err.contains("rates weak"),
        "{err}"
    );
    assert!(err.contains("SOURCEORRERY_PASSPHRASE"), "{err}");
    assert!(
        !err.contains("dev-only"),
        "the passphrase itself is never printed: {err}"
    );
    // A strong one passes silently.
    let out = env
        .cmd(&["vault", "create", "strongly", "--protector", "passphrase"])
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(!stderr(&out).contains("rates"), "{}", stderr(&out));
}
