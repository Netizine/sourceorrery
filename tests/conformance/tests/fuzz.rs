//! Bounded fuzz (B31, REC09): the parsers of input SourceOrrery does not
//! control, run over mangled copies of valid input (`fuzz::Mutator`). Each
//! case must give a value or an error, never a panic; a mangled vault file
//! must also never give back a value other than the one stored.

use std::path::Path;
use std::sync::Arc;

use sourceorrery_conformance::fuzz::Mutator;
use sourceorrery_core::manifest::Manifest;
use sourceorrery_core::secret::SecretReference;
use sourceorrery_core::{SecretBytes, SecretClient, SetSecretOptions, rotation, timestamp};
use sourceorrery_storage::{CreateVaultOptions, NoStore, SqliteVault, StaticRecoveryKey};

const MANIFEST: &str = r#"[project]
name = "my-application"
vault = "development"

[secrets.database-password]
required = true
purpose = "Database authentication"
env = "DB_PASSWORD"

[secrets.api-token]
required = false

[rotation.database-password]
issue = ["./rotate.sh", "issue"]
validate = ["./rotate.sh", "validate"]
retire_after = "7d"
"#;

/// What a project's `sourceorrery.toml`, a reference, a time or a grace
/// period can hold, whoever wrote it.
#[test]
fn text_from_users_and_repositories_is_parsed_or_refused_never_a_panic() {
    let mut m = Mutator::new(0xC0FF_EE00_0B31);
    for _ in 0..5000 {
        let _ = Manifest::parse(&m.mutate(MANIFEST));
        let _ = SecretReference::parse(
            &m.mutate("sourceorrery://development/database-password/0123abcd"),
        );
        let _ = m.mutate("sourceorrery://dev/k").parse::<SecretReference>();
        let _ = timestamp::parse(&m.mutate("2026-10-25T12:34:56.123456789+01:00"));
        let _ = rotation::parse_grace(&m.mutate("7d"));
    }
}

/// The SQL a mangling applies to one copy, one stored field at a time.
const FIELDS: [(&str, &str); 9] = [
    ("vault_meta", "value"),
    ("key_wraps", "kind_json"),
    ("key_wraps", "wrapped_key"),
    ("secrets", "tag"),
    ("secret_versions", "ciphertext"),
    ("secret_versions", "tags_json"),
    ("secret_versions", "tag"),
    ("audit_events", "detail"),
    ("audit_events", "state_tag"),
];

fn mangle(path: &Path, m: &mut Mutator) {
    let conn = rusqlite::Connection::open(path).unwrap();
    let (table, column) = FIELDS[m.below(FIELDS.len())];
    let rows: Vec<(i64, Option<Vec<u8>>)> = conn
        .prepare(&format!(
            "SELECT rowid, CAST({column} AS BLOB) FROM {table}"
        ))
        .unwrap()
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    let (rowid, value) = &rows[m.below(rows.len())];
    let mangled = m.mutate_bytes(value.as_deref().unwrap_or_default());
    // Text columns keep text, so the file stays well-formed SQLite: what is
    // tried is the vault's own reading of the content.
    if matches!(column, "value" | "kind_json" | "tags_json" | "detail") {
        let text = String::from_utf8_lossy(&mangled).into_owned();
        conn.execute(
            &format!("UPDATE {table} SET {column} = ?1 WHERE rowid = ?2"),
            rusqlite::params![text, rowid],
        )
        .unwrap();
    } else {
        conn.execute(
            &format!("UPDATE {table} SET {column} = ?1 WHERE rowid = ?2"),
            rusqlite::params![mangled, rowid],
        )
        .unwrap();
    }
}

/// A vault file someone else can write: each copy has one field of one row
/// mangled. Opening it, reading the secret, listing and verifying give the
/// stored value or an error, never a panic and never another value.
#[test]
fn a_mangled_vault_file_gives_the_stored_value_or_an_error() {
    let dir = tempfile::tempdir().unwrap();
    let template = dir.path().join("template.sorvault");
    let created = SqliteVault::create(
        &template,
        "dev",
        CreateVaultOptions::default(),
        Arc::new(NoStore),
    )
    .unwrap();
    let key = created.recovery_key.as_str().to_owned();
    created
        .vault
        .set_secret(
            "db",
            SecretBytes::from("the-stored-value"),
            SetSecretOptions {
                content_type: Some("text/plain".into()),
                ..SetSecretOptions::default()
            },
        )
        .unwrap();
    drop(created);
    let mut m = Mutator::new(0xF11E_0B31);
    let (mut opened, mut read) = (0, 0);
    for case in 0..300 {
        let path = dir.path().join(format!("case-{case}.sorvault"));
        std::fs::copy(&template, &path).unwrap();
        mangle(&path, &mut m);
        let Ok(vault) = SqliteVault::open(
            &path,
            Arc::new(NoStore),
            &StaticRecoveryKey::new(key.as_str()),
        ) else {
            std::fs::remove_file(&path).unwrap();
            continue;
        };
        opened += 1;
        if let Ok(secret) = vault.get_secret("db", None) {
            assert_eq!(secret.value.expose(), b"the-stored-value", "case {case}");
            read += 1;
        }
        let _ = vault.list_properties_of_secrets();
        let _ = vault.verify_audit_chain();
        drop(vault);
        std::fs::remove_file(&path).unwrap();
    }
    // Some manglings touch nothing that is checked (an audit detail is
    // only covered by the chain walk), most are refused: both happen.
    assert!(opened < 300, "every mangled copy opened");
    eprintln!("{opened} of 300 mangled copies opened, {read} read the stored value");
}
