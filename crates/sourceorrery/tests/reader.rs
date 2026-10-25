//! The read-only client against vaults created with the storage crate.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

use sourceorrery::{ErrorKind, OpenOptions, Project, SecretBytes, SecretReader};
use sourceorrery_core::audit::{AuditOperation, AuditQuery};
use sourceorrery_core::{
    ConnectionSettings, Credentials, SecretClient, SetSecretOptions, UpdateSecretProperties,
};
use sourceorrery_storage::{
    CatalogChange, CreateVaultOptions, NoStore, StaticRecoveryKey, VaultRegistry,
};
use time::macros::datetime;

const WRONG_KEY: &str = "AAAAA-AAAAA-AAAAA-AAAAA-AAAAA";
const CANARY: &str = "CANARY-value-that-must-not-leak-2c9a";

/// A temporary home whose vaults open with their recovery keys, which it
/// remembers; it has no credential store, so no test touches the real one.
struct Home {
    dir: tempfile::TempDir,
    keys: RefCell<BTreeMap<String, String>>,
}

impl Home {
    fn new() -> Self {
        Self {
            dir: tempfile::tempdir().expect("temp dir"),
            keys: RefCell::new(BTreeMap::new()),
        }
    }

    fn path(&self) -> &Path {
        self.dir.path()
    }

    fn create_vault(&self, name: &str) -> sourceorrery_storage::SqliteVault {
        let created = VaultRegistry::with_root(self.path())
            .with_store(Arc::new(NoStore))
            .create(name, CreateVaultOptions::default())
            .expect("create vault");
        self.keys
            .borrow_mut()
            .insert(name.to_owned(), created.recovery_key.to_string());
        created.vault
    }

    fn key(&self, name: &str) -> String {
        self.keys.borrow()[name].clone()
    }

    /// Options that open `dev`.
    fn options(&self) -> OpenOptions {
        self.options_for("dev")
    }

    fn options_for(&self, name: &str) -> OpenOptions {
        OpenOptions::new()
            .home(self.path())
            .recovery_key(self.key(name))
            .environment(false)
    }
}

fn set(vault: &impl SecretClient, name: &str, value: &str, options: SetSecretOptions) -> String {
    vault
        .set_secret(name, SecretBytes::from(value), options)
        .expect("set")
        .version
}

#[test]
fn reads_latest_pinned_properties_and_references() {
    let home = Home::new();
    let vault = home.create_vault("dev");
    let v1 = set(&vault, "db-password", "one", SetSecretOptions::default());
    let v2 = set(&vault, "db-password", CANARY, SetSecretOptions::default());
    drop(vault);

    let reader = SecretReader::open_with("dev", &home.options()).unwrap();
    assert_eq!(reader.vault_name(), "dev");
    assert_eq!(reader.home(), home.path());

    let latest = reader.get("db-password").unwrap();
    assert_eq!(latest.properties.version, v2);
    assert_eq!(latest.value.expose(), CANARY.as_bytes());
    assert!(!format!("{latest:?}").contains(CANARY));

    let pinned = reader.get_version("db-password", &v1).unwrap();
    assert_eq!(pinned.value.expose(), b"one");

    let props = reader.properties("db-password", None).unwrap();
    assert_eq!(props.version, v2);
    let props = reader.properties("db-password", Some(&v1)).unwrap();
    assert_eq!(props.version, v1);

    let by_ref = reader
        .resolve(&format!("sourceorrery://dev/db-password/{v1}"))
        .unwrap();
    assert_eq!(by_ref.value.expose(), b"one");
    let by_ref = reader.resolve("sourceorrery://dev/db-password").unwrap();
    assert_eq!(by_ref.properties.version, v2);

    let descriptor = reader.descriptor().unwrap();
    assert_eq!(descriptor.name, "dev");
    assert_eq!(descriptor.protectors.len(), 1);
}

#[test]
fn errors_carry_codes_kinds_and_hints() {
    let home = Home::new();
    let vault = home.create_vault("dev");
    set(&vault, "db-password", CANARY, SetSecretOptions::default());
    let old = set(&vault, "rotated", "old", SetSecretOptions::default());
    let new = set(&vault, "rotated", "new", SetSecretOptions::default());
    vault
        .update_secret_properties(
            "rotated",
            Some(&new),
            UpdateSecretProperties {
                enabled: Some(false),
                ..Default::default()
            },
        )
        .unwrap();
    set(
        &vault,
        "expired",
        "x",
        SetSecretOptions {
            expires_on: Some(datetime!(2020-01-01 00:00 UTC)),
            ..Default::default()
        },
    );
    set(
        &vault,
        "pending",
        "x",
        SetSecretOptions {
            not_before: Some(datetime!(2100-01-01 00:00 UTC)),
            ..Default::default()
        },
    );
    set(&vault, "gone", "x", SetSecretOptions::default());
    vault.delete_secret("gone").unwrap();
    drop(vault);

    let reader = SecretReader::open_with("dev", &home.options()).unwrap();

    let err = reader.get("missing").unwrap_err();
    assert_eq!(err.code(), "not_found");
    assert_eq!(err.kind(), ErrorKind::NotFound);
    assert!(
        err.hint().contains("secret set missing --vault dev"),
        "{err}"
    );

    let err = reader.get_version("db-password", "deadbeef").unwrap_err();
    assert_eq!(err.kind(), ErrorKind::VersionNotFound);
    assert!(err.hint().contains("secret versions db-password"), "{err}");

    // Disabled newest version: the reader falls back, an explicit read is refused.
    assert_eq!(reader.get("rotated").unwrap().properties.version, old);
    let err = reader.get_version("rotated", &new).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Disabled);
    assert!(err.kind().is_policy());
    assert!(err.hint().contains("--enable"), "{err}");
    assert!(!reader.properties("rotated", Some(&new)).unwrap().enabled);

    let err = reader.get("expired").unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Expired);
    assert!(err.hint().contains("Policy"), "{err}");
    let err = reader.get("pending").unwrap_err();
    assert_eq!(err.kind(), ErrorKind::NotYetValid);
    assert!(err.is_transient());
    let err = reader.get("gone").unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Deleted);
    assert!(err.hint().contains("secret recover gone"), "{err}");

    let err = reader
        .resolve("sourceorrery://other/db-password")
        .unwrap_err();
    assert_eq!(err.kind(), ErrorKind::InvalidArgument);
    let err = reader.resolve("https://dev/db-password").unwrap_err();
    assert_eq!(err.kind(), ErrorKind::InvalidArgument);
    let err = reader.get("bad_name").unwrap_err();
    assert_eq!(err.kind(), ErrorKind::InvalidName);

    // Nothing that reaches the caller as text carries a value.
    for err in [
        reader.get("missing").unwrap_err(),
        reader.get("expired").unwrap_err(),
    ] {
        assert!(!err.to_string().contains(CANARY));
        assert!(!format!("{err:?}").contains(CANARY));
    }
}

#[test]
fn vault_level_failures_explain_what_to_do() {
    let home = Home::new();
    home.create_vault("dev");

    let err = SecretReader::open_with("nope", &home.options()).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::VaultNotFound);
    assert!(
        err.hint().contains("sourceorrery vault create nope"),
        "{err}"
    );
    assert!(err.hint().contains(&home.path().display().to_string()));

    let wrong = OpenOptions::new()
        .home(home.path())
        .recovery_key(WRONG_KEY)
        .environment(false);
    let err = SecretReader::open_with("dev", &wrong).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Locked);
    assert!(err.hint().contains("recovery_key option: tried"), "{err}");
    assert!(
        err.hint().contains("SOURCEORRERY_RECOVERY_KEY: not set"),
        "{err}"
    );
    assert!(!err.to_string().contains(WRONG_KEY), "{err}");

    // No source at all is also `locked`, with every source reported empty.
    let none = OpenOptions::new().home(home.path()).environment(false);
    let err = SecretReader::open_with("dev", &none).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Locked);
    assert!(
        err.hint().contains("recovery_key option: not given"),
        "{err}"
    );

    // A recovery-key file works and is reported as tried.
    let file = home.path().join("recovery-key.txt");
    std::fs::write(&file, format!("{}\n", home.key("dev"))).unwrap();
    let from_file = OpenOptions::new()
        .home(home.path())
        .recovery_key_file(&file)
        .environment(false);
    SecretReader::open_with("dev", &from_file).unwrap();
    let bad_file = OpenOptions::new()
        .home(home.path())
        .recovery_key_file(home.path().join("missing.txt"))
        .environment(false);
    let err = SecretReader::open_with("dev", &bad_file).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Io);

    let err = SecretReader::open_with("Bad Name", &home.options()).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::InvalidName);
}

#[test]
fn project_load_mirrors_run() {
    let home = Home::new();
    let vault = home.create_vault("dev");
    set(&vault, "db-password", "pg", SetSecretOptions::default());
    let pinned = set(&vault, "signing-key", "k1", SetSecretOptions::default());
    set(&vault, "signing-key", "k2", SetSecretOptions::default());
    drop(vault);

    let project_dir = tempfile::tempdir().unwrap();
    let manifest = project_dir.path().join("sourceorrery.toml");
    std::fs::write(
        &manifest,
        format!(
            "[project]\nname = \"demo\"\nvault = \"dev\"\n\n\
             [secrets.db-password]\n\n\
             [secrets.signing-key]\nenv = \"SIGNING\"\nversion = \"{pinned}\"\n\n\
             [secrets.optional-thing]\nrequired = false\n"
        ),
    )
    .unwrap();

    let project = Project::load(Some(&manifest), &home.options()).unwrap();
    assert_eq!(project.name(), "demo");
    assert_eq!(project.manifest_path(), manifest);
    assert_eq!(project.secrets().len(), 2, "optional misses are skipped");
    assert_eq!(project.env("DB_PASSWORD").unwrap().expose(), b"pg");
    assert_eq!(project.env("SIGNING").unwrap().expose(), b"k1");
    assert_eq!(
        project.get("signing-key").unwrap().properties.version,
        pinned
    );
    assert!(project.get("optional-thing").is_none());
    let env = project.into_env();
    assert_eq!(env.len(), 2);

    // A required secret that is missing fails the whole load.
    std::fs::write(
        &manifest,
        "[project]\nname = \"demo\"\nvault = \"dev\"\n\n[secrets.db-password]\n\n[secrets.absent]\n",
    )
    .unwrap();
    let err = Project::load(Some(&manifest), &home.options()).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::NotFound);
    assert!(err.message().contains("sourceorrery://dev/absent"), "{err}");

    // Two missing required secrets are listed together.
    std::fs::write(
        &manifest,
        "[project]\nname = \"demo\"\nvault = \"dev\"\n\n[secrets.absent]\n\n[secrets.gone]\n",
    )
    .unwrap();
    let err = Project::load(Some(&manifest), &home.options()).unwrap_err();
    assert!(err.message().contains("2 required secrets"), "{err}");
    assert!(err.message().contains("(not_found)"), "{err}");

    // A vault that does not exist leaves out what is optional and fails what
    // is required.
    std::fs::write(
        &manifest,
        "[project]\nname = \"demo\"\nvault = \"other\"\n\n[secrets.maybe]\nrequired = false\n",
    )
    .unwrap();
    let project = Project::load(Some(&manifest), &home.options()).unwrap();
    assert!(project.secrets().is_empty());
    std::fs::write(
        &manifest,
        "[project]\nname = \"demo\"\nvault = \"other\"\n\n[secrets.maybe]\nrequired = false\n\n\
         [secrets.needed]\n",
    )
    .unwrap();
    let err = Project::load(Some(&manifest), &home.options()).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::VaultNotFound);
    assert!(
        err.message().contains("sourceorrery://other/needed"),
        "{err}"
    );

    // A vault that exists but cannot be unlocked fails even for optional entries.
    std::fs::write(
        &manifest,
        "[project]\nname = \"demo\"\nvault = \"dev\"\n\n[secrets.db-password]\nrequired = false\n",
    )
    .unwrap();
    let wrong = OpenOptions::new()
        .home(home.path())
        .recovery_key(WRONG_KEY)
        .environment(false);
    let err = Project::load(Some(&manifest), &wrong).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Locked);

    // Manifest problems are `manifest`, reported without echoing the document.
    std::fs::write(&manifest, "[project]\nname = \"demo\"\nvault = \"dev\"\n\n[secrets.db-password]\nvalue = \"CANARY-in-manifest\"\n").unwrap();
    let err = Project::load(Some(&manifest), &home.options()).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Manifest);
    assert!(!err.to_string().contains("CANARY-in-manifest"), "{err}");
    let err =
        Project::load(Some(&project_dir.path().join("nope.toml")), &home.options()).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Manifest);
}

#[test]
fn reader_is_shared_between_threads() {
    let home = Home::new();
    let vault = home.create_vault("dev");
    set(&vault, "shared", "value", SetSecretOptions::default());
    drop(vault);
    let reader = std::sync::Arc::new(SecretReader::open_with("dev", &home.options()).unwrap());
    let workers: Vec<_> = (0..4)
        .map(|_| {
            let reader = std::sync::Arc::clone(&reader);
            std::thread::spawn(move || {
                for _ in 0..5 {
                    assert_eq!(reader.get("shared").unwrap().value.expose(), b"value");
                }
            })
        })
        .collect();
    for worker in workers {
        worker.join().unwrap();
    }
}

#[test]
fn a_secret_a_connection_stores_is_read_at_its_provider() {
    let home = Home::new();
    let vault = home.create_vault("dev");
    set(
        &vault,
        "database-password",
        "pw",
        SetSecretOptions::default(),
    );
    // A connection to a HashiCorp Vault where nothing listens, with a token
    // stored so the environment's own does not matter, and a secret
    // catalogued there as a set through it would leave it.
    let settings = ConnectionSettings::HashicorpVault {
        address: "http://127.0.0.1:1".to_owned(),
        mount: "secret".to_owned(),
        namespace: None,
    };
    let token = Credentials::VaultToken(SecretBytes::from("hvs.stored"));
    let connection = vault.add_connection(&settings, Some(&token)).unwrap().id;
    vault
        .record_at_connection(
            &connection,
            AuditOperation::SecretSet,
            Some("api-key"),
            None,
            Ok(()),
            CatalogChange::Add,
            None,
        )
        .unwrap();
    drop(vault);

    // The file's own secret needs no provider; the other goes to it.
    let reader = SecretReader::open_with("dev", &home.options()).unwrap();
    assert_eq!(
        reader.get("database-password").unwrap().value.expose(),
        b"pw"
    );
    let err = reader.get("api-key").unwrap_err();
    assert_eq!(err.kind(), ErrorKind::ProviderUnavailable, "{err}");
    assert!(err.is_transient());
    assert!(
        err.hint().contains("the connection of vault 'dev'"),
        "{}",
        err.hint()
    );
    assert!(!err.to_string().contains("hvs.stored"), "{err}");
    drop(reader);

    // A project that needs it fails; one that does not never contacts it.
    let dir = tempfile::tempdir().unwrap();
    let manifest = dir.path().join("sourceorrery.toml");
    std::fs::write(
        &manifest,
        "[project]\nname = \"demo\"\nvault = \"dev\"\n\n[secrets.database-password]\n\n\
         [secrets.api-key]\n",
    )
    .unwrap();
    let err = Project::load(Some(&manifest), &home.options()).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::ProviderUnavailable, "{err}");
    std::fs::write(
        &manifest,
        "[project]\nname = \"demo\"\nvault = \"dev\"\n\n[secrets.database-password]\n\n\
         [secrets.api-key]\nrequired = false\n",
    )
    .unwrap();
    let project = Project::load(Some(&manifest), &home.options()).unwrap();
    assert_eq!(project.secrets().len(), 1);

    // Each read at the provider is in the vault's own log.
    let vault = VaultRegistry::with_root(home.path())
        .with_store(Arc::new(NoStore))
        .open("dev", &StaticRecoveryKey::new(home.key("dev").as_str()))
        .unwrap();
    let failed = vault
        .audit_events(AuditQuery {
            operation: Some(AuditOperation::SecretGet),
            secret_name: Some("api-key".to_owned()),
            ..AuditQuery::default()
        })
        .unwrap();
    assert!(
        failed.iter().all(|event| event.detail.as_deref()
            == Some(&format!("at connection {connection}: provider_unavailable")[..])),
        "{failed:?}"
    );
    assert_eq!(failed.len(), 3);
}
