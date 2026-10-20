//! Unlocking a vault and managing its key protectors: trying passphrases
//! within the resource ceilings, unwrapping the vault key under the schema
//! it was bound to, adding and removing protectors, and deciding which
//! OS-keyring entries this vault may delete.

use std::path::Path;

use rusqlite::{Connection, params};
use sourceorrery_core::audit::{AuditOperation, AuditOutcome};
use sourceorrery_core::{Result, SecretError, timestamp};
use sourceorrery_crypto::{Ciphertext, SymmetricKey, envelope, kdf, random};

use super::audit::AuditWriter;
use super::schema::{
    Meta, begin_write, crypto, db, from_nanos, nanos, open_connection, protector_aad, read_meta,
};
use super::{
    MAX_PASSPHRASE_PROTECTORS, MAX_UNLOCK_ATTEMPTS, OLDEST_SUPPORTED_SCHEMA, SCHEMA_VERSION,
    SqliteVault,
};
use crate::keystore;
use crate::protector::{ProtectorInfo, ProtectorKind, ProtectorRecord, ProtectorSpec};
use crate::unlock::{PassphrasePrompt, UnlockProvider};

/// What unlocked the vault: needed afterwards to re-wrap the key under the
/// current format and to judge a legacy schema marker.
pub(super) struct Unlocked {
    pub(super) protector_id: String,
    pub(super) kek: SymmetricKey,
    /// Schema whose AAD the stored wrapped key was bound to.
    pub(super) wrapped_schema: u32,
}

/// `(id, label, kind_json, wrapped_nonce, wrapped_dek, created_on)`
pub(super) type ProtectorRow = (String, String, String, Vec<u8>, Vec<u8>, i64);

/// Ask `unlock` for a passphrase up to [`MAX_UNLOCK_ATTEMPTS`] times and try
/// it against every passphrase protector (at most
/// [`MAX_PASSPHRASE_PROTECTORS`], each within `Argon2Params::MAX`). Returns
/// the vault key and what unlocked it; otherwise `None`, with the reasons
/// appended and every rejected attempt audited.
pub(super) fn try_passphrases(
    conn: &Connection,
    meta: &Meta,
    protectors: &[ProtectorRecord],
    unlock: &dyn UnlockProvider,
    unkeyed: &AuditWriter<'_>,
    reasons: &mut Vec<String>,
) -> Result<Option<(SymmetricKey, Unlocked)>> {
    let passphrase_protectors: Vec<&ProtectorRecord> = protectors
        .iter()
        .filter(|p| matches!(p.kind, ProtectorKind::Passphrase { .. }))
        .take(MAX_PASSPHRASE_PROTECTORS)
        .collect();
    if passphrase_protectors.is_empty() {
        reasons.push("no passphrase protector is installed".to_owned());
        return Ok(None);
    }
    let labels = passphrase_protectors
        .iter()
        .map(|p| p.label.as_str())
        .collect::<Vec<_>>()
        .join(", ");
    for attempt in 1..=MAX_UNLOCK_ATTEMPTS {
        let prompt = PassphrasePrompt {
            vault: &meta.name,
            protector_label: &labels,
            attempt,
            max_attempts: MAX_UNLOCK_ATTEMPTS,
        };
        let Some(passphrase) = unlock.passphrase(&prompt)? else {
            reasons.push("no passphrase supplied".to_owned());
            return Ok(None);
        };
        for protector in &passphrase_protectors {
            let ProtectorKind::Passphrase { salt, params } = &protector.kind else {
                continue;
            };
            // Parameters come from the file: a protector asking for more
            // work than the ceiling is skipped, never run.
            if !params.within_limits() {
                reasons.push(format!(
                    "{}: Argon2 parameters exceed the supported limits",
                    protector.label
                ));
                continue;
            }
            let salt = hex::decode(salt).map_err(|_| {
                SecretError::Storage(format!("corrupt salt on protector {}", protector.id))
            })?;
            let kek = kdf::derive_key(passphrase.expose(), &salt, *params).map_err(crypto)?;
            if let Ok((dek, wrapped_schema)) = try_unwrap(meta, protector, &kek) {
                let unlocked = Unlocked {
                    protector_id: protector.id.clone(),
                    kek,
                    wrapped_schema,
                };
                return Ok(Some((dek, unlocked)));
            }
        }
        unkeyed.record(
            conn,
            AuditOperation::VaultOpen,
            None,
            None,
            AuditOutcome::Denied,
            Some("incorrect passphrase"),
        )?;
        reasons.push(format!("passphrase attempt {attempt} rejected"));
    }
    Ok(None)
}

/// The OS-keyring account this vault creates for a protector.
pub(super) fn keyring_account_name(vault_id: &str, protector_id: &str) -> String {
    format!("vault/{vault_id}/{protector_id}")
}

/// Alias used by [`SqliteVault::keyring_accounts`].
pub(super) fn keyring_account(vault_id: &str, protector_id: &str) -> String {
    keyring_account_name(vault_id, protector_id)
}

/// Re-wrap the vault key for one protector under the current schema's AAD.
pub(super) fn rewrap_protector(
    conn: &Connection,
    meta: &Meta,
    dek: &SymmetricKey,
    protector_id: &str,
    kek: &SymmetricKey,
) -> Result<()> {
    let wrapped = envelope::wrap_key(
        kek,
        dek,
        protector_aad(&meta.id, protector_id, SCHEMA_VERSION).as_bytes(),
    )
    .map_err(crypto)?;
    conn.execute(
        "UPDATE key_protectors SET wrapped_nonce = ?2, wrapped_dek = ?3 WHERE id = ?1",
        params![protector_id, wrapped.nonce.as_slice(), wrapped.bytes],
    )
    .map_err(db)?;
    Ok(())
}

/// True when any OS-keyring protector's stored key unwraps under the
/// current schema's AAD: evidence that the file was already in the current
/// format whatever its schema marker says.
pub(super) fn any_keyring_protector_wrapped_current(
    conn: &Connection,
    meta: &Meta,
) -> Result<bool> {
    for protector in read_protectors(conn)? {
        let ProtectorKind::OsKeyring { account, .. } = &protector.kind else {
            continue;
        };
        let Ok(Some(kek)) = keystore::load_key(account) else {
            continue;
        };
        let current = envelope::unwrap_key(
            &kek,
            &protector.wrapped,
            protector_aad(&meta.id, &protector.id, SCHEMA_VERSION).as_bytes(),
        );
        if current.is_ok() {
            return Ok(true);
        }
    }
    Ok(false)
}

pub(super) fn read_protectors(conn: &Connection) -> Result<Vec<ProtectorRecord>> {
    let mut stmt = conn
        .prepare(
            "SELECT id, label, kind_json, wrapped_nonce, wrapped_dek, created_on
             FROM key_protectors ORDER BY created_on, id",
        )
        .map_err(db)?;
    let raw: Vec<ProtectorRow> = stmt
        .query_map([], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
            ))
        })
        .map_err(db)?
        .collect::<rusqlite::Result<_>>()
        .map_err(db)?;
    raw.into_iter()
        .map(|(id, label, kind_json, nonce, wrapped, created_on)| {
            let kind: ProtectorKind = serde_json::from_str(&kind_json)
                .map_err(|err| SecretError::Storage(format!("corrupt protector {id}: {err}")))?;
            Ok(ProtectorRecord {
                id,
                label,
                kind,
                wrapped: Ciphertext::from_parts(&nonce, wrapped).map_err(crypto)?,
                created_on: from_nanos(created_on)?,
            })
        })
        .collect()
}

/// Unwrap the vault key with `kek`, trying the current schema's AAD first
/// and then the oldest supported one. Returns the key and the schema whose
/// AAD matched.
pub(super) fn try_unwrap(
    meta: &Meta,
    protector: &ProtectorRecord,
    kek: &SymmetricKey,
) -> Result<(SymmetricKey, u32)> {
    let mut last = None;
    for schema in [SCHEMA_VERSION, OLDEST_SUPPORTED_SCHEMA] {
        match envelope::unwrap_key(
            kek,
            &protector.wrapped,
            protector_aad(&meta.id, &protector.id, schema).as_bytes(),
        ) {
            Ok(dek) => return Ok((dek, schema)),
            Err(err) => last = Some(err),
        }
    }
    Err(last.map_or_else(
        || SecretError::Crypto("no schema to unwrap under".to_owned()),
        crypto,
    ))
}

/// The label for a new protector: the caller's, if unique and non-empty,
/// else the kind's label, suffixed with part of the id when already taken.
pub(super) fn choose_label(
    conn: &Connection,
    requested: Option<&str>,
    kind_label: &str,
    id: &str,
) -> Result<String> {
    let existing: Vec<String> = read_protectors(conn)?
        .into_iter()
        .map(|p| p.label)
        .collect();
    if let Some(custom) = requested {
        if custom.trim().is_empty() {
            return Err(SecretError::InvalidArgument(
                "protector label must not be empty".to_owned(),
            ));
        }
        if existing.iter().any(|l| l == custom) {
            return Err(SecretError::InvalidArgument(format!(
                "a protector labelled '{custom}' already exists"
            )));
        }
        return Ok(custom.to_owned());
    }
    let base = kind_label.to_owned();
    Ok(if existing.contains(&base) {
        format!("{base}-{}", &id[..4])
    } else {
        base
    })
}

pub(super) fn add_protector(
    conn: &Connection,
    meta: &Meta,
    dek: &SymmetricKey,
    spec: ProtectorSpec,
    label: Option<&str>,
) -> Result<ProtectorInfo> {
    let id = random::random_hex(8).map_err(crypto)?;

    // Validate everything that can fail cheaply before touching the OS
    // credential store, so a rejected label never leaves an orphan key.
    let label = choose_label(conn, label, spec.kind_label(), &id)?;

    let (kind, kek, stored_account) = match spec {
        ProtectorSpec::OsKeyring => {
            if !keystore::available() {
                return Err(SecretError::Unsupported(format!(
                    "{} is not available ({}); use a passphrase protector instead",
                    keystore::STORE_NAME,
                    keystore::unavailable_reason().unwrap_or_default()
                )));
            }
            let account = keyring_account_name(&meta.id, &id);
            let kek = SymmetricKey::generate().map_err(crypto)?;
            keystore::store_key(&account, &kek)?;
            (
                ProtectorKind::OsKeyring {
                    service: keystore::SERVICE.to_owned(),
                    account: account.clone(),
                },
                kek,
                Some(account),
            )
        }
        ProtectorSpec::Passphrase { passphrase, params } => {
            if passphrase.is_empty() {
                return Err(SecretError::InvalidArgument(
                    "passphrase must not be empty".to_owned(),
                ));
            }
            if !params.within_limits() {
                return Err(SecretError::InvalidArgument(
                    "Argon2 parameters exceed the supported limits".to_owned(),
                ));
            }
            let salt = random::random_bytes::<{ kdf::SALT_LEN }>().map_err(crypto)?;
            let kek = kdf::derive_key(passphrase.expose(), &salt, params).map_err(crypto)?;
            (
                ProtectorKind::Passphrase {
                    salt: hex::encode(salt),
                    params,
                },
                kek,
                None,
            )
        }
    };

    let insert = || -> Result<()> {
        let wrapped = envelope::wrap_key(
            &kek,
            dek,
            protector_aad(&meta.id, &id, SCHEMA_VERSION).as_bytes(),
        )
        .map_err(crypto)?;
        let kind_json =
            serde_json::to_string(&kind).map_err(|err| SecretError::Storage(err.to_string()))?;
        conn.execute(
            "INSERT INTO key_protectors (id, label, kind_json, wrapped_nonce, wrapped_dek, created_on)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                id,
                label,
                kind_json,
                wrapped.nonce.as_slice(),
                wrapped.bytes,
                nanos(timestamp::now())?
            ],
        )
        .map_err(db)?;
        Ok(())
    };
    let created_on = timestamp::now();
    if let Err(err) = insert() {
        // The database row did not land: do not leave the key behind.
        if let Some(account) = &stored_account {
            let _ = keystore::delete_key(account);
        }
        return Err(err);
    }

    Ok(ProtectorInfo {
        id,
        label,
        kind: kind.label().to_owned(),
        created_on,
    })
}

impl SqliteVault {
    /// OS-keyring accounts referenced by the vault at `path`, without
    /// unlocking it, each with whether the account is the one this vault
    /// would have created for that protector (`vault/<vault id>/<protector
    /// id>`). Protector metadata is unauthenticated until the vault is
    /// unlocked, so callers must not delete an account that fails that
    /// check, and should also make sure no other vault references it.
    pub(crate) fn keyring_accounts(path: &Path) -> Result<Vec<(String, bool)>> {
        let conn = open_connection(path)?;
        let meta = read_meta(&conn)?;
        Ok(read_protectors(&conn)?
            .into_iter()
            .filter_map(|protector| match protector.kind {
                ProtectorKind::OsKeyring { account, .. } => {
                    let owned = account == keyring_account(&meta.id, &protector.id);
                    Some((account, owned))
                }
                ProtectorKind::Passphrase { .. } => None,
            })
            .collect())
    }

    /// Installed key protectors.
    pub fn protectors(&self) -> Result<Vec<ProtectorInfo>> {
        let conn = self.lock()?;
        Ok(read_protectors(&conn)?
            .iter()
            .map(ProtectorRecord::info)
            .collect())
    }

    /// Add another way to unlock this vault.
    pub fn add_protector(&self, spec: ProtectorSpec, label: Option<&str>) -> Result<ProtectorInfo> {
        let mut conn = self.lock()?;
        let tx = begin_write(&mut conn)?;
        let info = add_protector(&tx, &self.meta, &self.dek, spec, label)?;
        self.audit(
            &tx,
            AuditOperation::ProtectorAdd,
            None,
            None,
            AuditOutcome::Success,
            Some(&info.label),
        )?;
        tx.commit().map_err(db)?;
        Ok(info)
    }

    /// Remove a protector by id or label. The last protector cannot be
    /// removed: that would make the vault permanently unreadable.
    ///
    /// For an OS-keyring protector the credential-store entry is deleted
    /// only after the database change is committed, and only when the
    /// stored account is the one this vault created and no other vault file
    /// beside this one references it. Returns a note when the entry was kept
    /// (so the caller can tell the user), `None` otherwise.
    pub fn remove_protector(&self, id_or_label: &str) -> Result<Option<String>> {
        let mut conn = self.lock()?;
        let tx = begin_write(&mut conn)?;
        let protectors = read_protectors(&tx)?;
        let target = protectors
            .iter()
            .find(|p| p.id == id_or_label || p.label == id_or_label)
            .ok_or_else(|| {
                SecretError::InvalidArgument(format!("no protector named '{id_or_label}'"))
            })?;
        if protectors.len() == 1 {
            return Err(SecretError::InvalidArgument(
                "cannot remove the last key protector; add another one first".to_owned(),
            ));
        }
        let keyring_account = match &target.kind {
            ProtectorKind::OsKeyring { account, .. } => Some(account.clone()),
            ProtectorKind::Passphrase { .. } => None,
        };
        let target_id = target.id.clone();
        let target_label = target.label.clone();
        tx.execute(
            "DELETE FROM key_protectors WHERE id = ?1",
            params![target_id],
        )
        .map_err(db)?;
        self.audit(
            &tx,
            AuditOperation::ProtectorRemove,
            None,
            None,
            AuditOutcome::Success,
            Some(&target_label),
        )?;
        tx.commit().map_err(db)?;
        drop(conn);

        let Some(account) = keyring_account else {
            return Ok(None);
        };
        if account != keyring_account_name(&self.meta.id, &target_id) {
            return Ok(Some(format!(
                "kept OS-keyring entry {account}: its name does not match this vault's identity"
            )));
        }
        let registry = crate::VaultRegistry::with_root(
            self.path
                .parent()
                .and_then(Path::parent)
                .unwrap_or_else(|| Path::new(".")),
        );
        if registry.keyring_account_referenced_elsewhere(&self.path, &account)? {
            return Ok(Some(format!(
                "kept OS-keyring entry {account}: another vault in this home references it"
            )));
        }
        match keystore::delete_key(&account) {
            Ok(()) => Ok(None),
            Err(err) => Ok(Some(format!(
                "protector removed, but its OS-keyring entry {account} could not be deleted: {err}"
            ))),
        }
    }
}
