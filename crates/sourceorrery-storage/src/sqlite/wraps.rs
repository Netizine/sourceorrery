//! Opening a vault and managing its key wraps: the recovery wrap every
//! vault has, the this-machine wraps whose keys sit in a credential store,
//! and which credential-store entries this vault may delete (ADR 0009).

use std::path::Path;

use rusqlite::{Connection, params};
use sourceorrery_core::audit::{AuditOperation, AuditOutcome};
use sourceorrery_core::{Result, SecretBytes, SecretError, timestamp};
use sourceorrery_crypto::{Ciphertext, SymmetricKey, envelope, random};
use zeroize::Zeroizing;

use super::audit::AuditWriter;
use super::schema::{
    Meta, SettingsTag, crypto, db, from_nanos, nanos, open_connection, read_meta,
    write_settings_tag,
};
use super::{MAX_UNLOCK_ATTEMPTS, SqliteVault};
use crate::keystore::{self, CredentialStore};
use crate::unlock::{RecoveryKeyPrompt, UnlockProvider};
use crate::wrap::{WrapInfo, WrapKind, WrapRecord};

/// `(id, kind_json, wrapped_nonce, wrapped_key, created_on)`
type WrapRow = (String, String, Vec<u8>, Vec<u8>, i64);

/// Length of the recovery wrap's HKDF salt.
const RECOVERY_SALT_LEN: usize = 16;

/// AAD binding a wrapped vault key to its vault and wrap.
fn wrap_aad(vault_id: &str, wrap_id: &str) -> String {
    format!("sourceorrery/v4/wrap/{vault_id}/{wrap_id}")
}

/// The credential-store account this vault creates for a wrap.
pub(super) fn keyring_account(vault_id: &str, wrap_id: &str) -> String {
    format!("vault/{vault_id}/{wrap_id}")
}

/// The recovery wrap's key-encryption key for `typed`, or `None` when
/// `typed` does not have the shape of a recovery key. Case, spaces,
/// hyphens and the look-alike letters do not matter.
fn recovery_kek(meta: &Meta, salt_hex: &str, typed: &SecretBytes) -> Result<Option<SymmetricKey>> {
    let Some(form) = typed
        .expose_utf8()
        .and_then(sourceorrery_crypto::recovery_code_form)
    else {
        return Ok(None);
    };
    let salt = hex::decode(salt_hex)
        .map_err(|_| SecretError::Storage("corrupt recovery wrap salt".to_owned()))?;
    Ok(Some(sourceorrery_crypto::derive_from_secret(
        form.as_bytes(),
        &salt,
        &format!("sourceorrery/v4/recovery-key/{}", meta.id),
    )))
}

pub(super) fn read_wraps(conn: &Connection) -> Result<Vec<WrapRecord>> {
    let mut stmt = conn
        .prepare(
            "SELECT id, kind_json, wrapped_nonce, wrapped_key, created_on
             FROM key_wraps ORDER BY created_on, id",
        )
        .map_err(db)?;
    let raw: Vec<WrapRow> = stmt
        .query_map([], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
            ))
        })
        .map_err(db)?
        .collect::<rusqlite::Result<_>>()
        .map_err(db)?;
    raw.into_iter()
        .map(|(id, kind_json, nonce, wrapped, created_on)| {
            let kind: WrapKind = serde_json::from_str(&kind_json)
                .map_err(|err| SecretError::Storage(format!("corrupt key wrap {id}: {err}")))?;
            Ok(WrapRecord {
                id,
                kind,
                wrapped: Ciphertext::from_parts(&nonce, wrapped).map_err(crypto)?,
                created_on: from_nanos(created_on)?,
            })
        })
        .collect()
}

/// Unwrap the vault key with `kek`.
pub(super) fn try_unwrap(
    meta: &Meta,
    wrap: &WrapRecord,
    kek: &SymmetricKey,
) -> Result<SymmetricKey> {
    envelope::unwrap_key(kek, &wrap.wrapped, wrap_aad(&meta.id, &wrap.id).as_bytes())
        .map_err(crypto)
}

/// The vault key from any this-machine wrap whose key `store` holds.
/// Reasons for each wrap that could not be used are appended.
pub(super) fn try_this_machine(
    meta: &Meta,
    wraps: &[WrapRecord],
    store: &dyn CredentialStore,
    reasons: &mut Vec<String>,
) -> Option<SymmetricKey> {
    let mut installed = false;
    for wrap in wraps {
        let WrapKind::ThisMachine { account, .. } = &wrap.kind else {
            continue;
        };
        installed = true;
        if !store.available() {
            reasons.push(format!(
                "this machine's key: {} is not available ({})",
                store.name(),
                store.unavailable_reason().unwrap_or_default()
            ));
            return None;
        }
        match store.load_key(account) {
            Ok(Some(kek)) => match try_unwrap(meta, wrap, &kek) {
                Ok(dek) => return Some(dek),
                Err(err) => reasons.push(format!("this machine's key: {err}")),
            },
            Ok(None) => reasons.push(format!("this machine's key: no entry in {}", store.name())),
            Err(err) => reasons.push(format!("this machine's key: {err}")),
        }
    }
    if !installed {
        reasons.push("no key for this machine is installed".to_owned());
    }
    None
}

/// Ask `unlock` for the recovery key up to [`MAX_UNLOCK_ATTEMPTS`] times.
/// Returns the vault key; otherwise `None`, with the reasons appended and
/// every rejected attempt audited.
pub(super) fn try_recovery_key(
    conn: &Connection,
    meta: &Meta,
    wraps: &[WrapRecord],
    unlock: &dyn UnlockProvider,
    unkeyed: &AuditWriter<'_>,
    reasons: &mut Vec<String>,
) -> Result<Option<SymmetricKey>> {
    let Some((recovery, salt)) = wraps.iter().find_map(|w| match &w.kind {
        WrapKind::Recovery { salt } => Some((w, salt.as_str())),
        WrapKind::ThisMachine { .. } => None,
    }) else {
        reasons.push("the vault has no recovery key".to_owned());
        return Ok(None);
    };
    for attempt in 1..=MAX_UNLOCK_ATTEMPTS {
        let prompt = RecoveryKeyPrompt {
            vault: &meta.name,
            attempt,
            max_attempts: MAX_UNLOCK_ATTEMPTS,
        };
        let Some(typed) = unlock.recovery_key(&prompt)? else {
            reasons.push("no recovery key supplied".to_owned());
            return Ok(None);
        };
        if let Some(kek) = recovery_kek(meta, salt, &typed)?
            && let Ok(dek) = try_unwrap(meta, recovery, &kek)
        {
            return Ok(Some(dek));
        }
        unkeyed.record(
            conn,
            AuditOperation::VaultOpen,
            None,
            None,
            AuditOutcome::Denied,
            Some("incorrect recovery key"),
        )?;
        reasons.push(format!("recovery key attempt {attempt} rejected"));
    }
    Ok(None)
}

/// Insert a wrap row for `kind`, wrapping `dek` under `kek`.
fn insert_wrap(
    conn: &Connection,
    meta: &Meta,
    dek: &SymmetricKey,
    id: &str,
    kind: &WrapKind,
    kek: &SymmetricKey,
) -> Result<WrapInfo> {
    let wrapped =
        envelope::wrap_key(kek, dek, wrap_aad(&meta.id, id).as_bytes()).map_err(crypto)?;
    let kind_json =
        serde_json::to_string(kind).map_err(|err| SecretError::Storage(err.to_string()))?;
    let created_on = timestamp::now();
    conn.execute(
        "INSERT INTO key_wraps (id, kind_json, wrapped_nonce, wrapped_key, created_on)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            id,
            kind_json,
            wrapped.nonce.as_slice(),
            wrapped.bytes,
            nanos(created_on)?
        ],
    )
    .map_err(db)?;
    Ok(WrapInfo {
        id: id.to_owned(),
        kind: kind.label().to_owned(),
        created_on,
    })
}

/// A recovery key made before the vault it opens has it, so that its owner
/// can write it down first: the setup wizard shows it, and nothing is saved
/// until its review. [`crate::VaultRegistry::create_with_recovery_key`] and
/// [`SqliteVault::change_settings`] install it. It can only be generated,
/// never built from text, so it is always a fresh random code; it is wiped
/// when dropped and never shown by `Debug`. A clone is the same key, so a
/// commit that failed can be tried again with the key already written down.
#[derive(Clone)]
pub struct RecoveryKey(Zeroizing<String>);

impl RecoveryKey {
    /// A new recovery key from the operating system's random source.
    pub fn generate() -> Result<Self> {
        random::recovery_code().map(Self).map_err(crypto)
    }

    /// The key as its owner writes it down
    /// (`XXXXX-XXXXX-XXXXX-XXXXX-XXXXX`).
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub(super) fn into_text(self) -> Zeroizing<String> {
        self.0
    }
}

impl std::fmt::Debug for RecoveryKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RecoveryKey([REDACTED])")
    }
}

/// Install a new recovery wrap and return its recovery key, to show once.
/// Runs inside the caller's write transaction; any earlier recovery wrap
/// is the caller's to remove.
pub(super) fn new_recovery_wrap(
    conn: &Connection,
    meta: &Meta,
    dek: &SymmetricKey,
) -> Result<(WrapInfo, Zeroizing<String>)> {
    let key = RecoveryKey::generate()?;
    let info = recovery_wrap_for(conn, meta, dek, &key)?;
    Ok((info, key.into_text()))
}

/// Install a recovery wrap that `key` opens, inside the caller's write
/// transaction; any earlier recovery wrap is the caller's to remove.
pub(super) fn recovery_wrap_for(
    conn: &Connection,
    meta: &Meta,
    dek: &SymmetricKey,
    key: &RecoveryKey,
) -> Result<WrapInfo> {
    let id = random::random_hex(8).map_err(crypto)?;
    let salt = random::random_bytes::<RECOVERY_SALT_LEN>().map_err(crypto)?;
    let salt_hex = hex::encode(salt);
    let kek = recovery_kek(
        meta,
        &salt_hex,
        &SecretBytes::from_string(key.0.to_string()),
    )?
    .ok_or_else(|| {
        SecretError::Crypto("a generated recovery key has the wrong shape".to_owned())
    })?;
    insert_wrap(
        conn,
        meta,
        dek,
        &id,
        &WrapKind::Recovery { salt: salt_hex },
        &kek,
    )
}

/// Install a this-machine wrap whose key goes into `store`. Runs inside
/// the caller's write transaction; the stored key is removed again when
/// the row cannot be written, so no orphan key is left behind.
pub(super) fn new_this_machine_wrap(
    conn: &Connection,
    meta: &Meta,
    dek: &SymmetricKey,
    store: &dyn CredentialStore,
) -> Result<WrapInfo> {
    if !store.available() {
        return Err(SecretError::Unsupported(format!(
            "{} is not available ({})",
            store.name(),
            store.unavailable_reason().unwrap_or_default()
        )));
    }
    let id = random::random_hex(8).map_err(crypto)?;
    let account = keyring_account(&meta.id, &id);
    let kek = SymmetricKey::generate().map_err(crypto)?;
    store.store_key(&account, &kek)?;
    let kind = WrapKind::ThisMachine {
        service: keystore::SERVICE.to_owned(),
        account: account.clone(),
    };
    match insert_wrap(conn, meta, dek, &id, &kind, &kek) {
        Ok(info) => Ok(info),
        Err(err) => {
            let _ = store.delete_key(&account);
            Err(err)
        }
    }
}

impl SqliteVault {
    /// Credential-store accounts referenced by the vault at `path`, without
    /// opening it, each with whether the account is the one this vault would
    /// have created for that wrap (`vault/<vault id>/<wrap id>`). Wrap rows
    /// are unauthenticated until the vault is open, so callers must not
    /// delete an account that fails that check, and should also make sure
    /// no other vault references it.
    pub(crate) fn keyring_accounts(path: &Path) -> Result<Vec<(String, bool)>> {
        let conn = open_connection(path)?;
        let meta = read_meta(&conn)?;
        Ok(read_wraps(&conn)?
            .into_iter()
            .filter_map(|wrap| match wrap.kind {
                WrapKind::ThisMachine { account, .. } => {
                    let owned = account == keyring_account(&meta.id, &wrap.id);
                    Some((account, owned))
                }
                WrapKind::Recovery { .. } => None,
            })
            .collect())
    }

    /// The vault's key wraps.
    pub fn wraps(&self) -> Result<Vec<WrapInfo>> {
        let conn = self.lock()?;
        Ok(read_wraps(&conn)?.iter().map(WrapRecord::info).collect())
    }

    /// True when `typed` is this vault's recovery key. No audit row.
    pub(super) fn recovery_key_opens(
        &self,
        conn: &Connection,
        typed: &SecretBytes,
    ) -> Result<bool> {
        for wrap in read_wraps(conn)? {
            let WrapKind::Recovery { salt } = &wrap.kind else {
                continue;
            };
            if let Some(kek) = recovery_kek(&self.meta, salt, typed)?
                && let Ok(dek) = try_unwrap(&self.meta, &wrap, &kek)
                && dek == self.dek
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Make `key` the vault's recovery key, inside the caller's write
    /// transaction: the old one stops working, in this file, even if its
    /// wrap row is put back (ADR 0010). Returns the tag of the settings
    /// record, which lists the new set of wraps; the caller's audit event
    /// must carry it.
    pub(super) fn install_recovery_key(
        &self,
        conn: &Connection,
        key: &RecoveryKey,
    ) -> Result<SettingsTag> {
        let meta = self.verified_meta(conn)?;
        let old: Vec<String> = read_wraps(conn)?
            .into_iter()
            .filter(|w| matches!(w.kind, WrapKind::Recovery { .. }))
            .map(|w| w.id)
            .collect();
        for id in &old {
            conn.execute("DELETE FROM key_wraps WHERE id = ?1", params![id])
                .map_err(db)?;
        }
        recovery_wrap_for(conn, &self.meta, &self.dek, key)?;
        write_settings_tag(conn, &self.metadata_key, &meta)
    }

    /// Replace the recovery key: a new one is generated and installed and
    /// the old one stops working, in one transaction. The new key is
    /// returned to be shown once. Audited as `protector_add`, with the new
    /// set of wraps checkpointed. The vault key itself does not change:
    /// whoever holds the old key and an old copy of the file can still
    /// read that copy (ADR 0010).
    pub fn replace_recovery_key(&self) -> Result<Zeroizing<String>> {
        let op = AuditOperation::ProtectorAdd;
        let mut conn = self.lock()?;
        let tx = self.begin(&mut conn, op)?;
        let (key, tag) = match RecoveryKey::generate()
            .and_then(|key| self.install_recovery_key(&tx, &key).map(|tag| (key, tag)))
        {
            Ok(installed) => installed,
            Err(err) => return self.fail(tx, op, None, None, err),
        };
        let code = key.into_text();
        self.audit_settings(&tx, op, AuditOutcome::Success, "recovery key replaced", tag)?;
        tx.commit().map_err(db)?;
        Ok(code)
    }

    /// Let this machine open the vault without asking: a new this-machine
    /// wrap whose key goes into the vault's credential store. Refused when
    /// the store already holds a key that opens it. Audited as
    /// `protector_add`.
    pub fn add_this_machine_key(&self) -> Result<WrapInfo> {
        let op = AuditOperation::ProtectorAdd;
        let mut conn = self.lock()?;
        let tx = self.begin(&mut conn, op)?;
        let wraps = read_wraps(&tx)?;
        let mut reasons = Vec::new();
        if try_this_machine(&self.meta, &wraps, self.store.as_ref(), &mut reasons).is_some() {
            return self.fail(
                tx,
                op,
                None,
                None,
                SecretError::InvalidArgument(
                    "this machine can already open the vault without asking".to_owned(),
                ),
            );
        }
        let added = self.verified_meta(&tx).and_then(|meta| {
            let info = new_this_machine_wrap(&tx, &self.meta, &self.dek, self.store.as_ref())?;
            match write_settings_tag(&tx, &self.metadata_key, &meta) {
                Ok(tag) => Ok((info, tag)),
                Err(err) => {
                    // The key just stored is no use without its row.
                    let _ = self
                        .store
                        .delete_key(&keyring_account(&self.meta.id, &info.id));
                    Err(err)
                }
            }
        });
        let (info, tag) = match added {
            Ok(added) => added,
            Err(err) => return self.fail(tx, op, None, None, err),
        };
        self.audit_settings(
            &tx,
            op,
            AuditOutcome::Success,
            "this machine's key added",
            tag,
        )?;
        tx.commit().map_err(db)?;
        Ok(info)
    }
}
