//! The reveal guard, the second factor and the passphrase hint.
//!
//! The *reveal guard* says what an interactive reveal or export of this
//! vault must present again: the passphrase (even when the OS keyring
//! unlocked the vault), a second-factor code, both or neither. The vault
//! stores the decision and checks what it is shown; the CLI asks for it
//! and refuses when the check fails. The guard never applies to the
//! contract's `get_secret`: an application's reads go through `run` and
//! the SDKs as before.
//!
//! The *second factor* is a TOTP secret sealed with the vault key (so it
//! travels with the file and only an unlocked vault can use it), with the
//! last accepted step so a code is never accepted twice. An enrolment is
//! `verified` once its owner has produced one correct code; until then it
//! does not count.
//!
//! Both live in the authenticated settings record, so a file edit cannot
//! switch the guard off or swap the enrolment. The *passphrase hint* is
//! the opposite: stored in clear, outside the tag, readable before unlock,
//! and shown at the prompt as whatever the file says.
//!
//! Every check, change and refusal is audited under `guard`; the detail
//! names which, and never carries a code, a secret or the hint.

use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use sourceorrery_core::audit::{AuditOperation, AuditOutcome};
use sourceorrery_core::{Result, SecretBytes, SecretError, timestamp};
use sourceorrery_crypto::{TotpSecret, aead, kdf};
use time::OffsetDateTime;

use super::SqliteVault;
use super::protectors::{read_protectors, try_unwrap};
use super::schema::{
    GuardState, PASSPHRASE_HINT_KEY, REVEAL_GUARD_KEY, SECOND_FACTOR_KEY, crypto, db, delete_meta,
    from_nanos, nanos, put_meta, write_settings_tag,
};
use crate::protector::ProtectorKind;

/// What an interactive reveal or export must present again.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevealGuard {
    /// The vault passphrase, typed again, even when the OS keyring unlocked
    /// the vault.
    #[serde(default)]
    pub passphrase: bool,
    /// A code from the enrolled second factor.
    #[serde(default)]
    pub second_factor: bool,
}

impl RevealGuard {
    /// True when nothing is asked for.
    pub fn is_none(self) -> bool {
        !self.passphrase && !self.second_factor
    }

    /// `passphrase`, `second-factor`, `passphrase and second-factor` or
    /// `none`.
    pub fn describe(self) -> &'static str {
        match (self.passphrase, self.second_factor) {
            (true, true) => "passphrase and second-factor",
            (true, false) => "passphrase",
            (false, true) => "second-factor",
            (false, false) => "none",
        }
    }
}

/// What can be said about an enrolment without its secret.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SecondFactorInfo {
    /// When the secret was generated.
    #[serde(with = "time::serde::rfc3339")]
    pub enrolled_on: OffsetDateTime,
    /// Its owner has produced one correct code since enrolment; until then
    /// the guard does not count it.
    pub verified: bool,
}

/// The stored record: the sealed secret and the replay state.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SecondFactorRecord {
    /// Hex nonce of the sealed secret.
    nonce: String,
    /// Hex ciphertext (with tag) of the secret, sealed with the vault key.
    ciphertext: String,
    enrolled_on: i64,
    verified: bool,
    /// The last accepted step; a code for it or an earlier step is refused.
    #[serde(default)]
    last_counter: Option<u64>,
}

/// Most characters a hint may have.
pub const MAX_HINT_LEN: usize = 120;

fn second_factor_aad(vault_id: &str) -> String {
    format!("sourceorrery/v3/second-factor/{vault_id}")
}

fn storage(reason: &str) -> SecretError {
    SecretError::Storage(reason.to_owned())
}

impl SqliteVault {
    fn guard_state(&self) -> Result<GuardState> {
        self.guard
            .lock()
            .map(|state| state.clone())
            .map_err(|_| storage("guard state poisoned"))
    }

    fn second_factor_record(&self) -> Result<Option<SecondFactorRecord>> {
        self.guard_state()?
            .second_factor
            .as_deref()
            .map(|raw| serde_json::from_str(raw).map_err(|_| storage("corrupt second_factor")))
            .transpose()
    }

    /// What an interactive reveal or export must present again.
    pub fn reveal_guard(&self) -> Result<RevealGuard> {
        self.guard_state()?
            .reveal_guard
            .as_deref()
            .map_or(Ok(RevealGuard::default()), |raw| {
                serde_json::from_str(raw).map_err(|_| storage("corrupt reveal_guard"))
            })
    }

    /// The enrolment, without its secret.
    pub fn second_factor(&self) -> Result<Option<SecondFactorInfo>> {
        self.second_factor_record()?
            .map(|record| {
                Ok(SecondFactorInfo {
                    enrolled_on: from_nanos(record.enrolled_on)?,
                    verified: record.verified,
                })
            })
            .transpose()
    }

    /// The passphrase hint as the file stores it (in clear, unauthenticated).
    pub fn passphrase_hint(&self) -> Option<String> {
        self.meta.passphrase_hint.clone()
    }

    /// Write `state` into the file under a fresh settings tag, record the
    /// change and make it the live state.
    fn commit_guard(&self, conn: &mut Connection, state: GuardState, detail: &str) -> Result<()> {
        let tx = self.begin(conn, AuditOperation::Guard)?;
        match &state.second_factor {
            Some(raw) => put_meta(&tx, SECOND_FACTOR_KEY, raw)?,
            None => delete_meta(&tx, SECOND_FACTOR_KEY)?,
        }
        match &state.reveal_guard {
            Some(raw) => put_meta(&tx, REVEAL_GUARD_KEY, raw)?,
            None => delete_meta(&tx, REVEAL_GUARD_KEY)?,
        }
        write_settings_tag(&tx, &self.metadata_key, &self.meta.with_guard(&state))?;
        self.audit(
            &tx,
            AuditOperation::Guard,
            None,
            None,
            AuditOutcome::Success,
            Some(detail),
        )?;
        tx.commit().map_err(db)?;
        *self
            .guard
            .lock()
            .map_err(|_| storage("guard state poisoned"))? = state;
        Ok(())
    }

    /// Set what an interactive reveal or export must present again. Asking
    /// for the second factor needs a verified enrolment.
    pub fn set_reveal_guard(&self, guard: RevealGuard) -> Result<RevealGuard> {
        let mut conn = self.lock()?;
        if guard.second_factor && !self.second_factor()?.is_some_and(|f| f.verified) {
            let tx = self.begin(&mut conn, AuditOperation::Guard)?;
            return self.fail(
                tx,
                AuditOperation::Guard,
                None,
                None,
                SecretError::InvalidArgument(
                    "the guard cannot ask for a second factor before one is enrolled and \
                     verified"
                        .to_owned(),
                ),
            );
        }
        let mut state = self.guard_state()?;
        state.reveal_guard = if guard.is_none() {
            None
        } else {
            Some(serde_json::to_string(&guard).map_err(|err| storage(&err.to_string()))?)
        };
        self.commit_guard(
            &mut conn,
            state,
            &format!("reveal guard set: {}", guard.describe()),
        )?;
        Ok(guard)
    }

    /// Enrol a new second factor: a fresh secret, sealed with the vault
    /// key, returned once so its owner can scan or type it into an
    /// authenticator. It counts for nothing until
    /// [`SqliteVault::verify_second_factor`] has accepted one code. A
    /// verified enrolment must be disabled first; an unverified one is
    /// replaced.
    pub fn enrol_second_factor(&self) -> Result<TotpSecret> {
        let mut conn = self.lock()?;
        if self.second_factor()?.is_some_and(|f| f.verified) {
            let tx = self.begin(&mut conn, AuditOperation::Guard)?;
            return self.fail(
                tx,
                AuditOperation::Guard,
                None,
                None,
                SecretError::InvalidArgument(
                    "a second factor is already enrolled and verified; disable it before \
                     enrolling another"
                        .to_owned(),
                ),
            );
        }
        let secret = TotpSecret::generate().map_err(crypto)?;
        let sealed = aead::seal(
            &self.dek,
            second_factor_aad(&self.meta.id).as_bytes(),
            secret.expose(),
        )
        .map_err(crypto)?;
        let record = SecondFactorRecord {
            nonce: hex::encode(sealed.nonce),
            ciphertext: hex::encode(&sealed.bytes),
            enrolled_on: nanos(timestamp::now())?,
            verified: false,
            last_counter: None,
        };
        let mut state = self.guard_state()?;
        state.second_factor =
            Some(serde_json::to_string(&record).map_err(|err| storage(&err.to_string()))?);
        self.commit_guard(&mut conn, state, "second factor enrolled (unverified)")?;
        Ok(secret)
    }

    /// Check a code against the enrolled second factor at `now`. The first
    /// accepted code verifies the enrolment; every accepted code advances
    /// the replay guard. A refused code is audited as `denied` and answers
    /// `false`; no enrolment at all is an error.
    pub fn verify_second_factor(&self, code: &str, now: OffsetDateTime) -> Result<bool> {
        let mut conn = self.lock()?;
        let Some(mut record) = self.second_factor_record()? else {
            return Err(SecretError::InvalidArgument(
                "no second factor is enrolled for this vault".to_owned(),
            ));
        };
        let secret = self.open_second_factor(&record)?;
        let unix = u64::try_from(now.unix_timestamp()).unwrap_or(0);
        let Some(counter) = secret.verify(code, unix, record.last_counter) else {
            drop(secret);
            self.audit(
                &conn,
                AuditOperation::Guard,
                None,
                None,
                AuditOutcome::Denied,
                Some("second-factor code refused"),
            )?;
            return Ok(false);
        };
        drop(secret);
        let first = !record.verified;
        record.verified = true;
        record.last_counter = Some(counter);
        let mut state = self.guard_state()?;
        state.second_factor =
            Some(serde_json::to_string(&record).map_err(|err| storage(&err.to_string()))?);
        self.commit_guard(
            &mut conn,
            state,
            if first {
                "second factor verified"
            } else {
                "second-factor code accepted"
            },
        )?;
        Ok(true)
    }

    fn open_second_factor(&self, record: &SecondFactorRecord) -> Result<TotpSecret> {
        let nonce = hex::decode(&record.nonce).map_err(|_| storage("corrupt second_factor"))?;
        let bytes =
            hex::decode(&record.ciphertext).map_err(|_| storage("corrupt second_factor"))?;
        let sealed = aead::Ciphertext::from_parts(&nonce, bytes).map_err(crypto)?;
        let plain = aead::open(
            &self.dek,
            second_factor_aad(&self.meta.id).as_bytes(),
            &sealed,
        )
        .map_err(crypto)?;
        TotpSecret::from_bytes(plain.to_vec()).map_err(crypto)
    }

    /// Remove the enrolment. A guard that asked for the second factor stops
    /// asking for it (and keeps asking for the passphrase if it did).
    pub fn disable_second_factor(&self) -> Result<()> {
        let mut conn = self.lock()?;
        if self.second_factor_record()?.is_none() {
            return Err(SecretError::InvalidArgument(
                "no second factor is enrolled for this vault".to_owned(),
            ));
        }
        let mut guard = self.reveal_guard()?;
        guard.second_factor = false;
        let mut state = self.guard_state()?;
        state.second_factor = None;
        state.reveal_guard = if guard.is_none() {
            None
        } else {
            Some(serde_json::to_string(&guard).map_err(|err| storage(&err.to_string()))?)
        };
        self.commit_guard(&mut conn, state, "second factor disabled")
    }

    /// True when `passphrase` unlocks this vault through one of its
    /// passphrase protectors (a recovery code is one). No audit row.
    fn passphrase_unlocks(&self, conn: &Connection, passphrase: &SecretBytes) -> Result<bool> {
        for protector in read_protectors(conn)? {
            let ProtectorKind::Passphrase { salt, params } = &protector.kind else {
                continue;
            };
            if !params.within_limits() {
                continue;
            }
            let salt = hex::decode(salt).map_err(|_| storage("corrupt salt"))?;
            let kek = kdf::derive_key(passphrase.expose(), &salt, *params).map_err(crypto)?;
            if let Ok((dek, _)) = try_unwrap(&self.meta, &protector, &kek)
                && dek == self.dek
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Check `passphrase` against the passphrase protectors without
    /// reopening the vault: what the reveal guard asks for. The outcome is
    /// audited under `guard`.
    pub fn verify_passphrase(&self, passphrase: &SecretBytes) -> Result<bool> {
        let conn = self.lock()?;
        let ok = !passphrase.is_empty() && self.passphrase_unlocks(&conn, passphrase)?;
        self.audit(
            &conn,
            AuditOperation::Guard,
            None,
            None,
            if ok {
                AuditOutcome::Success
            } else {
                AuditOutcome::Denied
            },
            Some(if ok {
                "passphrase verified"
            } else {
                "incorrect passphrase"
            }),
        )?;
        Ok(ok)
    }

    /// Store a passphrase hint in clear in the file, or clear it with
    /// `None`. At most [`MAX_HINT_LEN`] characters, no control characters,
    /// and never the passphrase itself: a hint that unlocks the vault is
    /// refused.
    pub fn set_passphrase_hint(&self, hint: Option<&str>) -> Result<()> {
        let conn = self.lock()?;
        if let Some(hint) = hint {
            let hint = hint.trim();
            if hint.is_empty() {
                return Err(SecretError::InvalidArgument(
                    "a hint must not be empty; clear it instead".to_owned(),
                ));
            }
            if hint.chars().count() > MAX_HINT_LEN {
                return Err(SecretError::InvalidArgument(format!(
                    "a hint has at most {MAX_HINT_LEN} characters"
                )));
            }
            if hint.chars().any(char::is_control) {
                return Err(SecretError::InvalidArgument(
                    "a hint cannot contain control characters".to_owned(),
                ));
            }
            if self.passphrase_unlocks(&conn, &SecretBytes::from(hint))? {
                self.audit(
                    &conn,
                    AuditOperation::Guard,
                    None,
                    None,
                    AuditOutcome::Denied,
                    Some("hint refused: it unlocks the vault"),
                )?;
                return Err(SecretError::InvalidArgument(
                    "that hint is the passphrase itself (or a recovery code); a hint is stored \
                     in clear in the vault file and must not unlock it"
                        .to_owned(),
                ));
            }
            put_meta(&conn, PASSPHRASE_HINT_KEY, hint)?;
        } else {
            delete_meta(&conn, PASSPHRASE_HINT_KEY)?;
        }
        self.audit(
            &conn,
            AuditOperation::Guard,
            None,
            None,
            AuditOutcome::Success,
            Some(if hint.is_some() {
                "passphrase hint set"
            } else {
                "passphrase hint cleared"
            }),
        )
    }

    /// A key derived for tests and the recovery-code check: whether a
    /// passphrase unlocks, without an audit row.
    #[cfg(test)]
    pub(super) fn passphrase_unlocks_quietly(&self, passphrase: &SecretBytes) -> Result<bool> {
        let conn = self.lock()?;
        self.passphrase_unlocks(&conn, passphrase)
    }
}
