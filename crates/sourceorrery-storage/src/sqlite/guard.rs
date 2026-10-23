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
use super::protectors::{passphrase_candidates, read_protectors, try_unwrap};
use super::schema::{
    GuardState, PASSPHRASE_HINT_KEY, REVEAL_GUARD_KEY, SECOND_FACTOR_KEY, crypto, db, delete_meta,
    from_nanos, nanos, put_meta, read_meta, write_settings_tag,
};
use crate::integrity;
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

fn parse_record(raw: &str) -> Result<SecondFactorRecord> {
    serde_json::from_str(raw).map_err(|_| storage("corrupt second_factor"))
}

fn encode<T: Serialize>(value: &T) -> Result<String> {
    serde_json::to_string(value).map_err(|err| storage(&err.to_string()))
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
            .map(parse_record)
            .transpose()
    }

    /// The guard state as the file holds it right now, under a settings
    /// tag that verifies: what every change is applied to. Another process
    /// may have changed it since this handle unlocked the vault, so the
    /// snapshot taken then is never written back.
    fn stored_guard_state(&self, conn: &Connection) -> Result<GuardState> {
        let meta = read_meta(conn)?;
        let fields = meta.settings_fields()?;
        if !integrity::verify_settings_tag(
            &self.metadata_key,
            &fields,
            meta.settings_tag.as_deref(),
        ) {
            return Err(SecretError::Crypto(
                "vault settings integrity check failed (the guard state was altered)".to_owned(),
            ));
        }
        Ok(meta.guard)
    }

    fn write_guard_state(&self, conn: &Connection, state: &GuardState) -> Result<()> {
        match &state.second_factor {
            Some(raw) => put_meta(conn, SECOND_FACTOR_KEY, raw)?,
            None => delete_meta(conn, SECOND_FACTOR_KEY)?,
        }
        match &state.reveal_guard {
            Some(raw) => put_meta(conn, REVEAL_GUARD_KEY, raw)?,
            None => delete_meta(conn, REVEAL_GUARD_KEY)?,
        }
        write_settings_tag(conn, &self.metadata_key, &self.meta.with_guard(state))
    }

    fn remember(&self, state: GuardState) -> Result<()> {
        *self
            .guard
            .lock()
            .map_err(|_| storage("guard state poisoned"))? = state;
        Ok(())
    }

    /// Apply `change` to the stored guard state, in one transaction that
    /// passes the checks every operation passes, and record it. A refusal
    /// from `change` is audited as a failure and nothing is written.
    fn change_guard(
        &self,
        conn: &mut Connection,
        detail: &str,
        change: impl FnOnce(&mut GuardState) -> Result<()>,
    ) -> Result<GuardState> {
        let tx = self.begin(conn, AuditOperation::Guard)?;
        let mut state = match self.stored_guard_state(&tx) {
            Ok(state) => state,
            Err(err) => return self.fail(tx, AuditOperation::Guard, None, None, err),
        };
        if let Err(err) = change(&mut state) {
            return self.fail(tx, AuditOperation::Guard, None, None, err);
        }
        self.write_guard_state(&tx, &state)?;
        self.audit(
            &tx,
            AuditOperation::Guard,
            None,
            None,
            AuditOutcome::Success,
            Some(detail),
        )?;
        tx.commit().map_err(db)?;
        self.remember(state.clone())?;
        Ok(state)
    }

    /// One audited guard outcome, through the same checks every operation
    /// passes (a blocked vault records nothing).
    fn record_guard(
        &self,
        conn: &mut Connection,
        outcome: AuditOutcome,
        detail: &str,
    ) -> Result<()> {
        let tx = self.begin(conn, AuditOperation::Guard)?;
        self.audit(
            &tx,
            AuditOperation::Guard,
            None,
            None,
            outcome,
            Some(detail),
        )?;
        tx.commit().map_err(db)
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

    /// Set what an interactive reveal or export must present again. Asking
    /// for the second factor needs a verified enrolment.
    pub fn set_reveal_guard(&self, guard: RevealGuard) -> Result<RevealGuard> {
        let mut conn = self.lock()?;
        let detail = format!("reveal guard set: {}", guard.describe());
        self.change_guard(&mut conn, &detail, |state| {
            let verified = state
                .second_factor
                .as_deref()
                .map(parse_record)
                .transpose()?
                .is_some_and(|record| record.verified);
            if guard.second_factor && !verified {
                return Err(SecretError::InvalidArgument(
                    "the guard cannot ask for a second factor before one is enrolled and \
                     verified"
                        .to_owned(),
                ));
            }
            state.reveal_guard = if guard.is_none() {
                None
            } else {
                Some(encode(&guard)?)
            };
            Ok(())
        })?;
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
        let raw = encode(&record)?;
        self.change_guard(&mut conn, "second factor enrolled (unverified)", |state| {
            let verified = state
                .second_factor
                .as_deref()
                .map(parse_record)
                .transpose()?
                .is_some_and(|record| record.verified);
            if verified {
                return Err(SecretError::InvalidArgument(
                    "a second factor is already enrolled and verified; disable it before \
                     enrolling another"
                        .to_owned(),
                ));
            }
            state.second_factor = Some(raw);
            Ok(())
        })?;
        Ok(secret)
    }

    /// Check a code against the enrolled second factor at `now`. The first
    /// accepted code verifies the enrolment; every accepted code advances
    /// the replay guard. A refused code is audited as `denied` and answers
    /// `false`; no enrolment at all is an error.
    pub fn verify_second_factor(&self, code: &str, now: OffsetDateTime) -> Result<bool> {
        let mut conn = self.lock()?;
        let Some(snapshot) = self.second_factor_record()? else {
            return Err(SecretError::InvalidArgument(
                "no second factor is enrolled for this vault".to_owned(),
            ));
        };
        let secret = self.open_second_factor(&snapshot)?;
        let unix = u64::try_from(now.unix_timestamp()).unwrap_or(0);
        let accepted = secret.verify(code, unix, snapshot.last_counter);
        drop(secret);
        let Some(counter) = accepted else {
            self.record_guard(
                &mut conn,
                AuditOutcome::Denied,
                "second-factor code refused",
            )?;
            return Ok(false);
        };
        // The replay guard is judged against the file, not the snapshot:
        // another process may have accepted this step since this handle
        // unlocked the vault, and a step is good once.
        let tx = self.begin(&mut conn, AuditOperation::Guard)?;
        let mut state = match self.stored_guard_state(&tx) {
            Ok(state) => state,
            Err(err) => return self.fail(tx, AuditOperation::Guard, None, None, err),
        };
        let stored = state.second_factor.as_deref().map(parse_record).transpose();
        let mut record = match stored {
            Ok(Some(record)) if record.ciphertext == snapshot.ciphertext => record,
            Ok(_) => {
                return self.fail(
                    tx,
                    AuditOperation::Guard,
                    None,
                    None,
                    SecretError::InvalidArgument(
                        "the second factor changed while the code was checked; try again"
                            .to_owned(),
                    ),
                );
            }
            Err(err) => return self.fail(tx, AuditOperation::Guard, None, None, err),
        };
        if record.last_counter.is_some_and(|last| counter <= last) {
            drop(tx);
            self.record_guard(
                &mut conn,
                AuditOutcome::Denied,
                "second-factor code refused (already used)",
            )?;
            return Ok(false);
        }
        let first = !record.verified;
        record.verified = true;
        record.last_counter = Some(counter);
        state.second_factor = Some(encode(&record)?);
        self.write_guard_state(&tx, &state)?;
        self.audit(
            &tx,
            AuditOperation::Guard,
            None,
            None,
            AuditOutcome::Success,
            Some(if first {
                "second factor verified"
            } else {
                "second-factor code accepted"
            }),
        )?;
        tx.commit().map_err(db)?;
        self.remember(state)?;
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
        self.change_guard(&mut conn, "second factor disabled", |state| {
            if state.second_factor.is_none() {
                return Err(SecretError::InvalidArgument(
                    "no second factor is enrolled for this vault".to_owned(),
                ));
            }
            let mut guard: RevealGuard = state
                .reveal_guard
                .as_deref()
                .map(|raw| serde_json::from_str(raw).map_err(|_| storage("corrupt reveal_guard")))
                .transpose()?
                .unwrap_or_default();
            guard.second_factor = false;
            state.second_factor = None;
            state.reveal_guard = if guard.is_none() {
                None
            } else {
                Some(encode(&guard)?)
            };
            Ok(())
        })?;
        Ok(())
    }

    /// True when `passphrase` unlocks this vault through one of its
    /// passphrase protectors (a recovery code is one). No audit row.
    fn passphrase_unlocks(&self, conn: &Connection, passphrase: &SecretBytes) -> Result<bool> {
        let protectors = read_protectors(conn)?;
        for candidate in passphrase_candidates(passphrase) {
            for protector in &protectors {
                let ProtectorKind::Passphrase { salt, params } = &protector.kind else {
                    continue;
                };
                if !params.within_limits() {
                    continue;
                }
                let Ok(salt) = hex::decode(salt) else {
                    continue;
                };
                let Ok(kek) = kdf::derive_key(candidate.expose(), &salt, *params) else {
                    continue;
                };
                if let Ok((dek, _)) = try_unwrap(&self.meta, protector, &kek)
                    && dek == self.dek
                {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }

    /// Check `passphrase` against the passphrase protectors without
    /// reopening the vault: what the reveal guard asks for. The outcome is
    /// audited under `guard`.
    pub fn verify_passphrase(&self, passphrase: &SecretBytes) -> Result<bool> {
        let mut conn = self.lock()?;
        let ok = !passphrase.is_empty() && self.passphrase_unlocks(&conn, passphrase)?;
        self.record_guard(
            &mut conn,
            if ok {
                AuditOutcome::Success
            } else {
                AuditOutcome::Denied
            },
            if ok {
                "passphrase verified"
            } else {
                "incorrect passphrase"
            },
        )?;
        Ok(ok)
    }

    /// Store a passphrase hint in clear in the file, or clear it with
    /// `None`. At most [`MAX_HINT_LEN`] characters, no control characters,
    /// and never the passphrase itself: a hint that unlocks the vault is
    /// refused.
    pub fn set_passphrase_hint(&self, hint: Option<&str>) -> Result<()> {
        let mut conn = self.lock()?;
        let hint = hint.map(str::trim);
        if let Some(hint) = hint {
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
        }
        // The hint is outside every tag, but writing it is still an
        // operation: one transaction, the same checks, one audit row.
        let tx = self.begin(&mut conn, AuditOperation::Guard)?;
        match hint {
            Some(hint) => {
                if self.passphrase_unlocks(&tx, &SecretBytes::from(hint))? {
                    drop(tx);
                    self.record_guard(
                        &mut conn,
                        AuditOutcome::Denied,
                        "hint refused: it unlocks the vault",
                    )?;
                    return Err(SecretError::InvalidArgument(
                        "that hint is the passphrase itself (or a recovery code); a hint is \
                         stored in clear in the vault file and must not unlock it"
                            .to_owned(),
                    ));
                }
                put_meta(&tx, PASSPHRASE_HINT_KEY, hint)?;
            }
            None => delete_meta(&tx, PASSPHRASE_HINT_KEY)?,
        }
        self.audit(
            &tx,
            AuditOperation::Guard,
            None,
            None,
            AuditOutcome::Success,
            Some(if hint.is_some() {
                "passphrase hint set"
            } else {
                "passphrase hint cleared"
            }),
        )?;
        tx.commit().map_err(db)
    }

    /// A key derived for tests and the recovery-code check: whether a
    /// passphrase unlocks, without an audit row.
    #[cfg(test)]
    pub(super) fn passphrase_unlocks_quietly(&self, passphrase: &SecretBytes) -> Result<bool> {
        let conn = self.lock()?;
        self.passphrase_unlocks(&conn, passphrase)
    }
}
