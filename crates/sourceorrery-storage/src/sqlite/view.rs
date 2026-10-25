//! The view check (ADR 0009): an optional password, with an optional hint
//! and an optional authenticator code on top of it, that decides whether a
//! person may view the vault and reveal a value.
//!
//! It is a check, not encryption: it does not protect the values, which the
//! vault key protects as before. What it stops is a person using
//! SourceOrrery to look (the browser, listings, a reveal) without the
//! password and, when one is enrolled, the phone. Commands that run a
//! program and the SDKs never ask for it.
//!
//! Everything it keeps is sealed under the vault key and covered by the
//! authenticated settings record, whose tag the audit event of every change
//! records, so an older copy of the record is refused: the password's
//! salted Argon2id hash, the hint, the authenticator's TOTP secret with the
//! last accepted step (a code is good once), and the count of consecutive
//! wrong answers. After
//! [`FREE_FAILURES`] wrong answers in a row each further attempt waits, 30
//! seconds doubling to 15 minutes; the recovery key always passes. Every
//! answer, right or wrong, and every change is audited under `guard`; the
//! detail names the outcome, never an answer.

use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use sourceorrery_core::audit::{AuditOperation, AuditOutcome};
use sourceorrery_core::{Result, SecretBytes, SecretError, timestamp};
use sourceorrery_crypto::{Argon2Params, SymmetricKey, TotpSecret, aead, kdf, random};
use time::OffsetDateTime;
use zeroize::Zeroizing;

use super::SqliteVault;
use super::schema::{
    CHECK_FAILURES_KEY, PASSWORD_HINT_KEY, PASSWORD_KEY, SECOND_FACTOR_KEY, SettingsTag, ViewState,
    crypto, db, delete_meta, from_nanos, nanos, put_meta, write_settings_tag,
};

/// Most characters a hint may have.
pub const MAX_HINT_LEN: usize = 120;

/// Wrong answers in a row before each further attempt has to wait.
pub const FREE_FAILURES: u32 = 5;

/// The first wait, in seconds, once [`FREE_FAILURES`] is reached.
const FIRST_WAIT_SECS: i64 = 30;

/// The longest wait, in seconds.
const LONGEST_WAIT_SECS: i64 = 15 * 60;

/// What viewing this vault asks for.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct ViewCheck {
    /// The vault's password.
    pub password: bool,
    /// A code from the enrolled authenticator, on top of the password.
    pub authenticator: bool,
}

impl ViewCheck {
    /// True when viewing asks for nothing.
    pub fn is_none(self) -> bool {
        !self.password
    }

    /// `none`, `password` or `password and authenticator`.
    pub fn describe(self) -> &'static str {
        match (self.password, self.authenticator) {
            (false, _) => "none",
            (true, false) => "password",
            (true, true) => "password and authenticator",
        }
    }
}

/// The answers a person gave to the view check. Any of them may be missing;
/// the recovery key, when given, passes on its own.
#[derive(Default)]
pub struct ViewAnswers {
    /// The vault's password.
    pub password: Option<SecretBytes>,
    /// A code from the authenticator app.
    pub code: Option<String>,
    /// The vault's recovery key, which passes the check by itself.
    pub recovery_key: Option<SecretBytes>,
}

impl std::fmt::Debug for ViewAnswers {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ViewAnswers")
            .field("password", &self.password.as_ref().map(|_| "[REDACTED]"))
            .field("code", &self.code.as_ref().map(|_| "[REDACTED]"))
            .field(
                "recovery_key",
                &self.recovery_key.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

/// What can be said about an authenticator enrolment without its secret.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SecondFactorInfo {
    /// When the secret was generated.
    #[serde(with = "time::serde::rfc3339")]
    pub enrolled_on: OffsetDateTime,
    /// Its owner has produced one correct code since enrolment; until then
    /// the view check does not ask for it.
    pub verified: bool,
}

/// How [`SqliteVault::change_settings`] changes the password.
#[derive(Debug)]
pub enum PasswordChange {
    /// Leave it as it is.
    Keep,
    /// Set or change it, with an optional hint (see
    /// [`SqliteVault::set_password`] for the rules).
    Set {
        password: SecretBytes,
        hint: Option<String>,
        params: Argon2Params,
    },
    /// Remove the view check: the password, its hint and the authenticator.
    Clear,
}

/// How [`SqliteVault::change_settings`] changes the authenticator.
#[derive(Debug)]
pub enum AuthenticatorChange {
    /// Leave it as it is.
    Keep,
    /// Remove it; the password stays.
    Remove,
    /// Enrol `secret`, which its owner has verified already: `counter` is
    /// the step of the code they gave, so that code is not accepted again.
    /// It is a second check on top of the password, so one must be set.
    Verified { secret: TotpSecret, counter: u64 },
}

/// A sealed value as stored: hex nonce and hex ciphertext with its tag.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Sealed {
    nonce: String,
    ciphertext: String,
}

/// The password's salted Argon2id hash, sealed inside a [`Sealed`].
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PasswordHash {
    salt: String,
    params: Argon2Params,
    hash: String,
}

/// The stored authenticator record: the sealed secret and the replay state.
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

/// Consecutive wrong answers and when the last one was given.
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CheckFailures {
    count: u32,
    last_on: i64,
}

fn storage(reason: &str) -> SecretError {
    SecretError::Storage(reason.to_owned())
}

fn encode<T: Serialize>(value: &T) -> Result<String> {
    serde_json::to_string(value).map_err(|err| storage(&err.to_string()))
}

fn parse<T: for<'de> Deserialize<'de>>(raw: &str, what: &str) -> Result<T> {
    serde_json::from_str(raw).map_err(|_| storage(&format!("corrupt {what}")))
}

fn aad(kind: &str, vault_id: &str) -> String {
    format!("sourceorrery/v4/{kind}/{vault_id}")
}

fn denied(reason: &str) -> SecretError {
    SecretError::PermissionDenied(format!("the view check refused: {reason}"))
}

/// Seconds still to wait before the next answer is weighed, if any.
fn wait_secs(failures: CheckFailures, now: OffsetDateTime) -> Result<Option<i64>> {
    if failures.count < FREE_FAILURES {
        return Ok(None);
    }
    let doublings = failures.count - FREE_FAILURES;
    let wait = if doublings >= 5 {
        LONGEST_WAIT_SECS
    } else {
        (FIRST_WAIT_SECS << doublings).min(LONGEST_WAIT_SECS)
    };
    let elapsed_nanos = i128::from(nanos(now)?) - i128::from(failures.last_on);
    let elapsed = i64::try_from(elapsed_nanos.max(0) / 1_000_000_000).unwrap_or(i64::MAX);
    Ok((elapsed < wait).then_some(wait - elapsed))
}

/// Whether the outcome of one answer was right, and what the audit row and
/// the person are told.
enum Verdict {
    Passed(&'static str),
    Refused(&'static str),
}

impl SqliteVault {
    fn view_state(&self) -> Result<ViewState> {
        self.view
            .lock()
            .map(|state| state.clone())
            .map_err(|_| storage("view-check state poisoned"))
    }

    /// The view-check state as the file holds it now, verified, and
    /// remembered for this handle (SR11 of the 2026-10-25 review): another
    /// process may have set, replaced or cleared the check, enrolled or
    /// removed an authenticator, or counted wrong answers since this handle
    /// opened the vault. One read transaction, so the snapshot is
    /// consistent; nothing is written.
    fn current_view_state(&self) -> Result<ViewState> {
        let mut conn = self.lock()?;
        let tx = conn.transaction().map_err(db)?;
        let state = self.stored_view_state(&tx)?;
        drop(tx);
        drop(conn);
        self.remember(state.clone())?;
        Ok(state)
    }

    pub(super) fn remember(&self, state: ViewState) -> Result<()> {
        *self
            .view
            .lock()
            .map_err(|_| storage("view-check state poisoned"))? = state;
        Ok(())
    }

    /// The view-check state as the file holds it right now, in a settings
    /// record [`SqliteVault::verified_meta`] accepts: what every change and
    /// every answer is applied to. Another process may have changed it since
    /// this handle opened the vault, so the snapshot taken then is never
    /// written back.
    pub(super) fn stored_view_state(&self, conn: &Connection) -> Result<ViewState> {
        Ok(self.verified_meta(conn)?.view)
    }

    /// Write `state` and the settings tag that covers it; the caller's
    /// audit event records the tag.
    pub(super) fn write_view_state(
        &self,
        conn: &Connection,
        state: &ViewState,
    ) -> Result<SettingsTag> {
        for (key, value) in [
            (PASSWORD_KEY, &state.password),
            (PASSWORD_HINT_KEY, &state.password_hint),
            (SECOND_FACTOR_KEY, &state.second_factor),
            (CHECK_FAILURES_KEY, &state.check_failures),
        ] {
            match value {
                Some(raw) => put_meta(conn, key, raw)?,
                None => delete_meta(conn, key)?,
            }
        }
        write_settings_tag(conn, &self.metadata_key, &self.meta.with_view(state))
    }

    /// Apply `change` to the stored state, in one transaction that passes
    /// the checks every operation passes, and record it. A refusal from
    /// `change` is audited as a failure and nothing is written.
    fn change_view(
        &self,
        detail: &str,
        change: impl FnOnce(&mut ViewState) -> Result<()>,
    ) -> Result<ViewState> {
        let mut conn = self.lock()?;
        let tx = self.begin(&mut conn, AuditOperation::Guard)?;
        let mut state = match self.stored_view_state(&tx) {
            Ok(state) => state,
            Err(err) => return self.fail(tx, AuditOperation::Guard, None, None, err),
        };
        if let Err(err) = change(&mut state) {
            return self.fail(tx, AuditOperation::Guard, None, None, err);
        }
        let tag = self.write_view_state(&tx, &state)?;
        self.audit_settings(
            &tx,
            AuditOperation::Guard,
            AuditOutcome::Success,
            detail,
            tag,
        )?;
        tx.commit().map_err(db)?;
        drop(conn);
        self.remember(state.clone())?;
        Ok(state)
    }

    fn seal(&self, kind: &str, plaintext: &[u8]) -> Result<String> {
        self.seal_bound(&aad(kind, &self.meta.id), plaintext)
    }

    fn unseal(&self, kind: &str, raw: &str) -> Result<Zeroizing<Vec<u8>>> {
        self.unseal_bound(&aad(kind, &self.meta.id), raw, kind)
    }

    /// Seal `plaintext` under the vault key, bound to `aad`, as the stored
    /// `{"nonce", "ciphertext"}` record.
    pub(super) fn seal_bound(&self, aad: &str, plaintext: &[u8]) -> Result<String> {
        let sealed = aead::seal(&self.dek, aad.as_bytes(), plaintext).map_err(crypto)?;
        encode(&Sealed {
            nonce: hex::encode(sealed.nonce),
            ciphertext: hex::encode(&sealed.bytes),
        })
    }

    /// Open a record [`Self::seal_bound`] wrote with the same `aad`; `what`
    /// names it in errors.
    pub(super) fn unseal_bound(
        &self,
        aad: &str,
        raw: &str,
        what: &str,
    ) -> Result<Zeroizing<Vec<u8>>> {
        let sealed: Sealed = parse(raw, what)?;
        let nonce = hex::decode(&sealed.nonce).map_err(|_| storage(&format!("corrupt {what}")))?;
        let bytes =
            hex::decode(&sealed.ciphertext).map_err(|_| storage(&format!("corrupt {what}")))?;
        let ciphertext = aead::Ciphertext::from_parts(&nonce, bytes).map_err(crypto)?;
        aead::open(&self.dek, aad.as_bytes(), &ciphertext).map_err(crypto)
    }

    /// What viewing this vault asks for now, as the file holds it (not as
    /// it was when this handle opened the vault).
    pub fn view_check(&self) -> Result<ViewCheck> {
        let state = self.current_view_state()?;
        let authenticator = state
            .second_factor
            .as_deref()
            .map(|raw| parse::<SecondFactorRecord>(raw, "second factor"))
            .transpose()?
            .is_some_and(|record| record.verified);
        Ok(ViewCheck {
            password: state.password.is_some(),
            authenticator: state.password.is_some() && authenticator,
        })
    }

    /// True when the vault was opened with its recovery key, which passes
    /// the view check by itself.
    pub fn opened_with_recovery_key(&self) -> bool {
        self.opened_with_recovery_key
    }

    /// The password hint, shown at the password prompt: the current one.
    pub fn password_hint(&self) -> Result<Option<String>> {
        let Some(raw) = self.current_view_state()?.password_hint else {
            return Ok(None);
        };
        let plain = self.unseal("password-hint", &raw)?;
        String::from_utf8(plain.to_vec())
            .map(Some)
            .map_err(|_| storage("corrupt password hint"))
    }

    /// The authenticator enrolment, without its secret: the current one.
    pub fn authenticator(&self) -> Result<Option<SecondFactorInfo>> {
        self.current_view_state()?
            .second_factor
            .as_deref()
            .map(|raw| {
                let record: SecondFactorRecord = parse(raw, "second factor")?;
                Ok(SecondFactorInfo {
                    enrolled_on: from_nanos(record.enrolled_on)?,
                    verified: record.verified,
                })
            })
            .transpose()
    }

    /// Set or change the password, with an optional hint (at most
    /// [`MAX_HINT_LEN`] characters, no control characters, never the
    /// password itself). The hash is salted Argon2id with `params`; the hash
    /// and the hint are sealed under the vault key. An enrolled
    /// authenticator stays, and the count of wrong answers starts again.
    pub fn set_password(
        &self,
        password: &SecretBytes,
        hint: Option<&str>,
        params: Argon2Params,
    ) -> Result<()> {
        let (sealed_password, sealed_hint) = self.seal_password(password, hint, params)?;
        let changed = self.view_state()?.password.is_some();
        self.change_view(
            if changed {
                "password changed"
            } else {
                "password set"
            },
            |state| {
                state.password = Some(sealed_password);
                state.password_hint = sealed_hint;
                state.check_failures = None;
                Ok(())
            },
        )?;
        Ok(())
    }

    /// The sealed salted hash of `password` and the sealed hint, checked
    /// as [`SqliteVault::set_password`] describes.
    fn seal_password(
        &self,
        password: &SecretBytes,
        hint: Option<&str>,
        params: Argon2Params,
    ) -> Result<(String, Option<String>)> {
        if password.is_empty() {
            return Err(SecretError::InvalidArgument(
                "a password must not be empty".to_owned(),
            ));
        }
        if !params.within_limits() {
            return Err(SecretError::InvalidArgument(
                "Argon2 parameters exceed the supported limits".to_owned(),
            ));
        }
        let hint = hint.map(str::trim).filter(|h| !h.is_empty());
        if let Some(hint) = hint {
            check_hint(hint, password)?;
        }
        let salt = random::random_bytes::<{ kdf::SALT_LEN }>().map_err(crypto)?;
        let hash = kdf::derive_key(password.expose(), &salt, params).map_err(crypto)?;
        let record = Zeroizing::new(encode(&PasswordHash {
            salt: hex::encode(salt),
            params,
            hash: hex::encode(hash.expose()),
        })?);
        let sealed_password = self.seal("password", record.as_bytes())?;
        let sealed_hint = hint
            .map(|hint| self.seal("password-hint", hint.as_bytes()))
            .transpose()?;
        Ok((sealed_password, sealed_hint))
    }

    /// `state` with `password` and `authenticator` applied, and the audit
    /// detail of each change made: none exactly when `state` is unchanged.
    /// Nothing is written.
    pub(super) fn changed_view(
        &self,
        mut state: ViewState,
        password: &PasswordChange,
        authenticator: &AuthenticatorChange,
    ) -> Result<(ViewState, Vec<&'static str>)> {
        let mut done = Vec::new();
        match password {
            PasswordChange::Keep => {}
            PasswordChange::Clear => {
                if state != ViewState::default() {
                    done.push("view check cleared");
                }
                state = ViewState::default();
            }
            PasswordChange::Set {
                password,
                hint,
                params,
            } => {
                let (sealed, sealed_hint) =
                    self.seal_password(password, hint.as_deref(), *params)?;
                done.push(if state.password.is_some() {
                    "password changed"
                } else {
                    "password set"
                });
                state.password = Some(sealed);
                state.password_hint = sealed_hint;
                state.check_failures = None;
            }
        }
        match authenticator {
            AuthenticatorChange::Keep => {}
            AuthenticatorChange::Remove => {
                if state.second_factor.take().is_some() {
                    done.push("authenticator removed");
                }
            }
            AuthenticatorChange::Verified { secret, counter } => {
                if state.password.is_none() {
                    return Err(SecretError::InvalidArgument(
                        "set a password first: the authenticator code is a second check on top \
                         of it"
                            .to_owned(),
                    ));
                }
                let sealed = aead::seal(
                    &self.dek,
                    aad("second-factor", &self.meta.id).as_bytes(),
                    secret.expose(),
                )
                .map_err(crypto)?;
                state.second_factor = Some(encode(&SecondFactorRecord {
                    nonce: hex::encode(sealed.nonce),
                    ciphertext: hex::encode(&sealed.bytes),
                    enrolled_on: nanos(timestamp::now())?,
                    verified: true,
                    last_counter: Some(*counter),
                })?);
                done.push("authenticator enrolled and verified");
            }
        }
        Ok((state, done))
    }

    /// Remove the view check: the password, its hint and the
    /// authenticator. Viewing then asks for nothing.
    pub fn clear_view_check(&self) -> Result<()> {
        self.change_view("view check cleared", |state| {
            *state = ViewState::default();
            Ok(())
        })?;
        Ok(())
    }

    /// Enrol an authenticator: a fresh secret, sealed with the vault key,
    /// returned once so its owner can scan or type it into the app. It is a
    /// second check on top of the password, so a password must be set. It
    /// counts for nothing until [`SqliteVault::verify_authenticator`] has
    /// accepted one code. A verified enrolment must be removed first; an
    /// unverified one is replaced.
    pub fn enrol_authenticator(&self) -> Result<TotpSecret> {
        let secret = TotpSecret::generate().map_err(crypto)?;
        let sealed = aead::seal(
            &self.dek,
            aad("second-factor", &self.meta.id).as_bytes(),
            secret.expose(),
        )
        .map_err(crypto)?;
        let raw = encode(&SecondFactorRecord {
            nonce: hex::encode(sealed.nonce),
            ciphertext: hex::encode(&sealed.bytes),
            enrolled_on: nanos(timestamp::now())?,
            verified: false,
            last_counter: None,
        })?;
        self.change_view("authenticator enrolled (unverified)", |state| {
            if state.password.is_none() {
                return Err(SecretError::InvalidArgument(
                    "set a password first: the authenticator code is a second check on top of it"
                        .to_owned(),
                ));
            }
            let verified = state
                .second_factor
                .as_deref()
                .map(|raw| parse::<SecondFactorRecord>(raw, "second factor"))
                .transpose()?
                .is_some_and(|record| record.verified);
            if verified {
                return Err(SecretError::InvalidArgument(
                    "an authenticator is already enrolled and verified; remove it before \
                     enrolling another"
                        .to_owned(),
                ));
            }
            state.second_factor = Some(raw);
            Ok(())
        })?;
        Ok(secret)
    }

    /// The step `code` is accepted for against `record`, if it is: right,
    /// and later than the last accepted step.
    fn accept_code(
        &self,
        record: &SecondFactorRecord,
        code: &str,
        now: OffsetDateTime,
    ) -> Result<Option<u64>> {
        let nonce = hex::decode(&record.nonce).map_err(|_| storage("corrupt second factor"))?;
        let bytes =
            hex::decode(&record.ciphertext).map_err(|_| storage("corrupt second factor"))?;
        let sealed = aead::Ciphertext::from_parts(&nonce, bytes).map_err(crypto)?;
        let plain = aead::open(
            &self.dek,
            aad("second-factor", &self.meta.id).as_bytes(),
            &sealed,
        )
        .map_err(crypto)?;
        let secret = TotpSecret::from_bytes(plain.to_vec()).map_err(crypto)?;
        let unix = u64::try_from(now.unix_timestamp()).unwrap_or(0);
        Ok(secret.verify(code, unix, record.last_counter))
    }

    /// Check a code against the enrolled authenticator at `now`. The first
    /// accepted code verifies the enrolment, so the view check starts to ask
    /// for it; every accepted code advances the replay guard. A refused code
    /// is audited as `denied` and answers `false`; no enrolment is an error.
    pub fn verify_authenticator(&self, code: &str, now: OffsetDateTime) -> Result<bool> {
        let mut conn = self.lock()?;
        let tx = self.begin(&mut conn, AuditOperation::Guard)?;
        let mut state = match self.stored_view_state(&tx) {
            Ok(state) => state,
            Err(err) => return self.fail(tx, AuditOperation::Guard, None, None, err),
        };
        let Some(raw) = state.second_factor.clone() else {
            return self.fail(
                tx,
                AuditOperation::Guard,
                None,
                None,
                SecretError::InvalidArgument(
                    "no authenticator is enrolled for this vault".to_owned(),
                ),
            );
        };
        let mut record: SecondFactorRecord = parse(&raw, "second factor")?;
        let Some(counter) = self.accept_code(&record, code, now)? else {
            self.audit(
                &tx,
                AuditOperation::Guard,
                None,
                None,
                AuditOutcome::Denied,
                Some("authenticator code refused"),
            )?;
            tx.commit().map_err(db)?;
            return Ok(false);
        };
        let first = !record.verified;
        record.verified = true;
        record.last_counter = Some(counter);
        state.second_factor = Some(encode(&record)?);
        let tag = self.write_view_state(&tx, &state)?;
        self.audit_settings(
            &tx,
            AuditOperation::Guard,
            AuditOutcome::Success,
            if first {
                "authenticator verified"
            } else {
                "authenticator code accepted"
            },
            tag,
        )?;
        tx.commit().map_err(db)?;
        drop(conn);
        self.remember(state)?;
        Ok(true)
    }

    /// Remove the authenticator; the password stays.
    pub fn remove_authenticator(&self) -> Result<()> {
        self.change_view("authenticator removed", |state| {
            if state.second_factor.is_none() {
                return Err(SecretError::InvalidArgument(
                    "no authenticator is enrolled for this vault".to_owned(),
                ));
            }
            state.second_factor = None;
            Ok(())
        })?;
        Ok(())
    }

    /// Weigh `answers` against the view check at `now`.
    ///
    /// Nothing is asked when no password is set, and nothing when the vault
    /// was opened with its recovery key. Otherwise the recovery key, when
    /// given, passes on its own; else the password must match and, when an
    /// authenticator is enrolled and verified, a code it has not accepted
    /// before must too. A wrong or missing answer is `permission_denied`.
    /// After [`FREE_FAILURES`] wrong answers in a row each further attempt
    /// is refused unweighed until its wait is over. Every outcome is audited
    /// under `guard`, in one transaction with the count it changes.
    pub fn check_view(&self, answers: &ViewAnswers, now: OffsetDateTime) -> Result<()> {
        // The current state decides, read without a write lock; a check set
        // in between is caught by the transaction below, which reads again.
        if self.view_check()?.is_none() {
            return Ok(());
        }
        let mut conn = self.lock()?;
        // A vault blocked by an unacknowledged truncation still weighs the
        // check: its owner passes it to read the log and acknowledge.
        let tx = self.begin_view_check(&mut conn)?;
        let mut state = match self.stored_view_state(&tx) {
            Ok(state) => state,
            Err(err) => return self.fail(tx, AuditOperation::Guard, None, None, err),
        };
        if state.password.is_none() {
            // Cleared by another process since this handle opened the vault.
            drop(tx);
            drop(conn);
            self.remember(state)?;
            return Ok(());
        }
        let mut failures: CheckFailures = state
            .check_failures
            .as_deref()
            .map(|raw| parse(raw, "check failures"))
            .transpose()?
            .unwrap_or_default();

        let verdict = if self.opened_with_recovery_key {
            Verdict::Passed("view check passed: opened with the recovery key")
        } else if let Some(key) = &answers.recovery_key {
            if self.recovery_key_opens(&tx, key)? {
                Verdict::Passed("view check passed with the recovery key")
            } else {
                Verdict::Refused("incorrect recovery key")
            }
        } else if let Some(wait) = wait_secs(failures, now)? {
            self.audit(
                &tx,
                AuditOperation::Guard,
                None,
                None,
                AuditOutcome::Denied,
                Some("view check refused unweighed: waiting after repeated wrong answers"),
            )?;
            tx.commit().map_err(db)?;
            return Err(denied(&format!(
                "too many wrong answers in a row; try again in {wait} seconds (or give the \
                 recovery key)"
            )));
        } else {
            self.weigh(&mut state, answers, now)?
        };

        let result = match verdict {
            Verdict::Passed(detail) => {
                if failures.count > 0 {
                    state.check_failures = None;
                }
                let tag = self.write_view_state(&tx, &state)?;
                self.audit_settings(
                    &tx,
                    AuditOperation::Guard,
                    AuditOutcome::Success,
                    detail,
                    tag,
                )?;
                Ok(())
            }
            Verdict::Refused(reason) => {
                failures.count = failures.count.saturating_add(1);
                failures.last_on = nanos(now)?;
                state.check_failures = Some(encode(&failures)?);
                let tag = self.write_view_state(&tx, &state)?;
                self.audit_settings(
                    &tx,
                    AuditOperation::Guard,
                    AuditOutcome::Denied,
                    &format!("view check refused: {reason}"),
                    tag,
                )?;
                Err(denied(reason))
            }
        };
        tx.commit().map_err(db)?;
        drop(conn);
        self.remember(state)?;
        result
    }

    /// The password, then the code when one is asked for. An accepted code
    /// advances the replay guard in `state`.
    fn weigh(
        &self,
        state: &mut ViewState,
        answers: &ViewAnswers,
        now: OffsetDateTime,
    ) -> Result<Verdict> {
        let Some(password) = &answers.password else {
            return Ok(Verdict::Refused("the password was not given"));
        };
        let Some(sealed) = state.password.as_deref() else {
            return Ok(Verdict::Passed("view check passed"));
        };
        let plain = self.unseal("password", sealed)?;
        let record: PasswordHash =
            serde_json::from_slice(&plain).map_err(|_| storage("corrupt password record"))?;
        if !record.params.within_limits() {
            return Err(storage("password record asks for too much work"));
        }
        let salt = hex::decode(&record.salt).map_err(|_| storage("corrupt password record"))?;
        let expected = hex::decode(&record.hash)
            .ok()
            .and_then(|bytes| SymmetricKey::from_slice(&bytes).ok())
            .ok_or_else(|| storage("corrupt password record"))?;
        let given = kdf::derive_key(password.expose(), &salt, record.params).map_err(crypto)?;
        if given != expected {
            return Ok(Verdict::Refused("incorrect password"));
        }
        let Some(raw) = state.second_factor.clone() else {
            return Ok(Verdict::Passed("view check passed"));
        };
        let mut factor: SecondFactorRecord = parse(&raw, "second factor")?;
        if !factor.verified {
            return Ok(Verdict::Passed("view check passed"));
        }
        let Some(code) = answers.code.as_deref() else {
            return Ok(Verdict::Refused("the authenticator code was not given"));
        };
        let Some(counter) = self.accept_code(&factor, code, now)? else {
            return Ok(Verdict::Refused(
                "incorrect or already used authenticator code",
            ));
        };
        factor.last_counter = Some(counter);
        state.second_factor = Some(encode(&factor)?);
        Ok(Verdict::Passed("view check passed"))
    }
}

/// A hint is shown at the prompt, so it must not give the password away.
fn check_hint(hint: &str, password: &SecretBytes) -> Result<()> {
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
    if let Some(password) = password.expose_utf8() {
        let lower_hint = hint.to_lowercase();
        let lower_password = password.to_lowercase();
        if !lower_password.is_empty() && lower_hint.contains(&lower_password) {
            return Err(SecretError::InvalidArgument(
                "a hint must not contain the password".to_owned(),
            ));
        }
    }
    Ok(())
}
