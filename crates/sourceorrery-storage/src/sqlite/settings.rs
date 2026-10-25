//! Changing a vault's settings in one transaction (ADR 0009, section 7):
//! what the setup wizard's review confirms. The view check (password, its
//! hint, the authenticator), the recovery key and the connections change
//! together or not at all: a part refused rolls the others back, and the
//! refusal is the one audit row left.
//!
//! Each part is checked and recorded as it is when made alone: connections
//! as `vault_change`, the recovery key as `protector_add`, the view check as
//! `guard`, with the same details.

use sourceorrery_core::Result;
use sourceorrery_core::audit::{AuditOperation, AuditOutcome};

use super::schema::{ViewState, db};
use super::{AuthenticatorChange, ConnectionChange, PasswordChange, RecoveryKey, SqliteVault};

/// What [`SqliteVault::change_settings`] changes. Its `Debug` shows no
/// secret: each part redacts its own.
#[derive(Debug)]
pub struct SettingsChange {
    pub password: PasswordChange,
    pub authenticator: AuthenticatorChange,
    /// A new recovery key, which its owner has written down; the old one
    /// stops working.
    pub recovery_key: Option<RecoveryKey>,
    /// Made in order.
    pub connections: Vec<ConnectionChange>,
}

impl Default for SettingsChange {
    fn default() -> Self {
        Self {
            password: PasswordChange::Keep,
            authenticator: AuthenticatorChange::Keep,
            recovery_key: None,
            connections: Vec::new(),
        }
    }
}

impl SettingsChange {
    /// True when it changes nothing.
    pub fn is_empty(&self) -> bool {
        matches!(self.password, PasswordChange::Keep)
            && matches!(self.authenticator, AuthenticatorChange::Keep)
            && self.recovery_key.is_none()
            && self.connections.is_empty()
    }
}

impl SqliteVault {
    /// Make `change` in one transaction: the connections first, then the
    /// recovery key, then the view check. A part refused leaves the vault
    /// as it was and is audited as a `vault_change` failure.
    pub fn change_settings(&self, change: &SettingsChange) -> Result<()> {
        let op = AuditOperation::VaultChange;
        let mut conn = self.lock()?;
        let tx = self.begin(&mut conn, op)?;
        let view = match self.apply_settings(&tx, change) {
            Ok(view) => view,
            Err(err) => return self.fail(tx, op, None, None, err),
        };
        tx.commit().map_err(db)?;
        drop(conn);
        if let Some(view) = view {
            self.remember(view)?;
        }
        Ok(())
    }

    /// The parts of `change`, each recorded as it is made; the view-check
    /// state written, when it changed.
    fn apply_settings(
        &self,
        conn: &rusqlite::Connection,
        change: &SettingsChange,
    ) -> Result<Option<ViewState>> {
        let success = |op, detail: &str, tag| {
            self.audit_settings(conn, op, AuditOutcome::Success, detail, tag)
        };
        for connection in &change.connections {
            let (detail, tag) = self.apply_connection_change(conn, connection)?;
            success(AuditOperation::VaultChange, &detail, tag)?;
        }
        if let Some(key) = &change.recovery_key {
            let tag = self.install_recovery_key(conn, key)?;
            success(AuditOperation::ProtectorAdd, "recovery key replaced", tag)?;
        }
        if matches!(change.password, PasswordChange::Keep)
            && matches!(change.authenticator, AuthenticatorChange::Keep)
        {
            return Ok(None);
        }
        let stored = self.stored_view_state(conn)?;
        let (state, done) = self.changed_view(stored, &change.password, &change.authenticator)?;
        if done.is_empty() {
            // Nothing was there to clear or remove, so nothing changed.
            return Ok(None);
        }
        let tag = self.write_view_state(conn, &state)?;
        for detail in done {
            success(AuditOperation::Guard, detail, tag)?;
        }
        Ok(Some(state))
    }
}
