//! Key wraps: the ways a vault's key can be opened (ADR 0009).
//!
//! Every vault has exactly one **recovery** wrap, whose key-encryption key
//! is derived from the recovery key shown once when the vault is created:
//! it opens the vault anywhere, including an exported copy and a machine
//! with no credential store. A **this-machine** wrap keeps a random
//! key-encryption key in a credential store, so the vault opens on that
//! machine and user account without asking for anything.

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

/// How a wrap derives or keeps its key-encryption key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum WrapKind {
    /// A random KEK in a credential store.
    ThisMachine {
        /// Credential-store service name (`sourceorrery`).
        service: String,
        /// Credential-store account name (`vault/<vault id>/<wrap id>`).
        account: String,
    },
    /// A KEK derived from the recovery key with HKDF-SHA256.
    Recovery {
        /// Hex-encoded random HKDF salt.
        salt: String,
    },
}

impl WrapKind {
    /// Stable kind label (`this-machine`, `recovery`).
    pub fn label(&self) -> &'static str {
        match self {
            Self::ThisMachine { .. } => "this-machine",
            Self::Recovery { .. } => "recovery",
        }
    }
}

/// Non-sensitive description of a wrap.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WrapInfo {
    /// Random identifier.
    pub id: String,
    /// Kind label: `this-machine` or `recovery`.
    pub kind: String,
    /// When it was made.
    #[serde(with = "time::serde::rfc3339")]
    pub created_on: OffsetDateTime,
}

/// A full wrap row, including the wrapped vault key.
#[derive(Clone, Debug)]
pub(crate) struct WrapRecord {
    pub id: String,
    pub kind: WrapKind,
    pub wrapped: sourceorrery_crypto::Ciphertext,
    pub created_on: OffsetDateTime,
}

impl WrapRecord {
    pub(crate) fn info(&self) -> WrapInfo {
        WrapInfo {
            id: self.id.clone(),
            kind: self.kind.label().to_owned(),
            created_on: self.created_on,
        }
    }
}
