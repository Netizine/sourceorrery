//! Key protectors: the ways a vault's data-encryption key can be unlocked.

use serde::{Deserialize, Serialize};
use sourceorrery_core::SecretBytes;
use sourceorrery_crypto::Argon2Params;
use time::OffsetDateTime;

/// How a protector derives or stores its key-encryption key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum ProtectorKind {
    /// A random KEK stored in the operating-system credential store.
    OsKeyring {
        /// Keyring service name (`sourceorrery`).
        service: String,
        /// Keyring account/user name (`vault/<vault id>/<protector id>`).
        account: String,
    },
    /// A KEK derived from a passphrase with Argon2id.
    Passphrase {
        /// Hex-encoded random salt.
        salt: String,
        /// Argon2id cost parameters used when this protector was created.
        params: Argon2Params,
    },
}

impl ProtectorKind {
    /// Stable kind label (`os-keyring`, `passphrase`).
    pub fn label(&self) -> &'static str {
        match self {
            Self::OsKeyring { .. } => "os-keyring",
            Self::Passphrase { .. } => "passphrase",
        }
    }
}

/// A request to add a protector.
#[derive(Debug)]
pub enum ProtectorSpec {
    /// Generate a random KEK and store it in the OS credential store.
    OsKeyring,
    /// Derive the KEK from this passphrase with the given parameters.
    Passphrase {
        /// The passphrase.
        passphrase: SecretBytes,
        /// Cost parameters (use [`Argon2Params::default`] outside tests).
        params: Argon2Params,
    },
}

impl ProtectorSpec {
    /// Passphrase protector with default (interactive) cost parameters.
    pub fn passphrase(passphrase: impl Into<SecretBytes>) -> Self {
        Self::Passphrase {
            passphrase: passphrase.into(),
            params: Argon2Params::default(),
        }
    }

    /// Kind label this spec will produce.
    pub fn kind_label(&self) -> &'static str {
        match self {
            Self::OsKeyring => "os-keyring",
            Self::Passphrase { .. } => "passphrase",
        }
    }
}

/// Non-sensitive description of an installed protector.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtectorInfo {
    /// Random identifier.
    pub id: String,
    /// Unique human-readable label.
    pub label: String,
    /// Kind label.
    pub kind: String,
    /// When it was added.
    #[serde(with = "time::serde::rfc3339")]
    pub created_on: OffsetDateTime,
}

/// Full protector row, including the wrapped DEK.
#[derive(Clone, Debug)]
pub(crate) struct ProtectorRecord {
    pub id: String,
    pub label: String,
    pub kind: ProtectorKind,
    pub wrapped: sourceorrery_crypto::Ciphertext,
    pub created_on: OffsetDateTime,
}

impl ProtectorRecord {
    pub(crate) fn info(&self) -> ProtectorInfo {
        ProtectorInfo {
            id: self.id.clone(),
            label: self.label.clone(),
            kind: self.kind.label().to_owned(),
            created_on: self.created_on,
        }
    }
}
