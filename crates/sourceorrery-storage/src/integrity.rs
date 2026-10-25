//! Integrity protection for what the vault cannot encrypt.
//!
//! Secret values are AEAD ciphertext bound to their location, so they cannot
//! be edited or moved without detection. Everything else in the file is
//! plaintext: enabled flags, time windows, tags, deletion state and the audit
//! log. A writer who can edit the file could otherwise re-enable a disabled
//! version, extend an expiry, undelete a secret or remove the record of what
//! they did. Schema version 2 closes that with a *metadata key* derived from
//! the vault DEK with HKDF-SHA256 under [`METADATA_KEY_LABEL`]:
//!
//! * every `secrets` and `secret_versions` row carries an HMAC-SHA256 `tag`
//!   over a canonical encoding of its mutable fields, checked on every read;
//! * every `audit_events` row carries `hash = HMAC(key, prev_hash ‖ row)`, so
//!   removing, reordering or editing a row breaks the chain, and a keyed
//!   *head* record in `vault_meta` pins the last row written with the key so
//!   truncating the log is detected too.
//!
//! A row tag proves a row was written by the vault at *some* point, not that
//! it is the row's current state: an older authentic copy of the row, tag
//! included, would still verify. Schema version 3 therefore makes the audit
//! chain the record of current state as well. Every event that changes a
//! `secrets` or `secret_versions` row carries the tag that row has
//! afterwards (`state_tag`, `version_tag`), or the `Checkpoint::Absent`
//! marker when the row was removed, and the hash covers both. Before a row
//! is honoured its stored tag must equal the newest such *checkpoint* for it
//! in the keyed chain, so replaying an older row, resurrecting a purged one
//! or removing a version out of band is refused with `crypto`, and the
//! chain head is checked first so a truncated log cannot present an older
//! checkpoint as the newest.
//!
//! Schema version 4 adds the `connections` and `projects` tables. Each row
//! carries a tag over its fields, and the authenticated settings record
//! lists every row by id with the tag it carries, so a connection or a
//! project added, removed or replaced by an older copy out of band is
//! refused at unlock. The settings record is checkpointed like a row: every
//! event that rewrites it carries the tag it has afterwards
//! (`settings_tag`), and the record is honoured only when its tag equals
//! the newest one, so an older authentic copy of the whole record (from
//! before a password was set, say) is refused too. A project's path is also
//! kept as a keyed MAC (`project_path_mac`), so one folder is recorded
//! once without its path being readable in the file.
//!
//! Rows the vault writes **before** it is unlocked (failed `vault_open`
//! attempts) cannot use the metadata key. They are chained with an all-zero
//! key and flagged `keyed = 0`; verification reports them as *unkeyed* rather
//! than broken. Such rows are forgeable by design, but they still take part
//! in the chain, so inserting or deleting one ahead of a keyed row is
//! detected, and they never count as checkpoints.
//!
//! ## Canonical encoding
//!
//! Each authenticated record is encoded as a sequence of fields in a fixed
//! order: a domain string, the vault id, then the record's fields. Strings
//! and byte strings are prefixed with their length as a big-endian `u64`;
//! integers are 8-byte big-endian two's complement; booleans are one byte;
//! optional fields are a presence byte (`0`/`1`) followed by the value when
//! present. The encoding is unambiguous for a fixed field list, so a tag
//! computed over one record never verifies for another.

use serde::Serialize;
use sourceorrery_crypto::{self as crypto, MAC_LEN, SymmetricKey};

/// HKDF label under which the metadata key is derived from the vault DEK.
pub const METADATA_KEY_LABEL: &str = "sourceorrery/v2/metadata";

/// Domain string of a `secret_versions` tag.
pub(crate) const VERSION_DOMAIN: &str = "sourceorrery/v2/version";
/// Domain string of a `secrets` tag.
pub(crate) const SECRET_DOMAIN: &str = "sourceorrery/v2/secret";
/// Domain string of an `audit_events` chain hash (schema 3: the row's
/// checkpoint tags are part of the hashed record; schema 4: the settings
/// checkpoint too).
pub(crate) const AUDIT_DOMAIN: &str = "sourceorrery/v4/audit";
/// Domain string of the audit chain head record.
pub(crate) const AUDIT_HEAD_DOMAIN: &str = "sourceorrery/v2/audit-head";
/// `vault_meta` key holding the audit chain head.
pub(crate) const AUDIT_HEAD_KEY: &str = "audit_head";

/// Domain string of a `connections` tag.
pub(crate) const CONNECTION_DOMAIN: &str = "sourceorrery/v4/connection";

/// Domain string of a `projects` tag.
pub(crate) const PROJECT_DOMAIN: &str = "sourceorrery/v4/project";

/// Domain string of a project path's MAC.
pub(crate) const PROJECT_PATH_DOMAIN: &str = "sourceorrery/v4/project-path";

/// Domain of the vault settings tag.
pub(crate) const SETTINGS_DOMAIN: &str = "sourceorrery/v2/settings";

/// `vault_meta` key holding the hex HMAC over the vault-wide settings.
pub(crate) const SETTINGS_KEY: &str = "settings_tag";

/// `prev_hash` of the first audit row.
pub(crate) const ZERO_HASH: [u8; MAC_LEN] = [0u8; MAC_LEN];

/// Derive the metadata key from the vault DEK.
pub(crate) fn derive_metadata_key(dek: &SymmetricKey) -> SymmetricKey {
    crypto::derive_subkey(dek, METADATA_KEY_LABEL)
}

/// The public all-zero key used to chain rows written before unlock.
pub(crate) fn zero_key() -> SymmetricKey {
    SymmetricKey::from_bytes([0u8; sourceorrery_crypto::KEY_LEN])
}

/// A stored hash, or [`ZERO_HASH`] when it is missing or malformed.
pub(crate) fn hash_or_zero(hash: Option<&[u8]>) -> [u8; MAC_LEN] {
    hash.and_then(|h| <[u8; MAC_LEN]>::try_from(h).ok())
        .unwrap_or(ZERO_HASH)
}

// ---------------------------------------------------------------------------
// Canonical encoding
// ---------------------------------------------------------------------------

/// Builder for the canonical byte encoding described in the module docs.
#[derive(Debug)]
pub(crate) struct Canonical(Vec<u8>);

impl Canonical {
    pub(crate) fn new(domain: &str, vault_id: &str) -> Self {
        Self(Vec::with_capacity(256)).str(domain).str(vault_id)
    }

    pub(crate) fn bytes(mut self, value: &[u8]) -> Self {
        let len = u64::try_from(value.len()).unwrap_or(u64::MAX);
        self.0.extend_from_slice(&len.to_be_bytes());
        self.0.extend_from_slice(value);
        self
    }

    pub(crate) fn str(self, value: &str) -> Self {
        self.bytes(value.as_bytes())
    }

    pub(crate) fn int(mut self, value: i64) -> Self {
        self.0.extend_from_slice(&value.to_be_bytes());
        self
    }

    pub(crate) fn flag(mut self, value: bool) -> Self {
        self.0.push(u8::from(value));
        self
    }

    pub(crate) fn opt_str(self, value: Option<&str>) -> Self {
        match value {
            Some(v) => self.flag(true).str(v),
            None => self.flag(false),
        }
    }

    pub(crate) fn opt_int(self, value: Option<i64>) -> Self {
        match value {
            Some(v) => self.flag(true).int(v),
            None => self.flag(false),
        }
    }

    pub(crate) fn opt_bytes(self, value: Option<&[u8]>) -> Self {
        match value {
            Some(v) => self.flag(true).bytes(v),
            None => self.flag(false),
        }
    }

    pub(crate) fn finish(self) -> Vec<u8> {
        self.0
    }
}

// ---------------------------------------------------------------------------
// Secret versions
// ---------------------------------------------------------------------------

/// The authenticated fields of a `secret_versions` row, in stored form.
#[derive(Clone, Copy, Debug)]
pub(crate) struct VersionFields<'a> {
    pub vault_id: &'a str,
    pub name: &'a str,
    pub version: &'a str,
    pub seq: i64,
    pub enabled: bool,
    pub content_type: Option<&'a str>,
    pub tags_json: &'a str,
    pub not_before: Option<i64>,
    pub expires_on: Option<i64>,
    pub created_on: i64,
    pub updated_on: i64,
}

impl VersionFields<'_> {
    fn canonical(&self) -> Vec<u8> {
        Canonical::new(VERSION_DOMAIN, self.vault_id)
            .str(self.name)
            .str(self.version)
            .int(self.seq)
            .flag(self.enabled)
            .opt_str(self.content_type)
            .str(self.tags_json)
            .opt_int(self.not_before)
            .opt_int(self.expires_on)
            .int(self.created_on)
            .int(self.updated_on)
            .finish()
    }
}

/// Tag to store with a version row.
pub(crate) fn version_tag(key: &SymmetricKey, fields: &VersionFields<'_>) -> [u8; MAC_LEN] {
    crypto::mac(key, &fields.canonical())
}

/// True when `tag` authenticates `fields`.
pub(crate) fn verify_version_tag(
    key: &SymmetricKey,
    fields: &VersionFields<'_>,
    tag: Option<&[u8]>,
) -> bool {
    tag.is_some_and(|tag| crypto::verify_mac(key, &fields.canonical(), tag).is_ok())
}

// ---------------------------------------------------------------------------
// Secrets
// ---------------------------------------------------------------------------

/// The authenticated fields of a `secrets` row, in stored form.
#[derive(Clone, Copy, Debug)]
pub(crate) struct SecretFields<'a> {
    pub vault_id: &'a str,
    pub name: &'a str,
    pub created_on: i64,
    pub deleted_on: Option<i64>,
    pub scheduled_purge_on: Option<i64>,
    pub recovery_id: Option<&'a str>,
    /// The connection that stores the secret's value; `None` for the vault
    /// file (schema 4).
    pub storage: Option<&'a str>,
    /// What the secret is for, as its owner wrote it (schema 4).
    pub description: Option<&'a str>,
}

impl SecretFields<'_> {
    fn canonical(&self) -> Vec<u8> {
        Canonical::new(SECRET_DOMAIN, self.vault_id)
            .str(self.name)
            .int(self.created_on)
            .opt_int(self.deleted_on)
            .opt_int(self.scheduled_purge_on)
            .opt_str(self.recovery_id)
            .opt_str(self.storage)
            .opt_str(self.description)
            .finish()
    }
}

/// Tag to store with a secret row.
pub(crate) fn secret_tag(key: &SymmetricKey, fields: &SecretFields<'_>) -> [u8; MAC_LEN] {
    crypto::mac(key, &fields.canonical())
}

/// True when `tag` authenticates `fields`.
pub(crate) fn verify_secret_tag(
    key: &SymmetricKey,
    fields: &SecretFields<'_>,
    tag: Option<&[u8]>,
) -> bool {
    tag.is_some_and(|tag| crypto::verify_mac(key, &fields.canonical(), tag).is_ok())
}

// ---------------------------------------------------------------------------
// Connections
// ---------------------------------------------------------------------------

/// The authenticated fields of a `connections` row, in stored form. A row
/// tag proves the row was written by the vault; that it is the row's
/// current state, and that no row was added or removed, is the settings
/// record's to prove ([`SettingsFields::connections`]).
#[derive(Clone, Copy, Debug)]
pub(crate) struct ConnectionFields<'a> {
    pub vault_id: &'a str,
    pub id: &'a str,
    pub kind: &'a str,
    pub settings_json: &'a str,
    pub credential_source: &'a str,
    pub sealed_credentials: Option<&'a str>,
    pub created_on: i64,
    pub last_test_on: Option<i64>,
    pub last_test_outcome: Option<&'a str>,
}

impl ConnectionFields<'_> {
    fn canonical(&self) -> Vec<u8> {
        Canonical::new(CONNECTION_DOMAIN, self.vault_id)
            .str(self.id)
            .str(self.kind)
            .str(self.settings_json)
            .str(self.credential_source)
            .opt_str(self.sealed_credentials)
            .int(self.created_on)
            .opt_int(self.last_test_on)
            .opt_str(self.last_test_outcome)
            .finish()
    }
}

/// Tag to store with a connection row.
pub(crate) fn connection_tag(key: &SymmetricKey, fields: &ConnectionFields<'_>) -> [u8; MAC_LEN] {
    crypto::mac(key, &fields.canonical())
}

/// True when `tag` authenticates `fields`.
pub(crate) fn verify_connection_tag(
    key: &SymmetricKey,
    fields: &ConnectionFields<'_>,
    tag: Option<&[u8]>,
) -> bool {
    tag.is_some_and(|tag| crypto::verify_mac(key, &fields.canonical(), tag).is_ok())
}

// ---------------------------------------------------------------------------
// Projects
// ---------------------------------------------------------------------------

/// The authenticated fields of a `projects` row, in stored form. As for a
/// connection, that the row is current and that none was added or removed
/// is the settings record's to prove ([`SettingsFields::projects`]).
#[derive(Clone, Copy, Debug)]
pub(crate) struct ProjectFields<'a> {
    pub vault_id: &'a str,
    pub id: &'a str,
    pub path_mac: &'a [u8],
    pub sealed: &'a str,
    pub linked_on: i64,
}

impl ProjectFields<'_> {
    fn canonical(&self) -> Vec<u8> {
        Canonical::new(PROJECT_DOMAIN, self.vault_id)
            .str(self.id)
            .bytes(self.path_mac)
            .str(self.sealed)
            .int(self.linked_on)
            .finish()
    }
}

/// Tag to store with a project row.
pub(crate) fn project_tag(key: &SymmetricKey, fields: &ProjectFields<'_>) -> [u8; MAC_LEN] {
    crypto::mac(key, &fields.canonical())
}

/// True when `tag` authenticates `fields`.
pub(crate) fn verify_project_tag(
    key: &SymmetricKey,
    fields: &ProjectFields<'_>,
    tag: Option<&[u8]>,
) -> bool {
    tag.is_some_and(|tag| crypto::verify_mac(key, &fields.canonical(), tag).is_ok())
}

/// The keyed MAC of a project folder's path in vault `vault_id`: equal for
/// the same path, and without the key it says nothing about the path.
pub(crate) fn project_path_mac(key: &SymmetricKey, vault_id: &str, path: &str) -> [u8; MAC_LEN] {
    crypto::mac(
        key,
        &Canonical::new(PROJECT_PATH_DOMAIN, vault_id)
            .str(path)
            .finish(),
    )
}

// ---------------------------------------------------------------------------
// Checkpoints
// ---------------------------------------------------------------------------

/// What a keyed audit event records about a row's state afterwards: the
/// tag the row now carries, or that the row no longer exists. Stored in the
/// event's `state_tag` (for a `secrets` row) or `version_tag` (for a
/// `secret_versions` row) column; `NULL` there means the event did not
/// touch that row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Checkpoint {
    /// The row was removed (purged, hard-deleted or cascaded away); it must
    /// not exist.
    Absent,
    /// The row exists and carries exactly this tag.
    Present([u8; MAC_LEN]),
}

impl Checkpoint {
    /// The column value: the tag, or the empty blob for [`Checkpoint::Absent`].
    pub(crate) fn as_blob(&self) -> &[u8] {
        match self {
            Self::Absent => &[],
            Self::Present(tag) => tag,
        }
    }

    /// Decode a column value; `None` for a value of neither valid shape.
    pub(crate) fn from_blob(blob: &[u8]) -> Option<Self> {
        if blob.is_empty() {
            return Some(Self::Absent);
        }
        <[u8; MAC_LEN]>::try_from(blob).ok().map(Self::Present)
    }

    /// True when a row with `stored` tag (or no row, for `None`) is exactly
    /// the state this checkpoint recorded.
    pub(crate) fn matches(&self, stored: Option<&[u8]>) -> bool {
        match (self, stored) {
            (Self::Absent, None) => true,
            (Self::Present(tag), Some(stored)) => stored == tag,
            _ => false,
        }
    }
}

// ---------------------------------------------------------------------------
// Audit chain
// ---------------------------------------------------------------------------

/// The chained fields of an `audit_events` row, in stored form.
#[derive(Clone, Copy, Debug)]
pub(crate) struct AuditFields<'a> {
    pub vault_id: &'a str,
    pub id: i64,
    pub occurred_on: i64,
    pub actor: &'a str,
    pub operation: &'a str,
    pub secret_name: Option<&'a str>,
    pub version: Option<&'a str>,
    pub outcome: &'a str,
    pub detail: Option<&'a str>,
    pub keyed: bool,
    /// Checkpoint of the `secrets` row named by `secret_name`, as stored.
    pub state_tag: Option<&'a [u8]>,
    /// Checkpoint of the `secret_versions` row named by `secret_name` and
    /// `version`, as stored.
    pub version_tag: Option<&'a [u8]>,
    /// The tag the settings record carries after the event, as stored
    /// (schema 4).
    pub settings_tag: Option<&'a [u8]>,
}

impl AuditFields<'_> {
    fn canonical(&self, prev_hash: &[u8; MAC_LEN]) -> Vec<u8> {
        Canonical::new(AUDIT_DOMAIN, self.vault_id)
            .bytes(prev_hash)
            .int(self.id)
            .int(self.occurred_on)
            .str(self.actor)
            .str(self.operation)
            .opt_str(self.secret_name)
            .opt_str(self.version)
            .str(self.outcome)
            .opt_str(self.detail)
            .flag(self.keyed)
            .opt_bytes(self.state_tag)
            .opt_bytes(self.version_tag)
            .opt_bytes(self.settings_tag)
            .finish()
    }
}

/// Chain hash of an audit row: `HMAC(key, prev_hash ‖ row)`.
pub(crate) fn audit_hash(
    key: &SymmetricKey,
    prev_hash: &[u8; MAC_LEN],
    fields: &AuditFields<'_>,
) -> [u8; MAC_LEN] {
    crypto::mac(key, &fields.canonical(prev_hash))
}

/// True when `hash` is the chain hash of `fields` following `prev_hash`.
pub(crate) fn verify_audit_hash(
    key: &SymmetricKey,
    prev_hash: &[u8; MAC_LEN],
    fields: &AuditFields<'_>,
    hash: Option<&[u8]>,
) -> bool {
    hash.is_some_and(|hash| crypto::verify_mac(key, &fields.canonical(prev_hash), hash).is_ok())
}

/// The head's MAC input: the newest keyed row and, since the count was
/// added, how many keyed rows the log holds. A head written before the
/// count existed (`keyed` is `None`) is accepted by [`head_matches`] until
/// the next keyed write replaces it; the full chain walk at unlock covers
/// such a file in the meantime.
fn head_canonical(vault_id: &str, id: i64, hash: &[u8], keyed: Option<u64>) -> Vec<u8> {
    let canonical = Canonical::new(AUDIT_HEAD_DOMAIN, vault_id)
        .int(id)
        .bytes(hash);
    match keyed {
        Some(keyed) => canonical
            .str("keyed")
            .int(i64::try_from(keyed).unwrap_or(i64::MAX))
            .finish(),
        None => canonical.finish(),
    }
}

/// `vault_meta` value recording that row `id` with chain hash `hash` is the
/// newest row written with the metadata key, and that `keyed` rows carry
/// the key: `<id>:<keyed>:<hex HMAC>`. The count is what lets a write
/// notice a keyed row removed from the middle of the log without walking
/// it: a removed or demoted row changes the count under a MAC the
/// tamperer cannot recompute.
pub(crate) fn head_value(
    key: &SymmetricKey,
    vault_id: &str,
    id: i64,
    hash: &[u8],
    keyed: u64,
) -> String {
    let mac = crypto::mac(key, &head_canonical(vault_id, id, hash, Some(keyed)));
    format!("{id}:{keyed}:{}", hex::encode(mac))
}

/// A parsed head record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct HeadRecord {
    /// The newest keyed row it names.
    pub(crate) id: i64,
    /// Keyed rows in the log when it was written; `None` for a head
    /// written before the count existed.
    pub(crate) keyed: Option<u64>,
    mac: Vec<u8>,
}

/// Parse a head record, in either form.
pub(crate) fn parse_head(head: &str) -> Option<HeadRecord> {
    let parts: Vec<&str> = head.split(':').collect();
    let (id, keyed, mac_hex) = match parts.as_slice() {
        [id, mac_hex] => (id, None, mac_hex),
        [id, keyed, mac_hex] => (id, Some(keyed.parse::<u64>().ok()?), mac_hex),
        _ => return None,
    };
    Some(HeadRecord {
        id: id.parse().ok()?,
        keyed,
        mac: hex::decode(mac_hex).ok()?,
    })
}

/// The row id a head record claims, if it parses.
#[cfg(test)]
pub(crate) fn head_id(head: &str) -> Option<i64> {
    parse_head(head).map(|h| h.id)
}

/// True when `head` was produced by [`head_value`] for exactly this row
/// and, when the head carries a count, exactly `keyed` keyed rows.
pub(crate) fn head_matches(
    key: &SymmetricKey,
    vault_id: &str,
    head: &str,
    id: i64,
    hash: &[u8],
    keyed: u64,
) -> bool {
    let Some(record) = parse_head(head) else {
        return false;
    };
    if record.id != id || record.keyed.is_some_and(|n| n != keyed) {
        return false;
    }
    crypto::verify_mac(
        key,
        &head_canonical(vault_id, id, hash, record.keyed),
        &record.mac,
    )
    .is_ok()
}

// ---------------------------------------------------------------------------
// Vault settings
// ---------------------------------------------------------------------------

/// The vault-wide settings that drive policy: authenticated as one record so
/// that an edit to the file cannot shorten retention, flip the recovery
/// level, rename the vault or claim a different schema version.
#[derive(Clone, Copy, Debug)]
pub(crate) struct SettingsFields<'a> {
    pub vault_id: &'a str,
    pub schema: u32,
    pub name: &'a str,
    pub created_on: i64,
    /// `recovery_level` exactly as stored (its JSON string).
    pub recovery_level: &'a str,
    pub retention_days: u32,
    /// The view check's stored values exactly as stored (their JSON
    /// strings), each appended to the record only when present, under its
    /// key, so an absent one adds nothing: the sealed password hash, the
    /// sealed hint, the authenticator record and the count of wrong
    /// answers.
    pub password: Option<&'a str>,
    pub password_hint: Option<&'a str>,
    pub second_factor: Option<&'a str>,
    pub check_failures: Option<&'a str>,
    /// Every `connections` row as `(id, tag)`, ordered by id, so a row
    /// added, removed or replaced by an older authentic copy breaks the
    /// record. Appended only when there is one, so a vault without
    /// connections keeps the record it had before they existed.
    pub connections: &'a [(String, Vec<u8>)],
    /// Every `projects` row as `(id, tag)`, ordered by id, appended after
    /// the connections under the same rule: only when there is one.
    pub projects: &'a [(String, Vec<u8>)],
}

fn settings_canonical(fields: &SettingsFields<'_>) -> Vec<u8> {
    let mut canonical = Canonical::new(SETTINGS_DOMAIN, fields.vault_id)
        .int(i64::from(fields.schema))
        .str(fields.name)
        .int(fields.created_on)
        .str(fields.recovery_level)
        .int(i64::from(fields.retention_days));
    // Keyed, so that an absent field adds nothing and the two cannot be
    // mistaken for each other.
    for (key, value) in [
        ("password", fields.password),
        ("password_hint", fields.password_hint),
        ("second_factor", fields.second_factor),
        ("check_failures", fields.check_failures),
    ] {
        if let Some(value) = value {
            canonical = canonical.str(key).str(value);
        }
    }
    for (label, rows) in [
        ("connections", fields.connections),
        ("projects", fields.projects),
    ] {
        if !rows.is_empty() {
            canonical = canonical
                .str(label)
                .int(i64::try_from(rows.len()).unwrap_or(i64::MAX));
            for (id, tag) in rows {
                canonical = canonical.str(id).bytes(tag);
            }
        }
    }
    canonical.finish()
}

/// HMAC over the settings record: stored hex-encoded under
/// [`SETTINGS_KEY`], and as it is in the audit event that wrote it.
pub(crate) fn settings_tag(key: &SymmetricKey, fields: &SettingsFields<'_>) -> [u8; MAC_LEN] {
    crypto::mac(key, &settings_canonical(fields))
}

/// True when `tag` was produced by [`settings_tag`] for exactly these settings.
pub(crate) fn verify_settings_tag(
    key: &SymmetricKey,
    fields: &SettingsFields<'_>,
    tag: Option<&str>,
) -> bool {
    let Some(tag) = tag else {
        return false;
    };
    let Ok(mac) = hex::decode(tag) else {
        return false;
    };
    crypto::verify_mac(key, &settings_canonical(fields), &mac).is_ok()
}

// ---------------------------------------------------------------------------
// Verification result
// ---------------------------------------------------------------------------

/// Outcome of [`crate::SqliteVault::verify_audit_chain`].
///
/// The log is intact when no row is broken, no truncation has ever been
/// detected and the head record matches the newest keyed row. Unkeyed rows
/// are those written before the vault was unlocked (failed unlock attempts);
/// they are chained with a public key and so are forgeable, but they are not
/// *broken*.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct AuditVerification {
    /// Rows examined.
    pub rows: u64,
    /// Rows authenticated with the vault's metadata key.
    pub keyed: u64,
    /// Rows written before unlock and chained with the all-zero key.
    pub unkeyed: u64,
    /// Id of the first row whose chain link or hash does not verify.
    pub first_broken: Option<u64>,
    /// Keyed `audit_verify` / `failure` rows: each records a moment when a
    /// write found rows missing from the end of the log (or the head record
    /// missing or invalid). The evidence is itself part of the chain, and
    /// stays counted after the truncation is acknowledged.
    pub truncations: u64,
    /// Truncations recorded after the newest keyed `audit_verify` /
    /// `success` acknowledgement. While this is not zero the vault is
    /// blocked: every unlock and operation is refused until
    /// [`crate::SqliteVault::acknowledge_truncations`] has run.
    pub unacknowledged: u64,
    /// The head record matches the newest keyed row right now. False only
    /// when the file was altered after this handle last wrote to it; every
    /// keyed write re-checks the head and records a failure when it is
    /// stale, so a stale head normally shows up in `truncations` instead.
    pub head_valid: bool,
}

impl AuditVerification {
    /// True when no row is broken, nothing was ever truncated and the head
    /// record is current.
    pub fn is_intact(&self) -> bool {
        self.first_broken.is_none() && self.truncations == 0 && self.head_valid
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(byte: u8) -> SymmetricKey {
        SymmetricKey::from_bytes([byte; sourceorrery_crypto::KEY_LEN])
    }

    fn version<'a>(vault_id: &'a str, tags_json: &'a str) -> VersionFields<'a> {
        VersionFields {
            vault_id,
            name: "db",
            version: "0123",
            seq: 1,
            enabled: true,
            content_type: None,
            tags_json,
            not_before: None,
            expires_on: Some(10),
            created_on: 5,
            updated_on: 6,
        }
    }

    #[test]
    fn canonical_fields_cannot_shift_into_each_other() {
        let split_late = Canonical::new("d", "v").str("ab").str("c").finish();
        let split_early = Canonical::new("d", "v").str("a").str("bc").finish();
        assert_ne!(split_late, split_early);
        let absent = Canonical::new("d", "v").opt_str(None).str("x").finish();
        let empty = Canonical::new("d", "v").opt_str(Some("")).str("x").finish();
        assert_ne!(absent, empty);
        let none_then_zero = Canonical::new("d", "v").opt_int(None).int(0).finish();
        let some_zero = Canonical::new("d", "v").opt_int(Some(0)).finish();
        assert_ne!(none_then_zero, some_zero);
    }

    #[test]
    fn version_tag_covers_every_field() {
        let k = key(1);
        let base = version("vault", "{}");
        let tag = version_tag(&k, &base);
        assert!(verify_version_tag(&k, &base, Some(&tag)));
        assert!(!verify_version_tag(&k, &base, None));
        assert!(!verify_version_tag(&key(2), &base, Some(&tag)));

        let variants = [
            VersionFields {
                enabled: false,
                ..base
            },
            VersionFields {
                expires_on: Some(11),
                ..base
            },
            VersionFields {
                not_before: Some(1),
                ..base
            },
            VersionFields {
                content_type: Some("text/plain"),
                ..base
            },
            VersionFields { seq: 2, ..base },
            VersionFields {
                updated_on: 7,
                ..base
            },
            VersionFields {
                version: "4567",
                ..base
            },
            VersionFields {
                name: "other",
                ..base
            },
            version("other-vault", "{}"),
            version("vault", "{\"a\":\"b\"}"),
        ];
        for changed in variants {
            assert!(
                !verify_version_tag(&k, &changed, Some(&tag)),
                "tag must not verify after changing {changed:?}"
            );
        }
    }

    #[test]
    fn secret_tag_covers_deletion_state() {
        let k = key(1);
        let live = SecretFields {
            vault_id: "vault",
            name: "db",
            created_on: 1,
            deleted_on: None,
            scheduled_purge_on: None,
            recovery_id: None,
            storage: None,
            description: None,
        };
        let deleted = SecretFields {
            deleted_on: Some(2),
            scheduled_purge_on: Some(3),
            recovery_id: Some("sourceorrery://vault/deletedsecrets/db"),
            ..live
        };
        let tag = secret_tag(&k, &deleted);
        assert!(verify_secret_tag(&k, &deleted, Some(&tag)));
        assert!(!verify_secret_tag(&k, &live, Some(&tag)));
    }

    #[test]
    fn secret_tag_covers_the_storage() {
        let k = key(1);
        let local = SecretFields {
            vault_id: "vault",
            name: "db",
            created_on: 1,
            deleted_on: None,
            scheduled_purge_on: None,
            recovery_id: None,
            storage: None,
            description: None,
        };
        let tag = secret_tag(&k, &local);
        for moved in [Some("c1"), Some("c2"), Some("")] {
            let at = SecretFields {
                storage: moved,
                ..local
            };
            assert!(!verify_secret_tag(&k, &at, Some(&tag)), "{moved:?}");
        }
        let at = SecretFields {
            storage: Some("c1"),
            ..local
        };
        let at_tag = secret_tag(&k, &at);
        assert!(!verify_secret_tag(
            &k,
            &SecretFields {
                storage: Some("c2"),
                ..at
            },
            Some(&at_tag)
        ));
    }

    #[test]
    fn secret_tag_covers_the_description() {
        let k = key(1);
        let plain = SecretFields {
            vault_id: "vault",
            name: "db",
            created_on: 1,
            deleted_on: None,
            scheduled_purge_on: None,
            recovery_id: None,
            storage: None,
            description: None,
        };
        let described = SecretFields {
            description: Some("Database authentication"),
            ..plain
        };
        let tag = secret_tag(&k, &described);
        assert!(verify_secret_tag(&k, &described, Some(&tag)));
        for changed in [
            plain,
            SecretFields {
                description: Some("Database"),
                ..plain
            },
            SecretFields {
                description: Some(""),
                ..plain
            },
        ] {
            assert!(!verify_secret_tag(&k, &changed, Some(&tag)), "{changed:?}");
        }
    }

    #[test]
    fn project_tag_covers_every_field_and_the_path_mac_needs_the_key() {
        let k = key(1);
        let mac = project_path_mac(&k, "vault", "/home/me/app");
        assert_eq!(mac, project_path_mac(&k, "vault", "/home/me/app"));
        for other in [
            project_path_mac(&k, "vault", "/home/me/app2"),
            project_path_mac(&k, "other-vault", "/home/me/app"),
            project_path_mac(&key(2), "vault", "/home/me/app"),
        ] {
            assert_ne!(mac, other);
        }
        let base = ProjectFields {
            vault_id: "vault",
            id: "p1",
            path_mac: &mac,
            sealed: "{\"nonce\":\"00\"}",
            linked_on: 1,
        };
        let tag = project_tag(&k, &base);
        assert!(verify_project_tag(&k, &base, Some(&tag)));
        assert!(!verify_project_tag(&k, &base, None));
        let other_mac = [7u8; MAC_LEN];
        for changed in [
            ProjectFields { id: "p2", ..base },
            ProjectFields {
                path_mac: &other_mac,
                ..base
            },
            ProjectFields {
                sealed: "{}",
                ..base
            },
            ProjectFields {
                linked_on: 2,
                ..base
            },
            ProjectFields {
                vault_id: "other",
                ..base
            },
        ] {
            assert!(
                !verify_project_tag(&k, &changed, Some(&tag)),
                "tag must not verify after changing {changed:?}"
            );
        }
    }

    #[test]
    fn connection_tag_covers_every_field() {
        let k = key(1);
        let base = ConnectionFields {
            vault_id: "vault",
            id: "c1",
            kind: "hashicorp-vault",
            settings_json: "{}",
            credential_source: "stored",
            sealed_credentials: Some("{\"nonce\":\"00\"}"),
            created_on: 1,
            last_test_on: None,
            last_test_outcome: None,
        };
        let tag = connection_tag(&k, &base);
        assert!(verify_connection_tag(&k, &base, Some(&tag)));
        assert!(!verify_connection_tag(&k, &base, None));
        for changed in [
            ConnectionFields { id: "c2", ..base },
            ConnectionFields {
                kind: "aws-secrets-manager",
                ..base
            },
            ConnectionFields {
                settings_json: "{\"a\":1}",
                ..base
            },
            ConnectionFields {
                credential_source: "ambient",
                sealed_credentials: None,
                ..base
            },
            ConnectionFields {
                created_on: 2,
                ..base
            },
            ConnectionFields {
                last_test_on: Some(3),
                last_test_outcome: Some("ok"),
                ..base
            },
            ConnectionFields {
                vault_id: "other",
                ..base
            },
        ] {
            assert!(
                !verify_connection_tag(&k, &changed, Some(&tag)),
                "tag must not verify after changing {changed:?}"
            );
        }
    }

    #[test]
    fn the_settings_record_covers_the_connections_and_none_adds_nothing() {
        let k = key(1);
        let base = SettingsFields {
            vault_id: "vault",
            schema: 4,
            name: "dev",
            created_on: 1,
            recovery_level: "\"recoverable\"",
            retention_days: 90,
            password: None,
            password_hint: None,
            second_factor: None,
            check_failures: None,
            connections: &[],
            projects: &[],
        };
        let tag = hex::encode(settings_tag(&k, &base));
        let one = [("c1".to_owned(), vec![1u8; MAC_LEN])];
        let with_one = SettingsFields {
            connections: &one,
            ..base
        };
        assert!(!verify_settings_tag(&k, &with_one, Some(&tag)));
        let one_tag = hex::encode(settings_tag(&k, &with_one));
        let replayed = [("c1".to_owned(), vec![2u8; MAC_LEN])];
        let two = [
            ("c1".to_owned(), vec![1u8; MAC_LEN]),
            ("c2".to_owned(), vec![3u8; MAC_LEN]),
        ];
        for changed in [&replayed[..], &two[..], &[]] {
            let fields = SettingsFields {
                connections: changed,
                ..base
            };
            assert!(
                !verify_settings_tag(&k, &fields, Some(&one_tag)),
                "{changed:?}"
            );
        }
        // A project listed under the same id is not a connection.
        let as_project = SettingsFields {
            projects: &one,
            ..base
        };
        assert!(!verify_settings_tag(&k, &as_project, Some(&one_tag)));
        assert!(!verify_settings_tag(&k, &as_project, Some(&tag)));
        // Without connections or projects the record is the one written
        // before they existed: only the fields above, in that order.
        let before = Canonical::new(SETTINGS_DOMAIN, "vault")
            .int(4)
            .str("dev")
            .int(1)
            .str("\"recoverable\"")
            .int(90)
            .finish();
        assert_eq!(tag, hex::encode(crypto::mac(&k, &before)));
    }

    #[test]
    fn checkpoint_blob_round_trip_and_matching() {
        let tag = [9u8; MAC_LEN];
        let present = Checkpoint::Present(tag);
        assert_eq!(Checkpoint::from_blob(present.as_blob()), Some(present));
        assert_eq!(Checkpoint::from_blob(&[]), Some(Checkpoint::Absent));
        assert_eq!(Checkpoint::from_blob(&[1u8; 5]), None);
        assert!(present.matches(Some(&tag)));
        assert!(!present.matches(Some(&[8u8; MAC_LEN])));
        assert!(!present.matches(None), "a checkpointed row must exist");
        assert!(Checkpoint::Absent.matches(None));
        assert!(
            !Checkpoint::Absent.matches(Some(&tag)),
            "a purged row must stay gone"
        );
    }

    #[test]
    fn audit_hash_covers_the_checkpoint_tags() {
        let k = key(3);
        let base = AuditFields {
            vault_id: "vault",
            id: 7,
            occurred_on: 100,
            actor: "user:me",
            operation: "secret_update",
            secret_name: Some("db"),
            version: Some("0123"),
            outcome: "success",
            detail: None,
            keyed: true,
            state_tag: None,
            version_tag: Some(&[1u8; MAC_LEN]),
            settings_tag: None,
        };
        let h = audit_hash(&k, &ZERO_HASH, &base);
        assert!(verify_audit_hash(&k, &ZERO_HASH, &base, Some(&h)));
        let other_tag = [2u8; MAC_LEN];
        for changed in [
            AuditFields {
                version_tag: Some(&other_tag),
                ..base
            },
            AuditFields {
                version_tag: None,
                ..base
            },
            AuditFields {
                version_tag: Some(&[]),
                ..base
            },
            AuditFields {
                state_tag: Some(&[]),
                ..base
            },
            AuditFields {
                state_tag: Some(&[1u8; MAC_LEN]),
                version_tag: None,
                ..base
            },
            AuditFields {
                settings_tag: Some(&other_tag),
                ..base
            },
            AuditFields {
                version_tag: None,
                settings_tag: Some(&[1u8; MAC_LEN]),
                ..base
            },
        ] {
            assert!(
                !verify_audit_hash(&k, &ZERO_HASH, &changed, Some(&h)),
                "hash must not verify after changing {changed:?}"
            );
        }
    }

    #[test]
    fn audit_chain_links_and_head() {
        let k = key(3);
        let first = AuditFields {
            vault_id: "vault",
            id: 1,
            occurred_on: 100,
            actor: "user:me",
            operation: "vault_create",
            secret_name: None,
            version: None,
            outcome: "success",
            detail: Some("encrypted-sqlite"),
            keyed: true,
            state_tag: None,
            version_tag: None,
            settings_tag: None,
        };
        let h1 = audit_hash(&k, &ZERO_HASH, &first);
        assert!(verify_audit_hash(&k, &ZERO_HASH, &first, Some(&h1)));
        let second = AuditFields {
            id: 2,
            operation: "secret_set",
            secret_name: Some("db"),
            ..first
        };
        let h2 = audit_hash(&k, &h1, &second);
        assert!(verify_audit_hash(&k, &h1, &second, Some(&h2)));
        assert!(
            !verify_audit_hash(&k, &ZERO_HASH, &second, Some(&h2)),
            "a row re-linked to a different predecessor must fail"
        );
        assert!(!verify_audit_hash(&zero_key(), &h1, &second, Some(&h2)));
        let unkeyed = AuditFields {
            keyed: false,
            ..second
        };
        assert!(!verify_audit_hash(&k, &h1, &unkeyed, Some(&h2)));

        let head = head_value(&k, "vault", 2, &h2, 2);
        assert!(head_matches(&k, "vault", &head, 2, &h2, 2));
        assert!(!head_matches(&k, "vault", &head, 1, &h1, 2));
        assert!(!head_matches(&k, "other", &head, 2, &h2, 2));
        assert!(!head_matches(&key(4), "vault", &head, 2, &h2, 2));
        assert!(!head_matches(&k, "vault", "garbage", 2, &h2, 2));
        assert!(!head_matches(&k, "vault", "2:zz", 2, &h2, 2));
        assert!(
            !head_matches(&k, "vault", &head, 2, &h2, 1),
            "a keyed row removed from the middle changes the count"
        );
        assert_eq!(head_id(&head), Some(2));
        assert_eq!(head_id("garbage"), None);
        assert_eq!(head_id("x:abcd"), None);
        // A head written before the count existed is accepted with any
        // count until it is rewritten.
        let legacy_mac = crypto::mac(&k, &head_canonical("vault", 2, &h2, None));
        let legacy = format!("2:{}", hex::encode(legacy_mac));
        assert!(head_matches(&k, "vault", &legacy, 2, &h2, 7));
        assert!(!head_matches(&k, "vault", &legacy, 3, &h2, 7));
        assert_eq!(parse_head(&legacy).unwrap().keyed, None);
        assert_eq!(parse_head(&head).unwrap().keyed, Some(2));
    }

    #[test]
    fn hash_or_zero_tolerates_bad_input() {
        assert_eq!(hash_or_zero(None), ZERO_HASH);
        assert_eq!(hash_or_zero(Some(&[1u8; 5])), ZERO_HASH);
        assert_eq!(hash_or_zero(Some(&[1u8; MAC_LEN])), [1u8; MAC_LEN]);
    }

    #[test]
    fn verification_verdict() {
        let ok = AuditVerification {
            rows: 3,
            keyed: 2,
            unkeyed: 1,
            first_broken: None,
            truncations: 0,
            unacknowledged: 0,
            head_valid: true,
        };
        assert!(ok.is_intact());
        assert!(
            !AuditVerification {
                first_broken: Some(2),
                ..ok.clone()
            }
            .is_intact()
        );
        assert!(
            !AuditVerification {
                truncations: 1,
                ..ok.clone()
            }
            .is_intact()
        );
        assert!(
            !AuditVerification {
                head_valid: false,
                ..ok
            }
            .is_intact()
        );
    }
}
