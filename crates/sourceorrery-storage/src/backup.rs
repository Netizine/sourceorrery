//! The encrypted backup file: how a [`Snapshot`] is sealed under a
//! passphrase and opened again (`docs/backup-format.md`).
//!
//! ```text
//! "SOBACKUP" | header length (u32 LE) | header JSON | nonce (24) | payload ciphertext
//! ```
//!
//! The header is clear text and names only the format, the source vault
//! (name and id), the time, the Argon2id parameters and salt, and a key
//! *verifier*. The payload is one XChaCha20-Poly1305 box under a key
//! derived from the passphrase, with the magic and the header bytes as
//! additional authenticated data, so no header field can be changed
//! without the payload failing to open; its nonce sits between the header
//! and the box. Inside the box: a JSON
//! document with every secret's metadata and the length of each value,
//! followed by the values themselves, back to back. Values never pass
//! through `serde`: they are copied from [`SecretBytes`] into a zeroising
//! buffer that is encrypted at once, and sliced back into [`SecretBytes`]
//! when opened.
//!
//! The verifier is the magic sealed under the same key with its own AAD.
//! It tells a wrong passphrase ([`SecretError::BackupPassphrase`]) from a
//! file that was altered ([`SecretError::Crypto`]); both are refused.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sourceorrery_core::backup::{DeletedState, SecretSnapshot, Snapshot, VersionSnapshot};
use sourceorrery_core::{Result, SecretBytes, SecretError, timestamp, validate_secret_name};
use sourceorrery_crypto::{Argon2Params, Ciphertext, NONCE_LEN, SALT_LEN, aead, kdf, random};
use time::OffsetDateTime;
use zeroize::Zeroizing;

/// Newest backup format this build writes and reads.
pub const BACKUP_FORMAT: u16 = 1;

const MAGIC: &[u8; 8] = b"SOBACKUP";
const VERIFIER_AAD: &[u8] = b"sourceorrery/backup/v1/verifier";
/// Largest header this build accepts, so a crafted length cannot make it
/// allocate or parse without bound.
const MAX_HEADER: usize = 64 * 1024;

#[derive(Serialize, Deserialize)]
struct Header {
    format: u16,
    vault: String,
    vault_id: String,
    created_on: String,
    kdf: Kdf,
    salt: String,
    verifier: Box_,
}

#[derive(Serialize, Deserialize)]
struct Kdf {
    algorithm: String,
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
}

/// A small sealed box, hex-encoded for the header.
#[derive(Serialize, Deserialize)]
struct Box_ {
    nonce: String,
    bytes: String,
}

/// The metadata half of the payload. Every value's length is here; the
/// bytes follow the JSON, in this order.
#[derive(Serialize, Deserialize)]
struct Payload {
    secrets: Vec<SecretMeta>,
}

#[derive(Serialize, Deserialize)]
struct SecretMeta {
    name: String,
    created_on: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    deleted: Option<DeletedMeta>,
    versions: Vec<VersionMeta>,
}

#[derive(Serialize, Deserialize)]
struct DeletedMeta {
    deleted_on: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    scheduled_purge_on: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct VersionMeta {
    version: String,
    enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    content_type: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    tags: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    not_before: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    expires_on: Option<String>,
    created_on: String,
    updated_on: String,
    /// Length of the value in the bytes that follow the JSON.
    len: u64,
}

/// Just the format number of a header, read before the rest is parsed.
#[derive(Deserialize)]
struct FormatOnly {
    format: u16,
}

/// What the clear-text header says, readable without the passphrase.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct BackupInfo {
    pub format: u16,
    pub vault: String,
    pub vault_id: String,
    #[serde(with = "time::serde::rfc3339")]
    pub created_on: OffsetDateTime,
}

fn malformed(what: &str) -> SecretError {
    SecretError::Crypto(format!("backup file is malformed: {what}"))
}

/// A primitive failed (bad key, altered bytes): the file is refused.
#[allow(clippy::needless_pass_by_value)] // a `map_err` target
fn crypto(err: sourceorrery_crypto::CryptoError) -> SecretError {
    SecretError::Crypto(format!("backup file: {err}"))
}

fn fmt_opt(ts: Option<OffsetDateTime>) -> Option<String> {
    ts.map(timestamp::format)
}

fn parse_opt(text: Option<&str>) -> Result<Option<OffsetDateTime>> {
    text.map(timestamp::parse).transpose()
}

/// Seal `snapshot` under `passphrase` into the bytes of a backup file.
pub fn seal(
    snapshot: &Snapshot,
    passphrase: &SecretBytes,
    params: Argon2Params,
) -> Result<Vec<u8>> {
    if passphrase.is_empty() {
        return Err(SecretError::InvalidArgument(
            "the backup passphrase must not be empty".to_owned(),
        ));
    }
    // Metadata first, then every value back to back, all in one zeroising
    // buffer that the AEAD consumes whole.
    let mut metas = Vec::with_capacity(snapshot.secrets.len());
    let mut values_len = 0usize;
    for secret in &snapshot.secrets {
        metas.push(SecretMeta {
            name: secret.name.clone(),
            created_on: timestamp::format(secret.created_on),
            deleted: secret.deleted.as_ref().map(|d| DeletedMeta {
                deleted_on: timestamp::format(d.deleted_on),
                scheduled_purge_on: fmt_opt(d.scheduled_purge_on),
            }),
            versions: secret
                .versions
                .iter()
                .map(|v| {
                    values_len += v.value.len();
                    VersionMeta {
                        version: v.version.clone(),
                        enabled: v.enabled,
                        content_type: v.content_type.clone(),
                        tags: v.tags.clone(),
                        not_before: fmt_opt(v.not_before),
                        expires_on: fmt_opt(v.expires_on),
                        created_on: timestamp::format(v.created_on),
                        updated_on: timestamp::format(v.updated_on),
                        len: v.value.len() as u64,
                    }
                })
                .collect(),
        });
    }
    let meta_json = serde_json::to_vec(&Payload { secrets: metas })
        .map_err(|err| SecretError::Storage(format!("cannot encode backup: {err}")))?;
    let meta_len = u32::try_from(meta_json.len())
        .map_err(|_| SecretError::InvalidArgument("backup metadata too large".to_owned()))?;
    let mut plaintext = Zeroizing::new(Vec::with_capacity(4 + meta_json.len() + values_len));
    plaintext.extend_from_slice(&meta_len.to_le_bytes());
    plaintext.extend_from_slice(&meta_json);
    for secret in &snapshot.secrets {
        for version in &secret.versions {
            plaintext.extend_from_slice(version.value.expose());
        }
    }

    let salt: [u8; SALT_LEN] = random::random_bytes().map_err(crypto)?;
    let key = kdf::derive_key(passphrase.expose(), &salt, params).map_err(crypto)?;
    let verifier = aead::seal(&key, VERIFIER_AAD, MAGIC).map_err(crypto)?;
    let header = Header {
        format: BACKUP_FORMAT,
        vault: snapshot.vault.clone(),
        vault_id: snapshot.vault_id.clone(),
        created_on: timestamp::format(snapshot.created_on),
        kdf: Kdf {
            algorithm: "argon2id".to_owned(),
            memory_kib: params.memory_kib,
            iterations: params.iterations,
            parallelism: params.parallelism,
        },
        salt: hex::encode(salt),
        verifier: Box_ {
            nonce: hex::encode(verifier.nonce),
            bytes: hex::encode(&verifier.bytes),
        },
    };
    let header_json = serde_json::to_vec(&header)
        .map_err(|err| SecretError::Storage(format!("cannot encode backup header: {err}")))?;
    let header_len = u32::try_from(header_json.len())
        .map_err(|_| SecretError::InvalidArgument("backup header too large".to_owned()))?;

    let ciphertext = aead::seal(&key, &aad_for(&header_json), &plaintext).map_err(crypto)?;
    let mut out = Vec::with_capacity(
        MAGIC.len() + 4 + header_json.len() + NONCE_LEN + ciphertext.bytes.len(),
    );
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&header_len.to_le_bytes());
    out.extend_from_slice(&header_json);
    out.extend_from_slice(&ciphertext.nonce);
    out.extend_from_slice(&ciphertext.bytes);
    Ok(out)
}

fn aad_for(header_json: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(MAGIC.len() + header_json.len());
    aad.extend_from_slice(MAGIC);
    aad.extend_from_slice(header_json);
    aad
}

/// Split a backup file into its parsed header, the header's raw bytes and
/// the payload ciphertext.
fn split(bytes: &[u8]) -> Result<(Header, &[u8], &[u8])> {
    if bytes.len() < MAGIC.len() + 4 || &bytes[..MAGIC.len()] != MAGIC {
        return Err(malformed("not a SourceOrrery backup"));
    }
    let len_bytes: [u8; 4] = bytes[MAGIC.len()..MAGIC.len() + 4]
        .try_into()
        .map_err(|_| malformed("truncated header length"))?;
    let header_len = u32::from_le_bytes(len_bytes) as usize;
    if header_len > MAX_HEADER || bytes.len() < MAGIC.len() + 4 + header_len {
        return Err(malformed("header length out of range"));
    }
    let header_json = &bytes[MAGIC.len() + 4..MAGIC.len() + 4 + header_len];
    let payload = &bytes[MAGIC.len() + 4 + header_len..];
    // The format number is read before anything else, so a newer file is
    // reported as such rather than as malformed.
    let format: FormatOnly =
        serde_json::from_slice(header_json).map_err(|_| malformed("unreadable header"))?;
    if format.format > BACKUP_FORMAT {
        return Err(SecretError::BackupFormat {
            version: format.format,
        });
    }
    let header: Header =
        serde_json::from_slice(header_json).map_err(|_| malformed("unreadable header"))?;
    Ok((header, header_json, payload))
}

/// Read the clear-text header of a backup file. No passphrase is needed
/// and nothing is checked beyond the shape: use it for messages only.
pub fn inspect(bytes: &[u8]) -> Result<BackupInfo> {
    let (header, _, _) = split(bytes)?;
    Ok(BackupInfo {
        format: header.format,
        vault: header.vault,
        vault_id: header.vault_id,
        created_on: timestamp::parse(&header.created_on)?,
    })
}

fn decode_hex(text: &str, what: &str) -> Result<Vec<u8>> {
    hex::decode(text).map_err(|_| malformed(&format!("{what} is not hex")))
}

/// Open the bytes of a backup file with `passphrase`.
///
/// A wrong passphrase is [`SecretError::BackupPassphrase`]; a file that was
/// altered anywhere is [`SecretError::Crypto`]; a file from a newer build
/// is [`SecretError::BackupFormat`]. The Argon2id parameters are capped
/// like a protector's before they run.
pub fn open(bytes: &[u8], passphrase: &SecretBytes) -> Result<Snapshot> {
    let (header, header_json, payload) = split(bytes)?;
    if header.kdf.algorithm != "argon2id" {
        return Err(malformed("unknown key derivation"));
    }
    let params = Argon2Params {
        memory_kib: header.kdf.memory_kib,
        iterations: header.kdf.iterations,
        parallelism: header.kdf.parallelism,
    };
    if !params.within_limits() {
        return Err(malformed("key derivation parameters beyond the ceiling"));
    }
    let salt = decode_hex(&header.salt, "salt")?;
    let key = kdf::derive_key(passphrase.expose(), &salt, params).map_err(crypto)?;

    let verifier = Ciphertext::from_parts(
        &decode_hex(&header.verifier.nonce, "verifier nonce")?,
        decode_hex(&header.verifier.bytes, "verifier")?,
    )
    .map_err(|_| malformed("verifier"))?;
    match aead::open(&key, VERIFIER_AAD, &verifier) {
        Ok(magic) if magic.as_slice() == MAGIC => {}
        _ => return Err(SecretError::BackupPassphrase),
    }

    if payload.len() < NONCE_LEN {
        return Err(malformed("payload"));
    }
    let (nonce, boxed) = payload.split_at(NONCE_LEN);
    let ciphertext =
        Ciphertext::from_parts(nonce, boxed.to_vec()).map_err(|_| malformed("payload"))?;
    let plaintext = aead::open(&key, &aad_for(header_json), &ciphertext).map_err(crypto)?;
    decode_payload(&header, &plaintext)
}

fn decode_payload(header: &Header, plaintext: &[u8]) -> Result<Snapshot> {
    if plaintext.len() < 4 {
        return Err(malformed("payload"));
    }
    let meta_len = u32::from_le_bytes(plaintext[..4].try_into().expect("4 bytes")) as usize;
    if plaintext.len() < 4 + meta_len {
        return Err(malformed("payload metadata length"));
    }
    let payload: Payload = serde_json::from_slice(&plaintext[4..4 + meta_len])
        .map_err(|_| malformed("payload metadata"))?;
    let mut values = &plaintext[4 + meta_len..];
    let mut secrets = Vec::with_capacity(payload.secrets.len());
    for secret in payload.secrets {
        // A crafted file must not smuggle an invalid name into a vault.
        validate_secret_name(&secret.name)?;
        let mut versions = Vec::with_capacity(secret.versions.len());
        for v in secret.versions {
            let len = usize::try_from(v.len).map_err(|_| malformed("value length"))?;
            if values.len() < len {
                return Err(malformed("values shorter than declared"));
            }
            let (value, rest) = values.split_at(len);
            values = rest;
            versions.push(VersionSnapshot {
                version: v.version,
                enabled: v.enabled,
                content_type: v.content_type,
                tags: v.tags,
                not_before: parse_opt(v.not_before.as_deref())?,
                expires_on: parse_opt(v.expires_on.as_deref())?,
                created_on: timestamp::parse(&v.created_on)?,
                updated_on: timestamp::parse(&v.updated_on)?,
                value: SecretBytes::new(value.to_vec()),
            });
        }
        secrets.push(SecretSnapshot {
            name: secret.name,
            created_on: timestamp::parse(&secret.created_on)?,
            deleted: secret
                .deleted
                .map(|d| -> Result<DeletedState> {
                    Ok(DeletedState {
                        deleted_on: timestamp::parse(&d.deleted_on)?,
                        scheduled_purge_on: parse_opt(d.scheduled_purge_on.as_deref())?,
                    })
                })
                .transpose()?,
            versions,
        });
    }
    if !values.is_empty() {
        return Err(malformed("values longer than declared"));
    }
    Ok(Snapshot {
        vault: header.vault.clone(),
        vault_id: header.vault_id.clone(),
        created_on: timestamp::parse(&header.created_on)?,
        secrets,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot() -> Snapshot {
        Snapshot {
            vault: "dev".into(),
            vault_id: "0123".into(),
            created_on: OffsetDateTime::UNIX_EPOCH,
            secrets: vec![SecretSnapshot {
                name: "api-key".into(),
                created_on: OffsetDateTime::UNIX_EPOCH,
                deleted: None,
                versions: vec![
                    VersionSnapshot {
                        version: "a1".into(),
                        enabled: false,
                        content_type: Some("text/plain".into()),
                        tags: BTreeMap::from([("env".to_owned(), "ci".to_owned())]),
                        not_before: None,
                        expires_on: None,
                        created_on: OffsetDateTime::UNIX_EPOCH,
                        updated_on: OffsetDateTime::UNIX_EPOCH,
                        value: SecretBytes::from("CANARY-one"),
                    },
                    VersionSnapshot {
                        version: "a2".into(),
                        enabled: true,
                        content_type: None,
                        tags: BTreeMap::new(),
                        not_before: None,
                        expires_on: None,
                        created_on: OffsetDateTime::UNIX_EPOCH,
                        updated_on: OffsetDateTime::UNIX_EPOCH,
                        value: SecretBytes::new(Vec::new()),
                    },
                ],
            }],
        }
    }

    #[test]
    fn round_trip_keeps_metadata_and_values_and_hides_them_on_disk() {
        let passphrase = SecretBytes::from("backup-pass");
        let bytes = seal(&snapshot(), &passphrase, Argon2Params::TESTING).unwrap();
        assert!(bytes.starts_with(MAGIC));
        for needle in [
            b"CANARY-one".as_slice(),
            b"api-key",
            b"backup-pass",
            b"text/plain",
        ] {
            assert!(
                !bytes.windows(needle.len()).any(|w| w == needle),
                "{} must not be in the file",
                String::from_utf8_lossy(needle)
            );
        }
        let info = inspect(&bytes).unwrap();
        assert_eq!((info.format, info.vault.as_str()), (1, "dev"));
        let back = open(&bytes, &passphrase).unwrap();
        assert_eq!(back.vault, "dev");
        let secret = &back.secrets[0];
        assert_eq!(secret.name, "api-key");
        assert_eq!(secret.versions.len(), 2);
        assert_eq!(secret.versions[0].value.expose(), b"CANARY-one");
        assert!(!secret.versions[0].enabled);
        assert_eq!(secret.versions[0].tags["env"], "ci");
        assert!(secret.versions[1].value.is_empty());
    }

    #[test]
    fn wrong_passphrase_newer_format_and_tampering_are_told_apart() {
        let bytes = seal(
            &snapshot(),
            &SecretBytes::from("right"),
            Argon2Params::TESTING,
        )
        .unwrap();
        assert_eq!(
            open(&bytes, &SecretBytes::from("wrong"))
                .unwrap_err()
                .code(),
            "backup_passphrase"
        );
        let mut flipped = bytes.clone();
        let last = flipped.len() - 1;
        flipped[last] ^= 1;
        assert_eq!(
            open(&flipped, &SecretBytes::from("right"))
                .unwrap_err()
                .code(),
            "crypto"
        );
        let text = String::from_utf8_lossy(&bytes).into_owned();
        let newer = text.replacen("\"format\":1", "\"format\":9", 1);
        assert_eq!(
            open(newer.as_bytes(), &SecretBytes::from("right"))
                .unwrap_err()
                .code(),
            "backup_format"
        );
        assert_eq!(
            open(b"nope", &SecretBytes::from("right"))
                .unwrap_err()
                .code(),
            "crypto"
        );
        assert_eq!(
            seal(
                &snapshot(),
                &SecretBytes::new(Vec::new()),
                Argon2Params::TESTING
            )
            .unwrap_err()
            .code(),
            "invalid_argument"
        );
    }
}
