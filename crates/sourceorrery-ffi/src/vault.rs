//! Vault handles and the secret operations.
//!
//! Each exported function has one job: turn raw C arguments into safe Rust
//! values, call the corresponding `SecretClient` method, and hand the result
//! back as JSON or bytes. The `# Safety` section of every function is the
//! contract its caller must uphold; the `SAFETY:` comments inside refer to it.

use std::ptr;

use serde::de::DeserializeOwned;
use sourceorrery_core::{
    Result, SecretBytes, SecretClient, SecretError, SetSecretOptions, UpdateSecretProperties,
};
use sourceorrery_storage::{
    NoInteraction, ProtectorSpec, SqliteVault, StaticPassphrase, UnlockProvider, VaultRegistry,
};

use crate::buffer::so_bytes;
use crate::error::{guard, so_status};
use crate::json::{self, AuditFilter, CreateOptions};

/// An unlocked vault. Opaque: created by [`so_vault_create`] or
/// [`so_vault_open`], released by [`so_vault_close`], usable from several
/// threads at once.
#[derive(Debug)]
pub struct so_vault {
    inner: SqliteVault,
}

const fn assert_send_sync<T: Send + Sync>() {}
// A handle may be shared between threads, so the vault must be Sync.
const _: () = assert_send_sync::<so_vault>();

// ---------------------------------------------------------------------------
// Argument helpers. All `unsafe fn`s below rely on the exported function's
// caller contract: a pointer is either NULL or readable for `len` bytes
// (inputs) / writable (outputs) for the duration of the call.
// ---------------------------------------------------------------------------

pub(crate) fn invalid_argument(message: impl Into<String>) -> SecretError {
    SecretError::InvalidArgument(message.into())
}

/// A byte range that may be absent.
///
/// # Safety
///
/// `ptr` is NULL or readable for `len` bytes for the lifetime `'a`.
pub(crate) unsafe fn opt_bytes<'a>(
    ptr: *const u8,
    len: usize,
    what: &str,
) -> Result<Option<&'a [u8]>> {
    if ptr.is_null() {
        if len == 0 {
            return Ok(None);
        }
        return Err(invalid_argument(format!(
            "{what}: NULL pointer with non-zero length"
        )));
    }
    // SAFETY: the caller guarantees `ptr` is readable for `len` bytes and
    // outlives `'a`; `u8` has no alignment requirement.
    Ok(Some(unsafe { std::slice::from_raw_parts(ptr, len) }))
}

/// A required byte range (NULL with `len == 0` is the empty range).
///
/// # Safety
///
/// As [`opt_bytes`].
pub(crate) unsafe fn bytes<'a>(ptr: *const u8, len: usize, what: &str) -> Result<&'a [u8]> {
    // SAFETY: forwarded caller contract.
    Ok(unsafe { opt_bytes(ptr, len, what) }?.unwrap_or_default())
}

fn utf8<'a>(bytes: &'a [u8], what: &str) -> Result<&'a str> {
    std::str::from_utf8(bytes).map_err(|_| invalid_argument(format!("{what}: not valid UTF-8")))
}

/// A required UTF-8 string.
///
/// # Safety
///
/// As [`opt_bytes`].
pub(crate) unsafe fn string<'a>(ptr: *const u8, len: usize, what: &str) -> Result<&'a str> {
    // SAFETY: forwarded caller contract.
    utf8(unsafe { bytes(ptr, len, what) }?, what)
}

/// A UTF-8 string that may be absent.
///
/// # Safety
///
/// As [`opt_bytes`].
pub(crate) unsafe fn opt_string<'a>(
    ptr: *const u8,
    len: usize,
    what: &str,
) -> Result<Option<&'a str>> {
    // SAFETY: forwarded caller contract.
    unsafe { opt_bytes(ptr, len, what) }?
        .map(|bytes| utf8(bytes, what))
        .transpose()
}

/// A JSON document that may be absent (NULL or empty means "default").
///
/// # Safety
///
/// As [`opt_bytes`].
pub(crate) unsafe fn opt_json<T: DeserializeOwned + Default>(
    ptr: *const u8,
    len: usize,
    what: &str,
) -> Result<T> {
    // SAFETY: forwarded caller contract.
    match unsafe { opt_bytes(ptr, len, what) }? {
        None | Some([]) => Ok(T::default()),
        Some(bytes) => json::parse(bytes, what),
    }
}

/// A required JSON document.
///
/// # Safety
///
/// As [`opt_bytes`].
pub(crate) unsafe fn required_json<T: DeserializeOwned>(
    ptr: *const u8,
    len: usize,
    what: &str,
) -> Result<T> {
    // SAFETY: forwarded caller contract.
    let bytes = unsafe { bytes(ptr, len, what) }?;
    if bytes.is_empty() {
        return Err(invalid_argument(format!("{what}: must not be empty")));
    }
    json::parse(bytes, what)
}

/// The vault behind a handle.
///
/// # Safety
///
/// `handle` is NULL or a handle from [`so_vault_create`] / [`so_vault_open`]
/// that has not been closed and stays open for the lifetime `'a`.
unsafe fn vault<'a>(handle: *const so_vault) -> Result<&'a SqliteVault> {
    if handle.is_null() {
        return Err(invalid_argument("handle: NULL"));
    }
    // SAFETY: the caller guarantees a non-null handle is a live `so_vault`
    // leaked by `Box::into_raw` in `so_vault_create` / `so_vault_open`.
    Ok(unsafe { &(*handle).inner })
}

/// An output slot, reset to `initial` before anything else can fail.
///
/// The slot may hold uninitialised memory: a C caller passes `so_bytes out;`
/// without zeroing it. It is therefore written through the raw pointer first
/// and a reference is formed only once it holds a `T`; forming the reference
/// first would be undefined behaviour, and the assignment would drop
/// whatever garbage the slot held.
///
/// # Safety
///
/// `ptr` is NULL or valid for writes of `T` for the lifetime `'a`.
pub(crate) unsafe fn output<'a, T>(ptr: *mut T, initial: T, what: &str) -> Result<&'a mut T> {
    if ptr.is_null() {
        return Err(invalid_argument(format!("{what}: NULL")));
    }
    // SAFETY: the caller guarantees `ptr` is valid for writes of `T` and
    // not aliased for the duration of the call; `write` neither reads nor
    // drops the previous contents, and the reference is created only after
    // the slot has been initialised.
    unsafe {
        ptr.write(initial);
        Ok(&mut *ptr)
    }
}

fn registry(home: Option<&str>) -> Result<VaultRegistry> {
    match home {
        Some(home) if !home.is_empty() => Ok(VaultRegistry::with_root(home)),
        _ => VaultRegistry::from_env(),
    }
}

fn publish(out: &mut *mut so_vault, vault: SqliteVault) {
    *out = Box::into_raw(Box::new(so_vault { inner: vault }));
}

// ---------------------------------------------------------------------------
// Vault lifecycle
// ---------------------------------------------------------------------------

/// Create a vault and return an open handle to it.
///
/// `home` (nullable) is the SourceOrrery home directory; `NULL` or empty
/// selects `SOURCEORRERY_HOME` or the platform data directory. `name` must
/// satisfy the vault naming rules. `options_json` (nullable) is documented at
/// `CreateOptions` in the crate documentation. With a non-null `passphrase`
/// the vault gets a passphrase protector; with `NULL` it gets an OS-keyring
/// protector (`unsupported` where no credential store is available). An
/// empty passphrase is rejected.
///
/// On success `*out_handle` holds the handle; on failure it is `NULL`.
///
/// # Safety
///
/// Every `(pointer, length)` pair must be `NULL` or readable for that many
/// bytes for the duration of the call, and `out_handle` must be valid for
/// writes. The caller's `passphrase` buffer is copied and should be zeroised
/// by the caller afterwards.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn so_vault_create(
    home: *const u8,
    home_len: usize,
    name: *const u8,
    name_len: usize,
    options_json: *const u8,
    options_json_len: usize,
    passphrase: *const u8,
    passphrase_len: usize,
    out_handle: *mut *mut so_vault,
) -> so_status {
    guard(|| -> Result<()> {
        // SAFETY: the caller upholds this function's `# Safety` contract.
        let out = unsafe { output(out_handle, ptr::null_mut(), "out_handle") }?;
        // SAFETY: the caller upholds this function's `# Safety` contract.
        let (home, name, options, passphrase) = unsafe {
            (
                opt_string(home, home_len, "home")?,
                string(name, name_len, "name")?,
                opt_json::<CreateOptions>(options_json, options_json_len, "options_json")?,
                opt_bytes(passphrase, passphrase_len, "passphrase")?,
            )
        };
        let protector = match passphrase {
            None => ProtectorSpec::OsKeyring,
            Some([]) => return Err(invalid_argument("passphrase: must not be empty")),
            Some(passphrase) => ProtectorSpec::Passphrase {
                passphrase: SecretBytes::new(passphrase.to_vec()),
                params: options.argon2_params(),
            },
        };
        let vault = registry(home)?.create(name, options.vault_options(), protector)?;
        publish(out, vault);
        Ok(())
    })
}

/// Open and unlock an existing vault.
///
/// `home` and `name` are as for [`so_vault_create`]. OS-keyring protectors
/// are tried first. If none unlocks the vault and `passphrase` is non-null
/// it is tried once against the passphrase protectors; with `NULL` the call
/// fails with `locked` when the keyring cannot unlock the vault. Failed
/// unlock attempts are audited.
///
/// # Safety
///
/// As [`so_vault_create`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn so_vault_open(
    home: *const u8,
    home_len: usize,
    name: *const u8,
    name_len: usize,
    passphrase: *const u8,
    passphrase_len: usize,
    out_handle: *mut *mut so_vault,
) -> so_status {
    guard(|| -> Result<()> {
        // SAFETY: the caller upholds this function's `# Safety` contract.
        let out = unsafe { output(out_handle, ptr::null_mut(), "out_handle") }?;
        // SAFETY: the caller upholds this function's `# Safety` contract.
        let (home, name, passphrase) = unsafe {
            (
                opt_string(home, home_len, "home")?,
                string(name, name_len, "name")?,
                opt_bytes(passphrase, passphrase_len, "passphrase")?,
            )
        };
        let registry = registry(home)?;
        let vault = match passphrase {
            None => registry.open(name, &NoInteraction),
            Some(passphrase) => {
                let unlock = StaticPassphrase::new(SecretBytes::new(passphrase.to_vec()));
                let provider: &dyn UnlockProvider = &unlock;
                registry.open(name, provider)
            }
        }?;
        publish(out, vault);
        Ok(())
    })
}

/// Close a handle. The vault key held in memory is zeroised. `NULL` is
/// accepted and ignored.
///
/// # Safety
///
/// `handle` must be `NULL` or a handle from [`so_vault_create`] /
/// [`so_vault_open`] that is closed exactly once and is not in use by any
/// other thread at the time of the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn so_vault_close(handle: *mut so_vault) {
    if handle.is_null() {
        return;
    }
    // SAFETY: the caller guarantees `handle` was leaked by `Box::into_raw` in
    // `publish`, is closed only once, and has no other users right now.
    let vault = unsafe { Box::from_raw(handle) };
    // Dropping must not unwind into C; a failure here has nothing to report.
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || drop(vault)));
}

/// Non-sensitive description of the vault as JSON
/// (`sourceorrery_core::VaultDescriptor`: name, id, backend, path,
/// created_on, recovery_level, retention_days, protectors).
///
/// # Safety
///
/// `handle` must be a live handle; `out_json` must be valid for writes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn so_vault_descriptor(
    handle: *const so_vault,
    out_json: *mut so_bytes,
) -> so_status {
    guard(|| -> Result<()> {
        // SAFETY: the caller upholds this function's `# Safety` contract.
        let out = unsafe { output(out_json, so_bytes::EMPTY, "out_json") }?;
        // SAFETY: the caller upholds this function's `# Safety` contract.
        let vault = unsafe { vault(handle) }?;
        *out = json::to_bytes(&vault.descriptor()?)?;
        Ok(())
    })
}

// ---------------------------------------------------------------------------
// Secrets
// ---------------------------------------------------------------------------

/// Create a new immutable version of `name` holding `value`
/// (`SecretClient::set_secret`).
///
/// `options_json` (nullable) is a `SetSecretOptions` document:
/// `{"content_type": "...", "tags": {"k": "v"}, "enabled": true,
/// "not_before": "<RFC 3339>", "expires_on": "<RFC 3339>"}`, every field
/// optional. `*out_properties_json` receives the new version's
/// `SecretProperties`.
///
/// The value is copied; the Rust copy is zeroised before the call returns.
/// The caller should zeroise its own buffer afterwards.
///
/// # Safety
///
/// `handle` must be a live handle; every `(pointer, length)` pair must be
/// `NULL` or readable for that many bytes; `out_properties_json` must be
/// valid for writes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn so_secret_set(
    handle: *const so_vault,
    name: *const u8,
    name_len: usize,
    value: *const u8,
    value_len: usize,
    options_json: *const u8,
    options_json_len: usize,
    out_properties_json: *mut so_bytes,
) -> so_status {
    guard(|| -> Result<()> {
        // SAFETY: the caller upholds this function's `# Safety` contract.
        let out = unsafe { output(out_properties_json, so_bytes::EMPTY, "out_properties_json") }?;
        // SAFETY: the caller upholds this function's `# Safety` contract.
        let (vault, name, value, options) = unsafe {
            (
                vault(handle)?,
                string(name, name_len, "name")?,
                bytes(value, value_len, "value")?,
                opt_json::<SetSecretOptions>(options_json, options_json_len, "options_json")?,
            )
        };
        let props = vault.set_secret(name, SecretBytes::new(value.to_vec()), options)?;
        *out = json::to_bytes(&props)?;
        Ok(())
    })
}

/// Retrieve a version's value and metadata (`SecretClient::get_secret`).
///
/// `version` (nullable) selects a specific version; `NULL` selects the newest
/// accessible one (enabled and inside its time window). Policy errors are
/// `disabled`, `not_yet_valid` and `expired`. `*out_properties_json`
/// receives the version's `SecretProperties`; `*out_value` receives the
/// plaintext, which the caller must release with `so_bytes_free` as soon
/// as it has been used.
///
/// # Safety
///
/// `handle` must be a live handle; `name` and `version` must be `NULL` or
/// readable for their lengths; both output pointers must be valid for
/// writes and distinct.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn so_secret_get(
    handle: *const so_vault,
    name: *const u8,
    name_len: usize,
    version: *const u8,
    version_len: usize,
    out_properties_json: *mut so_bytes,
    out_value: *mut so_bytes,
) -> so_status {
    guard(|| -> Result<()> {
        // SAFETY: the caller upholds this function's `# Safety` contract.
        let (out_props, out_value) = unsafe {
            (
                output(out_properties_json, so_bytes::EMPTY, "out_properties_json")?,
                output(out_value, so_bytes::EMPTY, "out_value")?,
            )
        };
        // SAFETY: the caller upholds this function's `# Safety` contract.
        let (vault, name, version) = unsafe {
            (
                vault(handle)?,
                string(name, name_len, "name")?,
                opt_string(version, version_len, "version")?,
            )
        };
        let secret = vault.get_secret(name, version)?;
        *out_props = json::to_bytes(&secret.properties)?;
        *out_value = so_bytes::copy_of(secret.value.expose());
        Ok(())
    })
}

/// Retrieve metadata only (`SecretClient::get_secret_properties`). Policy is
/// not applied, so disabled and expired versions can be inspected.
///
/// # Safety
///
/// As [`so_secret_get`], with one output pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn so_secret_get_properties(
    handle: *const so_vault,
    name: *const u8,
    name_len: usize,
    version: *const u8,
    version_len: usize,
    out_properties_json: *mut so_bytes,
) -> so_status {
    guard(|| -> Result<()> {
        // SAFETY: the caller upholds this function's `# Safety` contract.
        let out = unsafe { output(out_properties_json, so_bytes::EMPTY, "out_properties_json") }?;
        // SAFETY: the caller upholds this function's `# Safety` contract.
        let (vault, name, version) = unsafe {
            (
                vault(handle)?,
                string(name, name_len, "name")?,
                opt_string(version, version_len, "version")?,
            )
        };
        *out = json::to_bytes(&vault.get_secret_properties(name, version)?)?;
        Ok(())
    })
}

/// Metadata of the newest version of every live secret, as a JSON array of
/// `SecretProperties` (`SecretClient::list_properties_of_secrets`).
///
/// # Safety
///
/// `handle` must be a live handle; `out_json` must be valid for writes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn so_secret_list(
    handle: *const so_vault,
    out_json: *mut so_bytes,
) -> so_status {
    guard(|| -> Result<()> {
        // SAFETY: the caller upholds this function's `# Safety` contract.
        let out = unsafe { output(out_json, so_bytes::EMPTY, "out_json") }?;
        // SAFETY: the caller upholds this function's `# Safety` contract.
        let vault = unsafe { vault(handle) }?;
        *out = json::to_bytes(&vault.list_properties_of_secrets()?)?;
        Ok(())
    })
}

/// Metadata of every version of `name`, newest first, as a JSON array of
/// `SecretProperties` (`SecretClient::list_properties_of_secret_versions`).
///
/// # Safety
///
/// `handle` must be a live handle; `name` must be readable for `name_len`
/// bytes; `out_json` must be valid for writes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn so_secret_versions(
    handle: *const so_vault,
    name: *const u8,
    name_len: usize,
    out_json: *mut so_bytes,
) -> so_status {
    guard(|| -> Result<()> {
        // SAFETY: the caller upholds this function's `# Safety` contract.
        let out = unsafe { output(out_json, so_bytes::EMPTY, "out_json") }?;
        // SAFETY: the caller upholds this function's `# Safety` contract.
        let (vault, name) = unsafe { (vault(handle)?, string(name, name_len, "name")?) };
        *out = json::to_bytes(&vault.list_properties_of_secret_versions(name)?)?;
        Ok(())
    })
}

/// Change the metadata of one version, never its value
/// (`SecretClient::update_secret_properties`).
///
/// `version` (nullable) selects the version; `NULL` selects the newest.
/// `update_json` is an `UpdateSecretProperties` document: `{"enabled": bool,
/// "content_type": "..." | null, "tags": {...}, "not_before": "<RFC 3339>" |
/// null, "expires_on": "<RFC 3339>" | null}`. An absent field is unchanged,
/// `null` clears it. An empty update is `invalid_argument`.
/// `*out_properties_json` receives the updated `SecretProperties`.
///
/// # Safety
///
/// As [`so_secret_set`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn so_secret_update(
    handle: *const so_vault,
    name: *const u8,
    name_len: usize,
    version: *const u8,
    version_len: usize,
    update_json: *const u8,
    update_json_len: usize,
    out_properties_json: *mut so_bytes,
) -> so_status {
    guard(|| -> Result<()> {
        // SAFETY: the caller upholds this function's `# Safety` contract.
        let out = unsafe { output(out_properties_json, so_bytes::EMPTY, "out_properties_json") }?;
        // SAFETY: the caller upholds this function's `# Safety` contract.
        let (vault, name, version, update) = unsafe {
            (
                vault(handle)?,
                string(name, name_len, "name")?,
                opt_string(version, version_len, "version")?,
                required_json::<UpdateSecretProperties>(
                    update_json,
                    update_json_len,
                    "update_json",
                )?,
            )
        };
        *out = json::to_bytes(&vault.update_secret_properties(name, version, update)?)?;
        Ok(())
    })
}

/// Soft-delete all versions of `name` (`SecretClient::delete_secret`).
/// `*out_deleted_json` receives the `DeletedSecret`
/// (`{"properties": {...}, "deleted_on", "scheduled_purge_on",
/// "recovery_id"}`). In a purgeable vault deletion is immediate.
///
/// # Safety
///
/// As [`so_secret_versions`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn so_secret_delete(
    handle: *const so_vault,
    name: *const u8,
    name_len: usize,
    out_deleted_json: *mut so_bytes,
) -> so_status {
    guard(|| -> Result<()> {
        // SAFETY: the caller upholds this function's `# Safety` contract.
        let out = unsafe { output(out_deleted_json, so_bytes::EMPTY, "out_deleted_json") }?;
        // SAFETY: the caller upholds this function's `# Safety` contract.
        let (vault, name) = unsafe { (vault(handle)?, string(name, name_len, "name")?) };
        *out = json::to_bytes(&vault.delete_secret(name)?)?;
        Ok(())
    })
}

/// Inspect a soft-deleted secret (`SecretClient::get_deleted_secret`).
///
/// # Safety
///
/// As [`so_secret_versions`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn so_secret_get_deleted(
    handle: *const so_vault,
    name: *const u8,
    name_len: usize,
    out_deleted_json: *mut so_bytes,
) -> so_status {
    guard(|| -> Result<()> {
        // SAFETY: the caller upholds this function's `# Safety` contract.
        let out = unsafe { output(out_deleted_json, so_bytes::EMPTY, "out_deleted_json") }?;
        // SAFETY: the caller upholds this function's `# Safety` contract.
        let (vault, name) = unsafe { (vault(handle)?, string(name, name_len, "name")?) };
        *out = json::to_bytes(&vault.get_deleted_secret(name)?)?;
        Ok(())
    })
}

/// All soft-deleted secrets as a JSON array of `DeletedSecret`
/// (`SecretClient::list_deleted_secrets`).
///
/// # Safety
///
/// As [`so_secret_list`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn so_secret_list_deleted(
    handle: *const so_vault,
    out_json: *mut so_bytes,
) -> so_status {
    guard(|| -> Result<()> {
        // SAFETY: the caller upholds this function's `# Safety` contract.
        let out = unsafe { output(out_json, so_bytes::EMPTY, "out_json") }?;
        // SAFETY: the caller upholds this function's `# Safety` contract.
        let vault = unsafe { vault(handle) }?;
        *out = json::to_bytes(&vault.list_deleted_secrets()?)?;
        Ok(())
    })
}

/// Undo a soft delete (`SecretClient::recover_deleted_secret`).
/// `*out_properties_json` receives the `SecretProperties` of the newest
/// restored version.
///
/// # Safety
///
/// As [`so_secret_versions`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn so_secret_recover(
    handle: *const so_vault,
    name: *const u8,
    name_len: usize,
    out_properties_json: *mut so_bytes,
) -> so_status {
    guard(|| -> Result<()> {
        // SAFETY: the caller upholds this function's `# Safety` contract.
        let out = unsafe { output(out_properties_json, so_bytes::EMPTY, "out_properties_json") }?;
        // SAFETY: the caller upholds this function's `# Safety` contract.
        let (vault, name) = unsafe { (vault(handle)?, string(name, name_len, "name")?) };
        *out = json::to_bytes(&vault.recover_deleted_secret(name)?)?;
        Ok(())
    })
}

/// Permanently remove a soft-deleted secret
/// (`SecretClient::purge_deleted_secret`). Fails with `not_deleted` for a
/// live secret and `not_found` for an unknown one.
///
/// # Safety
///
/// `handle` must be a live handle; `name` must be readable for `name_len`
/// bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn so_secret_purge(
    handle: *const so_vault,
    name: *const u8,
    name_len: usize,
) -> so_status {
    guard(|| -> Result<()> {
        // SAFETY: the caller upholds this function's `# Safety` contract.
        let (vault, name) = unsafe { (vault(handle)?, string(name, name_len, "name")?) };
        vault.purge_deleted_secret(name)
    })
}

// ---------------------------------------------------------------------------
// Audit
// ---------------------------------------------------------------------------

/// Metadata-only audit trail, newest first, as a JSON array of `AuditEvent`
/// (`{"id", "occurred_on", "actor": {"kind", "id"}, "operation",
/// "secret_name", "version", "outcome", "detail"}`).
///
/// `query_json` (nullable) is documented at `AuditFilter` in the crate
/// documentation; `NULL` or empty returns the newest 1000 events.
///
/// # Safety
///
/// `handle` must be a live handle; `query_json` must be `NULL` or readable
/// for `query_json_len` bytes; `out_json` must be valid for writes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn so_audit_events(
    handle: *const so_vault,
    query_json: *const u8,
    query_json_len: usize,
    out_json: *mut so_bytes,
) -> so_status {
    guard(|| -> Result<()> {
        // SAFETY: the caller upholds this function's `# Safety` contract.
        let out = unsafe { output(out_json, so_bytes::EMPTY, "out_json") }?;
        // SAFETY: the caller upholds this function's `# Safety` contract.
        let (vault, filter) = unsafe {
            (
                vault(handle)?,
                opt_json::<AuditFilter>(query_json, query_json_len, "query_json")?,
            )
        };
        *out = json::to_bytes(&vault.audit_events(filter.into())?)?;
        Ok(())
    })
}
