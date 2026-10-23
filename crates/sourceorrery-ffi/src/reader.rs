//! Read-only handles: the surface language SDKs are built on.
//!
//! `so_reader_*` wraps [`sourceorrery::SecretReader`] and `so_project_*`
//! wraps [`sourceorrery::Project`]. Neither can create, change, delete,
//! recover or purge anything: a binding that links only these functions
//! cannot write to a vault. Errors reported through them carry a hint
//! ([`crate::so_last_error_hint`]) produced by the client crate, so every
//! SDK explains a failure the same way.

use std::path::PathBuf;
use std::ptr;

use serde::{Deserialize, Serialize};
use sourceorrery::{OpenOptions, Project, SecretBytes, SecretProperties, SecretReader};

use crate::buffer::so_bytes;
use crate::error::{guard, so_status};
use crate::json;
use crate::vault::{invalid_argument, opt_bytes, opt_json, opt_string, output, string};

/// A read-only vault handle. Opaque: created by [`so_reader_open`],
/// released by [`so_reader_close`], usable from several threads at once.
#[derive(Debug)]
pub struct so_reader {
    inner: SecretReader,
}

/// The secrets a `sourceorrery.toml` manifest declares, resolved. Opaque:
/// created by [`so_project_load`], released by [`so_project_free`].
#[derive(Debug)]
pub struct so_project {
    inner: Project,
}

const fn assert_send_sync<T: Send + Sync>() {}
// Handles may be shared between threads.
const _: () = assert_send_sync::<so_reader>();
const _: () = assert_send_sync::<so_project>();

/// Options accepted by [`so_reader_open`] and [`so_project_load`]. Every
/// field is optional.
///
/// ```json
/// {
///   "home": "/path/to/sourceorrery-home",
///   "passphrase_file": "/run/secrets/vault-passphrase",
///   "environment": true,
///   "manifest": "/path/to/sourceorrery.toml"
/// }
/// ```
///
/// `home` replaces `SOURCEORRERY_HOME`; `passphrase_file` replaces
/// `SOURCEORRERY_PASSPHRASE_FILE`; `environment` (default `true`) says
/// whether `SOURCEORRERY_PASSPHRASE` and `SOURCEORRERY_PASSPHRASE_FILE` are
/// consulted at all; `manifest` is the `sourceorrery.toml` whose
/// `[vaults.<name>]` tables say which vaults are remote and where (default:
/// the nearest manifest above the current directory; `so_project_load`
/// always uses the manifest it loads). The passphrase itself never travels
/// in JSON: it is the separate raw-bytes argument.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReaderOptions {
    /// SourceOrrery home directory.
    #[serde(default)]
    pub home: Option<String>,
    /// File holding the passphrase.
    #[serde(default)]
    pub passphrase_file: Option<String>,
    /// Consult the `SOURCEORRERY_PASSPHRASE*` variables.
    #[serde(default)]
    pub environment: Option<bool>,
    /// The manifest that declares remote vaults.
    #[serde(default)]
    pub manifest: Option<String>,
}

impl ReaderOptions {
    fn into_open_options(self, passphrase: Option<&[u8]>) -> OpenOptions {
        OpenOptions {
            home: self.home.filter(|h| !h.is_empty()).map(PathBuf::from),
            passphrase: passphrase.map(|p| SecretBytes::new(p.to_vec())),
            passphrase_file: self
                .passphrase_file
                .filter(|f| !f.is_empty())
                .map(PathBuf::from),
            environment: self.environment.unwrap_or(true),
            manifest: self.manifest.filter(|m| !m.is_empty()).map(PathBuf::from),
        }
    }
}

/// One entry of a loaded project, as returned by [`so_project_entry`].
#[derive(Debug, Serialize)]
pub struct ProjectEntry<'a> {
    /// Secret name as written in the manifest.
    pub name: &'a str,
    /// Environment variable the manifest delivers it in.
    pub env: &'a str,
    /// The reference that was resolved.
    pub reference: String,
    /// Whether the manifest marks it required.
    pub required: bool,
    /// Metadata of the version that was read.
    pub properties: &'a SecretProperties,
}

/// Non-sensitive summary of a loaded project, as returned by
/// [`so_project_info`].
#[derive(Debug, Serialize)]
pub struct ProjectInfo<'a> {
    /// `[project].name`.
    pub name: &'a str,
    /// The manifest file that was loaded.
    pub manifest_path: String,
    /// Number of secrets that resolved.
    pub count: usize,
}

/// The reader behind a handle.
///
/// # Safety
///
/// `handle` is NULL or a handle from [`so_reader_open`] that has not been
/// closed and stays open for the lifetime `'a`.
unsafe fn reader<'a>(handle: *const so_reader) -> sourceorrery::Result<&'a SecretReader> {
    if handle.is_null() {
        return Err(invalid_argument("handle: NULL").into());
    }
    // SAFETY: the caller guarantees a non-null handle is a live `so_reader`
    // leaked by `Box::into_raw` in `so_reader_open`.
    Ok(unsafe { &(*handle).inner })
}

/// The project behind a handle.
///
/// # Safety
///
/// As [`reader`], for handles from [`so_project_load`].
unsafe fn project<'a>(handle: *const so_project) -> sourceorrery::Result<&'a Project> {
    if handle.is_null() {
        return Err(invalid_argument("handle: NULL").into());
    }
    // SAFETY: the caller guarantees a non-null handle is a live `so_project`
    // leaked by `Box::into_raw` in `so_project_load`.
    Ok(unsafe { &(*handle).inner })
}

/// Write a value and its properties to the two output slots.
fn publish_secret(
    out_props: &mut so_bytes,
    out_value: &mut so_bytes,
    secret: &sourceorrery::Secret,
) -> sourceorrery::Result<()> {
    *out_props = json::to_bytes(&secret.properties)?;
    *out_value = so_bytes::copy_of(secret.value.expose());
    Ok(())
}

// ---------------------------------------------------------------------------
// Reader lifecycle
// ---------------------------------------------------------------------------

/// Open a vault for reading, the way the CLI does.
///
/// `name` is the vault name. `options_json` (nullable) is a
/// [`ReaderOptions`] document. A vault the manifest declares as remote
/// (`[vaults.<name>]`) is opened at its provider with the credentials the
/// provider's own environment supplies. Otherwise the vault file is
/// unlocked in this order: the OS credential store, then `passphrase` if
/// non-null, then `SOURCEORRERY_PASSPHRASE`, then the passphrase file from
/// the options or `SOURCEORRERY_PASSPHRASE_FILE`. There is no prompt. A
/// vault in an older on-disk format is refused with `migration_required`.
///
/// On success `*out_handle` holds the handle; on failure it is `NULL` and
/// `so_last_error_hint()` says what to do.
///
/// # Safety
///
/// Every `(pointer, length)` pair must be `NULL` or readable for that many
/// bytes for the duration of the call, and `out_handle` must be valid for
/// writes. The caller's `passphrase` buffer is copied and should be
/// zeroised by the caller afterwards.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn so_reader_open(
    name: *const u8,
    name_len: usize,
    options_json: *const u8,
    options_json_len: usize,
    passphrase: *const u8,
    passphrase_len: usize,
    out_handle: *mut *mut so_reader,
) -> so_status {
    guard(|| -> sourceorrery::Result<()> {
        // SAFETY: the caller upholds this function's `# Safety` contract.
        let out = unsafe { output(out_handle, ptr::null_mut(), "out_handle") }?;
        // SAFETY: the caller upholds this function's `# Safety` contract.
        let (name, options, passphrase) = unsafe {
            (
                string(name, name_len, "name")?,
                opt_json::<ReaderOptions>(options_json, options_json_len, "options_json")?,
                opt_bytes(passphrase, passphrase_len, "passphrase")?,
            )
        };
        let reader = SecretReader::open_with(name, &options.into_open_options(passphrase))?;
        *out = Box::into_raw(Box::new(so_reader { inner: reader }));
        Ok(())
    })
}

/// Close a reader. The vault key held in memory is zeroised. `NULL` is
/// accepted and ignored.
///
/// # Safety
///
/// `handle` must be `NULL` or a handle from [`so_reader_open`] that is
/// closed exactly once and is not in use by any other thread at the time
/// of the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn so_reader_close(handle: *mut so_reader) {
    if handle.is_null() {
        return;
    }
    // SAFETY: the caller guarantees `handle` was leaked by `Box::into_raw` in
    // `so_reader_open`, is closed only once, and has no other users right now.
    let reader = unsafe { Box::from_raw(handle) };
    // Dropping must not unwind into C; a failure here has nothing to report.
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || drop(reader)));
}

/// Non-sensitive description of the vault as JSON
/// (`sourceorrery_core::VaultDescriptor`).
///
/// # Safety
///
/// `handle` must be a live reader; `out_json` must be valid for writes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn so_reader_descriptor(
    handle: *const so_reader,
    out_json: *mut so_bytes,
) -> so_status {
    guard(|| -> sourceorrery::Result<()> {
        // SAFETY: the caller upholds this function's `# Safety` contract.
        let out = unsafe { output(out_json, so_bytes::EMPTY, "out_json") }?;
        // SAFETY: the caller upholds this function's `# Safety` contract.
        let reader = unsafe { reader(handle) }?;
        *out = json::to_bytes(&reader.descriptor()?)?;
        Ok(())
    })
}

// ---------------------------------------------------------------------------
// Reads
// ---------------------------------------------------------------------------

/// Read a secret's value and metadata.
///
/// `version` (nullable) selects a specific version; `NULL` selects the
/// newest accessible one (enabled and inside its time window). Policy
/// refusals are `disabled`, `not_yet_valid` and `expired`.
/// `*out_properties_json` receives the version's `SecretProperties`;
/// `*out_value` receives the plaintext, which the caller must release with
/// `so_bytes_free` as soon as it has been used.
///
/// # Safety
///
/// `handle` must be a live reader; `name` and `version` must be `NULL` or
/// readable for their lengths; both output pointers must be valid for
/// writes and distinct.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn so_reader_get(
    handle: *const so_reader,
    name: *const u8,
    name_len: usize,
    version: *const u8,
    version_len: usize,
    out_properties_json: *mut so_bytes,
    out_value: *mut so_bytes,
) -> so_status {
    guard(|| -> sourceorrery::Result<()> {
        // SAFETY: the caller upholds this function's `# Safety` contract.
        let (out_props, out_value) = unsafe {
            (
                output(out_properties_json, so_bytes::EMPTY, "out_properties_json")?,
                output(out_value, so_bytes::EMPTY, "out_value")?,
            )
        };
        // SAFETY: the caller upholds this function's `# Safety` contract.
        let (reader, name, version) = unsafe {
            (
                reader(handle)?,
                string(name, name_len, "name")?,
                opt_string(version, version_len, "version")?,
            )
        };
        let secret = match version {
            Some(version) => reader.get_version(name, version)?,
            None => reader.get(name)?,
        };
        publish_secret(out_props, out_value, &secret)
    })
}

/// Read metadata only. Policy is not applied, so disabled and expired
/// versions can be inspected. `version` (nullable) as for [`so_reader_get`].
///
/// # Safety
///
/// As [`so_reader_get`], with one output pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn so_reader_properties(
    handle: *const so_reader,
    name: *const u8,
    name_len: usize,
    version: *const u8,
    version_len: usize,
    out_properties_json: *mut so_bytes,
) -> so_status {
    guard(|| -> sourceorrery::Result<()> {
        // SAFETY: the caller upholds this function's `# Safety` contract.
        let out = unsafe { output(out_properties_json, so_bytes::EMPTY, "out_properties_json") }?;
        // SAFETY: the caller upholds this function's `# Safety` contract.
        let (reader, name, version) = unsafe {
            (
                reader(handle)?,
                string(name, name_len, "name")?,
                opt_string(version, version_len, "version")?,
            )
        };
        *out = json::to_bytes(&reader.properties(name, version)?)?;
        Ok(())
    })
}

/// Resolve a `sourceorrery://vault/name[/version]` reference. The reference
/// must name the vault this reader is bound to (`invalid_argument`
/// otherwise). Outputs as for [`so_reader_get`].
///
/// # Safety
///
/// `handle` must be a live reader; `reference` must be readable for
/// `reference_len` bytes; both output pointers must be valid for writes and
/// distinct.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn so_reader_resolve(
    handle: *const so_reader,
    reference: *const u8,
    reference_len: usize,
    out_properties_json: *mut so_bytes,
    out_value: *mut so_bytes,
) -> so_status {
    guard(|| -> sourceorrery::Result<()> {
        // SAFETY: the caller upholds this function's `# Safety` contract.
        let (out_props, out_value) = unsafe {
            (
                output(out_properties_json, so_bytes::EMPTY, "out_properties_json")?,
                output(out_value, so_bytes::EMPTY, "out_value")?,
            )
        };
        // SAFETY: the caller upholds this function's `# Safety` contract.
        let (reader, reference) = unsafe {
            (
                reader(handle)?,
                string(reference, reference_len, "reference")?,
            )
        };
        publish_secret(out_props, out_value, &reader.resolve(reference)?)
    })
}

// ---------------------------------------------------------------------------
// Project manifests
// ---------------------------------------------------------------------------

/// Resolve every secret a `sourceorrery.toml` manifest declares, the way
/// `sourceorrery run` does.
///
/// `manifest_path` (nullable) is the manifest file; `NULL` finds the nearest
/// `sourceorrery.toml` above the current directory. `options_json` and
/// `passphrase` are as for [`so_reader_open`] and apply to every vault the
/// manifest names. A required secret that cannot be read fails the whole
/// call with that secret's error; an optional one that is missing, refused
/// by policy or whose vault does not exist is left out.
///
/// # Safety
///
/// As [`so_reader_open`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn so_project_load(
    manifest_path: *const u8,
    manifest_path_len: usize,
    options_json: *const u8,
    options_json_len: usize,
    passphrase: *const u8,
    passphrase_len: usize,
    out_handle: *mut *mut so_project,
) -> so_status {
    guard(|| -> sourceorrery::Result<()> {
        // SAFETY: the caller upholds this function's `# Safety` contract.
        let out = unsafe { output(out_handle, ptr::null_mut(), "out_handle") }?;
        // SAFETY: the caller upholds this function's `# Safety` contract.
        let (manifest, options, passphrase) = unsafe {
            (
                opt_string(manifest_path, manifest_path_len, "manifest_path")?,
                opt_json::<ReaderOptions>(options_json, options_json_len, "options_json")?,
                opt_bytes(passphrase, passphrase_len, "passphrase")?,
            )
        };
        let manifest = manifest.filter(|m| !m.is_empty()).map(PathBuf::from);
        let project = Project::load(manifest.as_deref(), &options.into_open_options(passphrase))?;
        *out = Box::into_raw(Box::new(so_project { inner: project }));
        Ok(())
    })
}

/// Number of secrets that resolved, or `0` for `NULL`.
///
/// # Safety
///
/// `handle` must be `NULL` or a live handle from [`so_project_load`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn so_project_count(handle: *const so_project) -> usize {
    // SAFETY: the caller upholds this function's `# Safety` contract.
    unsafe { project(handle) }.map_or(0, |p| p.secrets().len())
}

/// Non-sensitive summary of a loaded project as JSON ([`ProjectInfo`]:
/// `name`, `manifest_path`, `count`).
///
/// # Safety
///
/// `handle` must be a live handle from [`so_project_load`]; `out_json` must
/// be valid for writes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn so_project_info(
    handle: *const so_project,
    out_json: *mut so_bytes,
) -> so_status {
    guard(|| -> sourceorrery::Result<()> {
        // SAFETY: the caller upholds this function's `# Safety` contract.
        let out = unsafe { output(out_json, so_bytes::EMPTY, "out_json") }?;
        // SAFETY: the caller upholds this function's `# Safety` contract.
        let project = unsafe { project(handle) }?;
        *out = json::to_bytes(&ProjectInfo {
            name: project.name(),
            manifest_path: project.manifest_path().display().to_string(),
            count: project.secrets().len(),
        })?;
        Ok(())
    })
}

/// The `index`-th resolved secret (manifest order, `0`-based).
/// `*out_entry_json` receives a [`ProjectEntry`] (`name`, `env`,
/// `reference`, `required`, `properties`); `*out_value` receives the value,
/// to be released with `so_bytes_free` as soon as it has been used. An index
/// at or past [`so_project_count`] is `invalid_argument`.
///
/// # Safety
///
/// `handle` must be a live handle from [`so_project_load`]; both output
/// pointers must be valid for writes and distinct.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn so_project_entry(
    handle: *const so_project,
    index: usize,
    out_entry_json: *mut so_bytes,
    out_value: *mut so_bytes,
) -> so_status {
    guard(|| -> sourceorrery::Result<()> {
        // SAFETY: the caller upholds this function's `# Safety` contract.
        let (out_entry, out_value) = unsafe {
            (
                output(out_entry_json, so_bytes::EMPTY, "out_entry_json")?,
                output(out_value, so_bytes::EMPTY, "out_value")?,
            )
        };
        // SAFETY: the caller upholds this function's `# Safety` contract.
        let project = unsafe { project(handle) }?;
        let secret = project.secrets().get(index).ok_or_else(|| {
            sourceorrery::Error::from(invalid_argument(format!(
                "index {index} is out of range (the project has {} secrets)",
                project.secrets().len()
            )))
        })?;
        *out_entry = json::to_bytes(&ProjectEntry {
            name: &secret.name,
            env: &secret.env,
            reference: secret.reference.to_string(),
            required: secret.required,
            properties: &secret.properties,
        })?;
        *out_value = so_bytes::copy_of(secret.value.expose());
        Ok(())
    })
}

/// Release a project. Every value it holds is zeroised. `NULL` is accepted
/// and ignored.
///
/// # Safety
///
/// `handle` must be `NULL` or a handle from [`so_project_load`] that is
/// freed exactly once and is not in use by any other thread at the time of
/// the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn so_project_free(handle: *mut so_project) {
    if handle.is_null() {
        return;
    }
    // SAFETY: the caller guarantees `handle` was leaked by `Box::into_raw` in
    // `so_project_load`, is freed only once, and has no other users right now.
    let project = unsafe { Box::from_raw(handle) };
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || drop(project)));
}
