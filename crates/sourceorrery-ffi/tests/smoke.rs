//! Smoke test of the C ABI from Rust: the exported `extern "C"` functions are
//! called exactly as a C or P/Invoke caller would call them.

use std::ffi::CStr;
use std::ptr;

use sourceorrery_core::{AuditEvent, DeletedSecret, SecretProperties};
use sourceorrery_ffi::{
    so_abi_version, so_audit_events, so_bytes, so_bytes_free, so_contract_version,
    so_last_error_code, so_last_error_message, so_secret_delete, so_secret_get,
    so_secret_get_deleted, so_secret_get_properties, so_secret_list, so_secret_list_deleted,
    so_secret_purge, so_secret_recover, so_secret_set, so_secret_update, so_secret_versions,
    so_status, so_vault, so_vault_close, so_vault_create, so_vault_descriptor, so_vault_open,
};

const PASSPHRASE: &[u8] = b"smoke-test-passphrase";
const CANARY: &str = "CANARY-7f3a9c2e-plaintext-must-never-appear";
/// Cheap Argon2id parameters (`Argon2Params::TESTING`); never for real vaults.
const TEST_OPTIONS: &str = r#"{"argon2":{"memory_kib":8192,"iterations":1,"parallelism":1}}"#;

struct Arg(*const u8, usize);

fn arg(text: &str) -> Arg {
    Arg(text.as_ptr(), text.len())
}

const NONE: Arg = Arg(ptr::null(), 0);

fn last_code() -> Option<String> {
    let ptr = so_last_error_code();
    if ptr.is_null() {
        return None;
    }
    // SAFETY: a non-null code pointer is a NUL-terminated string owned by this
    // thread's error slot and valid until the next SourceOrrery call.
    Some(
        unsafe { CStr::from_ptr(ptr) }
            .to_string_lossy()
            .into_owned(),
    )
}

fn last_message() -> String {
    let ptr = so_last_error_message();
    assert!(!ptr.is_null(), "a failed call must leave a message");
    // SAFETY: as in `last_code`.
    unsafe { CStr::from_ptr(ptr) }
        .to_string_lossy()
        .into_owned()
}

/// Copy a buffer out and free it.
fn take(bytes: &mut so_bytes) -> Vec<u8> {
    assert!(!bytes.ptr.is_null(), "output buffer must be set on success");
    // SAFETY: a non-null buffer from the library holds `len + 1` readable bytes.
    let with_nul = unsafe { std::slice::from_raw_parts(bytes.ptr, bytes.len + 1) };
    assert_eq!(with_nul[bytes.len], 0, "buffers are NUL-terminated");
    let copy = with_nul[..bytes.len].to_vec();
    // SAFETY: `bytes` is an unmodified buffer filled by the library.
    unsafe { so_bytes_free(&raw mut *bytes) };
    assert!(bytes.ptr.is_null());
    copy
}

fn take_json<T: serde::de::DeserializeOwned>(bytes: &mut so_bytes) -> T {
    let json = take(bytes);
    serde_json::from_slice(&json).expect("well-formed JSON")
}

struct Home {
    dir: tempfile::TempDir,
}

impl Home {
    fn new() -> Self {
        Self {
            dir: tempfile::tempdir().expect("temp dir"),
        }
    }

    fn path(&self) -> String {
        self.dir
            .path()
            .to_str()
            .expect("utf-8 temp path")
            .to_owned()
    }

    fn create(
        &self,
        name: &str,
        passphrase: &[u8],
        options: &str,
    ) -> Result<*mut so_vault, String> {
        let home = self.path();
        let home = arg(&home);
        let name = arg(name);
        let options = arg(options);
        let mut handle: *mut so_vault = ptr::null_mut();
        // SAFETY: every pointer is backed by a live Rust value for the call.
        let status = unsafe {
            so_vault_create(
                home.0,
                home.1,
                name.0,
                name.1,
                options.0,
                options.1,
                passphrase.as_ptr(),
                passphrase.len(),
                &raw mut handle,
            )
        };
        if status == so_status::SO_STATUS_OK {
            assert!(!handle.is_null());
            Ok(handle)
        } else {
            assert!(handle.is_null(), "out_handle must be NULL on failure");
            Err(last_code().expect("error code"))
        }
    }

    fn open(&self, name: &str, passphrase: Option<&[u8]>) -> Result<*mut so_vault, String> {
        let home = self.path();
        let home = arg(&home);
        let name = arg(name);
        let (pass_ptr, pass_len) = passphrase.map_or((ptr::null(), 0), |p| (p.as_ptr(), p.len()));
        let mut handle: *mut so_vault = ptr::null_mut();
        // SAFETY: every pointer is backed by a live Rust value for the call.
        let status = unsafe {
            so_vault_open(
                home.0,
                home.1,
                name.0,
                name.1,
                pass_ptr,
                pass_len,
                &raw mut handle,
            )
        };
        if status == so_status::SO_STATUS_OK {
            Ok(handle)
        } else {
            assert!(handle.is_null());
            Err(last_code().expect("error code"))
        }
    }
}

fn close(handle: *mut so_vault) {
    // SAFETY: `handle` came from create/open and is closed exactly once here.
    unsafe { so_vault_close(handle) };
}

fn set(
    handle: *const so_vault,
    name: &str,
    value: &[u8],
    options: &str,
) -> Result<SecretProperties, String> {
    let name = arg(name);
    let options = arg(options);
    let mut out = so_bytes {
        ptr: ptr::null_mut(),
        len: 0,
    };
    // SAFETY: every pointer is backed by a live Rust value for the call.
    let status = unsafe {
        so_secret_set(
            handle,
            name.0,
            name.1,
            value.as_ptr(),
            value.len(),
            options.0,
            options.1,
            &raw mut out,
        )
    };
    if status == so_status::SO_STATUS_OK {
        Ok(take_json(&mut out))
    } else {
        assert!(out.ptr.is_null(), "outputs are empty on failure");
        Err(last_code().expect("error code"))
    }
}

fn get(
    handle: *const so_vault,
    name: &str,
    version: Option<&str>,
) -> Result<(SecretProperties, Vec<u8>), String> {
    let name = arg(name);
    let version = version.map_or(NONE, arg);
    let mut props = so_bytes {
        ptr: ptr::null_mut(),
        len: 0,
    };
    let mut value = so_bytes {
        ptr: ptr::null_mut(),
        len: 0,
    };
    // SAFETY: every pointer is backed by a live Rust value for the call.
    let status = unsafe {
        so_secret_get(
            handle,
            name.0,
            name.1,
            version.0,
            version.1,
            &raw mut props,
            &raw mut value,
        )
    };
    if status == so_status::SO_STATUS_OK {
        Ok((take_json(&mut props), take(&mut value)))
    } else {
        assert!(props.ptr.is_null() && value.ptr.is_null());
        Err(last_code().expect("error code"))
    }
}

fn update(
    handle: *const so_vault,
    name: &str,
    version: Option<&str>,
    update: &str,
) -> Result<SecretProperties, String> {
    let name = arg(name);
    let version = version.map_or(NONE, arg);
    let update = arg(update);
    let mut out = so_bytes {
        ptr: ptr::null_mut(),
        len: 0,
    };
    // SAFETY: every pointer is backed by a live Rust value for the call.
    let status = unsafe {
        so_secret_update(
            handle,
            name.0,
            name.1,
            version.0,
            version.1,
            update.0,
            update.1,
            &raw mut out,
        )
    };
    if status == so_status::SO_STATUS_OK {
        Ok(take_json(&mut out))
    } else {
        Err(last_code().expect("error code"))
    }
}

/// Call a `(handle, name, out)` shaped function.
fn named_json<T: serde::de::DeserializeOwned>(
    f: unsafe extern "C" fn(*const so_vault, *const u8, usize, *mut so_bytes) -> so_status,
    handle: *const so_vault,
    name: &str,
) -> Result<T, String> {
    let name = arg(name);
    let mut out = so_bytes {
        ptr: ptr::null_mut(),
        len: 0,
    };
    // SAFETY: every pointer is backed by a live Rust value for the call.
    let status = unsafe { f(handle, name.0, name.1, &raw mut out) };
    if status == so_status::SO_STATUS_OK {
        Ok(take_json(&mut out))
    } else {
        assert!(out.ptr.is_null());
        Err(last_code().expect("error code"))
    }
}

/// Call a `(handle, out)` shaped function.
fn plain_json<T: serde::de::DeserializeOwned>(
    f: unsafe extern "C" fn(*const so_vault, *mut so_bytes) -> so_status,
    handle: *const so_vault,
) -> Result<T, String> {
    let mut out = so_bytes {
        ptr: ptr::null_mut(),
        len: 0,
    };
    // SAFETY: `out` is a live local for the duration of the call.
    let status = unsafe { f(handle, &raw mut out) };
    if status == so_status::SO_STATUS_OK {
        Ok(take_json(&mut out))
    } else {
        assert!(out.ptr.is_null());
        Err(last_code().expect("error code"))
    }
}

fn audit(handle: *const so_vault, query: &str) -> Result<Vec<AuditEvent>, String> {
    let query = arg(query);
    let mut out = so_bytes {
        ptr: ptr::null_mut(),
        len: 0,
    };
    // SAFETY: every pointer is backed by a live Rust value for the call.
    let status = unsafe { so_audit_events(handle, query.0, query.1, &raw mut out) };
    if status == so_status::SO_STATUS_OK {
        Ok(take_json(&mut out))
    } else {
        Err(last_code().expect("error code"))
    }
}

#[test]
fn versions_are_reported() {
    assert_eq!(so_abi_version(), 1);
    let version = so_contract_version();
    assert!(!version.is_null());
    // SAFETY: so_contract_version returns a static NUL-terminated string.
    let version = unsafe { CStr::from_ptr(version) }.to_str().unwrap();
    assert_eq!(version, sourceorrery_core::CONTRACT_VERSION);
}

#[test]
fn create_set_get_and_reopen() {
    let home = Home::new();
    let vault = home.create("dev", PASSPHRASE, TEST_OPTIONS).unwrap();

    let v1 = set(vault, "db-password", b"one", "").unwrap();
    let v2 = set(
        vault,
        "db-password",
        b"two",
        r#"{"content_type":"text/plain","tags":{"env":"test"}}"#,
    )
    .unwrap();
    assert_ne!(
        v1.version, v2.version,
        "set creates a new version each time"
    );
    assert_eq!(v2.content_type.as_deref(), Some("text/plain"));
    assert_eq!(v2.tags["env"], "test");
    assert_eq!(v2.vault, "dev");

    let (props, value) = get(vault, "db-password", None).unwrap();
    assert_eq!(props.version, v2.version, "latest accessible");
    assert_eq!(value, b"two");
    let (props, value) = get(vault, "db-password", Some(&v1.version)).unwrap();
    assert_eq!(props.version, v1.version);
    assert_eq!(value, b"one", "old versions are immutable");

    let versions: Vec<SecretProperties> =
        named_json(so_secret_versions, vault, "db-password").unwrap();
    assert_eq!(versions.len(), 2);
    assert_eq!(versions[0].version, v2.version, "newest first");

    let listed: Vec<SecretProperties> = plain_json(so_secret_list, vault).unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].name, "db-password");

    let mut descriptor = so_bytes {
        ptr: ptr::null_mut(),
        len: 0,
    };
    // SAFETY: `vault` is live and `descriptor` is a live local.
    let status = unsafe { so_vault_descriptor(vault, &raw mut descriptor) };
    assert_eq!(status, so_status::SO_STATUS_OK);
    let descriptor: serde_json::Value = take_json(&mut descriptor);
    assert_eq!(descriptor["name"], "dev");
    assert_eq!(descriptor["backend"], "encrypted-sqlite");
    assert_eq!(descriptor["protectors"][0], "passphrase");

    close(vault);

    let reopened = home.open("dev", Some(PASSPHRASE)).unwrap();
    let (_, value) = get(reopened, "db-password", None).unwrap();
    assert_eq!(value, b"two");
    close(reopened);
}

#[test]
fn policy_update_delete_recover_purge() {
    let home = Home::new();
    let vault = home.create("dev", PASSPHRASE, TEST_OPTIONS).unwrap();
    let v1 = set(vault, "api-key", b"old", "").unwrap();
    let v2 = set(vault, "api-key", b"new", "").unwrap();

    // Disabling the newest version falls back to the previous one.
    let updated = update(vault, "api-key", None, r#"{"enabled":false}"#).unwrap();
    assert_eq!(updated.version, v2.version);
    assert!(!updated.enabled);
    let (props, value) = get(vault, "api-key", None).unwrap();
    assert_eq!(props.version, v1.version);
    assert_eq!(value, b"old");
    assert_eq!(
        get(vault, "api-key", Some(&v2.version)).unwrap_err(),
        "disabled"
    );

    // Metadata of the disabled version is still inspectable.
    let mut out = so_bytes {
        ptr: ptr::null_mut(),
        len: 0,
    };
    let name = arg("api-key");
    let version = arg(&v2.version);
    // SAFETY: every pointer is backed by a live Rust value for the call.
    let status = unsafe {
        so_secret_get_properties(vault, name.0, name.1, version.0, version.1, &raw mut out)
    };
    assert_eq!(status, so_status::SO_STATUS_OK);
    let props: SecretProperties = take_json(&mut out);
    assert!(!props.enabled);

    // Clearing a field uses JSON null; an empty update is rejected.
    let updated = update(
        vault,
        "api-key",
        None,
        r#"{"content_type":null,"expires_on":null}"#,
    )
    .unwrap();
    assert_eq!(updated.content_type, None);
    assert_eq!(
        update(vault, "api-key", None, "{}").unwrap_err(),
        "invalid_argument"
    );
    assert_eq!(
        update(vault, "api-key", None, "").unwrap_err(),
        "invalid_argument"
    );

    // Time window.
    assert_eq!(
        set(
            vault,
            "expired",
            b"x",
            r#"{"expires_on":"2020-01-01T00:00:00Z"}"#
        )
        .map(|_| ())
        .and_then(|()| get(vault, "expired", None).map(|_| ()))
        .unwrap_err(),
        "expired"
    );
    assert_eq!(
        set(
            vault,
            "pending",
            b"x",
            r#"{"not_before":"2100-01-01T00:00:00Z"}"#
        )
        .map(|_| ())
        .and_then(|()| get(vault, "pending", None).map(|_| ()))
        .unwrap_err(),
        "not_yet_valid"
    );

    // Delete, recover, purge.
    let deleted: DeletedSecret = named_json(so_secret_delete, vault, "api-key").unwrap();
    assert_eq!(deleted.properties.name, "api-key");
    assert_eq!(
        deleted.recovery_id,
        "sourceorrery://dev/deletedsecrets/api-key"
    );
    assert_eq!(get(vault, "api-key", None).unwrap_err(), "deleted");
    assert_eq!(
        set(vault, "api-key", b"again", "").unwrap_err(),
        "deleted_conflict"
    );
    let listed_deleted: Vec<DeletedSecret> = plain_json(so_secret_list_deleted, vault).unwrap();
    assert_eq!(listed_deleted.len(), 1);
    let inspected: DeletedSecret = named_json(so_secret_get_deleted, vault, "api-key").unwrap();
    assert_eq!(inspected, deleted);

    let recovered: SecretProperties = named_json(so_secret_recover, vault, "api-key").unwrap();
    assert_eq!(recovered.name, "api-key");
    assert_eq!(get(vault, "api-key", None).unwrap().1, b"old");

    let name = arg("api-key");
    // SAFETY: every pointer is backed by a live Rust value for the call.
    let status = unsafe { so_secret_purge(vault, name.0, name.1) };
    assert_eq!(status, so_status::SO_STATUS_ERROR);
    assert_eq!(last_code().as_deref(), Some("not_deleted"));

    named_json::<DeletedSecret>(so_secret_delete, vault, "api-key").unwrap();
    // SAFETY: as above.
    let status = unsafe { so_secret_purge(vault, name.0, name.1) };
    assert_eq!(status, so_status::SO_STATUS_OK);
    assert!(last_code().is_none(), "success clears the error state");
    assert_eq!(get(vault, "api-key", None).unwrap_err(), "not_found");
    close(vault);
}

#[test]
fn errors_cross_the_boundary_with_their_codes() {
    let home = Home::new();
    let vault = home.create("dev", PASSPHRASE, TEST_OPTIONS).unwrap();

    assert_eq!(get(vault, "missing", None).unwrap_err(), "not_found");
    assert!(last_message().contains("missing"));
    assert_eq!(
        set(vault, "bad_name", b"v", "").unwrap_err(),
        "invalid_name"
    );
    assert_eq!(
        set(vault, "k", b"v", r#"{"enabled":"maybe"}"#).unwrap_err(),
        "invalid_argument"
    );
    assert_eq!(get(ptr::null(), "k", None).unwrap_err(), "invalid_argument");
    assert!(last_message().contains("handle"));

    // Invalid UTF-8 and a NULL pointer with a length are argument errors.
    let mut props = so_bytes {
        ptr: ptr::null_mut(),
        len: 0,
    };
    let mut value = so_bytes {
        ptr: ptr::null_mut(),
        len: 0,
    };
    let bad = [0xffu8, 0xfe];
    // SAFETY: every pointer is backed by a live Rust value for the call.
    let status = unsafe {
        so_secret_get(
            vault,
            bad.as_ptr(),
            bad.len(),
            ptr::null(),
            0,
            &raw mut props,
            &raw mut value,
        )
    };
    assert_eq!(status, so_status::SO_STATUS_ERROR);
    assert_eq!(last_code().as_deref(), Some("invalid_argument"));
    // SAFETY: as above; a NULL name with a non-zero length is rejected before any read.
    let status = unsafe {
        so_secret_get(
            vault,
            ptr::null(),
            3,
            ptr::null(),
            0,
            &raw mut props,
            &raw mut value,
        )
    };
    assert_eq!(status, so_status::SO_STATUS_ERROR);
    assert_eq!(last_code().as_deref(), Some("invalid_argument"));
    // A NULL output pointer is an argument error, not a crash.
    let name = arg("k");
    // SAFETY: as above.
    let status = unsafe {
        so_secret_get(
            vault,
            name.0,
            name.1,
            ptr::null(),
            0,
            ptr::null_mut(),
            &raw mut value,
        )
    };
    assert_eq!(status, so_status::SO_STATUS_ERROR);
    assert_eq!(last_code().as_deref(), Some("invalid_argument"));
    close(vault);
}

#[test]
fn vault_errors_and_failed_unlocks() {
    let home = Home::new();
    let vault = home.create("dev", PASSPHRASE, TEST_OPTIONS).unwrap();
    assert_eq!(
        home.create("dev", PASSPHRASE, TEST_OPTIONS).unwrap_err(),
        "vault_exists"
    );
    assert_eq!(
        home.create("Bad Name", PASSPHRASE, TEST_OPTIONS)
            .unwrap_err(),
        "invalid_name"
    );
    assert_eq!(
        home.create("short", PASSPHRASE, r#"{"retention_days":3}"#)
            .unwrap_err(),
        "invalid_argument"
    );
    assert_eq!(
        home.create("typo", PASSPHRASE, r#"{"retentionDays":30}"#)
            .unwrap_err(),
        "invalid_argument"
    );
    assert_eq!(
        home.create("empty-pass", b"", TEST_OPTIONS).unwrap_err(),
        "invalid_argument"
    );
    assert_eq!(
        home.open("nope", Some(PASSPHRASE)).unwrap_err(),
        "vault_not_found"
    );
    assert_eq!(home.open("dev", Some(b"wrong")).unwrap_err(), "locked");
    assert_eq!(
        home.open("dev", None).unwrap_err(),
        "locked",
        "no keyring protector, no passphrase"
    );

    // Failed unlocks are audited, and the audit filter works.
    let events = audit(vault, r#"{"operation":"vault_open","limit":10}"#).unwrap();
    assert!(
        events
            .iter()
            .all(|e| e.operation == sourceorrery_core::AuditOperation::VaultOpen)
    );
    assert!(
        events
            .iter()
            .any(|e| e.outcome == sourceorrery_core::AuditOutcome::Denied)
    );
    assert_eq!(
        audit(vault, r#"{"operation":"nonsense"}"#).unwrap_err(),
        "invalid_argument"
    );
    close(vault);
}

#[test]
fn values_never_appear_in_metadata_errors_or_audit() {
    let home = Home::new();
    let vault = home.create("dev", PASSPHRASE, TEST_OPTIONS).unwrap();
    let props = set(vault, "canary", CANARY.as_bytes(), "").unwrap();
    let props_json = serde_json::to_string(&props).unwrap();
    assert!(!props_json.contains(CANARY));

    let (_, value) = get(vault, "canary", None).unwrap();
    assert_eq!(value, CANARY.as_bytes());
    assert_eq!(
        get(vault, "canary", Some("deadbeef")).unwrap_err(),
        "version_not_found"
    );
    assert!(!last_message().contains(CANARY));

    let listed: Vec<SecretProperties> = plain_json(so_secret_list, vault).unwrap();
    assert!(!serde_json::to_string(&listed).unwrap().contains(CANARY));
    let events = audit(vault, "").unwrap();
    let dump = serde_json::to_string(&events).unwrap();
    assert!(!dump.contains(CANARY));
    assert!(!dump.contains(std::str::from_utf8(PASSPHRASE).unwrap()));
    assert!(
        events
            .iter()
            .any(|e| e.operation == sourceorrery_core::AuditOperation::SecretGet)
    );
    assert!(!format!("{vault:?}").contains(CANARY));
    close(vault);
}

#[test]
fn handle_is_shared_between_threads() {
    let home = Home::new();
    let vault = home.create("dev", PASSPHRASE, TEST_OPTIONS).unwrap();
    set(vault, "shared", b"value", "").unwrap();
    let address = vault as usize;
    let workers: Vec<_> = (0..4)
        .map(|i| {
            std::thread::spawn(move || {
                let handle = address as *const so_vault;
                for _ in 0..5 {
                    let (_, value) = get(handle, "shared", None).unwrap();
                    assert_eq!(value, b"value");
                    set(handle, &format!("worker-{i}"), b"w", "").unwrap();
                }
                // Each thread has its own error state.
                assert_eq!(get(handle, "missing", None).unwrap_err(), "not_found");
            })
        })
        .collect();
    for worker in workers {
        worker.join().unwrap();
    }
    assert!(
        last_code().is_none(),
        "another thread's error does not leak here"
    );
    let listed: Vec<SecretProperties> = plain_json(so_secret_list, vault).unwrap();
    assert_eq!(listed.len(), 5);
    close(vault);
}

#[test]
fn close_and_free_accept_null() {
    close(ptr::null_mut());
    // SAFETY: NULL is accepted.
    unsafe { so_bytes_free(ptr::null_mut()) };
}

/// A C caller passes `so_bytes out;` or `so_vault *handle;` without zeroing
/// it. The library must initialise such a slot through the raw pointer, never
/// read or drop what it held, and leave it in the documented failure state.
/// Written against `MaybeUninit` so Miri can check the contract.
#[test]
fn uninitialised_output_slots_are_initialised_on_failure() {
    let mut out = std::mem::MaybeUninit::<so_bytes>::uninit();
    // SAFETY: `out` is valid for writes; a NULL handle makes the call fail
    // after the slot has been reset.
    let status = unsafe { so_vault_descriptor(ptr::null(), out.as_mut_ptr()) };
    assert_eq!(status, so_status::SO_STATUS_ERROR);
    assert_eq!(last_code().as_deref(), Some("invalid_argument"));
    // SAFETY: the call initialised the slot.
    let out = unsafe { out.assume_init() };
    assert!(out.ptr.is_null());
    assert_eq!(out.len, 0);

    let home = Home::new();
    let home_path = home.path();
    let home_arg = arg(&home_path);
    let name = arg("no_such_vault"); // an invalid name fails before any I/O
    let mut handle = std::mem::MaybeUninit::<*mut so_vault>::uninit();
    // SAFETY: as above.
    let status = unsafe {
        so_vault_open(
            home_arg.0,
            home_arg.1,
            name.0,
            name.1,
            ptr::null(),
            0,
            handle.as_mut_ptr(),
        )
    };
    assert_eq!(status, so_status::SO_STATUS_ERROR);
    // SAFETY: the call initialised the slot.
    assert!(unsafe { handle.assume_init() }.is_null());
}
