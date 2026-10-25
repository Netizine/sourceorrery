//! The read-only `so_reader_*` / `so_project_*` surface, called exactly as a
//! C or P/Invoke caller would call it. Vaults are created through the
//! write-capable `so_vault_*` functions only to set the scene.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::ffi::CStr;
use std::ptr;

use sourceorrery_core::SecretProperties;
use sourceorrery_ffi::{
    so_bytes, so_bytes_free, so_last_error_code, so_last_error_hint, so_last_error_message,
    so_project, so_project_count, so_project_entry, so_project_free, so_project_info,
    so_project_load, so_reader, so_reader_close, so_reader_descriptor, so_reader_get,
    so_reader_open, so_reader_properties, so_reader_resolve, so_secret_set, so_secret_update,
    so_status, so_vault, so_vault_close, so_vault_create,
};

const WRONG_KEY: &[u8] = b"AAAAA-AAAAA-AAAAA-AAAAA-AAAAA";
const CANARY: &str = "CANARY-9b1d-value-that-must-never-appear";
/// No key for this machine: a test never touches the real OS credential
/// store, and its vaults open with their recovery keys.
const TEST_OPTIONS: &str = r#"{"this_machine":false}"#;

fn c_str(ptr: *const std::ffi::c_char) -> Option<String> {
    if ptr.is_null() {
        return None;
    }
    // SAFETY: a non-null pointer from the error accessors is a NUL-terminated
    // string owned by this thread's error slot, valid until the next call.
    Some(
        unsafe { CStr::from_ptr(ptr) }
            .to_string_lossy()
            .into_owned(),
    )
}

fn last_code() -> String {
    c_str(so_last_error_code()).expect("a failed call leaves a code")
}

fn last_hint() -> String {
    c_str(so_last_error_hint()).unwrap_or_default()
}

fn take(bytes: &mut so_bytes) -> Vec<u8> {
    assert!(!bytes.ptr.is_null(), "output buffer must be set on success");
    // SAFETY: a non-null buffer from the library holds `len + 1` readable bytes.
    let with_nul = unsafe { std::slice::from_raw_parts(bytes.ptr, bytes.len + 1) };
    assert_eq!(with_nul[bytes.len], 0);
    let copy = with_nul[..bytes.len].to_vec();
    // SAFETY: `bytes` is an unmodified buffer filled by the library.
    unsafe { so_bytes_free(&raw mut *bytes) };
    copy
}

fn take_json<T: serde::de::DeserializeOwned>(bytes: &mut so_bytes) -> T {
    serde_json::from_slice(&take(bytes)).expect("well-formed JSON")
}

const EMPTY: so_bytes = so_bytes {
    ptr: ptr::null_mut(),
    len: 0,
};

/// A temporary home whose vaults are populated through the write-capable
/// ABI; it remembers each vault's recovery key.
struct Scene {
    home: tempfile::TempDir,
    keys: RefCell<BTreeMap<String, Vec<u8>>>,
}

impl Scene {
    fn new() -> Self {
        Self {
            home: tempfile::tempdir().expect("temp dir"),
            keys: RefCell::new(BTreeMap::new()),
        }
    }

    fn home(&self) -> String {
        self.home.path().to_str().unwrap().to_owned()
    }

    fn options(&self) -> String {
        format!(
            r#"{{"home":{},"environment":false}}"#,
            serde_json::to_string(&self.home()).unwrap()
        )
    }

    fn key(&self, name: &str) -> Vec<u8> {
        self.keys.borrow()[name].clone()
    }

    fn create_vault(&self, name: &str) -> *mut so_vault {
        let home = self.home();
        let mut key = EMPTY;
        let mut handle: *mut so_vault = ptr::null_mut();
        // SAFETY: every pointer is backed by a live Rust value for the call.
        let status = unsafe {
            so_vault_create(
                home.as_ptr(),
                home.len(),
                name.as_ptr(),
                name.len(),
                TEST_OPTIONS.as_ptr(),
                TEST_OPTIONS.len(),
                &raw mut key,
                &raw mut handle,
            )
        };
        assert_eq!(status, so_status::SO_STATUS_OK, "{}", last_code());
        let key = take(&mut key);
        self.keys.borrow_mut().insert(name.to_owned(), key);
        handle
    }

    fn open(&self, name: &str, recovery_key: Option<&[u8]>) -> Result<*mut so_reader, String> {
        let options = self.options();
        let (key_ptr, key_len) = recovery_key.map_or((ptr::null(), 0), |k| (k.as_ptr(), k.len()));
        let mut handle: *mut so_reader = ptr::null_mut();
        // SAFETY: every pointer is backed by a live Rust value for the call.
        let status = unsafe {
            so_reader_open(
                name.as_ptr(),
                name.len(),
                options.as_ptr(),
                options.len(),
                key_ptr,
                key_len,
                &raw mut handle,
            )
        };
        if status == so_status::SO_STATUS_OK {
            assert!(!handle.is_null());
            Ok(handle)
        } else {
            assert!(handle.is_null(), "out_handle must be NULL on failure");
            Err(last_code())
        }
    }
}

fn set(vault: *const so_vault, name: &str, value: &[u8], options: &str) -> SecretProperties {
    let mut out = EMPTY;
    // SAFETY: every pointer is backed by a live Rust value for the call.
    let status = unsafe {
        so_secret_set(
            vault,
            name.as_ptr(),
            name.len(),
            value.as_ptr(),
            value.len(),
            options.as_ptr(),
            options.len(),
            &raw mut out,
        )
    };
    assert_eq!(status, so_status::SO_STATUS_OK, "{}", last_code());
    take_json(&mut out)
}

fn disable(vault: *const so_vault, name: &str, version: &str) {
    let update = r#"{"enabled":false}"#;
    let mut out = EMPTY;
    // SAFETY: every pointer is backed by a live Rust value for the call.
    let status = unsafe {
        so_secret_update(
            vault,
            name.as_ptr(),
            name.len(),
            version.as_ptr(),
            version.len(),
            update.as_ptr(),
            update.len(),
            &raw mut out,
        )
    };
    assert_eq!(status, so_status::SO_STATUS_OK);
    take(&mut out);
}

fn get(
    reader: *const so_reader,
    name: &str,
    version: Option<&str>,
) -> Result<(SecretProperties, Vec<u8>), String> {
    let (v_ptr, v_len) = version.map_or((ptr::null(), 0), |v| (v.as_ptr(), v.len()));
    let mut props = EMPTY;
    let mut value = EMPTY;
    // SAFETY: every pointer is backed by a live Rust value for the call.
    let status = unsafe {
        so_reader_get(
            reader,
            name.as_ptr(),
            name.len(),
            v_ptr,
            v_len,
            &raw mut props,
            &raw mut value,
        )
    };
    if status == so_status::SO_STATUS_OK {
        Ok((take_json(&mut props), take(&mut value)))
    } else {
        assert!(props.ptr.is_null() && value.ptr.is_null());
        Err(last_code())
    }
}

fn resolve(
    reader: *const so_reader,
    reference: &str,
) -> Result<(SecretProperties, Vec<u8>), String> {
    let mut props = EMPTY;
    let mut value = EMPTY;
    // SAFETY: every pointer is backed by a live Rust value for the call.
    let status = unsafe {
        so_reader_resolve(
            reader,
            reference.as_ptr(),
            reference.len(),
            &raw mut props,
            &raw mut value,
        )
    };
    if status == so_status::SO_STATUS_OK {
        Ok((take_json(&mut props), take(&mut value)))
    } else {
        Err(last_code())
    }
}

fn properties(
    reader: *const so_reader,
    name: &str,
    version: Option<&str>,
) -> Result<SecretProperties, String> {
    let (v_ptr, v_len) = version.map_or((ptr::null(), 0), |v| (v.as_ptr(), v.len()));
    let mut props = EMPTY;
    // SAFETY: every pointer is backed by a live Rust value for the call.
    let status = unsafe {
        so_reader_properties(
            reader,
            name.as_ptr(),
            name.len(),
            v_ptr,
            v_len,
            &raw mut props,
        )
    };
    if status == so_status::SO_STATUS_OK {
        Ok(take_json(&mut props))
    } else {
        Err(last_code())
    }
}

fn close_reader(reader: *mut so_reader) {
    // SAFETY: `reader` came from so_reader_open and is closed exactly once here.
    unsafe { so_reader_close(reader) };
}

fn close_vault(vault: *mut so_vault) {
    // SAFETY: `vault` came from so_vault_create and is closed exactly once here.
    unsafe { so_vault_close(vault) };
}

#[test]
fn reader_reads_latest_pinned_properties_and_references() {
    let scene = Scene::new();
    let vault = scene.create_vault("dev");
    let v1 = set(vault, "db-password", b"one", "");
    let v2 = set(vault, "db-password", CANARY.as_bytes(), "");
    close_vault(vault);

    let reader = scene.open("dev", Some(&scene.key("dev"))).unwrap();
    let (props, value) = get(reader, "db-password", None).unwrap();
    assert_eq!(props.version, v2.version);
    assert_eq!(value, CANARY.as_bytes());
    let (props, value) = get(reader, "db-password", Some(&v1.version)).unwrap();
    assert_eq!(props.version, v1.version);
    assert_eq!(value, b"one");

    let props = properties(reader, "db-password", None).unwrap();
    assert_eq!(props.version, v2.version);
    let props = properties(reader, "db-password", Some(&v1.version)).unwrap();
    assert_eq!(props.version, v1.version);

    let (props, value) = resolve(reader, "sourceorrery://dev/db-password").unwrap();
    assert_eq!(props.version, v2.version);
    assert_eq!(value, CANARY.as_bytes());
    let (_, value) = resolve(
        reader,
        &format!("sourceorrery://dev/db-password/{}", v1.version),
    )
    .unwrap();
    assert_eq!(value, b"one");
    assert_eq!(
        resolve(reader, "sourceorrery://other/db-password").unwrap_err(),
        "invalid_argument"
    );

    let mut descriptor = EMPTY;
    // SAFETY: `reader` is live and `descriptor` is a live local.
    let status = unsafe { so_reader_descriptor(reader, &raw mut descriptor) };
    assert_eq!(status, so_status::SO_STATUS_OK);
    let descriptor: serde_json::Value = take_json(&mut descriptor);
    assert_eq!(descriptor["name"], "dev");
    assert_eq!(descriptor["protectors"][0], "recovery");
    assert!(!descriptor.to_string().contains(CANARY));
    close_reader(reader);
}

#[test]
fn reader_errors_carry_codes_messages_and_hints() {
    let scene = Scene::new();
    let vault = scene.create_vault("dev");
    set(vault, "db-password", CANARY.as_bytes(), "");
    let old = set(vault, "rotated", b"old", "");
    let new = set(vault, "rotated", b"new", "");
    disable(vault, "rotated", &new.version);
    set(
        vault,
        "expired",
        b"x",
        r#"{"expires_on":"2020-01-01T00:00:00Z"}"#,
    );
    close_vault(vault);

    assert_eq!(
        scene.open("nope", Some(&scene.key("dev"))).unwrap_err(),
        "vault_not_found"
    );
    assert!(
        last_hint().contains("sourceorrery vault create nope"),
        "{}",
        last_hint()
    );
    assert!(last_hint().contains(&scene.home()));

    assert_eq!(scene.open("dev", Some(WRONG_KEY)).unwrap_err(), "locked");
    let hint = last_hint();
    assert!(hint.contains("recovery_key option: tried"), "{hint}");
    assert!(
        hint.contains("SOURCEORRERY_RECOVERY_KEY: not set"),
        "{hint}"
    );
    assert!(!hint.contains("AAAAA"));
    assert!(!c_str(so_last_error_message()).unwrap().contains("AAAAA"));

    assert_eq!(scene.open("dev", None).unwrap_err(), "locked");
    assert!(last_hint().contains("recovery_key option: not given"));

    let reader = scene.open("dev", Some(&scene.key("dev"))).unwrap();
    assert!(so_last_error_hint().is_null(), "success clears the hint");

    assert_eq!(get(reader, "missing", None).unwrap_err(), "not_found");
    assert!(
        last_hint().contains("secret set missing --vault dev"),
        "{}",
        last_hint()
    );
    assert_eq!(
        get(reader, "db-password", Some("deadbeef")).unwrap_err(),
        "version_not_found"
    );
    assert!(last_hint().contains("secret versions db-password"));
    assert_eq!(get(reader, "rotated", None).unwrap().0.version, old.version);
    assert_eq!(
        get(reader, "rotated", Some(&new.version)).unwrap_err(),
        "disabled"
    );
    assert!(last_hint().contains("--enable"));
    assert!(
        !properties(reader, "rotated", Some(&new.version))
            .unwrap()
            .enabled
    );
    assert_eq!(get(reader, "expired", None).unwrap_err(), "expired");
    assert!(last_hint().starts_with("Policy"), "{}", last_hint());
    assert_eq!(get(reader, "bad_name", None).unwrap_err(), "invalid_name");
    assert_eq!(resolve(reader, "nonsense").unwrap_err(), "invalid_argument");
    assert!(last_hint().contains("sourceorrery://vault/name"));

    // Argument errors and a NULL handle are reported, not crashes.
    assert_eq!(get(ptr::null(), "k", None).unwrap_err(), "invalid_argument");
    let key = scene.key("dev");
    let bad_options = "{\"nope\":1}";
    let name = "dev";
    let mut handle: *mut so_reader = ptr::null_mut();
    // SAFETY: every pointer is backed by a live Rust value for the call.
    let status = unsafe {
        so_reader_open(
            name.as_ptr(),
            name.len(),
            bad_options.as_ptr(),
            bad_options.len(),
            key.as_ptr(),
            key.len(),
            &raw mut handle,
        )
    };
    assert_eq!(status, so_status::SO_STATUS_ERROR);
    assert_eq!(last_code(), "invalid_argument");
    assert!(handle.is_null());

    // Nothing that reaches the caller as text carries a value.
    assert_eq!(get(reader, "expired", None).unwrap_err(), "expired");
    assert!(!c_str(so_last_error_message()).unwrap().contains(CANARY));
    assert!(!last_hint().contains(CANARY));
    close_reader(reader);
}

#[test]
fn reader_is_shared_between_threads() {
    let scene = Scene::new();
    let vault = scene.create_vault("dev");
    set(vault, "shared", b"value", "");
    close_vault(vault);
    let reader = scene.open("dev", Some(&scene.key("dev"))).unwrap();
    let address = reader as usize;
    let workers: Vec<_> = (0..4)
        .map(|_| {
            std::thread::spawn(move || {
                let handle = address as *const so_reader;
                for _ in 0..5 {
                    assert_eq!(get(handle, "shared", None).unwrap().1, b"value");
                }
                assert_eq!(get(handle, "missing", None).unwrap_err(), "not_found");
            })
        })
        .collect();
    for worker in workers {
        worker.join().unwrap();
    }
    assert!(
        so_last_error_code().is_null(),
        "another thread's error does not leak here"
    );
    close_reader(reader);
}

#[test]
#[allow(clippy::too_many_lines)] // one scene, many assertions
fn project_load_resolves_the_manifest() {
    let scene = Scene::new();
    let vault = scene.create_vault("dev");
    set(vault, "db-password", b"pg", "");
    let pinned = set(vault, "signing-key", b"k1", "");
    set(vault, "signing-key", b"k2", "");
    close_vault(vault);

    let project_dir = tempfile::tempdir().unwrap();
    let manifest = project_dir.path().join("sourceorrery.toml");
    std::fs::write(
        &manifest,
        format!(
            "[project]\nname = \"demo\"\nvault = \"dev\"\n\n[secrets.db-password]\n\n\
             [secrets.signing-key]\nenv = \"SIGNING\"\nversion = \"{}\"\n\n\
             [secrets.optional-thing]\nrequired = false\n",
            pinned.version
        ),
    )
    .unwrap();
    let manifest = manifest.to_str().unwrap().to_owned();
    let options = scene.options();
    let key = scene.key("dev");

    let mut handle: *mut so_project = ptr::null_mut();
    // SAFETY: every pointer is backed by a live Rust value for the call.
    let status = unsafe {
        so_project_load(
            manifest.as_ptr(),
            manifest.len(),
            options.as_ptr(),
            options.len(),
            key.as_ptr(),
            key.len(),
            &raw mut handle,
        )
    };
    assert_eq!(status, so_status::SO_STATUS_OK, "{}", last_code());
    // SAFETY: `handle` is live.
    assert_eq!(unsafe { so_project_count(handle) }, 2);
    // SAFETY: NULL is accepted.
    assert_eq!(unsafe { so_project_count(ptr::null()) }, 0);

    let mut info = EMPTY;
    // SAFETY: `handle` is live and `info` is a live local.
    let status = unsafe { so_project_info(handle, &raw mut info) };
    assert_eq!(status, so_status::SO_STATUS_OK);
    let info: serde_json::Value = take_json(&mut info);
    assert_eq!(info["name"], "demo");
    assert_eq!(info["count"], 2);

    let mut seen = Vec::new();
    for index in 0..2 {
        let mut entry = EMPTY;
        let mut value = EMPTY;
        // SAFETY: `handle` is live and both outputs are live, distinct locals.
        let status = unsafe { so_project_entry(handle, index, &raw mut entry, &raw mut value) };
        assert_eq!(status, so_status::SO_STATUS_OK);
        let entry: serde_json::Value = take_json(&mut entry);
        let value = take(&mut value);
        assert!(!entry.to_string().contains("pg"));
        seen.push((entry["env"].as_str().unwrap().to_owned(), value));
        if entry["name"] == "signing-key" {
            assert_eq!(entry["properties"]["version"], pinned.version);
            assert_eq!(
                entry["reference"],
                format!("sourceorrery://dev/signing-key/{}", pinned.version)
            );
        }
    }
    assert!(seen.contains(&("DB_PASSWORD".to_owned(), b"pg".to_vec())));
    assert!(seen.contains(&("SIGNING".to_owned(), b"k1".to_vec())));

    let mut entry = EMPTY;
    let mut value = EMPTY;
    // SAFETY: as above; an out-of-range index is an argument error.
    let status = unsafe { so_project_entry(handle, 2, &raw mut entry, &raw mut value) };
    assert_eq!(status, so_status::SO_STATUS_ERROR);
    assert_eq!(last_code(), "invalid_argument");
    assert!(entry.ptr.is_null() && value.ptr.is_null());
    // SAFETY: `handle` is freed exactly once here.
    unsafe { so_project_free(handle) };
    // SAFETY: NULL is accepted.
    unsafe { so_project_free(ptr::null_mut()) };

    // A missing required secret fails the load with that secret's code.
    std::fs::write(
        &manifest,
        "[project]\nname = \"demo\"\nvault = \"dev\"\n\n[secrets.absent]\n",
    )
    .unwrap();
    let mut handle: *mut so_project = ptr::null_mut();
    // SAFETY: as above.
    let status = unsafe {
        so_project_load(
            manifest.as_ptr(),
            manifest.len(),
            options.as_ptr(),
            options.len(),
            key.as_ptr(),
            key.len(),
            &raw mut handle,
        )
    };
    assert_eq!(status, so_status::SO_STATUS_ERROR);
    assert_eq!(last_code(), "not_found");
    assert!(
        c_str(so_last_error_message())
            .unwrap()
            .contains("sourceorrery://dev/absent")
    );
    assert!(handle.is_null());

    // No manifest at all is a manifest error.
    let missing = project_dir
        .path()
        .join("nope.toml")
        .to_str()
        .unwrap()
        .to_owned();
    // SAFETY: as above.
    let status = unsafe {
        so_project_load(
            missing.as_ptr(),
            missing.len(),
            options.as_ptr(),
            options.len(),
            key.as_ptr(),
            key.len(),
            &raw mut handle,
        )
    };
    assert_eq!(status, so_status::SO_STATUS_ERROR);
    assert_eq!(last_code(), "manifest");
}

#[test]
fn close_accepts_null() {
    close_reader(ptr::null_mut());
}

#[test]
fn reader_options_refuse_keys_they_do_not_have() {
    let scene = Scene::new();
    close_vault(scene.create_vault("dev"));
    let key = scene.key("dev");
    let open = |options: &str| {
        let mut handle: *mut so_reader = ptr::null_mut();
        // SAFETY: every pointer is backed by a live Rust value for the call.
        let status = unsafe {
            so_reader_open(
                "dev".as_ptr(),
                3,
                options.as_ptr(),
                options.len(),
                key.as_ptr(),
                key.len(),
                &raw mut handle,
            )
        };
        (status, handle)
    };
    let (status, handle) = open(&scene.options());
    assert_eq!(status, so_status::SO_STATUS_OK, "{}", last_code());
    close_reader(handle);

    // There is no `manifest` option: the vault's connections say where its
    // secrets are kept, so it is an unknown key, like any other.
    for bad in [r#"{"manifest":"x"}"#, r#"{"manifest_path":"x"}"#] {
        let (status, handle) = open(bad);
        assert_eq!(status, so_status::SO_STATUS_ERROR, "{bad}");
        assert!(handle.is_null());
        assert_eq!(last_code(), "invalid_argument", "{bad}");
    }
}
