//! The native part of `@sourceorreryai/sdk`: a thin napi-rs layer over the
//! `sourceorrery` client crate.
//!
//! Everything that decides anything (unlock order, policy, hints) lives in
//! Rust in the client crate. This addon converts arguments, hands metadata
//! across as JSON text (parsed by `lib/index.js`) and wraps values in
//! [`SecretValue`]. A failure is thrown as a JS `Error` whose message is a
//! JSON document `{"sourceorrery":{"code","message","hint"}}`; the wrapper
//! turns it into the typed error class for the code.

use std::path::PathBuf;
use std::sync::Mutex;

use napi::bindgen_prelude::Buffer;
use napi::{Error, Result, Status};
use napi_derive::napi;
use sourceorrery::{OpenOptions, Project, SecretBytes, SecretReader};

#[derive(serde::Serialize)]
struct ErrorParts<'a> {
    code: &'a str,
    message: &'a str,
    hint: &'a str,
}

#[derive(serde::Serialize)]
struct ErrorEnvelope<'a> {
    sourceorrery: ErrorParts<'a>,
}

fn to_js(err: &sourceorrery::Error) -> Error {
    let envelope = ErrorEnvelope {
        sourceorrery: ErrorParts {
            code: err.code(),
            message: err.message(),
            hint: err.hint(),
        },
    };
    let text = serde_json::to_string(&envelope).unwrap_or_else(|_| err.to_string());
    Error::new(Status::GenericFailure, text)
}

fn internal(message: impl Into<String>) -> Error {
    Error::new(Status::GenericFailure, message.into())
}

fn json_text<T: serde::Serialize>(value: &T) -> Result<String> {
    serde_json::to_string(value)
        .map_err(|err| internal(format!("cannot serialise metadata: {err}")))
}

fn open_options(
    home: Option<String>,
    recovery_key: Option<Buffer>,
    recovery_key_file: Option<String>,
    environment: Option<bool>,
) -> OpenOptions {
    OpenOptions {
        home: home.filter(|h| !h.is_empty()).map(PathBuf::from),
        recovery_key: recovery_key.map(|b| SecretBytes::new(b.to_vec())),
        recovery_key_file: recovery_key_file
            .filter(|f| !f.is_empty())
            .map(PathBuf::from),
        environment: environment.unwrap_or(true),
    }
}

/// A secret value together with the JSON metadata that came with it. The
/// bytes stay on the Rust side until `close()` zeroises them; `expose()`
/// returns a copy the application owns.
#[napi]
#[derive(Debug)]
pub struct SecretValue {
    bytes: Mutex<Option<SecretBytes>>,
    metadata: String,
}

impl SecretValue {
    fn wrap(value: SecretBytes, metadata: String) -> Self {
        Self {
            bytes: Mutex::new(Some(value)),
            metadata,
        }
    }

    fn with_bytes<T>(&self, f: impl FnOnce(&[u8]) -> Result<T>) -> Result<T> {
        let guard = self.bytes.lock().map_err(|_| internal("poisoned"))?;
        match guard.as_ref() {
            Some(bytes) => f(bytes.expose()),
            None => Err(internal("SecretValue is closed; its bytes were zeroised")),
        }
    }
}

#[napi]
impl SecretValue {
    /// A copy of the bytes.
    #[napi]
    pub fn expose(&self) -> Result<Buffer> {
        self.with_bytes(|bytes| Ok(Buffer::from(bytes.to_vec())))
    }

    /// The value decoded as UTF-8.
    #[napi]
    pub fn expose_text(&self) -> Result<String> {
        self.with_bytes(|bytes| {
            std::str::from_utf8(bytes)
                .map(str::to_owned)
                .map_err(|_| internal("secret value is not valid UTF-8"))
        })
    }

    /// Zeroise the bytes. Idempotent.
    #[napi]
    pub fn close(&self) {
        if let Ok(mut guard) = self.bytes.lock() {
            *guard = None;
        }
    }

    #[napi(getter)]
    pub fn closed(&self) -> bool {
        self.bytes.lock().map_or(true, |g| g.is_none())
    }

    #[napi(getter)]
    pub fn length(&self) -> u32 {
        self.bytes
            .lock()
            .ok()
            .and_then(|g| g.as_ref().map(SecretBytes::len))
            .and_then(|len| u32::try_from(len).ok())
            .unwrap_or(0)
    }

    /// Metadata JSON that accompanied the value (`SecretProperties`, or a
    /// project entry for values from `loadProject`).
    #[napi(getter)]
    pub fn metadata_json(&self) -> String {
        self.metadata.clone()
    }

    #[napi(js_name = "toString")]
    pub fn to_string_redacted(&self) -> &'static str {
        "[REDACTED]"
    }

    #[napi(js_name = "toJSON")]
    pub fn to_json_redacted(&self) -> &'static str {
        "[REDACTED]"
    }
}

/// A read-only vault handle (see `SecretReader` in `lib/index.js`).
#[napi]
#[derive(Debug)]
pub struct NativeReader {
    inner: Mutex<Option<SecretReader>>,
}

impl NativeReader {
    fn with_reader<T>(
        &self,
        f: impl FnOnce(&SecretReader) -> sourceorrery::Result<T>,
    ) -> Result<T> {
        let guard = self.inner.lock().map_err(|_| internal("poisoned"))?;
        let reader = guard
            .as_ref()
            .ok_or_else(|| internal("SecretReader is closed"))?;
        f(reader).map_err(|err| to_js(&err))
    }

    fn secret(
        &self,
        f: impl FnOnce(&SecretReader) -> sourceorrery::Result<sourceorrery::Secret>,
    ) -> Result<SecretValue> {
        let secret = self.with_reader(f)?;
        Ok(SecretValue::wrap(
            secret.value,
            json_text(&secret.properties)?,
        ))
    }
}

#[napi]
impl NativeReader {
    /// Open `vault`. A secret one of its connections stores is read at that
    /// provider.
    #[napi(constructor)]
    pub fn new(
        vault: String,
        home: Option<String>,
        recovery_key: Option<Buffer>,
        recovery_key_file: Option<String>,
        environment: Option<bool>,
    ) -> Result<Self> {
        let options = open_options(home, recovery_key, recovery_key_file, environment);
        let reader = SecretReader::open_with(&vault, &options).map_err(|err| to_js(&err))?;
        Ok(Self {
            inner: Mutex::new(Some(reader)),
        })
    }

    #[napi(getter)]
    pub fn vault_name(&self) -> Result<String> {
        self.with_reader(|r| Ok(r.vault_name().to_owned()))
    }

    #[napi(getter)]
    pub fn home(&self) -> Result<String> {
        self.with_reader(|r| Ok(r.home().display().to_string()))
    }

    /// The newest accessible version of `name`, or exactly `version`.
    #[napi]
    pub fn get(&self, name: String, version: Option<String>) -> Result<SecretValue> {
        self.secret(|r| match version.as_deref() {
            Some(version) => r.get_version(&name, version),
            None => r.get(&name),
        })
    }

    /// Properties JSON of one version (`undefined`: the newest), policy not applied.
    #[napi]
    pub fn properties(&self, name: String, version: Option<String>) -> Result<String> {
        let props = self.with_reader(|r| r.properties(&name, version.as_deref()))?;
        json_text(&props)
    }

    /// Resolve a `sourceorrery://` reference bound to this vault.
    #[napi]
    pub fn resolve(&self, reference: String) -> Result<SecretValue> {
        self.secret(|r| r.resolve(&reference))
    }

    /// Vault descriptor JSON.
    #[napi]
    pub fn descriptor(&self) -> Result<String> {
        let descriptor = self.with_reader(SecretReader::descriptor)?;
        json_text(&descriptor)
    }

    /// Release the vault; the key held in memory is zeroised. Idempotent.
    #[napi]
    pub fn close(&self) {
        if let Ok(mut guard) = self.inner.lock() {
            *guard = None;
        }
    }

    #[napi(getter)]
    pub fn closed(&self) -> bool {
        self.inner.lock().map_or(true, |g| g.is_none())
    }
}

#[derive(serde::Serialize)]
struct ProjectInfo<'a> {
    name: &'a str,
    manifest_path: String,
}

#[derive(serde::Serialize)]
struct ProjectEntry<'a> {
    name: &'a str,
    env: &'a str,
    reference: String,
    required: bool,
    properties: &'a sourceorrery::SecretProperties,
}

/// A loaded project: `infoJson` plus one `SecretValue` per resolved entry
/// (each carrying its entry JSON as `metadataJson`), handed out once by
/// `takeEntries()`.
#[napi]
#[derive(Debug)]
pub struct NativeProject {
    info_json: String,
    entries: Mutex<Vec<SecretValue>>,
}

#[napi]
impl NativeProject {
    #[napi(getter)]
    pub fn info_json(&self) -> String {
        self.info_json.clone()
    }

    /// The resolved entries, in manifest order. Empty after the first call.
    #[napi]
    pub fn take_entries(&self) -> Vec<SecretValue> {
        self.entries
            .lock()
            .map(|mut entries| std::mem::take(&mut *entries))
            .unwrap_or_default()
    }
}

/// Resolve a project manifest the way `sourceorrery run` does.
#[napi]
pub fn load_project(
    manifest: Option<String>,
    home: Option<String>,
    recovery_key: Option<Buffer>,
    recovery_key_file: Option<String>,
    environment: Option<bool>,
) -> Result<NativeProject> {
    let options = open_options(home, recovery_key, recovery_key_file, environment);
    let manifest = manifest.filter(|m| !m.is_empty()).map(PathBuf::from);
    let project = Project::load(manifest.as_deref(), &options).map_err(|err| to_js(&err))?;
    let info_json = json_text(&ProjectInfo {
        name: project.name(),
        manifest_path: project.manifest_path().display().to_string(),
    })?;
    let mut entries = Vec::with_capacity(project.secrets().len());
    for secret in project.secrets() {
        let entry = json_text(&ProjectEntry {
            name: &secret.name,
            env: &secret.env,
            reference: secret.reference.to_string(),
            required: secret.required,
            properties: &secret.properties,
        })?;
        entries.push(SecretValue::wrap(secret.value.clone(), entry));
    }
    Ok(NativeProject {
        info_json,
        entries: Mutex::new(entries),
    })
}

/// Contract version of the core this addon was built with.
#[napi]
pub fn contract_version() -> &'static str {
    sourceorrery::CONTRACT_VERSION
}
