//! `sourceorrery._native`: the thin PyO3 layer over the `sourceorrery`
//! client crate.
//!
//! Everything that decides anything (unlock order, policy, hints) lives in
//! Rust in the client crate. This module only converts arguments, hands
//! metadata across as JSON text (parsed into dataclasses by the Python
//! package) and wraps values in [`SecretValue`]. Errors become the typed
//! exceptions defined in `sourceorrery.errors`, chosen by stable code.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use pyo3::exceptions::{PyTypeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyModule};
use sourceorrery::{OpenOptions, Project, SecretBytes, SecretReader};

/// Build the Python exception for `err`: `sourceorrery.errors.error_for`
/// picks the class by code, so the mapping lives in one place.
fn to_py(py: Python<'_>, err: &sourceorrery::Error) -> PyErr {
    let built = py
        .import("sourceorrery.errors")
        .and_then(|module| module.getattr("error_for"))
        .and_then(|factory| factory.call1((err.code(), err.message(), err.hint())));
    match built {
        Ok(instance) => PyErr::from_value(instance),
        Err(import_error) => import_error,
    }
}

fn open_options(
    home: Option<PathBuf>,
    passphrase: Option<Vec<u8>>,
    passphrase_file: Option<PathBuf>,
    environment: bool,
) -> OpenOptions {
    OpenOptions {
        home,
        passphrase: passphrase.map(SecretBytes::new),
        passphrase_file,
        environment,
    }
}

fn json_text<T: serde::Serialize>(value: &T) -> PyResult<String> {
    serde_json::to_string(value)
        .map_err(|err| PyValueError::new_err(format!("cannot serialise metadata: {err}")))
}

/// A secret value. Holds the bytes on the Rust side until `close()` (or the
/// end of a `with` block) zeroises them. `expose()` returns a Python `bytes`
/// copy, which Python cannot wipe: keep it short-lived.
#[pyclass(frozen, name = "SecretValue", module = "sourceorrery")]
#[derive(Debug)]
pub struct SecretValue {
    inner: Mutex<Option<SecretBytes>>,
}

impl SecretValue {
    fn wrap(value: SecretBytes) -> Self {
        Self {
            inner: Mutex::new(Some(value)),
        }
    }

    fn with_bytes<T>(&self, f: impl FnOnce(&[u8]) -> T) -> PyResult<T> {
        let guard = self
            .inner
            .lock()
            .map_err(|_| PyValueError::new_err("poisoned"))?;
        match guard.as_ref() {
            Some(bytes) => Ok(f(bytes.expose())),
            None => Err(PyValueError::new_err(
                "SecretValue is closed; its bytes were zeroised",
            )),
        }
    }
}

#[pymethods]
impl SecretValue {
    /// A `bytes` copy of the value.
    fn expose<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        self.with_bytes(|bytes| PyBytes::new(py, bytes))
    }

    /// The value decoded as UTF-8.
    fn expose_text(&self) -> PyResult<String> {
        self.with_bytes(|bytes| {
            std::str::from_utf8(bytes)
                .map(str::to_owned)
                .map_err(|_| PyValueError::new_err("secret value is not valid UTF-8"))
        })?
    }

    /// Zeroise the bytes. Idempotent.
    fn close(&self) {
        if let Ok(mut guard) = self.inner.lock() {
            *guard = None;
        }
    }

    /// True once `close()` has run.
    #[getter]
    fn closed(&self) -> bool {
        self.inner.lock().map_or(true, |g| g.is_none())
    }

    fn __len__(&self) -> usize {
        self.inner
            .lock()
            .ok()
            .and_then(|g| g.as_ref().map(SecretBytes::len))
            .unwrap_or(0)
    }

    fn __enter__(slf: Bound<'_, Self>) -> Bound<'_, Self> {
        slf
    }

    #[pyo3(signature = (_exc_type=None, _exc_value=None, _traceback=None))]
    fn __exit__(
        &self,
        _exc_type: Option<Bound<'_, PyAny>>,
        _exc_value: Option<Bound<'_, PyAny>>,
        _traceback: Option<Bound<'_, PyAny>>,
    ) -> bool {
        self.close();
        false
    }

    #[allow(clippy::unused_self)] // pyo3 dunder methods take the receiver
    fn __repr__(&self) -> &'static str {
        "SecretValue([REDACTED])"
    }

    #[allow(clippy::unused_self)]
    fn __str__(&self) -> &'static str {
        "[REDACTED]"
    }

    /// Pickling, copying and `json.dumps` of a value are refused.
    #[allow(clippy::unused_self)]
    fn __reduce__(&self) -> PyResult<()> {
        Err(PyTypeError::new_err(
            "SecretValue cannot be pickled or copied; call expose() deliberately",
        ))
    }
}

/// A read-only vault handle (see `sourceorrery.SecretReader`).
///
/// The reader is shared through an `Arc` so that no lock is held while the
/// Rust call runs or while a Python exception is built: holding a lock
/// across either would let another Python thread block on it while holding
/// the GIL, which deadlocks. `close()` just drops this handle's reference;
/// the vault key is zeroised when the last in-flight call finishes.
#[pyclass(frozen, name = "Reader", module = "sourceorrery._native")]
#[derive(Debug)]
pub struct Reader {
    inner: Mutex<Option<Arc<SecretReader>>>,
}

impl Reader {
    fn reader(&self) -> PyResult<Arc<SecretReader>> {
        let guard = self
            .inner
            .lock()
            .map_err(|_| PyValueError::new_err("poisoned"))?;
        guard
            .as_ref()
            .cloned()
            .ok_or_else(|| PyValueError::new_err("SecretReader is closed"))
    }

    /// Run `f` against the vault with the GIL released, then convert the
    /// outcome with the GIL held again.
    fn with_reader<T: Send>(
        &self,
        py: Python<'_>,
        f: impl FnOnce(&SecretReader) -> sourceorrery::Result<T> + Send,
    ) -> PyResult<T> {
        let reader = self.reader()?;
        let outcome = py.detach(move || f(&reader));
        outcome.map_err(|err| to_py(py, &err))
    }

    fn secret(
        &self,
        py: Python<'_>,
        f: impl FnOnce(&SecretReader) -> sourceorrery::Result<sourceorrery::Secret> + Send,
    ) -> PyResult<(String, SecretValue)> {
        let secret = self.with_reader(py, f)?;
        Ok((
            json_text(&secret.properties)?,
            SecretValue::wrap(secret.value),
        ))
    }
}

#[pymethods]
impl Reader {
    #[new]
    #[pyo3(signature = (vault, home=None, passphrase=None, passphrase_file=None, environment=true))]
    fn new(
        py: Python<'_>,
        vault: &str,
        home: Option<PathBuf>,
        passphrase: Option<Vec<u8>>,
        passphrase_file: Option<PathBuf>,
        environment: bool,
    ) -> PyResult<Self> {
        let options = open_options(home, passphrase, passphrase_file, environment);
        let outcome = py.detach(move || SecretReader::open_with(vault, &options));
        let reader = outcome.map_err(|err| to_py(py, &err))?;
        Ok(Self {
            inner: Mutex::new(Some(Arc::new(reader))),
        })
    }

    #[getter]
    fn vault_name(&self, py: Python<'_>) -> PyResult<String> {
        self.with_reader(py, |r| Ok(r.vault_name().to_owned()))
    }

    #[getter]
    fn home(&self, py: Python<'_>) -> PyResult<PathBuf> {
        self.with_reader(py, |r| Ok(r.home().to_path_buf()))
    }

    /// `(properties_json, value)` of the newest accessible version, or of
    /// `version`.
    #[pyo3(signature = (name, version=None))]
    fn get(
        &self,
        py: Python<'_>,
        name: &str,
        version: Option<&str>,
    ) -> PyResult<(String, SecretValue)> {
        self.secret(py, |r| match version {
            Some(version) => r.get_version(name, version),
            None => r.get(name),
        })
    }

    /// Properties JSON of one version (`None`: the newest), policy not applied.
    #[pyo3(signature = (name, version=None))]
    fn properties(&self, py: Python<'_>, name: &str, version: Option<&str>) -> PyResult<String> {
        let props = self.with_reader(py, |r| r.properties(name, version))?;
        json_text(&props)
    }

    /// Resolve a `sourceorrery://` reference bound to this vault.
    fn resolve(&self, py: Python<'_>, reference: &str) -> PyResult<(String, SecretValue)> {
        self.secret(py, |r| r.resolve(reference))
    }

    /// Vault descriptor JSON.
    fn descriptor(&self, py: Python<'_>) -> PyResult<String> {
        let descriptor = self.with_reader(py, SecretReader::descriptor)?;
        json_text(&descriptor)
    }

    /// Release the vault; the key held in memory is zeroised. Idempotent.
    fn close(&self) {
        if let Ok(mut guard) = self.inner.lock() {
            *guard = None;
        }
    }

    #[getter]
    fn closed(&self) -> bool {
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

/// Resolve a project manifest: `(info_json, [(entry_json, value), ...])`.
#[pyfunction]
#[pyo3(signature = (manifest=None, home=None, passphrase=None, passphrase_file=None, environment=true))]
fn load_project(
    py: Python<'_>,
    manifest: Option<PathBuf>,
    home: Option<PathBuf>,
    passphrase: Option<Vec<u8>>,
    passphrase_file: Option<PathBuf>,
    environment: bool,
) -> PyResult<(String, Vec<(String, SecretValue)>)> {
    let options = open_options(home, passphrase, passphrase_file, environment);
    let outcome = py.detach(move || Project::load(manifest.as_deref(), &options));
    let project = outcome.map_err(|err| to_py(py, &err))?;
    let info = json_text(&ProjectInfo {
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
        entries.push((entry, SecretValue::wrap(secret.value.clone())));
    }
    Ok((info, entries))
}

/// Contract version of the core this module was built with.
#[pyfunction]
fn contract_version() -> &'static str {
    sourceorrery::CONTRACT_VERSION
}

#[pymodule(name = "_native")]
fn native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<SecretValue>()?;
    m.add_class::<Reader>()?;
    m.add_function(wrap_pyfunction!(load_project, m)?)?;
    m.add_function(wrap_pyfunction!(contract_version, m)?)?;
    Ok(())
}
