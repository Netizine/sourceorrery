//! Status codes and per-thread error state.
//!
//! Errors are reported the way SQLite and libgit2 report them: a status code
//! from the call, details from thread-local accessors. The details never
//! include a secret value: [`sourceorrery_core::SecretError`] messages carry
//! names, versions and timestamps only, and this crate never formats a value.
//!
//! Besides the code and message, every error carries a *hint*: the
//! actionable part, produced by the [`sourceorrery`] client crate so that all
//! SDKs explain a failure the same way.

use std::any::Any;
use std::cell::RefCell;
use std::ffi::{CString, c_char};
use std::panic::{AssertUnwindSafe, catch_unwind};

use sourceorrery_core::SecretError;

/// Outcome of a call.
#[repr(i32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum so_status {
    /// The call succeeded and every output parameter is valid.
    SO_STATUS_OK = 0,
    /// The call failed. `so_last_error_code()` and `so_last_error_message()`
    /// describe why. Output parameters are left empty.
    SO_STATUS_ERROR = 1,
    /// A Rust panic was caught at the boundary. The error code is
    /// `internal`. Report it as a bug and treat the handle as unusable.
    SO_STATUS_PANIC = 2,
}

/// Error code reported with [`so_status::SO_STATUS_PANIC`]. It is not a
/// `SecretError` code and never originates from the core.
pub(crate) const INTERNAL_ERROR_CODE: &str = "internal";

struct LastError {
    code: CString,
    message: CString,
    hint: CString,
}

/// An error that can be stored as the thread's last error.
pub(crate) trait Reportable {
    /// Stable code.
    fn code(&self) -> &str;
    /// Message without the hint.
    fn message(&self) -> String;
    /// What to do about it; empty when nothing specific applies.
    fn hint(&self) -> String;
}

impl Reportable for SecretError {
    fn code(&self) -> &str {
        Self::code(self)
    }

    fn message(&self) -> String {
        self.to_string()
    }

    fn hint(&self) -> String {
        sourceorrery::Error::from_core(self, None).hint().to_owned()
    }
}

impl Reportable for sourceorrery::Error {
    fn code(&self) -> &str {
        Self::code(self)
    }

    fn message(&self) -> String {
        Self::message(self).to_owned()
    }

    fn hint(&self) -> String {
        Self::hint(self).to_owned()
    }
}

thread_local! {
    static LAST_ERROR: RefCell<Option<LastError>> = const { RefCell::new(None) };
}

/// Build a C string, dropping interior NULs (a message may echo bytes a
/// caller passed in an option field, and those are not validated).
fn c_string(text: &str) -> CString {
    CString::new(text.replace('\0', "")).unwrap_or_default()
}

pub(crate) fn set_last_error(code: &str, message: &str, hint: &str) {
    LAST_ERROR.with(|slot| {
        *slot.borrow_mut() = Some(LastError {
            code: c_string(code),
            message: c_string(message),
            hint: c_string(hint),
        });
    });
}

pub(crate) fn clear_last_error() {
    LAST_ERROR.with(|slot| *slot.borrow_mut() = None);
}

fn panic_text(payload: &(dyn Any + Send)) -> String {
    if let Some(text) = payload.downcast_ref::<&str>() {
        format!("panic: {text}")
    } else if let Some(text) = payload.downcast_ref::<String>() {
        format!("panic: {text}")
    } else {
        "panic".to_owned()
    }
}

/// Run the body of an exported function: clear the thread's error state,
/// translate an error into [`so_status::SO_STATUS_ERROR`] plus error state,
/// and keep a panic from unwinding into the caller.
pub(crate) fn guard<E, F>(body: F) -> so_status
where
    E: Reportable,
    F: FnOnce() -> Result<(), E>,
{
    clear_last_error();
    match catch_unwind(AssertUnwindSafe(body)) {
        Ok(Ok(())) => so_status::SO_STATUS_OK,
        Ok(Err(err)) => {
            set_last_error(err.code(), &err.message(), &err.hint());
            so_status::SO_STATUS_ERROR
        }
        Err(payload) => {
            set_last_error(
                INTERNAL_ERROR_CODE,
                &panic_text(payload.as_ref()),
                "This is a bug in SourceOrrery; please report it with the message above",
            );
            so_status::SO_STATUS_PANIC
        }
    }
}

/// Stable code of the error reported by the last call on this thread
/// (`not_found`, `disabled`, `locked`, ...), or `NULL` if that call
/// succeeded. The string is NUL-terminated and valid until the next
/// SourceOrrery call on this thread.
#[unsafe(no_mangle)]
pub extern "C" fn so_last_error_code() -> *const c_char {
    LAST_ERROR.with(|slot| {
        slot.borrow()
            .as_ref()
            .map_or(std::ptr::null(), |err| err.code.as_ptr())
    })
}

/// Human-readable message of the error reported by the last call on this
/// thread, or `NULL` if that call succeeded. Messages may change between
/// releases; codes do not. The string is NUL-terminated and valid until the
/// next SourceOrrery call on this thread. It never contains a secret value.
#[unsafe(no_mangle)]
pub extern "C" fn so_last_error_message() -> *const c_char {
    LAST_ERROR.with(|slot| {
        slot.borrow()
            .as_ref()
            .map_or(std::ptr::null(), |err| err.message.as_ptr())
    })
}

/// What to do about the error reported by the last call on this thread
/// (which command creates the vault, which passphrase sources were tried,
/// why a version was refused, ...), or `NULL` if that call succeeded or has
/// nothing specific to suggest. Wording may change between releases. The
/// string is NUL-terminated and valid until the next SourceOrrery call on
/// this thread. It never contains a secret value.
#[unsafe(no_mangle)]
pub extern "C" fn so_last_error_hint() -> *const c_char {
    LAST_ERROR.with(|slot| {
        slot.borrow().as_ref().map_or(std::ptr::null(), |err| {
            if err.hint.as_bytes().is_empty() {
                std::ptr::null()
            } else {
                err.hint.as_ptr()
            }
        })
    })
}

/// Forget the error state of this thread.
#[unsafe(no_mangle)]
pub extern "C" fn so_last_error_clear() {
    clear_last_error();
}

#[cfg(test)]
mod tests {
    use std::ffi::CStr;

    use super::*;

    fn code() -> Option<String> {
        let ptr = so_last_error_code();
        if ptr.is_null() {
            return None;
        }
        // SAFETY: a non-null pointer from so_last_error_code is a NUL-terminated
        // string owned by this thread's error slot, alive until the next call.
        Some(
            unsafe { CStr::from_ptr(ptr) }
                .to_string_lossy()
                .into_owned(),
        )
    }

    #[test]
    fn guard_translates_errors_and_clears_on_success() {
        let status = guard(|| Err(SecretError::NotFound { name: "k".into() }));
        assert_eq!(status, so_status::SO_STATUS_ERROR);
        assert_eq!(code().as_deref(), Some("not_found"));
        assert!(!so_last_error_message().is_null());

        // SAFETY: the hint pointer is non-null right after a not_found error.
        let hint = unsafe { CStr::from_ptr(so_last_error_hint()) }
            .to_str()
            .unwrap();
        assert!(hint.contains("sourceorrery secret set k"), "{hint}");

        assert_eq!(guard(|| Ok::<(), SecretError>(())), so_status::SO_STATUS_OK);
        assert!(code().is_none());
        assert!(so_last_error_message().is_null());
        assert!(so_last_error_hint().is_null());
    }

    #[test]
    fn errors_without_a_hint_report_null() {
        set_last_error("storage", "m", "");
        assert!(!so_last_error_code().is_null());
        assert!(so_last_error_hint().is_null());
    }

    #[test]
    fn guard_catches_panics() {
        let status = guard(|| -> Result<(), SecretError> { panic!("boom") });
        assert_eq!(status, so_status::SO_STATUS_PANIC);
        assert_eq!(code().as_deref(), Some("internal"));
        so_last_error_clear();
        assert!(code().is_none());
    }

    #[test]
    fn interior_nuls_do_not_truncate_the_message() {
        set_last_error("invalid_argument", "a\0b", "");
        // SAFETY: the message pointer is non-null right after set_last_error.
        let message = unsafe { CStr::from_ptr(so_last_error_message()) };
        assert_eq!(message.to_str().unwrap(), "ab");
    }
}
