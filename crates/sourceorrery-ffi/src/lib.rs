//! # SourceOrrery C ABI
//!
//! A stable, minimal C interface over [`sourceorrery_storage::SqliteVault`]
//! for language bindings (.NET, Python, Node.js, ...) and for anyone building
//! their own. The semantics are exactly those of
//! [`sourceorrery_core::SecretClient`]; this crate adds no behaviour of its
//! own, in line with ADR 0001 (the Rust core owns all semantics).
//!
//! The generated header lives at `include/sourceorrery.h`.
//!
//! ## Conventions
//!
//! * **Strings in** are UTF-8 byte ranges `(ptr, len)`, never NUL-terminated.
//!   Arguments documented as nullable accept `NULL` for "absent"; a `NULL`
//!   pointer with a non-zero length is rejected as `invalid_argument`.
//! * **Data out** is an [`so_bytes`] buffer owned by the caller and released
//!   with [`so_bytes_free`], which zeroises the memory before freeing it. The
//!   buffer always carries one extra `0` byte after `len`, so JSON outputs
//!   can be read as C strings. Output parameters are set to the empty buffer
//!   before anything else happens, so they are safe to free after a failure.
//! * **Metadata** (properties, deleted secrets, audit events, options and
//!   queries) crosses as JSON in the shape produced by the core's serde
//!   implementations: `snake_case` keys, RFC 3339 timestamps.
//! * **Errors**: every fallible call returns an [`so_status`]. On
//!   `SO_STATUS_ERROR` the stable code ([`sourceorrery_core::SecretError::code`])
//!   and a human-readable message are available from [`so_last_error_code`]
//!   and [`so_last_error_message`] until the next SourceOrrery call on the
//!   same thread. Argument problems detected at this boundary (null pointers,
//!   invalid UTF-8, malformed JSON) use the core's `invalid_argument` code.
//!   A panic caught at the boundary yields `SO_STATUS_PANIC` with the code
//!   `internal`.
//! * **Secret values** are never logged, formatted or embedded in JSON. They
//!   cross only as raw bytes: into [`so_secret_set`] and out of
//!   [`so_secret_get`]. The copy handed to the caller is zeroised by
//!   [`so_bytes_free`]; the Rust-side copy is zeroised when the call returns.
//! * **Threads**: a vault handle may be used from several threads at once.
//!   Closing it must not race with any other use of it. Error state is per
//!   thread.
//!
//! This is the only crate in the workspace permitted to use `unsafe`. Every
//! `unsafe` block states the invariant it relies on, and every exported
//! function documents the contract its caller must uphold.

#![allow(non_camel_case_types)] // exported names follow C conventions
#![allow(clippy::too_many_arguments)] // C signatures carry explicit lengths

pub mod buffer;
pub mod error;
pub mod json;
pub mod vault;

use std::ffi::{CString, c_char};
use std::sync::OnceLock;

pub use buffer::{so_bytes, so_bytes_free};
pub use error::{so_last_error_clear, so_last_error_code, so_last_error_message, so_status};
pub use vault::{
    so_audit_events, so_secret_delete, so_secret_get, so_secret_get_deleted,
    so_secret_get_properties, so_secret_list, so_secret_list_deleted, so_secret_purge,
    so_secret_recover, so_secret_set, so_secret_update, so_secret_versions, so_vault,
    so_vault_close, so_vault_create, so_vault_descriptor, so_vault_open,
};

/// Version of this C ABI. Bumped only for incompatible changes to the
/// functions or structs in the header; additions do not bump it.
pub const SO_ABI_VERSION: u32 = 1;

/// Version of the C ABI this library was built with. Compare with
/// `SO_ABI_VERSION` from the header you compiled against.
#[unsafe(no_mangle)]
pub extern "C" fn so_abi_version() -> u32 {
    SO_ABI_VERSION
}

/// Version of the SourceOrrery contract (`sourceorrery_core::CONTRACT_VERSION`)
/// implemented by this library, as a static NUL-terminated string that stays
/// valid for the lifetime of the process.
#[unsafe(no_mangle)]
pub extern "C" fn so_contract_version() -> *const c_char {
    static VERSION: OnceLock<CString> = OnceLock::new();
    VERSION
        .get_or_init(|| {
            CString::new(sourceorrery_core::CONTRACT_VERSION).expect("contract version has no NUL")
        })
        .as_ptr()
}
