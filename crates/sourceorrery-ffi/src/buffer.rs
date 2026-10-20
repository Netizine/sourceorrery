//! Caller-owned output buffers.

use std::ptr;

use zeroize::Zeroize;

/// A buffer allocated by SourceOrrery and owned by the caller.
///
/// `ptr` points at `len` bytes followed by one extra `0` byte that is not
/// counted in `len`, so a UTF-8 payload can be read as a C string. Release
/// it with [`so_bytes_free`], which zeroises the memory before freeing it;
/// never free it with `free()`. Do not modify the fields: they describe the
/// allocation.
///
/// A buffer with `ptr == NULL` and `len == 0` is the empty buffer; it is what
/// output parameters hold after a failed call, and freeing it is a no-op.
#[repr(C)]
#[derive(Debug)]
pub struct so_bytes {
    /// Start of the data, or `NULL` for the empty buffer.
    pub ptr: *mut u8,
    /// Number of bytes, excluding the trailing `0`.
    pub len: usize,
}

impl so_bytes {
    /// The empty buffer.
    pub(crate) const EMPTY: Self = Self {
        ptr: ptr::null_mut(),
        len: 0,
    };

    /// Hand `bytes` to the caller.
    ///
    /// The vector should have at least one spare byte of capacity when it
    /// holds a secret value, so that appending the terminator cannot
    /// reallocate and leave an unzeroised copy behind (see `copy_of`).
    pub(crate) fn from_vec(mut bytes: Vec<u8>) -> Self {
        bytes.reserve_exact(1);
        bytes.push(0);
        let len = bytes.len() - 1;
        let boxed: Box<[u8]> = bytes.into_boxed_slice();
        Self {
            ptr: Box::into_raw(boxed).cast::<u8>(),
            len,
        }
    }

    /// Copy `bytes` into a new buffer with exactly the capacity needed, so no
    /// intermediate allocation ever holds the data.
    pub(crate) fn copy_of(bytes: &[u8]) -> Self {
        let mut owned = Vec::with_capacity(bytes.len() + 1);
        owned.extend_from_slice(bytes);
        Self::from_vec(owned)
    }
}

/// Zeroise and free a buffer returned by SourceOrrery, then reset it to the
/// empty buffer. Passing `NULL`, or a buffer that is already empty, is a
/// no-op, so freeing twice is harmless.
///
/// # Safety
///
/// `bytes` must be `NULL` or point to an `so_bytes` that was filled by a
/// SourceOrrery call and whose fields have not been modified since.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn so_bytes_free(bytes: *mut so_bytes) {
    if bytes.is_null() {
        return;
    }
    // SAFETY: the caller guarantees `bytes` points to a valid `so_bytes`.
    let bytes = unsafe { &mut *bytes };
    if bytes.ptr.is_null() {
        bytes.len = 0;
        return;
    }
    let total = bytes.len + 1;
    // SAFETY: a non-null `ptr` with unmodified `len` came from `from_vec`,
    // which leaked a `Box<[u8]>` of exactly `len + 1` bytes; it has not been
    // freed yet because freeing resets `ptr` to NULL. Rebuilding the box with
    // the same length restores the original allocation for deallocation.
    let slice: &mut [u8] = unsafe { std::slice::from_raw_parts_mut(bytes.ptr, total) };
    slice.zeroize();
    // SAFETY: `slice` covers exactly the allocation leaked by `Box::into_raw`.
    drop(unsafe { Box::from_raw(ptr::from_mut::<[u8]>(slice)) });
    bytes.ptr = ptr::null_mut();
    bytes.len = 0;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn buffers_are_nul_terminated_and_free_resets() {
        let mut out = so_bytes::copy_of(b"hello");
        assert_eq!(out.len, 5);
        // SAFETY: `out` holds len + 1 readable bytes allocated by copy_of.
        let seen = unsafe { std::slice::from_raw_parts(out.ptr, out.len + 1) };
        assert_eq!(seen, b"hello\0");
        // SAFETY: `out` is a valid, unmodified buffer from copy_of.
        unsafe { so_bytes_free(&raw mut out) };
        assert!(out.ptr.is_null());
        assert_eq!(out.len, 0);
        // SAFETY: freeing the empty buffer is defined as a no-op.
        unsafe { so_bytes_free(&raw mut out) };
        // SAFETY: NULL is accepted.
        unsafe { so_bytes_free(ptr::null_mut()) };
    }

    #[test]
    fn empty_payload_still_allocates_a_terminator() {
        let mut out = so_bytes::copy_of(b"");
        assert!(!out.ptr.is_null());
        assert_eq!(out.len, 0);
        // SAFETY: valid buffer from copy_of.
        unsafe { so_bytes_free(&raw mut out) };
        assert!(out.ptr.is_null());
    }
}
