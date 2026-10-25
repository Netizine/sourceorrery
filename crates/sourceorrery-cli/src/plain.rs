//! Owned buffers for plaintext the CLI reads: a value from a file or stdin,
//! a password or recovery key from a file, a `.env` value (REC07 of the
//! 2026-10-25 review).
//!
//! Each buffer is wiped when it drops, and when it has to grow its bytes move
//! to a new buffer and the old one is wiped as it drops, so no copy is left
//! in freed memory by a reallocation; a read that fails part way wipes what
//! it had. A buffer that becomes a [`SecretBytes`] moves into it without a
//! copy. Copies the operating system, the terminal, the standard library's
//! own buffers or another process make are outside this guarantee.

use std::io::{ErrorKind, Read};
use std::path::Path;

use sourceorrery_core::SecretBytes;
use zeroize::Zeroizing;

/// The size reads are made in.
const CHUNK: usize = 8 * 1024;

/// Append `bytes` to `buf`, growing it the wiping way.
pub(crate) fn push(buf: &mut Zeroizing<Vec<u8>>, bytes: &[u8]) {
    let needed = buf.len() + bytes.len();
    if needed > buf.capacity() {
        let capacity = needed.max(buf.capacity().saturating_mul(2)).max(64);
        let mut grown = Zeroizing::new(Vec::with_capacity(capacity));
        grown.extend_from_slice(buf);
        // The old buffer is wiped as it drops here.
        *buf = grown;
    }
    buf.extend_from_slice(bytes);
}

/// Everything `reader` gives, in a buffer of `capacity` to start with.
pub(crate) fn read_to_end(
    mut reader: impl Read,
    capacity: usize,
) -> std::io::Result<Zeroizing<Vec<u8>>> {
    let mut buf = Zeroizing::new(Vec::with_capacity(capacity));
    let mut chunk = Zeroizing::new([0u8; CHUNK]);
    loop {
        match reader.read(&mut chunk[..]) {
            Ok(0) => return Ok(buf),
            Ok(n) => push(&mut buf, &chunk[..n]),
            Err(err) if err.kind() == ErrorKind::Interrupted => {}
            // `buf` and `chunk` are wiped as they drop.
            Err(err) => return Err(err),
        }
    }
}

/// The file at `path`, in a buffer sized from its length.
pub(crate) fn read_file(path: &Path) -> std::io::Result<Zeroizing<Vec<u8>>> {
    let file = std::fs::File::open(path)?;
    let size = file
        .metadata()
        .ok()
        .and_then(|meta| usize::try_from(meta.len()).ok())
        .unwrap_or(0);
    read_to_end(file, size)
}

/// The bytes of `buf` as a [`SecretBytes`], moved without a copy.
pub(crate) fn into_secret(mut buf: Zeroizing<Vec<u8>>) -> SecretBytes {
    SecretBytes::new(std::mem::take(&mut *buf))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn growing_keeps_every_byte_in_order() {
        let mut buf = Zeroizing::new(Vec::new());
        for i in 0..10_000u32 {
            push(&mut buf, &i.to_le_bytes());
        }
        assert_eq!(buf.len(), 40_000);
        assert_eq!(&buf[39_996..], &9_999u32.to_le_bytes());
    }

    /// A reader that gives `good` bytes, is interrupted once, then fails.
    struct Failing {
        good: usize,
        interrupted: bool,
    }

    impl Read for Failing {
        fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
            if !self.interrupted {
                self.interrupted = true;
                return Err(ErrorKind::Interrupted.into());
            }
            if self.good == 0 {
                return Err(std::io::Error::other("the pipe broke"));
            }
            let n = self.good.min(out.len());
            out[..n].fill(b's');
            self.good -= n;
            Ok(n)
        }
    }

    #[test]
    fn a_read_retries_an_interruption_and_reports_a_failure() {
        let err = read_to_end(
            Failing {
                good: 20_000,
                interrupted: false,
            },
            0,
        )
        .unwrap_err();
        assert_eq!(err.to_string(), "the pipe broke");
        let read = read_to_end(&b"one\ntwo"[..], 0).unwrap();
        assert_eq!(&read[..], b"one\ntwo");
    }

    #[test]
    fn a_file_is_read_whole_and_moved_without_a_copy() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("value");
        let bytes: Vec<u8> = (0..=255).cycle().take(100_000).collect();
        std::fs::write(&path, &bytes).unwrap();
        let read = read_file(&path).unwrap();
        assert_eq!(
            read.capacity(),
            bytes.len(),
            "sized from the file: no growth"
        );
        let pointer = read.as_ptr();
        let secret = into_secret(read);
        assert_eq!(secret.expose(), &bytes[..]);
        assert_eq!(secret.expose().as_ptr(), pointer, "moved, not copied");
        assert!(read_file(&dir.path().join("missing")).is_err());
    }
}
