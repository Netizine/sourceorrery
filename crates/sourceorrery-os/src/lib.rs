//! # SourceOrrery OS primitives
//!
//! One operation: create a new, empty file that only its creator can open,
//! for a secret (a vault's recovery key) that is about to be written to it
//! ([ADR 0010](https://github.com/Netizine/sourceorrery/blob/main/docs/adr/0010-authenticated-key-wraps-and-private-files.md)).
//!
//! * **Windows:** the file is created with `CREATE_NEW` and an explicit
//!   security descriptor: owned by the process's user, with a protected
//!   DACL that grants full access to that user and to `SYSTEM` only, so no
//!   permission is inherited from the folder. The handle is not
//!   inheritable and is opened without sharing. Before the file is
//!   returned, its owner and DACL are read back through the handle and must
//!   be exactly that, and the volume must keep ACLs (`FILE_PERSISTENT_ACLS`;
//!   FAT does not).
//! * **Unix:** `O_CREAT | O_EXCL` with mode `0600`, then the mode is
//!   checked for group and other bits.
//!
//! An existing file is never opened or changed. On any failure after the
//! file was created, the empty file is removed and an error returned: there
//! is no fallback to ordinary creation. No key material passes through this
//! crate; the caller writes to the returned file.
//!
//! This crate and `sourceorrery-ffi` are the only crates of the workspace
//! that use `unsafe`. Every `unsafe` block states the facts it relies on.

#[cfg(windows)]
mod windows;

use std::fs::File;
use std::io;
use std::path::Path;

/// Create `path` as a new, empty file that only the current user (and, on
/// Windows, `SYSTEM`) can open, and return it open for reading and writing.
///
/// # Errors
///
/// [`io::ErrorKind::AlreadyExists`] when `path` exists (it is left as it
/// was); [`io::ErrorKind::Unsupported`] when the file system cannot keep the
/// permissions, or on a platform with no implementation; any other I/O
/// error from creating the file or reading its permissions back. In every
/// case after creation the file is removed again.
pub fn create_private_new(path: &Path) -> io::Result<File> {
    imp::create_private_new(path)
}

/// What the created file's permissions are described as to its owner.
#[must_use]
pub fn private_file_description() -> &'static str {
    imp::DESCRIPTION
}

#[cfg(windows)]
use windows as imp;

#[cfg(unix)]
mod imp {
    use std::fs::{File, OpenOptions};
    use std::io;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    use std::path::Path;

    pub(crate) const DESCRIPTION: &str = "readable by you only";

    pub(crate) fn create_private_new(path: &Path) -> io::Result<File> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?;
        // The umask can only take bits away from 0600; check anyway, so a
        // platform that ignores the mode is refused rather than trusted.
        let mode = file.metadata()?.permissions().mode();
        if mode & 0o077 != 0 {
            drop(file);
            let _ = std::fs::remove_file(path);
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!(
                    "{} was created with mode {:o}, not readable by its owner only",
                    path.display(),
                    mode & 0o777
                ),
            ));
        }
        Ok(file)
    }
}

#[cfg(not(any(windows, unix)))]
mod imp {
    use std::fs::File;
    use std::io;
    use std::path::Path;

    pub(crate) const DESCRIPTION: &str = "not restricted";

    pub(crate) fn create_private_new(path: &Path) -> io::Result<File> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!(
                "cannot create {} with owner-only permissions on this platform",
                path.display()
            ),
        ))
    }
}

#[cfg(all(test, unix))]
mod unix_tests {
    use std::io::{Read as _, Write as _};
    use std::os::unix::fs::PermissionsExt;

    use super::create_private_new;

    #[test]
    fn a_new_file_is_mode_0600_and_an_existing_one_is_left_alone() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("key");
        let mut file = create_private_new(&path).unwrap();
        assert_eq!(file.metadata().unwrap().permissions().mode() & 0o777, 0o600);
        file.write_all(b"synthetic").unwrap();
        drop(file);

        let err = create_private_new(&path).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);
        let mut kept = String::new();
        std::fs::File::open(&path)
            .unwrap()
            .read_to_string(&mut kept)
            .unwrap();
        assert_eq!(kept, "synthetic");
    }
}
