//! Windows: `CreateFileW` with an owner-only security descriptor, read
//! back and checked through the handle before the file is returned.

use std::ffi::{OsStr, c_void};
use std::fs::File;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::Path;
use std::ptr;

use windows_sys::Win32::Foundation::{ERROR_SUCCESS, HANDLE, INVALID_HANDLE_VALUE, LocalFree};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo,
    SDDL_REVISION_1, SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, DACL_SECURITY_INFORMATION, GetAce,
    GetSecurityDescriptorControl, GetTokenInformation, INHERITED_ACE, OWNER_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR, PSID, SE_DACL_PROTECTED, SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER,
    TokenUser,
};
use windows_sys::Win32::Storage::FileSystem::{
    CREATE_NEW, CreateFileW, FILE_ALL_ACCESS, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_READ,
    FILE_GENERIC_WRITE, GetVolumeInformationByHandleW,
};
use windows_sys::Win32::System::SystemServices::{ACCESS_ALLOWED_ACE_TYPE, FILE_PERSISTENT_ACLS};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows_sys::core::PWSTR;

pub(crate) const DESCRIPTION: &str = "restricted to your account and Windows SYSTEM";

/// The well-known SID of the operating system (`NT AUTHORITY\SYSTEM`).
const SYSTEM_SID: &str = "S-1-5-18";

pub(crate) fn create_private_new(path: &Path) -> io::Result<File> {
    create_checked(path, check_file)
}

/// Create `path` as [`create_private_new`] does, with `check` deciding
/// whether the created file may be returned. Split out so the tests can
/// make the check fail and see the file removed.
fn create_checked(
    path: &Path,
    check: impl FnOnce(&File, &str) -> io::Result<()>,
) -> io::Result<File> {
    let user = current_user_sid()?;
    let descriptor = owner_only_descriptor(&user)?;
    let attributes = SECURITY_ATTRIBUTES {
        nLength: u32::try_from(size_of::<SECURITY_ATTRIBUTES>()).expect("a small struct"),
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: 0,
    };
    let wide_path = wide(path.as_os_str())?;
    // SAFETY: `wide_path` is a NUL-terminated wide string and `attributes`
    // (with the descriptor it points to, owned by `descriptor`) are alive
    // until the call returns; no template handle is passed. CreateFileW only
    // reads them.
    let handle = unsafe {
        CreateFileW(
            wide_path.as_ptr(),
            FILE_GENERIC_READ | FILE_GENERIC_WRITE,
            0,
            &raw const attributes,
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL,
            ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: CreateFileW returned a valid handle that nothing else owns;
    // `OwnedHandle` (inside the `File`) closes it exactly once.
    let file = File::from(unsafe { OwnedHandle::from_raw_handle(handle) });
    match check(&file, &user) {
        Ok(()) => Ok(file),
        Err(err) => {
            drop(file);
            let _ = std::fs::remove_file(path);
            Err(err)
        }
    }
}

/// `text` as a NUL-terminated wide string; refused if it contains a NUL.
fn wide(text: &OsStr) -> io::Result<Vec<u16>> {
    let mut wide: Vec<u16> = text.encode_wide().collect();
    if wide.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "a path or name contains a NUL character",
        ));
    }
    wide.push(0);
    Ok(wide)
}

/// Memory the system allocated for us (with `LocalAlloc`), freed with
/// `LocalFree` when dropped.
struct Local(*mut c_void);

impl Drop for Local {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: the pointer came from an API documented to allocate
            // with LocalAlloc and to be freed with LocalFree, and this owner
            // frees it once.
            unsafe { LocalFree(self.0) };
        }
    }
}

/// A kernel handle closed when dropped.
struct Handle(OwnedHandle);

/// The string form (`S-1-5-…`) of the process's user SID.
fn current_user_sid() -> io::Result<String> {
    let mut raw: HANDLE = ptr::null_mut();
    // SAFETY: GetCurrentProcess returns a pseudo-handle that needs no
    // closing; `raw` is a valid out-pointer for the call.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut raw) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: OpenProcessToken succeeded, so `raw` is a token handle that
    // nothing else owns; `OwnedHandle` closes it once.
    let token = Handle(unsafe { OwnedHandle::from_raw_handle(raw) });
    let token_handle = token.0.as_raw_handle();
    let mut len = 0u32;
    // SAFETY: a null buffer of length 0 only asks for the size, which is
    // written to `len`; the call reports "insufficient buffer" by design.
    unsafe { GetTokenInformation(token_handle, TokenUser, ptr::null_mut(), 0, &raw mut len) };
    if len == 0 {
        return Err(io::Error::last_os_error());
    }
    // u64 elements, so the buffer is aligned for TOKEN_USER, which holds a
    // pointer.
    let mut buffer = vec![0u64; (len as usize).div_ceil(8)];
    // SAFETY: `buffer` is writable for at least `len` bytes and outlives
    // the call; `len` is a valid in/out pointer.
    if unsafe {
        GetTokenInformation(
            token_handle,
            TokenUser,
            buffer.as_mut_ptr().cast(),
            len,
            &raw mut len,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the call succeeded, so the buffer begins with an initialized,
    // suitably aligned TOKEN_USER whose SID points into the same buffer.
    let sid = unsafe { (*buffer.as_ptr().cast::<TOKEN_USER>()).User.Sid };
    // SAFETY: `sid` points into `buffer`, which is alive until this
    // function returns, after the conversion.
    unsafe { sid_string(sid) }
}

/// The string form (`S-1-5-…`) of `sid`.
///
/// # Safety
///
/// `sid` must point to a valid SID that stays alive for the call.
unsafe fn sid_string(sid: PSID) -> io::Result<String> {
    let mut text: PWSTR = ptr::null_mut();
    // SAFETY: `sid` is valid (the caller's contract); `text` is a valid
    // out-pointer.
    if unsafe { ConvertSidToStringSidW(sid, &raw mut text) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let _owned = Local(text.cast());
    // SAFETY: on success `text` is a NUL-terminated wide string the system
    // allocated, alive until `_owned` is dropped at the end of this function.
    Ok(unsafe { from_wide(text) })
}

/// A NUL-terminated wide string as a `String` (lossily).
///
/// # Safety
///
/// `text` must point to a NUL-terminated sequence of `u16` that stays
/// alive and unchanged for the call.
unsafe fn from_wide(text: *const u16) -> String {
    let mut len = 0usize;
    // SAFETY: the sequence is NUL-terminated (the caller's contract), so
    // every offset read before the NUL is within it.
    while unsafe { *text.add(len) } != 0 {
        len += 1;
    }
    // SAFETY: the `len` elements before the NUL are initialized and alive.
    String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(text, len) })
}

/// A security descriptor owned by `user` whose protected DACL grants full
/// access to `user` and to `SYSTEM` only.
fn owner_only_descriptor(user: &str) -> io::Result<Local> {
    let sddl = format!("O:{user}D:P(A;;FA;;;{user})(A;;FA;;;SY)");
    let wide_sddl = wide(OsStr::new(&sddl))?;
    let mut descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
    // SAFETY: `wide_sddl` is a NUL-terminated wide string alive for the
    // call; `descriptor` is a valid out-pointer; the size out-pointer may be
    // null.
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            wide_sddl.as_ptr(),
            SDDL_REVISION_1,
            &raw mut descriptor,
            ptr::null_mut(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(Local(descriptor))
}

/// One access-control entry as read back.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Ace {
    allowed: bool,
    inherited: bool,
    mask: u32,
    sid: String,
}

/// A file's owner and DACL as read back through its handle.
#[derive(Clone, Debug)]
struct Observed {
    owner: String,
    protected: bool,
    has_dacl: bool,
    aces: Vec<Ace>,
}

/// Read `file`'s owner and DACL back, and refuse unless the volume keeps
/// ACLs and they are exactly what [`owner_only_descriptor`] asked for.
fn check_file(file: &File, user: &str) -> io::Result<()> {
    let handle = file.as_raw_handle();
    let mut flags = 0u32;
    // SAFETY: `handle` is open for the call (borrowed from `file`); the
    // name buffers are null with size 0, which the API accepts; `flags` is a
    // valid out-pointer.
    if unsafe {
        GetVolumeInformationByHandleW(
            handle,
            ptr::null_mut(),
            0,
            ptr::null_mut(),
            ptr::null_mut(),
            &raw mut flags,
            ptr::null_mut(),
            0,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let observed = read_permissions(handle)?;
    check_permissions(&observed, user, flags & FILE_PERSISTENT_ACLS != 0)
}

/// The owner and DACL of the open `handle`.
fn read_permissions(handle: HANDLE) -> io::Result<Observed> {
    let mut owner: PSID = ptr::null_mut();
    let mut dacl: *mut ACL = ptr::null_mut();
    let mut raw_descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
    // SAFETY: `handle` is open with READ_CONTROL (part of FILE_GENERIC_READ)
    // for the call; the out-pointers are valid; the group and SACL are not
    // requested, so their out-pointers may be null.
    let status = unsafe {
        GetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &raw mut owner,
            ptr::null_mut(),
            &raw mut dacl,
            ptr::null_mut(),
            &raw mut raw_descriptor,
        )
    };
    if status != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(
            i32::try_from(status).unwrap_or(i32::MAX),
        ));
    }
    // `owner` and `dacl` point into this descriptor, which is freed only
    // when `descriptor` is dropped at the end of this function.
    let descriptor = Local(raw_descriptor);
    let owner = if owner.is_null() {
        String::new()
    } else {
        // SAFETY: `owner` points to the owner SID inside `descriptor`.
        unsafe { sid_string(owner)? }
    };
    let mut control = 0u16;
    let mut revision = 0u32;
    // SAFETY: `descriptor.0` is the valid security descriptor just returned;
    // the out-pointers are valid.
    if unsafe { GetSecurityDescriptorControl(descriptor.0, &raw mut control, &raw mut revision) }
        == 0
    {
        return Err(io::Error::last_os_error());
    }
    let mut aces = Vec::new();
    if !dacl.is_null() {
        // SAFETY: `dacl` points to the valid ACL inside `descriptor`.
        let count = unsafe { (*dacl).AceCount };
        for index in 0..u32::from(count) {
            let mut ace: *mut c_void = ptr::null_mut();
            // SAFETY: `dacl` is valid and `index` is below its ACE count;
            // `ace` is a valid out-pointer.
            if unsafe { GetAce(dacl, index, &raw mut ace) } == 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: GetAce returned a pointer to an ACE inside the ACL,
            // which begins with an ACE_HEADER.
            let header = unsafe { ace.cast::<ACE_HEADER>().read_unaligned() };
            let allowed = u32::from(header.AceType) == ACCESS_ALLOWED_ACE_TYPE;
            let (mask, sid) = if allowed {
                let allowed_ace = ace.cast::<ACCESS_ALLOWED_ACE>();
                // SAFETY: an ACE of type ACCESS_ALLOWED has the
                // ACCESS_ALLOWED_ACE layout; its mask is within the ACE.
                let mask = unsafe { ptr::addr_of!((*allowed_ace).Mask).read_unaligned() };
                // SAFETY: the ACE's SID starts at `SidStart` and lies within
                // the ACE, inside `descriptor`.
                let sid_ptr = unsafe { ptr::addr_of_mut!((*allowed_ace).SidStart) };
                // SAFETY: `sid_ptr` points to the valid SID just described.
                (mask, unsafe { sid_string(sid_ptr.cast())? })
            } else {
                (0, String::new())
            };
            aces.push(Ace {
                allowed,
                inherited: u32::from(header.AceFlags) & INHERITED_ACE != 0,
                mask,
                sid,
            });
        }
    }
    drop(descriptor);
    Ok(Observed {
        owner,
        protected: control & SE_DACL_PROTECTED != 0,
        has_dacl: !dacl.is_null(),
        aces,
    })
}

fn refused(message: String) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message)
}

/// Refuse unless the volume keeps ACLs and `observed` is exactly: owned by
/// `user`, a protected DACL, and one non-inherited full-access allow entry
/// each for `user` and `SYSTEM`, nothing else.
fn check_permissions(observed: &Observed, user: &str, persistent_acls: bool) -> io::Result<()> {
    if !persistent_acls {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "the volume does not keep file permissions (FAT, for example), so the file \
             cannot be restricted to your account",
        ));
    }
    if observed.owner != user {
        return Err(refused(format!(
            "the new file is owned by {}, not by your account ({user})",
            observed.owner
        )));
    }
    if !observed.has_dacl {
        return Err(refused(
            "the new file has no access list, so anyone could open it".to_owned(),
        ));
    }
    if !observed.protected {
        return Err(refused(
            "the new file's permissions are not protected from its folder's".to_owned(),
        ));
    }
    let expected = |sid: &str| Ace {
        allowed: true,
        inherited: false,
        mask: FILE_ALL_ACCESS,
        sid: sid.to_owned(),
    };
    let only_expected = observed
        .aces
        .iter()
        .all(|ace| *ace == expected(user) || *ace == expected(SYSTEM_SID));
    let has = |sid: &str| observed.aces.contains(&expected(sid));
    if !only_expected || !has(user) || !has(SYSTEM_SID) || observed.aces.len() > 2 {
        return Err(refused(format!(
            "the new file's access list is not your account and SYSTEM only: {:?}",
            observed.aces
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::{Read as _, Write as _};
    use std::process::Command;

    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSidToSidW, GetEffectiveRightsFromAclW, NO_MULTIPLE_TRUSTEE, TRUSTEE_IS_SID,
        TRUSTEE_IS_UNKNOWN, TRUSTEE_W,
    };

    use super::*;

    const USERS: &str = "S-1-5-32-545";
    const EVERYONE: &str = "S-1-1-0";
    const AUTHENTICATED_USERS: &str = "S-1-5-11";

    /// The access `sid` would get from the DACL of the file at `path`, as
    /// Windows computes it for that trustee and the groups in the ACL.
    fn effective_rights(path: &Path, sid: &str) -> u32 {
        let file = File::open(path).unwrap();
        let mut dacl: *mut ACL = ptr::null_mut();
        let mut raw_descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
        // SAFETY: the handle is open for the call; out-pointers are valid;
        // only the DACL is requested.
        let status = unsafe {
            GetSecurityInfo(
                file.as_raw_handle(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                ptr::null_mut(),
                ptr::null_mut(),
                &raw mut dacl,
                ptr::null_mut(),
                &raw mut raw_descriptor,
            )
        };
        assert_eq!(status, ERROR_SUCCESS);
        let _descriptor = Local(raw_descriptor);
        let wide_sid = wide(OsStr::new(sid)).unwrap();
        let mut raw_sid: PSID = ptr::null_mut();
        // SAFETY: `wide_sid` is NUL-terminated; `raw_sid` a valid out-pointer.
        let converted = unsafe { ConvertStringSidToSidW(wide_sid.as_ptr(), &raw mut raw_sid) };
        assert_ne!(converted, 0);
        let _sid = Local(raw_sid);
        let trustee = TRUSTEE_W {
            pMultipleTrustee: ptr::null_mut(),
            MultipleTrusteeOperation: NO_MULTIPLE_TRUSTEE,
            TrusteeForm: TRUSTEE_IS_SID,
            TrusteeType: TRUSTEE_IS_UNKNOWN,
            ptstrName: raw_sid.cast(),
        };
        let mut rights = 0u32;
        // SAFETY: `dacl` is valid inside `_descriptor`; `trustee` names the
        // SID owned by `_sid`; both live across the call.
        let status =
            unsafe { GetEffectiveRightsFromAclW(dacl, &raw const trustee, &raw mut rights) };
        assert_eq!(status, ERROR_SUCCESS);
        rights
    }

    #[test]
    fn a_new_file_admits_only_its_owner_and_system() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("recovery.key");
        let mut file = create_private_new(&path).unwrap();
        assert_eq!(file.metadata().unwrap().len(), 0);
        file.write_all(b"synthetic").unwrap();
        drop(file);
        let user = current_user_sid().unwrap();
        assert_eq!(effective_rights(&path, &user), FILE_ALL_ACCESS);
        assert_eq!(effective_rights(&path, SYSTEM_SID), FILE_ALL_ACCESS);
        for other in [USERS, EVERYONE, AUTHENTICATED_USERS] {
            assert_eq!(effective_rights(&path, other), 0, "{other} has access");
        }
    }

    #[test]
    fn a_folder_that_grants_users_read_grants_them_nothing_on_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let granted = Command::new("icacls")
            .arg(dir.path())
            .args(["/grant", &format!("*{USERS}:(OI)(CI)(RX)")])
            .output()
            .unwrap();
        assert!(granted.status.success(), "icacls failed: {granted:?}");
        // The fixture works: an ordinary file there is readable by Users.
        let ordinary = dir.path().join("ordinary");
        File::create(&ordinary).unwrap();
        assert_ne!(effective_rights(&ordinary, USERS), 0);

        let path = dir.path().join("recovery.key");
        drop(create_private_new(&path).unwrap());
        assert_eq!(effective_rights(&path, USERS), 0);
    }

    #[test]
    fn an_existing_file_is_left_as_it_was() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("recovery.key");
        std::fs::write(&path, "earlier").unwrap();
        let err = create_private_new(&path).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
        let mut kept = String::new();
        File::open(&path)
            .unwrap()
            .read_to_string(&mut kept)
            .unwrap();
        assert_eq!(kept, "earlier");
    }

    #[test]
    fn a_failed_check_removes_the_empty_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("recovery.key");
        let err = create_checked(&path, |_, _| {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "synthetic refusal",
            ))
        })
        .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);
        assert!(!path.exists());
    }

    fn good(user: &str) -> Observed {
        let ace = |sid: &str| Ace {
            allowed: true,
            inherited: false,
            mask: FILE_ALL_ACCESS,
            sid: sid.to_owned(),
        };
        Observed {
            owner: user.to_owned(),
            protected: true,
            has_dacl: true,
            aces: vec![ace(user), ace(SYSTEM_SID)],
        }
    }

    #[test]
    fn the_check_accepts_exactly_owner_and_system() {
        let user = "S-1-5-21-1-2-3-1001";
        check_permissions(&good(user), user, true).unwrap();

        let refuses = |observed: Observed, persistent: bool| {
            check_permissions(&observed, user, persistent).unwrap_err()
        };
        assert_eq!(
            refuses(good(user), false).kind(),
            io::ErrorKind::Unsupported
        );
        let mut other_owner = good(user);
        other_owner.owner = "S-1-5-32-544".to_owned();
        refuses(other_owner, true);
        let mut unprotected = good(user);
        unprotected.protected = false;
        refuses(unprotected, true);
        let mut no_dacl = good(user);
        no_dacl.has_dacl = false;
        no_dacl.aces.clear();
        refuses(no_dacl, true);
        let mut inherited = good(user);
        inherited.aces[0].inherited = true;
        refuses(inherited, true);
        let mut narrower = good(user);
        narrower.aces[1].mask = FILE_GENERIC_READ;
        refuses(narrower, true);
        let mut extra = good(user);
        extra.aces.push(Ace {
            allowed: true,
            inherited: false,
            mask: FILE_GENERIC_READ,
            sid: USERS.to_owned(),
        });
        refuses(extra, true);
        let mut no_system = good(user);
        no_system.aces.pop();
        refuses(no_system, true);
        let mut denied = good(user);
        denied.aces.push(Ace {
            allowed: false,
            inherited: false,
            mask: 0,
            sid: String::new(),
        });
        refuses(denied, true);
    }
}
