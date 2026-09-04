//! Minimal descriptor FFI used outside the post-fork process module.
//!
//! Each wrapper owns or borrows only integer file descriptors. No raw pointer
//! supplied by an external caller is dereferenced.

#![allow(unsafe_code)]

use crate::SupervisorError;
use std::fs::File;
use std::io;
use std::os::fd::{FromRawFd, RawFd};

const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;
const CAPABILITY_WORDS: usize = 2;
const MAX_LINUX_CAPABILITY: libc::c_ulong = 63;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProcessPrivilegeState {
    pub real_uid: libc::uid_t,
    pub effective_uid: libc::uid_t,
    pub saved_uid: libc::uid_t,
    pub real_gid: libc::gid_t,
    pub effective_gid: libc::gid_t,
    pub saved_gid: libc::gid_t,
    pub effective_capabilities: u64,
    pub permitted_capabilities: u64,
    pub inheritable_capabilities: u64,
    pub ambient_capabilities: u64,
}

pub fn clear_inheritable_capabilities() -> Result<(), SupervisorError> {
    let mut header = CapabilityHeader {
        version: LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let mut data = [CapabilityData {
        effective: 0,
        permitted: 0,
        inheritable: 0,
    }; CAPABILITY_WORDS];
    // SAFETY: capget receives the version-3 header and the required two-word
    // storage. The pointers remain valid for the duration of the syscall.
    if unsafe { libc::syscall(libc::SYS_capget, &raw mut header, data.as_mut_ptr()) } != 0 {
        return Err(SupervisorError::new(
            "privilege_boundary_unavailable",
            format!(
                "runtime supervisor capabilities cannot be inspected: {}",
                io::Error::last_os_error()
            ),
        ));
    }
    for word in &mut data {
        word.inheritable = 0;
    }
    // SAFETY: capset reads the same fixed version-3 structures. This operation
    // only drops inheritable capability bits and preserves effective/permitted
    // words already verified by the caller.
    if unsafe { libc::syscall(libc::SYS_capset, &raw const header, data.as_ptr()) } != 0 {
        return Err(SupervisorError::new(
            "privilege_boundary_unavailable",
            format!(
                "runtime supervisor inheritable capabilities cannot be dropped: {}",
                io::Error::last_os_error()
            ),
        ));
    }
    Ok(())
}

#[repr(C)]
struct CapabilityHeader {
    version: u32,
    pid: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct CapabilityData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

pub fn duplicate_cloexec(descriptor: RawFd) -> Result<RawFd, SupervisorError> {
    // SAFETY: `fcntl` does not dereference pointers for `F_DUPFD_CLOEXEC`.
    let duplicate = unsafe { libc::fcntl(descriptor, libc::F_DUPFD_CLOEXEC, 3) };
    if duplicate < 0 {
        return Err(SupervisorError::new(
            "descriptor_unavailable",
            io::Error::last_os_error().to_string(),
        ));
    }
    Ok(duplicate)
}

pub fn set_cloexec(descriptor: RawFd) -> Result<(), SupervisorError> {
    // SAFETY: descriptor-only `fcntl` calls do not dereference pointers.
    let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFD) };
    if flags < 0
        // SAFETY: same descriptor-only `fcntl` contract as above.
        || unsafe { libc::fcntl(descriptor, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0
    {
        return Err(SupervisorError::new(
            "descriptor_unavailable",
            io::Error::last_os_error().to_string(),
        ));
    }
    Ok(())
}

pub fn set_nonblocking(descriptor: RawFd) -> Result<(), SupervisorError> {
    // SAFETY: descriptor-only fcntl calls do not dereference pointers.
    let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFL) };
    if flags < 0
        // SAFETY: same descriptor-only fcntl contract as above.
        || unsafe { libc::fcntl(descriptor, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
    {
        return Err(SupervisorError::new(
            "descriptor_unavailable",
            io::Error::last_os_error().to_string(),
        ));
    }
    Ok(())
}

pub fn file_status_flags(descriptor: RawFd) -> Result<i32, SupervisorError> {
    // SAFETY: descriptor-only fcntl does not dereference pointers.
    let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFL) };
    if flags < 0 {
        Err(SupervisorError::new(
            "descriptor_unavailable",
            io::Error::last_os_error().to_string(),
        ))
    } else {
        Ok(flags)
    }
}

pub fn read_nonblocking(descriptor: RawFd, output: &mut [u8]) -> io::Result<usize> {
    // SAFETY: the mutable output slice is valid for the read duration.
    let count = unsafe { libc::read(descriptor, output.as_mut_ptr().cast(), output.len()) };
    if count < 0 {
        Err(io::Error::last_os_error())
    } else {
        usize::try_from(count).map_err(|_| io::Error::other("read length cannot be represented"))
    }
}

pub fn poll_readable(descriptors: &[RawFd], timeout_milliseconds: i32) -> io::Result<()> {
    let mut items: Vec<libc::pollfd> = descriptors
        .iter()
        .map(|descriptor| libc::pollfd {
            fd: *descriptor,
            events: libc::POLLIN,
            revents: 0,
        })
        .collect();
    // SAFETY: the pollfd vector remains valid for the complete call.
    let result = unsafe {
        libc::poll(
            items.as_mut_ptr(),
            items.len() as libc::nfds_t,
            timeout_milliseconds,
        )
    };
    if result < 0 && io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

pub fn truncate_file(descriptor: RawFd, size: u64) -> io::Result<()> {
    let size = libc::off_t::try_from(size)
        .map_err(|_| io::Error::other("file size cannot be represented"))?;
    // SAFETY: ftruncate takes only an open descriptor and integer length.
    if unsafe { libc::ftruncate(descriptor, size) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

pub fn owned_file(descriptor: RawFd) -> File {
    // SAFETY: callers pass a newly duplicated descriptor and transfer its sole
    // ownership to the returned `File`.
    unsafe { File::from_raw_fd(descriptor) }
}

pub fn close_fd(descriptor: RawFd) {
    // SAFETY: closing a best-effort integer descriptor has no memory-safety precondition.
    unsafe {
        libc::close(descriptor);
    }
}

pub fn parent_pid() -> u32 {
    // SAFETY: `getppid` has no arguments or memory-safety preconditions.
    unsafe { libc::getppid().try_into().unwrap_or(0) }
}

pub fn process_privilege_state() -> Result<ProcessPrivilegeState, SupervisorError> {
    #[derive(Default)]
    struct UserIdentity {
        real: libc::uid_t,
        effective: libc::uid_t,
        saved: libc::uid_t,
    }
    #[derive(Default)]
    struct GroupIdentity {
        real: libc::gid_t,
        effective: libc::gid_t,
        saved: libc::gid_t,
    }
    let mut user = UserIdentity::default();
    let mut group = GroupIdentity::default();
    // SAFETY: all six pointers refer to initialized local scalar storage and
    // remain valid for the complete getresuid/getresgid calls.
    if unsafe {
        libc::getresuid(
            &raw mut user.real,
            &raw mut user.effective,
            &raw mut user.saved,
        )
    } != 0
        // SAFETY: same pointer-lifetime contract as the getresuid call above.
        || unsafe {
            libc::getresgid(
                &raw mut group.real,
                &raw mut group.effective,
                &raw mut group.saved,
            )
        } != 0
    {
        return Err(SupervisorError::new(
            "privilege_boundary_unavailable",
            format!(
                "runtime supervisor credentials cannot be inspected: {}",
                io::Error::last_os_error()
            ),
        ));
    }

    let mut header = CapabilityHeader {
        version: LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let mut data = [CapabilityData {
        effective: 0,
        permitted: 0,
        inheritable: 0,
    }; CAPABILITY_WORDS];
    // SAFETY: capget receives a valid version-3 header and storage for the two
    // capability words required by that ABI. The kernel writes only those
    // fixed-size structures.
    if unsafe { libc::syscall(libc::SYS_capget, &raw mut header, data.as_mut_ptr()) } != 0 {
        return Err(SupervisorError::new(
            "privilege_boundary_unavailable",
            format!(
                "runtime supervisor capabilities cannot be inspected: {}",
                io::Error::last_os_error()
            ),
        ));
    }

    let mut ambient_capabilities = 0_u64;
    for capability in 0..=MAX_LINUX_CAPABILITY {
        // SAFETY: PR_CAP_AMBIENT_IS_SET reads process state only; the remaining
        // arguments are the fixed capability number and required zero values.
        let result = unsafe {
            libc::prctl(
                libc::PR_CAP_AMBIENT,
                libc::PR_CAP_AMBIENT_IS_SET,
                capability,
                0,
                0,
            )
        };
        if result == 1 {
            ambient_capabilities |= 1_u64 << capability;
        } else if result < 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EINVAL) {
                break;
            }
            return Err(SupervisorError::new(
                "privilege_boundary_unavailable",
                format!("runtime supervisor ambient capabilities cannot be inspected: {error}"),
            ));
        }
    }

    Ok(ProcessPrivilegeState {
        real_uid: user.real,
        effective_uid: user.effective,
        saved_uid: user.saved,
        real_gid: group.real,
        effective_gid: group.effective,
        saved_gid: group.saved,
        effective_capabilities: capability_words(&data, |word| word.effective),
        permitted_capabilities: capability_words(&data, |word| word.permitted),
        inheritable_capabilities: capability_words(&data, |word| word.inheritable),
        ambient_capabilities,
    })
}

fn capability_words(
    data: &[CapabilityData; CAPABILITY_WORDS],
    select: impl Fn(&CapabilityData) -> u32,
) -> u64 {
    u64::from(select(&data[0])) | (u64::from(select(&data[1])) << 32)
}

pub fn has_file_capabilities(descriptor: RawFd) -> Result<bool, SupervisorError> {
    let name = c"security.capability";
    // SAFETY: `fgetxattr` receives an open descriptor, a fixed NUL-terminated
    // attribute name, and a null/zero probe buffer, so it cannot write memory.
    let result = unsafe { libc::fgetxattr(descriptor, name.as_ptr(), std::ptr::null_mut(), 0) };
    interpret_file_capability_probe(result, &io::Error::last_os_error())
}

fn interpret_file_capability_probe(
    result: libc::ssize_t,
    error: &io::Error,
) -> Result<bool, SupervisorError> {
    if result >= 0 {
        Ok(true)
    } else if matches!(
        error.raw_os_error(),
        Some(code) if code == libc::ENODATA || code == libc::ENOTSUP
    ) {
        Ok(false)
    } else {
        Err(SupervisorError::new(
            "identity_unavailable",
            format!("file capabilities cannot be inspected: {error}"),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::{interpret_file_capability_probe, process_privilege_state};
    use std::io;

    #[test]
    fn file_capability_probe_rejects_present_or_uninspectable_attributes() {
        assert!(
            interpret_file_capability_probe(20, &io::Error::from_raw_os_error(0))
                .expect("present capability attribute")
        );
        assert!(
            !interpret_file_capability_probe(-1, &io::Error::from_raw_os_error(libc::ENODATA))
                .expect("absent capability attribute")
        );
        let error = interpret_file_capability_probe(-1, &io::Error::from_raw_os_error(libc::EPERM))
            .expect_err("uninspectable capability attribute");
        assert_eq!(error.code, "identity_unavailable");
    }

    #[test]
    fn process_privilege_syscalls_report_the_current_unprivileged_test_process() {
        let state = process_privilege_state().expect("process privilege state");
        assert_ne!(state.effective_uid, 0);
        assert_eq!(state.real_uid, state.effective_uid);
        assert_eq!(state.saved_uid, state.effective_uid);
        assert_eq!(state.real_gid, state.effective_gid);
        assert_eq!(state.saved_gid, state.effective_gid);
        assert_eq!(state.effective_capabilities, 0);
        assert_eq!(state.permitted_capabilities, 0);
        // The package test runner may intentionally inherit CAP_PERFMON from
        // an administrator-selected Collector deployment.  This probe must
        // report that state faithfully; `supervise` drops inheritable-only
        // bits before applying its strict execution boundary.
        assert_eq!(state.ambient_capabilities, 0);
    }
}
