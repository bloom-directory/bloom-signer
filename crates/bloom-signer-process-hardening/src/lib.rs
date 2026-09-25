//! Narrow, audited operating-system hardening for the Signer process.
//!
//! Unsafe FFI is isolated here so the Signer binary and custody engine retain
//! `#![forbid(unsafe_code)]`. Failure is returned to the caller: production
//! startup must fail closed rather than silently run dumpable.

use std::io;
use std::os::fd::AsRawFd as _;
use zeroize::Zeroize as _;

/// A private page-aligned mapping kept resident while unlocked custody
/// material is live. Each value owns distinct pages, so dropping one cannot
/// unlock another live secret that shared an allocator page.
pub struct LockedSecret {
    address: std::ptr::NonNull<u8>,
    len: usize,
    mapping_len: usize,
}

// The mapping has unique ownership and exposes only immutable read access.
unsafe impl Send for LockedSecret {}
unsafe impl Sync for LockedSecret {}

impl LockedSecret {
    pub fn new(mut bytes: Vec<u8>) -> io::Result<Self> {
        if bytes.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "empty locked secret",
            ));
        }
        // SAFETY: sysconf reads the process page size without side effects.
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        if page_size <= 0 {
            bytes.zeroize();
            return Err(io::Error::last_os_error());
        }
        let page_size = page_size as usize;
        let mapping_len = match bytes
            .len()
            .checked_add(page_size - 1)
            .map(|size| size / page_size * page_size)
        {
            Some(size) => size,
            None => {
                bytes.zeroize();
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "locked secret too large",
                ));
            }
        };
        // SAFETY: private anonymous mmap allocates dedicated page-aligned
        // storage. No other LockedSecret can share these pages.
        let pointer = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                mapping_len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANON,
                -1,
                0,
            )
        };
        if pointer == libc::MAP_FAILED {
            let error = io::Error::last_os_error();
            bytes.zeroize();
            return Err(error);
        }
        // SAFETY: pointer names a valid mapping of mapping_len bytes.
        if unsafe { libc::mlock(pointer, mapping_len) } != 0 {
            let error = io::Error::last_os_error();
            unsafe { libc::munmap(pointer, mapping_len) };
            bytes.zeroize();
            return Err(error);
        }
        // SAFETY: the mapping is writable and at least bytes.len() long.
        unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), pointer.cast(), bytes.len()) };
        let len = bytes.len();
        bytes.zeroize();
        Ok(Self {
            address: std::ptr::NonNull::new(pointer.cast()).expect("mmap address"),
            len,
            mapping_len,
        })
    }

    pub fn as_slice(&self) -> &[u8] {
        // SAFETY: this value owns the mapping until Drop; read access is immutable.
        unsafe { std::slice::from_raw_parts(self.address.as_ptr(), self.len) }
    }
}

impl std::ops::Deref for LockedSecret {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

impl Drop for LockedSecret {
    fn drop(&mut self) {
        // SAFETY: this mapping is uniquely owned. Wipe before unlocking and
        // returning it to the kernel. Include the page-rounded tail.
        unsafe {
            std::slice::from_raw_parts_mut(self.address.as_ptr(), self.mapping_len).zeroize();
            libc::munlock(self.address.as_ptr().cast(), self.mapping_len);
            libc::munmap(self.address.as_ptr().cast(), self.mapping_len);
        }
    }
}

/// Change ownership only through the already-open descriptor, so a writable
/// destination directory cannot redirect a pathname-based chown.
pub fn set_open_file_owner(file: &std::fs::File, uid: u32, gid: u32) -> io::Result<()> {
    // SAFETY: `file` owns a valid descriptor for the duration of this call.
    if unsafe { libc::fchown(file.as_raw_fd(), uid, gid) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Return the kernel's effective user ID for privilege decisions.
///
/// This lives beside the crate's other audited libc calls so callers with
/// `forbid(unsafe_code)` do not need to approximate effective identity with an
/// environment variable or real-user lookup.
pub fn effective_uid() -> u32 {
    // SAFETY: `geteuid` has no arguments and no failure case.
    unsafe { libc::geteuid() }
}

/// Disable core dumps and same-user debugger/process-memory attachment.
pub fn harden_process() -> io::Result<()> {
    disable_core_dumps()?;
    disable_process_attachment()
}

fn disable_core_dumps() -> io::Result<()> {
    let limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `limit` is a valid `rlimit` value for the duration of the call.
    if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &limit) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn disable_process_attachment() -> io::Result<()> {
    // SAFETY: PR_SET_DUMPABLE accepts one integer argument; zero makes this
    // process non-dumpable and blocks same-uid process-memory attachment.
    if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn disable_process_attachment() -> io::Result<()> {
    // SAFETY: PT_DENY_ATTACH takes no address payload and refuses subsequent
    // debugger attachment to this process.
    if unsafe { libc::ptrace(libc::PT_DENY_ATTACH, 0, std::ptr::null_mut(), 0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn disable_process_attachment() -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "Signer process attachment hardening is unsupported on this platform",
    ))
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn hardening_is_observable_in_kernel_process_state() {
        harden_process().expect("process hardening must succeed");

        let mut limit = libc::rlimit {
            rlim_cur: libc::RLIM_INFINITY,
            rlim_max: libc::RLIM_INFINITY,
        };
        // SAFETY: `limit` is valid writable storage for `getrlimit`.
        assert_eq!(unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut limit) }, 0);
        assert_eq!(limit.rlim_cur, 0);
        assert_eq!(limit.rlim_max, 0);

        // SAFETY: PR_GET_DUMPABLE takes no additional arguments and returns
        // the current kernel dumpability state.
        assert_eq!(unsafe { libc::prctl(libc::PR_GET_DUMPABLE) }, 0);
    }
}

#[cfg(test)]
mod locked_secret_tests {
    use super::LockedSecret;

    #[test]
    fn dropping_one_secret_cannot_unlock_a_surviving_secret_page() {
        let first = LockedSecret::new(vec![0x11; 32]).unwrap();
        let second = LockedSecret::new(vec![0x22; 32]).unwrap();
        assert_ne!(
            first.address.as_ptr() as usize,
            second.address.as_ptr() as usize
        );
        assert_eq!(first.address.as_ptr() as usize % first.mapping_len, 0);
        assert_eq!(second.address.as_ptr() as usize % second.mapping_len, 0);
        drop(first);
        assert_eq!(second.as_slice(), &[0x22; 32]);
        // The second mapping remains owned and locked until its own Drop.
        assert_eq!(
            second.mapping_len,
            unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize
        );
    }
}
