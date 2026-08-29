//! Narrow, audited operating-system hardening for the Signer process.
//!
//! Unsafe FFI is isolated here so the Signer binary and custody engine retain
//! `#![forbid(unsafe_code)]`. Failure is returned to the caller: production
//! startup must fail closed rather than silently run dumpable.

use std::io;

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
