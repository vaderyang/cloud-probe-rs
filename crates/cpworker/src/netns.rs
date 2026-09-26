//! Network namespace switching. Port of `netns_linux.c` / `netns_noop.c`.

use crate::error::{Error, Result};

#[cfg(target_os = "linux")]
mod imp {
    use super::*;
    use std::ffi::CString;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

    const NETNS_RUN_DIR: &str = "/var/run/netns";

    fn errno() -> i32 {
        std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
    }

    /// Open a file descriptor for the current thread's network namespace.
    ///
    /// # Errors
    /// Returns an error if `/proc/self/ns/net` cannot be opened.
    pub fn open_self_netns() -> Result<OwnedFd> {
        let fd = unsafe { libc::open(c"/proc/self/ns/net".as_ptr(), libc::O_RDONLY) };
        if fd < 0 {
            return Err(Error::new(format!("open self netns error: {}", errno())));
        }
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }

    /// Accepts either a path (`/proc/<pid>/ns/net`, `/var/run/netns/<name>`) or a bare name.
    ///
    /// # Errors
    /// Returns an error if the path contains a NUL byte, cannot be opened, or if
    /// entering the namespace fails.
    pub fn enter_netns_by_path(ns_path: &str) -> Result<OwnedFd> {
        let cpath = CString::new(ns_path).map_err(|_| Error::new("invalid netns path"))?;
        let fd = unsafe { libc::open(cpath.as_ptr(), libc::O_RDONLY) };
        if fd < 0 {
            // Try the conventional netns run dir for a bare name.
            if !ns_path.contains('/') {
                let alt = format!("{NETNS_RUN_DIR}/{ns_path}");
                let calt = CString::new(alt).map_err(|_| Error::new("invalid netns path"))?;
                let fd = unsafe { libc::open(calt.as_ptr(), libc::O_RDONLY) };
                if fd < 0 {
                    return Err(Error::new(format!(
                        "open netns {ns_path} error: {}",
                        errno()
                    )));
                }
                return setns_fd(fd);
            }
            return Err(Error::new(format!(
                "open netns {ns_path} error: {}",
                errno()
            )));
        }
        setns_fd(fd)
    }

    fn setns_fd(fd: RawFd) -> Result<OwnedFd> {
        if unsafe { libc::setns(fd, libc::CLONE_NEWNET) } != 0 {
            let e = errno();
            unsafe { libc::close(fd) };
            return Err(Error::new(format!("setns error: {e}")));
        }
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }

    /// Enter the network namespace referenced by an already-open fd.
    ///
    /// # Errors
    /// Returns an error if the `setns` syscall fails.
    pub fn enter_netns_by_fd(fd: &OwnedFd) -> Result<()> {
        if unsafe { libc::setns(fd.as_raw_fd(), libc::CLONE_NEWNET) } != 0 {
            return Err(Error::new(format!("setns error: {}", errno())));
        }
        Ok(())
    }
}

#[cfg(not(target_os = "linux"))]
mod imp {
    use super::*;
    use std::os::fd::OwnedFd;

    /// Open a file descriptor for the current thread's network namespace.
    ///
    /// # Errors
    /// Always returns an error on non-Linux platforms.
    pub fn open_self_netns() -> Result<OwnedFd> {
        Err(Error::new("netns not supported on this platform"))
    }
    /// Enter a network namespace by path.
    ///
    /// # Errors
    /// Always returns an error on non-Linux platforms.
    pub fn enter_netns_by_path(_ns_path: &str) -> Result<OwnedFd> {
        Err(Error::new("netns not supported on this platform"))
    }
    /// Enter a network namespace by fd.
    ///
    /// # Errors
    /// Always returns an error on non-Linux platforms.
    pub fn enter_netns_by_fd(_fd: &OwnedFd) -> Result<()> {
        Err(Error::new("netns not supported on this platform"))
    }
}

pub use imp::{enter_netns_by_fd, enter_netns_by_path, open_self_netns};
