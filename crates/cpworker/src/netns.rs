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

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn open_self_netns_returns_a_fd() {
        // `/proc/self/ns/net` is readable by an unprivileged process.
        let fd = open_self_netns().expect("open self netns");
        drop(fd);
    }

    #[test]
    fn entering_the_current_namespace_is_a_noop_or_a_permission_error() {
        // `setns(CLONE_NEWNET)` needs CAP_SYS_ADMIN: the unprivileged test job
        // gets EPERM, the privileged live job succeeds (into the *same*
        // namespace, so it is still a no-op). Both arms exercise the call.
        match enter_netns_by_path("/proc/self/ns/net") {
            Ok(fd) => drop(fd),
            Err(e) => assert!(e.to_string().contains("setns error"), "{e}"),
        }
        let self_fd = open_self_netns().expect("open self netns");
        let _ = enter_netns_by_fd(&self_fd);
    }

    #[test]
    fn a_bad_path_is_reported() {
        let e = enter_netns_by_path("/nonexistent/netns/path").unwrap_err();
        assert!(e.to_string().contains("open netns"), "{e}");
    }

    #[test]
    fn a_bare_name_falls_back_to_the_run_dir() {
        let e = enter_netns_by_path("cp-no-such-netns").unwrap_err();
        assert!(e.to_string().contains("open netns"), "{e}");
    }

    #[test]
    fn a_nul_path_is_rejected() {
        let e = enter_netns_by_path("bad\0path").unwrap_err();
        assert!(e.to_string().contains("invalid netns path"), "{e}");
    }

    #[test]
    fn a_non_netns_fd_is_a_setns_error() {
        // A regular file fd is not a namespace handle, so `setns(CLONE_NEWNET)`
        // fails with EINVAL even for an unprivileged process (no root needed).
        use std::os::fd::OwnedFd;
        let fd: OwnedFd = std::fs::File::open("/dev/null")
            .expect("open /dev/null")
            .into();
        let e = enter_netns_by_fd(&fd).unwrap_err();
        assert!(e.to_string().contains("setns error"), "{e}");
    }
}
