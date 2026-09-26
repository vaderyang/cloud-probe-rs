//! Platform-specific socket-option helpers.
//!
//! Shared output code calls these instead of poking OS constants directly, so a
//! future Windows backend can translate them (e.g. `SO_BINDTODEVICE` →
//! `IP_UNICAST_IF`, `IP_MTU_DISCOVER` → `IP_DONTFRAGMENT`) without touching the
//! callers.

#[cfg(target_os = "linux")]
mod imp {
    use std::io;
    use std::os::fd::AsRawFd;

    use socket2::Socket;

    /// Bind a socket to a network device (`SO_BINDTODEVICE` on Linux).
    ///
    /// # Errors
    /// Returns an error if `device` contains a NUL byte or `setsockopt` fails.
    pub fn bind_to_device(socket: &Socket, device: &str) -> io::Result<()> {
        let cdev = std::ffi::CString::new(device).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "bind_device contains a NUL byte",
            )
        })?;
        // SAFETY: `cdev` is a valid NUL-terminated string; the kernel copies it.
        let ret = unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_BINDTODEVICE,
                cdev.as_ptr().cast::<libc::c_void>(),
                (device.len() + 1) as libc::socklen_t,
            )
        };
        if ret != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Set the IPv4 path-MTU-discovery mode (`IP_MTU_DISCOVER` on Linux).
    ///
    /// # Errors
    /// Returns an error if `setsockopt` fails.
    pub fn set_pmtudisc(socket: &Socket, mode: i32) -> io::Result<()> {
        // SAFETY: `mode` is a valid `i32` for the option.
        let ret = unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::IPPROTO_IP,
                libc::IP_MTU_DISCOVER,
                std::ptr::addr_of!(mode).cast::<libc::c_void>(),
                std::mem::size_of::<i32>() as libc::socklen_t,
            )
        };
        if ret != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

#[cfg(not(target_os = "linux"))]
mod imp {
    use std::io;

    use socket2::Socket;

    /// Bind a socket to a network device (unsupported on this platform).
    ///
    /// # Errors
    /// Always returns `Unsupported`.
    pub fn bind_to_device(_socket: &Socket, _device: &str) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "binding a socket to a device is not implemented on this platform",
        ))
    }

    /// Set the IPv4 path-MTU-discovery mode (unsupported on this platform).
    ///
    /// # Errors
    /// Always returns `Unsupported`.
    pub fn set_pmtudisc(_socket: &Socket, _mode: i32) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "IP_MTU_DISCOVER is not implemented on this platform",
        ))
    }
}

pub use imp::{bind_to_device, set_pmtudisc};
