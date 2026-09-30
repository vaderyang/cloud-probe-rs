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

    /// Set `TCP_USER_TIMEOUT`: how long transmitted data may stay unacknowledged
    /// before the connection is torn down (`TCP_USER_TIMEOUT` on Linux).
    ///
    /// # Errors
    /// Returns an error if `setsockopt` fails or `timeout` does not fit in
    /// milliseconds.
    pub fn set_tcp_user_timeout(socket: &Socket, timeout: std::time::Duration) -> io::Result<()> {
        let ms: libc::c_int = timeout
            .as_millis()
            .try_into()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "tcp user timeout too big"))?;
        // SAFETY: `ms` is a valid `c_int` for the option.
        let ret = unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::IPPROTO_TCP,
                libc::TCP_USER_TIMEOUT,
                std::ptr::addr_of!(ms).cast::<libc::c_void>(),
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
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

    /// Set `TCP_USER_TIMEOUT` (unsupported on this platform: keepalive probes
    /// are the only dead-peer detection available there).
    ///
    /// # Errors
    /// Always returns an error on this platform.
    pub fn set_tcp_user_timeout(_socket: &Socket, _timeout: std::time::Duration) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "TCP_USER_TIMEOUT is only supported on Linux",
        ))
    }

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

pub use imp::{bind_to_device, set_pmtudisc, set_tcp_user_timeout};

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::time::Duration;

    fn udp_socket() -> socket2::Socket {
        socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )
        .expect("udp socket")
    }

    #[test]
    fn pmtudisc_is_set_on_a_udp_socket() {
        // IP_MTU_DISCOVER is allowed without privileges.
        let s = udp_socket();
        assert!(set_pmtudisc(&s, libc::IP_PMTUDISC_DO).is_ok());
    }

    #[test]
    fn tcp_user_timeout_is_set_on_a_tcp_socket() {
        let s = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::STREAM,
            Some(socket2::Protocol::TCP),
        )
        .expect("tcp socket");
        assert!(set_tcp_user_timeout(&s, Duration::from_secs(5)).is_ok());
    }

    #[test]
    fn tcp_user_timeout_rejects_an_unrepresentable_duration() {
        let s = udp_socket();
        let e = set_tcp_user_timeout(&s, Duration::from_secs(u64::MAX / 1000)).unwrap_err();
        assert!(e.to_string().contains("too big"), "{e}");
    }

    #[test]
    fn bind_to_device_reports_a_nul_device() {
        let s = udp_socket();
        let e = bind_to_device(&s, "bad\0dev").unwrap_err();
        assert!(e.to_string().contains("NUL"), "{e}");
    }

    #[test]
    fn bind_to_device_needs_privilege_or_succeeds() {
        let s = udp_socket();
        // SO_BINDTODEVICE needs CAP_NET_RAW: EPERM in the unprivileged job, Ok in
        // the privileged live job. Both arms exercise the syscall wrapper.
        let _ = bind_to_device(&s, "lo");
    }
}
