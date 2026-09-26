//! Network interface helpers. Port of `if_util.c` plus `bpf_filter_replace_nic`.

use crate::config::LOG_INFO;
use crate::error::{Error, Result};
use crate::log::log;
use crate::packet::IpAddr;
use nix::ifaddrs::getifaddrs;
use nix::sys::socket::SockaddrLike;

/// Resolve an interface's MAC address. Port of `get_if_mac_addr`.
///
/// # Errors
/// Returns an error if `ifname` is empty, `getifaddrs` fails, or no MAC
/// address is found for the interface.
pub fn get_if_mac_addr(ifname: &str) -> Result<[u8; 6]> {
    if ifname.is_empty() {
        return Err(Error::new("ifname is empty"));
    }
    for ifa in getifaddrs().map_err(|e| Error::new(format!("getifaddrs error: {e}")))? {
        if ifa.interface_name != ifname {
            continue;
        }
        if let Some(addr) = ifa.address.as_ref() {
            if let Some(link) = addr.as_link_addr() {
                if let Some(b) = link.addr() {
                    return Ok(b);
                }
            }
        }
    }
    Err(Error::new(format!(
        "Failed to find MAC address for interface '{ifname}'"
    )))
}

/// Resolve an interface's first IP address. Port of `get_if_ip_addr`.
///
/// # Errors
/// Returns an error if `getifaddrs` fails or the interface has no IP address.
pub fn get_if_ip_addr(ifname: &str) -> Result<IpAddr> {
    for ifa in getifaddrs().map_err(|e| Error::new(format!("getifaddrs error: {e}")))? {
        if ifa.interface_name != ifname {
            continue;
        }
        let Some(addr) = ifa.address.as_ref() else {
            continue;
        };
        if let Some(v4) = addr.as_sockaddr_in() {
            return Ok(IpAddr::V4(v4.ip().octets()));
        }
        if let Some(v6) = addr.as_sockaddr_in6() {
            return Ok(IpAddr::V6(v6.ip().octets()));
        }
    }
    Err(Error::new(format!("No IP address found for {ifname}")))
}

/// Replace every `nic.<ifname>` token in a BPF filter with the interface IP.
/// Port of `bpf_filter_replace_nic`.
///
/// # Errors
/// Returns an error if an interface referenced by the filter cannot be resolved.
pub fn bpf_filter_replace_nic(bpf: &str) -> Result<String> {
    let mut out = String::with_capacity(bpf.len() * 2);
    let bytes = bpf.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if !bytes[i..].starts_with(b"nic.") {
            out.push(bytes[i] as char);
            i += 1;
            continue;
        }
        let start = i + 4;
        let mut end = start;
        while end < bytes.len() && !(bytes[end] as char).is_whitespace() {
            end += 1;
        }
        let ifname = &bpf[start..end];
        let addr = get_if_ip_addr(ifname)
            .map_err(|_| Error::new(format!("no ip found for interface {ifname}")))?;
        let ip = addr.format();
        log(
            LOG_INFO,
            &format!("bpf_filter interface {ifname} addresss is {ip}"),
        );
        out.push_str(&ip);
        i = end;
    }
    Ok(out)
}
