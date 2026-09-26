//! Network interface helpers. Port of `if_util.c` plus `bpf_filter_replace_nic`.

use crate::config::LOG_INFO;
use crate::error::{Error, Result};
use crate::log::log;
use crate::packet::IpAddr;
use nix::ifaddrs::getifaddrs;

/// `nic.` token prefix introducing an interface reference in a BPF filter.
const NIC_TOKEN: &str = "nic.";

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
    replace_nic(bpf, get_if_ip_addr)
}

/// [`bpf_filter_replace_nic`] with an injectable resolver (unit-testable
/// without real network interfaces).
///
/// Text that is not part of a `nic.<ifname>` token is copied **byte for byte**.
/// The original port of the C loop re-encoded the filter one *byte* at a time
/// (`bytes[i] as char`), which turned every multi-byte UTF-8 sequence into
/// Latin-1 mojibake and produced a filter that no longer compiles
/// (AUDIT4 P5-21).
fn replace_nic(bpf: &str, resolve: impl Fn(&str) -> Result<IpAddr>) -> Result<String> {
    let mut out: Vec<u8> = Vec::with_capacity(bpf.len() + 16);
    let mut rest = bpf;
    while let Some(pos) = rest.find(NIC_TOKEN) {
        out.extend_from_slice(&rest.as_bytes()[..pos]);
        let name = &rest[pos + NIC_TOKEN.len()..];
        // `str::find` with a `char` predicate yields a char boundary, so
        // non-ASCII whitespace (U+3000 IDEOGRAPHIC SPACE, NBSP is not
        // whitespace and stays part of the name) ends the interface name
        // exactly where a UTF-8-aware scan would stop.
        let end = name.find(char::is_whitespace).unwrap_or(name.len());
        let ifname = &name[..end];
        let addr = resolve(ifname)
            .map_err(|_| Error::new(format!("no ip found for interface {ifname}")))?;
        let ip = addr.format();
        log(
            LOG_INFO,
            &format!("bpf_filter interface {ifname} addresss is {ip}"),
        );
        out.extend_from_slice(ip.as_bytes());
        rest = &name[end..];
    }
    out.extend_from_slice(rest.as_bytes());
    // Every piece pushed above is either a verbatim slice of the (valid UTF-8)
    // input or an ASCII address, so this cannot fail. It stays fallible rather
    // than panicking (AUDIT4 P5-23).
    String::from_utf8(out).map_err(|e| Error::new(format!("bpf filter is not UTF-8: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_ip(name: &str) -> Result<IpAddr> {
        match name {
            "eth0" => Ok(IpAddr::V4([192, 0, 2, 1])),
            "eth1" => Ok(IpAddr::V6([
                0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
            ])),
            _ => Err(Error::new(format!("no such interface {name}"))),
        }
    }

    #[test]
    fn replaces_every_nic_token() {
        let out = replace_nic("nic.eth0 or src host nic.eth1", fake_ip).expect("replace");
        assert_eq!(out, "192.0.2.1 or src host fe80::1");
    }

    #[test]
    fn unresolved_interface_is_an_error() {
        let e = replace_nic("nic.eth0 or nic.bogus", fake_ip)
            .unwrap_err()
            .to_string();
        assert!(e.contains("no ip found for interface bogus"), "{e}");
    }

    /// AUDIT4 P5-21: the per-byte `as char` re-encoding mangled every non-ASCII
    /// byte, so a filter containing e.g. a Chinese comment came back as Latin-1
    /// mojibake (and then failed to compile). Non-ASCII text must survive
    /// unchanged.
    #[test]
    fn non_ascii_text_survives_unchanged() {
        for expr in [
            "icmp and 网络",
            "port 80 or端口 443",
            "# фильтр: не трогать镜像流量",
            "emoji 🚀 filter",
            "not host 10.0.0.1 —\u{00a0} dropped",
        ] {
            assert_eq!(replace_nic(expr, fake_ip).expect("ok"), expr);
            // Same through the public entry point (no token to resolve, so the
            // test needs no real interface).
            assert_eq!(bpf_filter_replace_nic(expr).expect("ok"), expr);
        }
    }

    #[test]
    fn non_ascii_around_a_token_is_preserved() {
        let out = replace_nic("端口 网卡：nic.eth0 and 更多", fake_ip).expect("replace");
        assert_eq!(out, "端口 网卡：192.0.2.1 and 更多");
    }

    /// Non-ASCII whitespace must terminate the interface name. The old loop
    /// tested `(bytes[end] as char).is_whitespace()`, which saw 0xE4 as 'Ä'
    /// (not whitespace) and swallowed the following text into the name.
    #[test]
    fn unicode_whitespace_terminates_the_interface_name() {
        let out = replace_nic("nic.eth0\u{3000}and nic.eth0", fake_ip).expect("replace");
        assert_eq!(out, "192.0.2.1\u{3000}and 192.0.2.1");
    }
}
