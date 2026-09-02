//! LAN-interface enumeration (for the explicit non-`0.0.0.0` bind) and the
//! RFC1918/ULA/link-local source-IP classifier (the defense-in-depth 403
//! gate on inbound requests).
//!
//! `benix-mdns-advertiser` gets this for free from `mdns-sd`'s own
//! auto-address-detection (`ServiceInfo::enable_addr_auto()`); this crate
//! has no `mdns-sd` dependency, so it enumerates directly with `if-addrs`,
//! the alternative that advertiser's own README names.

use std::net::IpAddr;

/// The box's own non-loopback LAN addresses, as candidates for an explicit
/// bind. Loopback and link-local-but-not-really-reachable oddities aside,
/// this deliberately does NOT filter down to "private" addresses only —
/// binding is about "this box's own interface," not about re-deriving the
/// RFC1918/ULA/link-local classification [`is_lan_source`] applies to
/// *inbound* requests. A box with a public IP on its LAN NIC (unusual, but
/// not this crate's business to second-guess) should still be bindable;
/// the actual WAN-reachability defense is bind-scoping itself (never
/// `0.0.0.0`) plus the source-IP check on every request.
pub fn non_loopback_addrs() -> std::io::Result<Vec<IpAddr>> {
    let interfaces = if_addrs::get_if_addrs()?;
    Ok(interfaces
        .into_iter()
        .map(|iface| iface.ip())
        .filter(|ip| !ip.is_loopback())
        .collect())
}

/// Defense-in-depth gate (security-engineer's explicit hardening
/// requirement, per the finalized contract): is `ip` RFC1918, IPv6 ULA, or
/// link-local (v4 or v6)? Bind-scoping should already make a non-LAN
/// source unreachable by construction — this is the second layer, checked
/// on every request regardless.
pub fn is_lan_source(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            // RFC1918: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16.
            (o[0] == 10)
                || (o[0] == 172 && (16..=31).contains(&o[1]))
                || (o[0] == 192 && o[1] == 168)
                // RFC3927 link-local: 169.254.0.0/16.
                || (o[0] == 169 && o[1] == 254)
        }
        IpAddr::V6(v6) => {
            let seg = v6.segments();
            // RFC4193 Unique Local Address: fc00::/7.
            (seg[0] & 0xfe00) == 0xfc00
                // RFC4291 link-local: fe80::/10.
                || (seg[0] & 0xffc0) == 0xfe80
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn accepts_rfc1918_ranges() {
        assert!(is_lan_source(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert!(is_lan_source(IpAddr::V4(Ipv4Addr::new(10, 255, 255, 255))));
        assert!(is_lan_source(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1))));
        assert!(is_lan_source(IpAddr::V4(Ipv4Addr::new(172, 31, 255, 255))));
        assert!(is_lan_source(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
    }

    #[test]
    fn rejects_addresses_just_outside_rfc1918_boundaries() {
        assert!(!is_lan_source(IpAddr::V4(Ipv4Addr::new(172, 15, 255, 255))));
        assert!(!is_lan_source(IpAddr::V4(Ipv4Addr::new(172, 32, 0, 0))));
        assert!(!is_lan_source(IpAddr::V4(Ipv4Addr::new(192, 167, 0, 0))));
        assert!(!is_lan_source(IpAddr::V4(Ipv4Addr::new(192, 169, 0, 0))));
    }

    #[test]
    fn accepts_v4_link_local() {
        assert!(is_lan_source(IpAddr::V4(Ipv4Addr::new(169, 254, 1, 1))));
    }

    #[test]
    fn rejects_public_v4() {
        assert!(!is_lan_source(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
        assert!(!is_lan_source(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))));
    }

    #[test]
    fn rejects_v4_loopback() {
        // Deliberately not on the allow-list — see is_lan_source's docs.
        assert!(!is_lan_source(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
    }

    #[test]
    fn accepts_v6_unique_local_and_link_local() {
        assert!(is_lan_source(IpAddr::V6(Ipv6Addr::new(
            0xfd00, 0, 0, 0, 0, 0, 0, 1
        ))));
        assert!(is_lan_source(IpAddr::V6(Ipv6Addr::new(
            0xfe80, 0, 0, 0, 0, 0, 0, 1
        ))));
    }

    #[test]
    fn rejects_public_v6() {
        assert!(!is_lan_source(IpAddr::V6(Ipv6Addr::new(
            0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888
        ))));
    }
}
