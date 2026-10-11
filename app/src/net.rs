// Classifies the visitor's address so services that are only reachable over a
// private network (for example a Tailscale tailnet) can be shown as such.

use std::net::IpAddr;

/// Default private ranges: Tailscale's IPv4 CGNAT block and its IPv6 ULA prefix.
pub const DEFAULT_TAILNET_CIDRS: [&str; 2] = ["100.64.0.0/10", "fd7a:115c:a1e0::/48"];

/// Parses `address/prefix` into a network address and prefix length.
pub fn parse_cidr(cidr: &str) -> Option<(IpAddr, u8)> {
    let (address, prefix) = cidr.trim().split_once('/')?;
    let address: IpAddr = address.parse().ok()?;
    let prefix: u8 = prefix.parse().ok()?;
    let max = if address.is_ipv4() { 32 } else { 128 };
    (prefix <= max).then_some((address, prefix))
}

fn contains(network: IpAddr, prefix: u8, ip: IpAddr) -> bool {
    match (network, ip.to_canonical()) {
        (IpAddr::V4(network), IpAddr::V4(ip)) => {
            let mask = u32::MAX.checked_shl(32 - u32::from(prefix)).unwrap_or(0);
            u32::from(network) & mask == u32::from(ip) & mask
        }
        (IpAddr::V6(network), IpAddr::V6(ip)) => {
            let mask = u128::MAX.checked_shl(128 - u32::from(prefix)).unwrap_or(0);
            u128::from(network) & mask == u128::from(ip) & mask
        }
        _ => false,
    }
}

/// True when `ip` falls inside any of the given CIDR ranges. Invalid entries
/// never match (they are rejected when the config is loaded).
pub fn ip_in_any(ip: IpAddr, cidrs: &[String]) -> bool {
    cidrs
        .iter()
        .filter_map(|cidr| parse_cidr(cidr))
        .any(|(network, prefix)| contains(network, prefix, ip))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn defaults() -> Vec<String> {
        DEFAULT_TAILNET_CIDRS.iter().map(|cidr| (*cidr).to_owned()).collect()
    }

    fn on_tailnet(ip: &str) -> bool {
        ip_in_any(ip.parse().unwrap(), &defaults())
    }

    #[test]
    fn tailscale_ipv4_range_matches_its_boundaries_only() {
        assert!(on_tailnet("100.64.0.0"));
        assert!(on_tailnet("100.80.163.74"));
        assert!(on_tailnet("100.127.255.255"));
        assert!(!on_tailnet("100.63.255.255"));
        assert!(!on_tailnet("100.128.0.0"));
    }

    #[test]
    fn docker_and_public_addresses_are_not_tailnet() {
        assert!(!on_tailnet("172.26.0.1"));
        assert!(!on_tailnet("192.168.1.10"));
        assert!(!on_tailnet("8.8.8.8"));
        assert!(!on_tailnet("2001:4860:4860::8888"));
    }

    #[test]
    fn ipv4_mapped_ipv6_and_tailscale_ipv6_match() {
        assert!(on_tailnet("::ffff:100.80.163.74"));
        assert!(on_tailnet("fd7a:115c:a1e0:ab12:4843:cd96:6258:b240"));
        assert!(!on_tailnet("fd7a:115c:a1e1::1"));
    }

    #[test]
    fn cidr_parsing_rejects_bad_input_and_handles_edge_prefixes() {
        assert!(parse_cidr("100.64.0.0/33").is_none());
        assert!(parse_cidr("100.64.0.0").is_none());
        assert!(parse_cidr("not-an-ip/8").is_none());
        assert!(parse_cidr("fd00::/129").is_none());
        assert_eq!(parse_cidr(" 10.0.0.0/8 ").map(|(_, prefix)| prefix), Some(8));
        assert!(ip_in_any("8.8.8.8".parse().unwrap(), &["0.0.0.0/0".to_owned()]));
        assert!(ip_in_any("10.1.2.3".parse().unwrap(), &["10.1.2.3/32".to_owned()]));
        assert!(!ip_in_any("10.1.2.4".parse().unwrap(), &["10.1.2.3/32".to_owned()]));
    }
}
