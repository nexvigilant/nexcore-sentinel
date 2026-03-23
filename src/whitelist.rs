//! Whitelist — CIDR-based IP allow-list.
//!
//! ## Primitive Foundation
//!
//! | Primitive | Manifestation |
//! |-----------|---------------|
//! | T1: Exists (∃) | IP-in-whitelist membership check |
//! | T1: Mapping (μ) | CIDR network → match predicate |

use std::net::IpAddr;

use ipnetwork::IpNetwork;

use crate::error::{Result, SentinelError};

/// Tier: T2-C — A set of CIDR networks that should never be banned.
#[derive(Debug, Clone)]
pub struct Whitelist {
    networks: Vec<IpNetwork>,
}

impl Whitelist {
    /// Parse a list of CIDR strings into a `Whitelist`.
    ///
    /// # Errors
    /// Returns `SentinelError::Network` if any CIDR string is malformed.
    pub fn new(cidrs: &[String]) -> Result<Self> {
        let mut networks = Vec::with_capacity(cidrs.len());
        for cidr in cidrs {
            let net: IpNetwork = cidr
                .parse()
                .map_err(|e| SentinelError::Network(format!("invalid CIDR '{cidr}': {e}")))?;
            networks.push(net);
        }
        Ok(Self { networks })
    }

    /// Check if an IP address is in the whitelist.
    #[must_use]
    pub fn contains(&self, ip: IpAddr) -> bool {
        self.networks.iter().any(|net| net.contains(ip))
    }

    /// Return the number of CIDR networks in the whitelist.
    #[must_use]
    pub fn len(&self) -> usize {
        self.networks.len()
    }

    /// Check if the whitelist is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.networks.is_empty()
    }
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn default_whitelist() -> Whitelist {
        Whitelist::new(&["127.0.0.1/8".to_string(), "::1/128".to_string()])
            .unwrap_or_else(|_| Whitelist { networks: vec![] })
    }

    #[test]
    fn localhost_ipv4_is_whitelisted() {
        let wl = default_whitelist();
        let ip: IpAddr = "127.0.0.1"
            .parse()
            .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
        assert!(wl.contains(ip));
    }

    #[test]
    fn localhost_ipv6_is_whitelisted() {
        let wl = default_whitelist();
        let ip: IpAddr = "::1"
            .parse()
            .unwrap_or(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST));
        assert!(wl.contains(ip));
    }

    #[test]
    fn loopback_range_is_whitelisted() {
        let wl = default_whitelist();
        let ip: IpAddr = "127.0.0.254"
            .parse()
            .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
        assert!(wl.contains(ip));
    }

    #[test]
    fn external_ip_not_whitelisted() {
        let wl = default_whitelist();
        let ip: IpAddr = "8.8.8.8"
            .parse()
            .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
        assert!(!wl.contains(ip));
    }

    #[test]
    fn private_range_whitelisted() {
        let wl = Whitelist::new(&["10.0.0.0/8".to_string()])
            .unwrap_or_else(|_| Whitelist { networks: vec![] });
        let ip: IpAddr = "10.255.0.1"
            .parse()
            .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
        assert!(wl.contains(ip));
    }

    #[test]
    fn invalid_cidr_returns_error() {
        let result = Whitelist::new(&["not-a-cidr".to_string()]);
        assert!(result.is_err());
    }

    #[test]
    fn empty_whitelist() {
        let wl = Whitelist::new(&[]).unwrap_or_else(|_| Whitelist { networks: vec![] });
        assert!(wl.is_empty());
        let ip: IpAddr = "127.0.0.1"
            .parse()
            .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
        assert!(!wl.contains(ip));
    }
}
