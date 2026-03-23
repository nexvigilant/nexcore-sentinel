//! Firewall backend — iptables ban/unban via trait abstraction.
//!
//! ## Primitive Foundation
//!
//! | Primitive | Manifestation |
//! |-----------|---------------|
//! | T1: State (ς) | Ban/unban mutation of firewall rules |
//! | T1: Exists (∃) | Chain existence check |

use std::net::IpAddr;
use std::process::Command;

use crate::error::{Result, SentinelError};

/// Tier: T2-C — Abstraction over firewall operations for testability.
pub trait FirewallBackend: Send + Sync {
    /// Initialize the iptables chain and insert into INPUT.
    fn init(&self, chain: &str, port: u16) -> Result<()>;

    /// Ban an IP by inserting a REJECT/DROP rule.
    fn ban(&self, chain: &str, ip: IpAddr, action: &str) -> Result<()>;

    /// Unban an IP by deleting its rule.
    fn unban(&self, chain: &str, ip: IpAddr, action: &str) -> Result<()>;

    /// Clean up: remove from INPUT, flush chain, delete chain.
    fn cleanup(&self, chain: &str, port: u16) -> Result<()>;

    /// List currently banned IPs in the chain.
    fn list_banned(&self, chain: &str) -> Result<Vec<IpAddr>>;
}

// ── iptables helpers (flat, no nesting) ────────────────────────────

/// Run an iptables command and return stdout.
fn run_iptables(args: &[&str]) -> Result<String> {
    let output =
        Command::new("iptables")
            .args(args)
            .output()
            .map_err(|e| SentinelError::Firewall {
                command: format!("iptables {}", args.join(" ")),
                message: e.to_string(),
            })?;

    if output.status.success() {
        return Ok(String::from_utf8_lossy(&output.stdout).to_string());
    }

    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    Err(SentinelError::Firewall {
        command: format!("iptables {}", args.join(" ")),
        message: stderr,
    })
}

/// Check if an iptables chain exists.
fn chain_exists(chain: &str) -> bool {
    Command::new("iptables")
        .args(["-n", "-L", chain])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Check if the INPUT chain already references our chain.
fn input_has_chain(chain: &str, port: u16) -> bool {
    let port_str = port.to_string();
    Command::new("iptables")
        .args([
            "-C",
            "INPUT",
            "-p",
            "tcp",
            "-m",
            "multiport",
            "--dports",
            &port_str,
            "-j",
            chain,
        ])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Parse a string that may be an IP address or CIDR notation (e.g., "10.0.0.1/32" or "0.0.0.0/0").
///
/// **Lesson (CIDR boundary)**: iptables output uses CIDR notation in source/destination
/// fields. `IpAddr::parse()` rejects CIDR suffixes like `/0` or `/32`, so we strip
/// the prefix length before parsing. Wildcard CIDRs (`0.0.0.0/0`, `::/0`) are filtered
/// as they represent "any" rather than a specific banned host.
pub fn parse_ip_or_cidr(s: &str) -> Option<IpAddr> {
    let ip_part = s.split('/').next().unwrap_or(s);
    let ip: IpAddr = ip_part.parse().ok()?;
    match ip {
        IpAddr::V4(v4) if v4.is_unspecified() => None,
        IpAddr::V6(v6) if v6.is_unspecified() => None,
        _ => Some(ip),
    }
}

/// Parse IPs from iptables chain listing output.
fn parse_iptables_listing(output: &str) -> Vec<IpAddr> {
    output
        .lines()
        .skip(2) // skip header lines
        .filter_map(|line| {
            let parts: Vec<&str> = line.split_whitespace().collect();
            // Format: "REJECT  all  --  <ip>  0.0.0.0/0  ..."
            if parts.len() >= 4 {
                parse_ip_or_cidr(parts[3])
            } else {
                None
            }
        })
        .collect()
}

/// Tier: T3 — Real iptables firewall backend.
#[derive(Debug, Clone)]
pub struct IptablesFirewall;

impl FirewallBackend for IptablesFirewall {
    fn init(&self, chain: &str, port: u16) -> Result<()> {
        if !chain_exists(chain) {
            run_iptables(&["-N", chain])?;
            run_iptables(&["-A", chain, "-j", "RETURN"])?;
            tracing::info!("Created iptables chain: {chain}");
        }

        if !input_has_chain(chain, port) {
            let port_str = port.to_string();
            run_iptables(&[
                "-I",
                "INPUT",
                "1",
                "-p",
                "tcp",
                "-m",
                "multiport",
                "--dports",
                &port_str,
                "-j",
                chain,
            ])?;
            tracing::info!("Inserted {chain} into INPUT chain for port {port}");
        }

        Ok(())
    }

    fn ban(&self, chain: &str, ip: IpAddr, action: &str) -> Result<()> {
        let ip_str = ip.to_string();
        run_iptables(&["-I", chain, "1", "-s", &ip_str, "-j", action])?;
        tracing::warn!("Banned {ip} via iptables ({action})");
        Ok(())
    }

    fn unban(&self, chain: &str, ip: IpAddr, action: &str) -> Result<()> {
        let ip_str = ip.to_string();
        run_iptables(&["-D", chain, "-s", &ip_str, "-j", action])?;
        tracing::info!("Unbanned {ip} via iptables");
        Ok(())
    }

    fn cleanup(&self, chain: &str, port: u16) -> Result<()> {
        let port_str = port.to_string();
        let _ = run_iptables(&[
            "-D",
            "INPUT",
            "-p",
            "tcp",
            "-m",
            "multiport",
            "--dports",
            &port_str,
            "-j",
            chain,
        ]);
        let _ = run_iptables(&["-F", chain]);
        let _ = run_iptables(&["-X", chain]);
        tracing::info!("Cleaned up iptables chain: {chain}");
        Ok(())
    }

    fn list_banned(&self, chain: &str) -> Result<Vec<IpAddr>> {
        let output = run_iptables(&["-n", "-L", chain])?;
        Ok(parse_iptables_listing(&output))
    }
}

// ── Mock firewall ──────────────────────────────────────────────────

/// A recorded firewall operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FirewallOp {
    /// Chain initialized.
    Init { chain: String, port: u16 },
    /// IP banned.
    Ban {
        chain: String,
        ip: IpAddr,
        action: String,
    },
    /// IP unbanned.
    Unban {
        chain: String,
        ip: IpAddr,
        action: String,
    },
    /// Chain cleaned up.
    Cleanup { chain: String, port: u16 },
}

/// Tier: T3 — Mock firewall for testing (records commands without executing).
#[derive(Debug, Default)]
pub struct MockFirewall {
    /// Log of operations performed.
    pub operations: std::sync::Mutex<Vec<FirewallOp>>,
}

impl MockFirewall {
    fn push_op(&self, op: FirewallOp) {
        if let Ok(mut ops) = self.operations.lock() {
            ops.push(op);
        }
    }

    fn extract_banned(&self) -> Vec<IpAddr> {
        let ops = self.operations.lock().unwrap_or_else(|e| e.into_inner());
        ops.iter().filter_map(extract_ban_ip).collect()
    }
}

/// Extract IP from a Ban operation.
fn extract_ban_ip(op: &FirewallOp) -> Option<IpAddr> {
    match op {
        FirewallOp::Ban { ip, .. } => Some(*ip),
        _ => None,
    }
}

impl FirewallBackend for MockFirewall {
    fn init(&self, chain: &str, port: u16) -> Result<()> {
        self.push_op(FirewallOp::Init {
            chain: chain.to_string(),
            port,
        });
        Ok(())
    }

    fn ban(&self, chain: &str, ip: IpAddr, action: &str) -> Result<()> {
        self.push_op(FirewallOp::Ban {
            chain: chain.to_string(),
            ip,
            action: action.to_string(),
        });
        Ok(())
    }

    fn unban(&self, chain: &str, ip: IpAddr, action: &str) -> Result<()> {
        self.push_op(FirewallOp::Unban {
            chain: chain.to_string(),
            ip,
            action: action.to_string(),
        });
        Ok(())
    }

    fn cleanup(&self, chain: &str, port: u16) -> Result<()> {
        self.push_op(FirewallOp::Cleanup {
            chain: chain.to_string(),
            port,
        });
        Ok(())
    }

    fn list_banned(&self, _chain: &str) -> Result<Vec<IpAddr>> {
        Ok(self.extract_banned())
    }
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_ip(s: &str) -> IpAddr {
        s.parse()
            .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST))
    }

    #[test]
    fn mock_firewall_records_init() {
        let fw = MockFirewall::default();
        let result = fw.init("f2b-test", 22);
        assert!(result.is_ok());

        let ops = fw.operations.lock().unwrap_or_else(|e| e.into_inner());
        assert_eq!(ops.len(), 1);
        assert_eq!(
            ops[0],
            FirewallOp::Init {
                chain: "f2b-test".to_string(),
                port: 22
            }
        );
    }

    #[test]
    fn mock_firewall_records_ban_unban() {
        let fw = MockFirewall::default();
        let ip = parse_ip("10.0.0.1");

        let _ = fw.ban("f2b-test", ip, "REJECT");
        let _ = fw.unban("f2b-test", ip, "REJECT");

        let ops = fw.operations.lock().unwrap_or_else(|e| e.into_inner());
        assert_eq!(ops.len(), 2);
    }

    #[test]
    fn mock_firewall_list_banned() {
        let fw = MockFirewall::default();
        let ip1 = parse_ip("10.0.0.1");
        let ip2 = parse_ip("10.0.0.2");

        let _ = fw.ban("f2b-test", ip1, "REJECT");
        let _ = fw.ban("f2b-test", ip2, "REJECT");

        let banned = fw.list_banned("f2b-test").unwrap_or_default();
        assert_eq!(banned.len(), 2);
        assert!(banned.contains(&ip1));
        assert!(banned.contains(&ip2));
    }

    #[test]
    fn mock_firewall_cleanup() {
        let fw = MockFirewall::default();
        let result = fw.cleanup("f2b-test", 22);
        assert!(result.is_ok());
    }

    #[test]
    fn parse_iptables_listing_works() {
        let output = "Chain f2b-sentinel (1 references)\ntarget     prot opt source               destination\nREJECT     all  --  10.0.0.1             0.0.0.0/0\nREJECT     all  --  10.0.0.2             0.0.0.0/0\nRETURN     all  --  0.0.0.0/0            0.0.0.0/0\n";
        let ips = parse_iptables_listing(output);
        assert_eq!(ips.len(), 2); // 10.0.0.1, 10.0.0.2 (RETURN's 0.0.0.0/0 filtered as wildcard)
    }

    #[test]
    fn parse_ip_or_cidr_plain_ip() {
        assert_eq!(parse_ip_or_cidr("10.0.0.1"), Some(parse_ip("10.0.0.1")));
    }

    #[test]
    fn parse_ip_or_cidr_with_prefix() {
        assert_eq!(
            parse_ip_or_cidr("192.168.1.1/32"),
            Some(parse_ip("192.168.1.1"))
        );
    }

    #[test]
    fn parse_ip_or_cidr_wildcard_filtered() {
        assert_eq!(parse_ip_or_cidr("0.0.0.0/0"), None);
        assert_eq!(parse_ip_or_cidr("::/0"), None);
    }

    #[test]
    fn parse_ip_or_cidr_invalid() {
        assert_eq!(parse_ip_or_cidr("not-an-ip"), None);
        assert_eq!(parse_ip_or_cidr(""), None);
    }
}
