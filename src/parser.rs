//! Auth log parser — regex-based extraction of SSH failure events.
//!
//! ## Primitive Foundation
//!
//! | Primitive | Manifestation |
//! |-----------|---------------|
//! | T1: Sequence (σ) | Log lines streamed one-by-one |
//! | T1: Mapping (μ) | Line → Option<AuthEvent> |

use std::net::IpAddr;
use std::sync::LazyLock;

use nexcore_chrono::{DateTime, parse_naive_with_format};
use regex::Regex;

use crate::error::{Result, SentinelError};
use crate::types::AuthEvent;

/// Regex for "Failed password for <user> from <ip> port <port> ssh2"
static FAILED_PASSWORD_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+\S+\s+sshd\[\d+\]:\s+Failed password for (?:invalid user )?(\S+) from (\S+) port \d+"
    )
    .unwrap_or_else(|_| Regex::new("^$").unwrap_or_else(|_| unreachable!()))
});

/// Regex for "Invalid user <user> from <ip> port <port>"
static INVALID_USER_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+\S+\s+sshd\[\d+\]:\s+Invalid user (\S+) from (\S+)",
    )
    .unwrap_or_else(|_| Regex::new("^$").unwrap_or_else(|_| unreachable!()))
});

/// Parse a syslog timestamp like "Feb  4 14:23:01" into a `DateTime`.
///
/// Assumes the current year (syslog doesn't include year).
fn parse_syslog_timestamp(ts: &str) -> Result<nexcore_chrono::DateTime> {
    let year = DateTime::now().format("%Y").unwrap_or_default();
    let with_year = format!("{year} {ts}");
    let naive = parse_naive_with_format(&with_year, "%Y %b %e %H:%M:%S")
        .map_err(|_| SentinelError::Parse(format!("timestamp '{ts}'")))?;
    Ok(naive.to_datetime())
}

/// Parse a single auth log line into an `AuthEvent`, if it matches.
///
/// Returns `None` for non-matching lines (normal log entries).
///
/// # Errors
/// Returns `SentinelError::InvalidIp` if the IP in the log line is malformed.
pub fn parse_line(line: &str) -> Result<Option<AuthEvent>> {
    // Try "Failed password" pattern first (more common)
    if let Some(caps) = FAILED_PASSWORD_RE.captures(line) {
        let ts_str = caps.get(1).map(|m| m.as_str()).unwrap_or_default();
        let user = caps.get(2).map(|m| m.as_str()).unwrap_or_default();
        let ip_str = caps.get(3).map(|m| m.as_str()).unwrap_or_default();

        let timestamp = parse_syslog_timestamp(ts_str)?;
        let ip: IpAddr = ip_str
            .parse()
            .map_err(|_| SentinelError::InvalidIp(ip_str.to_string()))?;

        return Ok(Some(AuthEvent::FailedPassword {
            ip,
            user: user.to_string(),
            timestamp,
        }));
    }

    // Try "Invalid user" pattern
    if let Some(caps) = INVALID_USER_RE.captures(line) {
        let ts_str = caps.get(1).map(|m| m.as_str()).unwrap_or_default();
        let user = caps.get(2).map(|m| m.as_str()).unwrap_or_default();
        let ip_str = caps.get(3).map(|m| m.as_str()).unwrap_or_default();

        let timestamp = parse_syslog_timestamp(ts_str)?;
        let ip: IpAddr = ip_str
            .parse()
            .map_err(|_| SentinelError::InvalidIp(ip_str.to_string()))?;

        return Ok(Some(AuthEvent::InvalidUser {
            ip,
            user: user.to_string(),
            timestamp,
        }));
    }

    Ok(None)
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_failed_password_ipv4() {
        let line = "Feb  4 14:23:01 myhost sshd[12345]: Failed password for root from 192.168.1.100 port 22 ssh2";
        let result = parse_line(line);
        assert!(result.is_ok());
        let evt = result.unwrap_or(None);
        assert!(evt.is_some());
        if let Some(AuthEvent::FailedPassword { ip, user, .. }) = evt {
            assert_eq!(ip.to_string(), "192.168.1.100");
            assert_eq!(user, "root");
        }
    }

    #[test]
    fn parse_failed_password_invalid_user_prefix() {
        let line = "Feb  4 14:23:01 myhost sshd[12345]: Failed password for invalid user admin from 10.0.0.5 port 44322 ssh2";
        let result = parse_line(line);
        assert!(result.is_ok());
        let evt = result.unwrap_or(None);
        assert!(evt.is_some());
        if let Some(AuthEvent::FailedPassword { ip, user, .. }) = evt {
            assert_eq!(ip.to_string(), "10.0.0.5");
            assert_eq!(user, "admin");
        }
    }

    #[test]
    fn parse_invalid_user() {
        let line =
            "Feb  4 14:23:01 myhost sshd[12345]: Invalid user hacker from 203.0.113.50 port 55555";
        let result = parse_line(line);
        assert!(result.is_ok());
        let evt = result.unwrap_or(None);
        assert!(evt.is_some());
        if let Some(AuthEvent::InvalidUser { ip, user, .. }) = evt {
            assert_eq!(ip.to_string(), "203.0.113.50");
            assert_eq!(user, "hacker");
        }
    }

    #[test]
    fn parse_ipv6() {
        let line = "Feb  4 14:23:01 myhost sshd[12345]: Failed password for root from 2001:db8::1 port 22 ssh2";
        let result = parse_line(line);
        assert!(result.is_ok());
        let evt = result.unwrap_or(None);
        assert!(evt.is_some());
        if let Some(AuthEvent::FailedPassword { ip, .. }) = evt {
            assert!(ip.is_ipv6());
        }
    }

    #[test]
    fn parse_non_matching_line() {
        let line = "Feb  4 14:23:01 myhost sshd[12345]: Accepted publickey for user from 10.0.0.1 port 22 ssh2";
        let result = parse_line(line);
        assert!(result.is_ok());
        assert!(
            result
                .unwrap_or(Some(AuthEvent::FailedPassword {
                    ip: IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                    user: String::new(),
                    timestamp: DateTime::now(),
                }))
                .is_none()
        );
    }

    #[test]
    fn parse_empty_line() {
        let result = parse_line("");
        assert!(result.is_ok());
        assert!(result.unwrap_or(None).is_none());
    }

    #[test]
    fn parse_syslog_timestamp_valid() {
        let ts = parse_syslog_timestamp("Feb  4 14:23:01");
        assert!(ts.is_ok());
    }

    #[test]
    fn parse_syslog_timestamp_invalid() {
        let ts = parse_syslog_timestamp("not a timestamp");
        assert!(ts.is_err());
    }
}
