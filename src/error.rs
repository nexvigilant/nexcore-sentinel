//! Error types for nexcore-sentinel.
//!
//! Uses `thiserror` for library errors, following nexcore conventions.

use std::net::IpAddr;
use std::path::PathBuf;

/// Sentinel error hierarchy.
#[derive(Debug, nexcore_error::Error)]
pub enum SentinelError {
    /// Failed to parse a log line.
    #[error("parse error: {0}")]
    Parse(String),

    /// Failed to parse an IP address from log.
    #[error("invalid IP address: {0}")]
    InvalidIp(String),

    /// I/O error (file watching, persistence, etc.).
    #[error("I/O error at {path:?}: {source}")]
    Io {
        /// Path involved in the error.
        path: PathBuf,
        /// Underlying I/O error.
        source: std::io::Error,
    },

    /// Firewall command failed.
    #[error("firewall command failed: {command} — {message}")]
    Firewall {
        /// The command that was attempted.
        command: String,
        /// Error message from stderr or exit code.
        message: String,
    },

    /// Configuration error.
    #[error("config error: {0}")]
    Config(String),

    /// TOML deserialization failed.
    #[error("TOML parse error: {0}")]
    Toml(#[from] toml::de::Error),

    /// JSON serialization/deserialization failed.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// CIDR/network parsing failed.
    #[error("network parse error: {0}")]
    Network(String),

    /// Attempted to operate on an IP that is whitelisted.
    #[error("IP {0} is whitelisted")]
    Whitelisted(IpAddr),

    /// File watcher error.
    #[error("watcher error: {0}")]
    Watcher(String),

    /// Persistence state error.
    #[error("persistence error: {0}")]
    Persistence(String),

    /// Channel communication error.
    #[error("channel error: {0}")]
    Channel(String),
}

/// Convenience result type.
pub type Result<T> = std::result::Result<T, SentinelError>;

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_display_parse() {
        let e = SentinelError::Parse("bad line".into());
        assert!(e.to_string().contains("bad line"));
    }

    #[test]
    fn error_display_firewall() {
        let e = SentinelError::Firewall {
            command: "iptables -I".into(),
            message: "permission denied".into(),
        };
        let msg = e.to_string();
        assert!(msg.contains("iptables -I"));
        assert!(msg.contains("permission denied"));
    }

    #[test]
    fn error_display_whitelisted() {
        let ip: IpAddr = "127.0.0.1"
            .parse()
            .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
        let e = SentinelError::Whitelisted(ip);
        assert!(e.to_string().contains("127.0.0.1"));
    }

    #[test]
    fn result_type_alias_works() {
        let ok: Result<u32> = Ok(42);
        assert!(ok.is_ok());
        let err: Result<u32> = Err(SentinelError::Parse("test".into()));
        assert!(err.is_err());
    }
}
