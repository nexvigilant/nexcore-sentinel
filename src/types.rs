//! Domain types for nexcore-sentinel, tiered T1 → T3.
//!
//! ## Primitive Foundation
//!
//! | Tier | Type | Grounding |
//! |------|------|-----------|
//! | T1 | `Timestamp` | State (ς) — moment in time |
//! | T1 | `Count` | Sequence (σ) — cardinality |
//! | T2-P | `BanDuration` | Newtype over Duration |
//! | T2-P | `FindWindow` | Newtype over Duration |
//! | T2-C | `FailureRecord` | IP + timestamps |
//! | T3 | `BanRecord` | Full ban domain object |
//! | T3 | `AuthEvent` | Parsed log event |

use std::fmt;
use std::net::IpAddr;
use std::time::Duration;

use nexcore_chrono::DateTime;
use serde::{Deserialize, Serialize};

// ── T1: Primitive aliases ──────────────────────────────────────────

/// Tier: T1 — A moment in time (State primitive).
pub type Timestamp = DateTime;

/// Tier: T1 — Cardinality count (Sequence primitive).
pub type Count = u32;

// ── T2-P: Newtypes over T1 ────────────────────────────────────────

/// Tier: T2-P — Duration for which an IP stays banned.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BanDuration(pub Duration);

impl BanDuration {
    /// Create from seconds.
    #[must_use]
    pub fn from_secs(secs: u64) -> Self {
        Self(Duration::from_secs(secs))
    }

    /// Inner duration.
    #[must_use]
    pub fn as_duration(&self) -> Duration {
        self.0
    }
}

/// Tier: T2-P — Sliding window within which failures are counted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FindWindow(pub Duration);

impl FindWindow {
    /// Create from seconds.
    #[must_use]
    pub fn from_secs(secs: u64) -> Self {
        Self(Duration::from_secs(secs))
    }

    /// Inner duration.
    #[must_use]
    pub fn as_duration(&self) -> Duration {
        self.0
    }
}

/// Tier: T2-P — Maximum allowed failures before banning.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MaxRetry(pub Count);

// ── T2-C: Composed types ──────────────────────────────────────────

/// Tier: T2-C — Tracks failure timestamps for a single IP.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FailureRecord {
    /// The offending IP address.
    pub ip: IpAddr,
    /// Timestamps of each authentication failure.
    pub timestamps: Vec<Timestamp>,
}

impl FailureRecord {
    /// Create a new record with one failure.
    #[must_use]
    pub fn new(ip: IpAddr, when: Timestamp) -> Self {
        Self {
            ip,
            timestamps: vec![when],
        }
    }

    /// Add a failure timestamp.
    pub fn record_failure(&mut self, when: Timestamp) {
        self.timestamps.push(when);
    }

    /// Prune timestamps outside the sliding window.
    pub fn prune(&mut self, window: FindWindow, now: Timestamp) {
        let cutoff = now - nexcore_chrono::Duration::from_std(window.as_duration());
        self.timestamps.retain(|&t| t >= cutoff);
    }

    /// Count of failures remaining after pruning.
    #[must_use]
    pub fn count(&self) -> Count {
        self.timestamps.len() as Count
    }
}

// ── T3: Domain types ──────────────────────────────────────────────

/// Tier: T3 — A ban record for a blocked IP.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BanRecord {
    /// The banned IP address.
    pub ip: IpAddr,
    /// When the ban was applied.
    pub banned_at: Timestamp,
    /// When the ban expires.
    pub expires_at: Timestamp,
    /// Number of failures that triggered the ban.
    pub failure_count: Count,
}

impl BanRecord {
    /// Check if the ban has expired relative to `now`.
    #[must_use]
    pub fn is_expired(&self, now: Timestamp) -> bool {
        now >= self.expires_at
    }
}

/// Tier: T3 — A parsed authentication event from a log line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthEvent {
    /// Failed password attempt.
    FailedPassword {
        /// Source IP.
        ip: IpAddr,
        /// Username attempted.
        user: String,
        /// Timestamp parsed from log.
        timestamp: Timestamp,
    },
    /// Invalid user attempt (user doesn't exist).
    InvalidUser {
        /// Source IP.
        ip: IpAddr,
        /// Username attempted.
        user: String,
        /// Timestamp parsed from log.
        timestamp: Timestamp,
    },
}

impl AuthEvent {
    /// Extract the IP address from any event variant.
    #[must_use]
    pub fn ip(&self) -> IpAddr {
        match self {
            Self::FailedPassword { ip, .. } | Self::InvalidUser { ip, .. } => *ip,
        }
    }

    /// Extract the timestamp from any event variant.
    #[must_use]
    pub fn timestamp(&self) -> Timestamp {
        match self {
            Self::FailedPassword { timestamp, .. } | Self::InvalidUser { timestamp, .. } => {
                *timestamp
            }
        }
    }

    /// Extract the username from any event variant.
    #[must_use]
    pub fn user(&self) -> &str {
        match self {
            Self::FailedPassword { user, .. } | Self::InvalidUser { user, .. } => user,
        }
    }
}

impl fmt::Display for AuthEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FailedPassword { ip, user, .. } => {
                write!(f, "Failed password for {user} from {ip}")
            }
            Self::InvalidUser { ip, user, .. } => {
                write!(f, "Invalid user {user} from {ip}")
            }
        }
    }
}

/// Tier: T3 — The persistent state saved to disk.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SentinelState {
    /// Currently active bans.
    pub bans: Vec<BanRecord>,
    /// In-progress failure tracking (not yet banned).
    pub failures: Vec<FailureRecord>,
}

/// Tier: T3 — Action the engine should take after processing an event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EngineAction {
    /// No action needed (below threshold or whitelisted).
    None,
    /// Ban the IP.
    Ban(IpAddr),
    /// Record the failure (not yet at threshold).
    RecordFailure(IpAddr),
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ban_duration_round_trip() {
        let d = BanDuration::from_secs(86400);
        assert_eq!(d.as_duration(), Duration::from_secs(86400));
    }

    #[test]
    fn find_window_round_trip() {
        let w = FindWindow::from_secs(600);
        assert_eq!(w.as_duration(), Duration::from_secs(600));
    }

    #[test]
    fn failure_record_prune() {
        let ip: IpAddr = "192.168.1.1"
            .parse()
            .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
        let now = DateTime::now();
        let window = FindWindow::from_secs(600);

        let mut rec = FailureRecord::new(ip, now - nexcore_chrono::Duration::seconds(700));
        rec.record_failure(now - nexcore_chrono::Duration::seconds(300));
        rec.record_failure(now);

        assert_eq!(rec.count(), 3);
        rec.prune(window, now);
        assert_eq!(rec.count(), 2); // 700s-old entry pruned
    }

    #[test]
    fn ban_record_expiry() {
        let now = DateTime::now();
        let ban = BanRecord {
            ip: "10.0.0.1"
                .parse()
                .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
            banned_at: now - nexcore_chrono::Duration::seconds(100),
            expires_at: now - nexcore_chrono::Duration::seconds(1),
            failure_count: 3,
        };
        assert!(ban.is_expired(now));
    }

    #[test]
    fn auth_event_accessors() {
        let ip: IpAddr = "1.2.3.4"
            .parse()
            .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
        let ts = DateTime::now();
        let evt = AuthEvent::FailedPassword {
            ip,
            user: "root".to_string(),
            timestamp: ts,
        };
        assert_eq!(evt.ip(), ip);
        assert_eq!(evt.user(), "root");
        assert_eq!(evt.timestamp(), ts);
    }

    #[test]
    fn engine_action_equality() {
        let ip: IpAddr = "5.6.7.8"
            .parse()
            .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
        assert_eq!(EngineAction::Ban(ip), EngineAction::Ban(ip));
        assert_eq!(EngineAction::None, EngineAction::None);
    }
}
