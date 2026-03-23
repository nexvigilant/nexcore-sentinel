//! Temporal-safe test utilities for nexcore-sentinel.
//!
//! ## Lesson: Syslog Timestamp Gotcha
//!
//! Auth log timestamps (e.g., "Feb 4 14:23:01") don't include the year.
//! `parse_syslog_timestamp()` infers it from the system clock, so parsed
//! timestamps may already be in the past. When tests build `BanRecord`s
//! from parsed log lines, the ban's `expires_at` can already be expired,
//! causing `tracker.restore()` to silently discard them.
//!
//! **Solution**: Build ban records using explicit future timestamps,
//! bypassing the parser entirely for temporal assertions.
//!
//! ## Primitive Foundation
//!
//! | Primitive | Manifestation |
//! |-----------|---------------|
//! | T1: State (ς) | Temporal state with guaranteed validity window |

use std::net::IpAddr;

use nexcore_chrono::{DateTime, Duration};

use crate::types::{BanRecord, Count, FailureRecord};

/// Tier: T2-C — Builder for `BanRecord` with guaranteed non-expired timestamps.
///
/// Ensures `expires_at` is always in the future relative to construction time,
/// avoiding the syslog-timestamp-in-the-past trap.
///
/// # Example
/// ```
/// use nexcore_sentinel::test_helpers::FutureBanBuilder;
///
/// let ban = FutureBanBuilder::new("10.0.0.1")
///     .ban_duration_secs(3600)
///     .failure_count(3)
///     .build();
///
/// assert!(!ban.is_expired(nexcore_chrono::DateTime::now()));
/// ```
pub struct FutureBanBuilder {
    ip: IpAddr,
    banned_at: DateTime,
    ban_duration_secs: i64,
    failure_count: Count,
}

impl FutureBanBuilder {
    /// Create a new builder. `ip_str` is parsed; defaults to 127.0.0.1 on error.
    #[must_use]
    pub fn new(ip_str: &str) -> Self {
        let ip = ip_str
            .parse()
            .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
        Self {
            ip,
            banned_at: DateTime::now(),
            ban_duration_secs: 86400,
            failure_count: 3,
        }
    }

    /// Set when the ban was applied (default: now).
    #[must_use]
    pub fn banned_at(mut self, when: DateTime) -> Self {
        self.banned_at = when;
        self
    }

    /// Set the ban duration in seconds (default: 86400 = 24h).
    #[must_use]
    pub fn ban_duration_secs(mut self, secs: i64) -> Self {
        self.ban_duration_secs = secs;
        self
    }

    /// Set the failure count that triggered the ban (default: 3).
    #[must_use]
    pub fn failure_count(mut self, count: Count) -> Self {
        self.failure_count = count;
        self
    }

    /// Build the `BanRecord` with guaranteed future expiry.
    #[must_use]
    pub fn build(self) -> BanRecord {
        BanRecord {
            ip: self.ip,
            banned_at: self.banned_at,
            expires_at: self.banned_at + Duration::seconds(self.ban_duration_secs),
            failure_count: self.failure_count,
        }
    }
}

/// Tier: T2-C — Builder for `BanRecord` that is already expired.
///
/// Useful for testing expiry/unban logic without `thread::sleep`.
pub struct ExpiredBanBuilder {
    ip: IpAddr,
    expired_secs_ago: i64,
    failure_count: Count,
}

impl ExpiredBanBuilder {
    /// Create a new expired ban builder.
    #[must_use]
    pub fn new(ip_str: &str) -> Self {
        let ip = ip_str
            .parse()
            .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
        Self {
            ip,
            expired_secs_ago: 10,
            failure_count: 3,
        }
    }

    /// How many seconds ago the ban expired (default: 10).
    #[must_use]
    pub fn expired_secs_ago(mut self, secs: i64) -> Self {
        self.expired_secs_ago = secs;
        self
    }

    /// Set the failure count (default: 3).
    #[must_use]
    pub fn failure_count(mut self, count: Count) -> Self {
        self.failure_count = count;
        self
    }

    /// Build the `BanRecord` with guaranteed past expiry.
    #[must_use]
    pub fn build(self) -> BanRecord {
        let now = DateTime::now();
        let banned_at = now - Duration::seconds(self.expired_secs_ago + 3600);
        let expires_at = now - Duration::seconds(self.expired_secs_ago);
        BanRecord {
            ip: self.ip,
            banned_at,
            expires_at,
            failure_count: self.failure_count,
        }
    }
}

/// Create a `FailureRecord` with `count` timestamps spread evenly within a window.
///
/// All timestamps are recent (within the last `window_secs`), so they won't
/// be pruned by the sliding window.
#[must_use]
pub fn recent_failures(ip_str: &str, count: usize, window_secs: i64) -> FailureRecord {
    let ip = ip_str
        .parse()
        .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
    let now = DateTime::now();
    let spacing = if count > 1 {
        window_secs / count as i64
    } else {
        0
    };

    let mut rec = FailureRecord::new(ip, now - Duration::seconds(window_secs));
    for i in 1..count {
        let offset = window_secs - (spacing * i as i64);
        rec.record_failure(now - Duration::seconds(offset));
    }
    rec
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn future_ban_is_not_expired() {
        let ban = FutureBanBuilder::new("10.0.0.1").build();
        assert!(!ban.is_expired(DateTime::now()));
    }

    #[test]
    fn future_ban_custom_duration() {
        let ban = FutureBanBuilder::new("10.0.0.1")
            .ban_duration_secs(1)
            .build();
        assert!(!ban.is_expired(DateTime::now()));
        assert_eq!(ban.failure_count, 3);
    }

    #[test]
    fn expired_ban_is_expired() {
        let ban = ExpiredBanBuilder::new("10.0.0.2").build();
        assert!(ban.is_expired(DateTime::now()));
    }

    #[test]
    fn expired_ban_custom_timing() {
        let ban = ExpiredBanBuilder::new("10.0.0.2")
            .expired_secs_ago(60)
            .failure_count(5)
            .build();
        assert!(ban.is_expired(DateTime::now()));
        assert_eq!(ban.failure_count, 5);
    }

    #[test]
    fn recent_failures_count() {
        let rec = recent_failures("10.0.0.3", 5, 300);
        assert_eq!(rec.count(), 5);
        assert_eq!(
            rec.ip,
            "10.0.0.3"
                .parse::<IpAddr>()
                .ok()
                .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST))
        );
    }

    #[test]
    fn recent_failures_single() {
        let rec = recent_failures("10.0.0.4", 1, 60);
        assert_eq!(rec.count(), 1);
    }
}
