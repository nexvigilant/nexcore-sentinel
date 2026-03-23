//! Failure tracker — sliding-window ban decisions.
//!
//! ## Primitive Foundation
//!
//! | Primitive | Manifestation |
//! |-----------|---------------|
//! | T1: Mapping (μ) | IP → failure timestamps |
//! | T1: State (ς) | Failure counts, ban records |
//! | T1: Sequence (σ) | Sliding window over timestamps |

use std::collections::HashMap;
use std::net::IpAddr;

use nexcore_chrono::DateTime;

use crate::config::SentinelConfig;
use crate::types::{
    BanDuration, BanRecord, Count, EngineAction, FailureRecord, FindWindow, Timestamp,
};
use crate::whitelist::Whitelist;

/// Tier: T3 — Tracks IP failures and manages bans.
#[derive(Debug)]
pub struct Tracker {
    /// IP → failure timestamps (not yet banned).
    failures: HashMap<IpAddr, FailureRecord>,
    /// Currently active bans.
    bans: HashMap<IpAddr, BanRecord>,
    /// Max failures before ban.
    max_retry: Count,
    /// Sliding window duration.
    find_window: FindWindow,
    /// Ban duration.
    ban_duration: BanDuration,
    /// IPs that should never be banned.
    whitelist: Whitelist,
}

impl Tracker {
    /// Create a new tracker from config and whitelist.
    #[must_use]
    pub fn new(config: &SentinelConfig, whitelist: Whitelist) -> Self {
        Self {
            failures: HashMap::new(),
            bans: HashMap::new(),
            max_retry: config.max_retry,
            find_window: FindWindow::from_secs(config.find_time_secs),
            ban_duration: BanDuration::from_secs(config.ban_time_secs),
            whitelist,
        }
    }

    /// Record a failure from an IP. Returns the action to take.
    pub fn record_failure(&mut self, ip: IpAddr, when: Timestamp) -> EngineAction {
        // Never ban whitelisted IPs
        if self.whitelist.contains(ip) {
            tracing::debug!("Ignoring whitelisted IP: {ip}");
            return EngineAction::None;
        }

        // Don't record if already banned
        if self.bans.contains_key(&ip) {
            tracing::debug!("IP {ip} already banned, ignoring");
            return EngineAction::None;
        }

        // Update or create failure record
        let record = self
            .failures
            .entry(ip)
            .or_insert_with(|| FailureRecord::new(ip, when));

        let is_duplicate = record.timestamps.last().is_some_and(|&last| last == when);
        if !is_duplicate {
            record.record_failure(when);
        }

        // Prune old entries outside the sliding window
        record.prune(self.find_window, when);

        let count = record.count();
        tracing::debug!("IP {ip}: {count}/{} failures in window", self.max_retry);

        if count >= self.max_retry {
            // Threshold reached — ban!
            let ban = BanRecord {
                ip,
                banned_at: when,
                expires_at: when
                    + nexcore_chrono::Duration::from_std(self.ban_duration.as_duration()),
                failure_count: count,
            };
            self.bans.insert(ip, ban);
            self.failures.remove(&ip);
            tracing::warn!("Banning IP {ip} after {count} failures");
            EngineAction::Ban(ip)
        } else {
            EngineAction::RecordFailure(ip)
        }
    }

    /// Check for expired bans and return IPs to unban.
    pub fn tick_unbans(&mut self) -> Vec<IpAddr> {
        let now = DateTime::now();
        let expired: Vec<IpAddr> = self
            .bans
            .iter()
            .filter(|(_, ban)| ban.is_expired(now))
            .map(|(&ip, _)| ip)
            .collect();

        for ip in &expired {
            self.bans.remove(ip);
            tracing::info!("Unbanning expired IP: {ip}");
        }

        expired
    }

    /// Manually unban an IP. Returns true if it was banned.
    pub fn unban(&mut self, ip: IpAddr) -> bool {
        self.bans.remove(&ip).is_some()
    }

    /// Check if an IP is currently banned.
    #[must_use]
    pub fn is_banned(&self, ip: IpAddr) -> bool {
        self.bans.contains_key(&ip)
    }

    /// Get all currently banned IPs with their records.
    #[must_use]
    pub fn banned_ips(&self) -> Vec<&BanRecord> {
        self.bans.values().collect()
    }

    /// Number of active bans.
    #[must_use]
    pub fn ban_count(&self) -> usize {
        self.bans.len()
    }

    /// Number of IPs being tracked (not yet banned).
    #[must_use]
    pub fn tracking_count(&self) -> usize {
        self.failures.len()
    }

    /// Restore state from persistence.
    pub fn restore(&mut self, bans: Vec<BanRecord>, failures: Vec<FailureRecord>) {
        let now = DateTime::now();
        // Only restore non-expired bans
        for ban in bans {
            if !ban.is_expired(now) {
                self.bans.insert(ban.ip, ban);
            }
        }
        for failure in failures {
            self.failures.insert(failure.ip, failure);
        }
        tracing::info!(
            "Restored {} bans, {} tracking entries",
            self.bans.len(),
            self.failures.len()
        );
    }

    /// Export current state for persistence.
    #[must_use]
    pub fn export_state(&self) -> (Vec<BanRecord>, Vec<FailureRecord>) {
        (
            self.bans.values().cloned().collect(),
            self.failures.values().cloned().collect(),
        )
    }
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SentinelConfig;

    fn test_config() -> SentinelConfig {
        SentinelConfig {
            max_retry: 3,
            ban_time_secs: 3600,
            find_time_secs: 600,
            ..SentinelConfig::default()
        }
    }

    fn test_whitelist() -> Whitelist {
        Whitelist::new(&["127.0.0.1/8".to_string()]).unwrap_or_else(|_| {
            Whitelist::new(&[]).unwrap_or_else(|_| {
                // Fallback: empty whitelist
                Whitelist::new(&[]).ok().unwrap_or_else(|| unreachable!())
            })
        })
    }

    fn parse_ip(s: &str) -> IpAddr {
        s.parse()
            .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST))
    }

    #[test]
    fn below_threshold_no_ban() {
        let config = test_config();
        let wl = test_whitelist();
        let mut tracker = Tracker::new(&config, wl);
        let ip = parse_ip("10.0.0.1");
        let now = DateTime::now();

        let action = tracker.record_failure(ip, now);
        assert_eq!(action, EngineAction::RecordFailure(ip));

        let action = tracker.record_failure(ip, now + nexcore_chrono::Duration::seconds(1));
        assert_eq!(action, EngineAction::RecordFailure(ip));

        assert!(!tracker.is_banned(ip));
        assert_eq!(tracker.tracking_count(), 1);
    }

    #[test]
    fn at_threshold_triggers_ban() {
        let config = test_config();
        let wl = test_whitelist();
        let mut tracker = Tracker::new(&config, wl);
        let ip = parse_ip("10.0.0.1");
        let now = DateTime::now();

        tracker.record_failure(ip, now);
        tracker.record_failure(ip, now + nexcore_chrono::Duration::seconds(1));
        let action = tracker.record_failure(ip, now + nexcore_chrono::Duration::seconds(2));

        assert_eq!(action, EngineAction::Ban(ip));
        assert!(tracker.is_banned(ip));
        assert_eq!(tracker.ban_count(), 1);
        assert_eq!(tracker.tracking_count(), 0); // cleared after ban
    }

    #[test]
    fn window_expiry_resets_count() {
        let config = test_config();
        let wl = test_whitelist();
        let mut tracker = Tracker::new(&config, wl);
        let ip = parse_ip("10.0.0.1");
        let now = DateTime::now();

        // Two failures within window
        tracker.record_failure(ip, now);
        tracker.record_failure(ip, now + nexcore_chrono::Duration::seconds(1));

        // Third failure WAY outside window (700 seconds later, window is 600)
        let action = tracker.record_failure(ip, now + nexcore_chrono::Duration::seconds(700));

        // Should not ban — old entries pruned, only 1 remaining in window
        assert_eq!(action, EngineAction::RecordFailure(ip));
        assert!(!tracker.is_banned(ip));
    }

    #[test]
    fn whitelisted_ip_never_banned() {
        let config = test_config();
        let wl = test_whitelist();
        let mut tracker = Tracker::new(&config, wl);
        let ip = parse_ip("127.0.0.1");
        let now = DateTime::now();

        for i in 0..10 {
            let action = tracker.record_failure(ip, now + nexcore_chrono::Duration::seconds(i));
            assert_eq!(action, EngineAction::None);
        }

        assert!(!tracker.is_banned(ip));
    }

    #[test]
    fn unban_tick() {
        let mut config = test_config();
        config.ban_time_secs = 1; // 1 second ban for testing
        let wl = test_whitelist();
        let mut tracker = Tracker::new(&config, wl);
        let ip = parse_ip("10.0.0.1");

        // Use a timestamp far in the past so the ban is already expired
        let past = DateTime::now() - nexcore_chrono::Duration::seconds(100);
        tracker.record_failure(ip, past);
        tracker.record_failure(ip, past + nexcore_chrono::Duration::seconds(1));
        tracker.record_failure(ip, past + nexcore_chrono::Duration::seconds(2));
        assert!(tracker.is_banned(ip));

        // Ban expires_at = past+2s + 1s = past+3s, which is ~97s ago
        let unbanned = tracker.tick_unbans();
        assert!(unbanned.contains(&ip));
        assert!(!tracker.is_banned(ip));
    }

    #[test]
    fn manual_unban() {
        let config = test_config();
        let wl = test_whitelist();
        let mut tracker = Tracker::new(&config, wl);
        let ip = parse_ip("10.0.0.1");
        let now = DateTime::now();

        tracker.record_failure(ip, now);
        tracker.record_failure(ip, now + nexcore_chrono::Duration::seconds(1));
        tracker.record_failure(ip, now + nexcore_chrono::Duration::seconds(2));
        assert!(tracker.is_banned(ip));

        assert!(tracker.unban(ip));
        assert!(!tracker.is_banned(ip));
    }

    #[test]
    fn export_restore_round_trip() {
        let config = test_config();
        let wl = test_whitelist();
        let mut tracker = Tracker::new(&config, wl);
        let ip = parse_ip("10.0.0.1");
        let now = DateTime::now();

        tracker.record_failure(ip, now);
        tracker.record_failure(ip, now + nexcore_chrono::Duration::seconds(1));
        tracker.record_failure(ip, now + nexcore_chrono::Duration::seconds(2));

        let (bans, failures) = tracker.export_state();
        assert_eq!(bans.len(), 1);

        // Restore into a new tracker
        let wl2 = Whitelist::new(&["127.0.0.1/8".to_string()])
            .unwrap_or_else(|_| Whitelist::new(&[]).ok().unwrap_or_else(|| unreachable!()));
        let mut tracker2 = Tracker::new(&config, wl2);
        tracker2.restore(bans, failures);
        assert!(tracker2.is_banned(ip));
    }
}
