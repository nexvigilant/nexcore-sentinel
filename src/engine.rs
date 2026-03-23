//! Engine — async orchestration loop tying all components together.
//!
//! ## Primitive Foundation
//!
//! | Primitive | Manifestation |
//! |-----------|---------------|
//! | T1: Sequence (σ) | watcher → parser → tracker → firewall pipeline |
//! | T1: State (ς) | Engine running state, tracker + firewall |
//!
//! ## Design Pattern: `tokio::select!` Decomposition
//!
//! **Lesson**: `tokio::select!` macro arms count toward nesting depth, which
//! triggers the `pretool_complexity_gate` hook (max 4 levels). The fix is to
//! extract the select body into a `select_once()` method and each arm handler
//! into its own flat method:
//!
//! ```text
//! // BEFORE (5+ nesting levels — blocked by gate):
//! async fn run(&mut self, rx: Receiver) {
//!     loop {                                     // level 1
//!         tokio::select! {                       // level 2
//!             line = rx.recv() => {              // level 3
//!                 match line {                   // level 4
//!                     Some(l) => { ... }        // level 5 ← BLOCKED
//!
//! // AFTER (max 3 levels — passes gate):
//! async fn run(&mut self, rx: Receiver) {
//!     loop {                                     // level 1
//!         let done = self.select_once(&mut rx).await?;  // flat call
//!         if done { break; }                     // level 2
//!     }
//! }
//! async fn select_once(&mut self, rx: &mut Receiver) -> Result<bool> {
//!     tokio::select! {                           // level 1
//!         line = rx.recv() => self.handle_line(line),  // flat call
//!         _ = interval.tick() => { self.tick()?; Ok(false) }
//!     }
//! }
//! fn handle_line(&mut self, line: Option<String>) -> Result<bool> {
//!     match line {                               // level 1
//!         Some(l) => { self.process(&l)?; Ok(false) }  // level 2
//!         None => Ok(true),                      // level 2
//!     }
//! }
//! ```
//!
//! This pattern applies to any `tokio::select!` with non-trivial match arms.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc as tokio_mpsc;

use crate::config::SentinelConfig;
use crate::error::{Result, SentinelError};
use crate::firewall::FirewallBackend;
use crate::parser;
use crate::persistence;
use crate::tracker::Tracker;
use crate::types::EngineAction;
use crate::whitelist::Whitelist;

// ── Pure pipeline functions (flat) ─────────────────────────────────

/// Parse a log line and get the engine action from the tracker.
fn classify_line(line: &str, tracker: &mut Tracker) -> Result<EngineAction> {
    let event = parser::parse_line(line)?;
    let event = match event {
        Some(e) => e,
        None => return Ok(EngineAction::None),
    };
    Ok(tracker.record_failure(event.ip(), event.timestamp()))
}

/// Execute a ban action against the firewall.
fn execute_ban(ip: IpAddr, firewall: &dyn FirewallBackend, config: &SentinelConfig) -> Result<()> {
    firewall.ban(&config.chain_name, ip, &config.block_type)?;
    tracing::warn!("Banned IP: {ip}");
    Ok(())
}

/// Unban a single IP via firewall.
fn execute_unban(
    ip: IpAddr,
    firewall: &dyn FirewallBackend,
    config: &SentinelConfig,
) -> Result<()> {
    firewall.unban(&config.chain_name, ip, &config.block_type)?;
    tracing::info!("Unbanned IP: {ip}");
    Ok(())
}

/// Save tracker state to disk.
fn persist(tracker: &Tracker, config: &SentinelConfig) {
    let (bans, failures) = tracker.export_state();
    let state = crate::types::SentinelState { bans, failures };
    if let Err(e) = persistence::save_state(&state, &config.state_path) {
        tracing::error!("Failed to save state: {e}");
    }
}

// ── Engine ─────────────────────────────────────────────────────────

/// Tier: T3 — The sentinel engine orchestrating the pipeline.
pub struct Engine {
    config: SentinelConfig,
    tracker: Tracker,
    firewall: Arc<dyn FirewallBackend>,
}

/// Tier: T2-C — Engine statistics snapshot.
#[derive(Debug, Clone)]
pub struct EngineStats {
    pub active_bans: usize,
    pub tracking: usize,
}

impl Engine {
    /// Create a new engine from config.
    pub fn new(config: SentinelConfig, firewall: Arc<dyn FirewallBackend>) -> Result<Self> {
        let whitelist = Whitelist::new(&config.whitelist)?;
        let mut tracker = Tracker::new(&config, whitelist);
        restore_state(&mut tracker, &config)?;
        Ok(Self {
            config,
            tracker,
            firewall,
        })
    }

    /// Initialize the firewall chain.
    pub fn init_firewall(&self) -> Result<()> {
        self.firewall
            .init(&self.config.chain_name, self.config.port)
    }

    /// Process a single log line through the pipeline.
    pub fn process_line(&mut self, line: &str) -> Result<()> {
        let action = classify_line(line, &mut self.tracker)?;
        self.apply_action(action)
    }

    /// Apply an engine action.
    fn apply_action(&self, action: EngineAction) -> Result<()> {
        match action {
            EngineAction::Ban(ip) => execute_ban(ip, self.firewall.as_ref(), &self.config),
            EngineAction::RecordFailure(_) => Ok(()),
            EngineAction::None => Ok(()),
        }
    }

    /// Process expired bans.
    pub fn tick(&mut self) -> Result<()> {
        let expired = self.tracker.tick_unbans();
        for ip in expired {
            execute_unban(ip, self.firewall.as_ref(), &self.config)?;
        }
        persist(&self.tracker, &self.config);
        Ok(())
    }

    /// Run the main async event loop.
    pub async fn run(&mut self, mut line_rx: tokio_mpsc::Receiver<String>) -> Result<()> {
        let tick = Duration::from_secs(self.config.tick_interval_secs);
        let mut interval = tokio::time::interval(tick);
        tracing::info!("Engine started");

        loop {
            let should_break = self.select_once(&mut line_rx, &mut interval).await?;
            if should_break {
                break;
            }
        }

        persist(&self.tracker, &self.config);
        Ok(())
    }

    /// One iteration of the select loop. Returns true when channel closes.
    async fn select_once(
        &mut self,
        line_rx: &mut tokio_mpsc::Receiver<String>,
        interval: &mut tokio::time::Interval,
    ) -> Result<bool> {
        tokio::select! {
            line = line_rx.recv() => self.handle_line(line),
            _ = interval.tick() => { self.tick()?; Ok(false) }
        }
    }

    /// Handle a received line (or channel close).
    fn handle_line(&mut self, line: Option<String>) -> Result<bool> {
        match line {
            Some(l) => {
                self.process_line(&l)?;
                Ok(false)
            }
            None => {
                tracing::info!("Channel closed");
                Ok(true)
            }
        }
    }

    /// Clean up the firewall chain on shutdown.
    pub fn cleanup(&self) -> Result<()> {
        self.firewall
            .cleanup(&self.config.chain_name, self.config.port)
    }

    /// Manually unban an IP.
    pub fn manual_unban(&mut self, ip: IpAddr) -> Result<bool> {
        let was_banned = self.tracker.unban(ip);
        if was_banned {
            execute_unban(ip, self.firewall.as_ref(), &self.config)?;
        }
        Ok(was_banned)
    }

    /// List all currently banned IPs.
    pub fn list_bans(&self) -> Vec<&crate::types::BanRecord> {
        self.tracker.banned_ips()
    }

    /// Get engine statistics.
    pub fn stats(&self) -> EngineStats {
        EngineStats {
            active_bans: self.tracker.ban_count(),
            tracking: self.tracker.tracking_count(),
        }
    }
}

/// Restore persisted state into tracker.
fn restore_state(tracker: &mut Tracker, config: &SentinelConfig) -> Result<()> {
    let state = persistence::load_state(&config.state_path)?;
    if let Some(s) = state {
        tracker.restore(s.bans, s.failures);
    }
    Ok(())
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::firewall::{FirewallOp, MockFirewall};

    fn test_config() -> SentinelConfig {
        let dir = tempfile::tempdir().ok();
        let state_path = dir
            .as_ref()
            .map(|d| d.path().join("state.json"))
            .unwrap_or_else(|| "/tmp/sentinel-test-state.json".into());
        SentinelConfig {
            max_retry: 3,
            ban_time_secs: 3600,
            find_time_secs: 600,
            state_path,
            ..SentinelConfig::default()
        }
    }

    #[test]
    fn engine_creation() {
        let config = test_config();
        let fw = Arc::new(MockFirewall::default());
        assert!(Engine::new(config, fw).is_ok());
    }

    #[test]
    fn process_line_bans_after_threshold() {
        let config = test_config();
        let fw = Arc::new(MockFirewall::default());
        let mut engine = match Engine::new(config, fw.clone()) {
            Ok(e) => e,
            Err(_) => return,
        };

        let lines = [
            "Feb  4 14:23:01 host sshd[100]: Failed password for root from 10.0.0.1 port 22 ssh2",
            "Feb  4 14:23:02 host sshd[100]: Failed password for root from 10.0.0.1 port 22 ssh2",
            "Feb  4 14:23:03 host sshd[100]: Failed password for root from 10.0.0.1 port 22 ssh2",
        ];
        for line in &lines {
            let _ = engine.process_line(line);
        }

        let ops = fw.operations.lock().unwrap_or_else(|e| e.into_inner());
        let has_ban = ops.iter().any(|op| matches!(op, FirewallOp::Ban { .. }));
        assert!(has_ban);
    }

    #[test]
    fn process_line_ignores_non_matching() {
        let config = test_config();
        let fw = Arc::new(MockFirewall::default());
        let mut engine = match Engine::new(config, fw.clone()) {
            Ok(e) => e,
            Err(_) => return,
        };

        let line = "Feb  4 14:23:01 host sshd[100]: Accepted publickey for user from 10.0.0.1";
        assert!(engine.process_line(line).is_ok());

        let ops = fw.operations.lock().unwrap_or_else(|e| e.into_inner());
        assert!(ops.is_empty());
    }

    #[test]
    fn engine_stats_initial() {
        let config = test_config();
        let fw = Arc::new(MockFirewall::default());
        let engine = match Engine::new(config, fw) {
            Ok(e) => e,
            Err(_) => return,
        };
        let stats = engine.stats();
        assert_eq!(stats.active_bans, 0);
        assert_eq!(stats.tracking, 0);
    }
}
