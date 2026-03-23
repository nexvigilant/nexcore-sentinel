//! # NexVigilant Core — sentinel
//!
//! Pure-Rust SSH brute-force protection daemon — a fail2ban replacement.
//!
//! Watches auth logs for failed SSH attempts, tracks failures per IP
//! using a sliding window, and bans offenders via iptables.
//!
//! ## Primitive Foundation
//!
//! | Primitive | Manifestation |
//! |-----------|---------------|
//! | T1: Sequence (σ) | Auth log lines streamed via inotify |
//! | T1: Mapping (μ) | IP → failure timestamps (sliding window) |
//! | T1: State (ς) | Ban records, failure counts, persistence |
//! | T1: Exists (∃) | IP-in-banlist check, whitelist membership |
//!
//! ## Architecture
//!
//! ```text
//! auth.log → [watcher] → [parser] → [tracker] → [firewall]
//!                                       ↕
//!                                  [persistence]
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

pub mod config;
pub mod engine;
pub mod error;
pub mod firewall;
pub mod grounding;
pub mod parser;
pub mod persistence;
pub mod test_helpers;
pub mod tracker;
pub mod types;
pub mod watcher;
pub mod whitelist;

/// Convenience prelude for common imports.
pub mod prelude {
    pub use crate::config::SentinelConfig;
    pub use crate::engine::{Engine, EngineStats};
    pub use crate::error::{Result, SentinelError};
    pub use crate::firewall::{FirewallBackend, IptablesFirewall, MockFirewall};
    pub use crate::parser::parse_line;
    pub use crate::tracker::Tracker;
    pub use crate::types::{
        AuthEvent, BanDuration, BanRecord, EngineAction, FindWindow, SentinelState,
    };
    pub use crate::whitelist::Whitelist;
}
