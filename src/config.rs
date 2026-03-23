//! Configuration for nexcore-sentinel.
//!
//! Defaults match the current fail2ban `jail.local` [sshd] section.
//! Loaded from TOML; every field has a serde default.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{Result, SentinelError};

/// Tier: T3 — Complete sentinel configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SentinelConfig {
    /// Maximum failed attempts before banning.
    pub max_retry: u32,

    /// Ban duration in seconds (24h default).
    pub ban_time_secs: u64,

    /// Sliding window in seconds (10m default).
    pub find_time_secs: u64,

    /// Path to the auth log file.
    pub log_path: PathBuf,

    /// Whitelisted CIDRs (never banned).
    pub whitelist: Vec<String>,

    /// iptables chain name.
    pub chain_name: String,

    /// iptables block action (REJECT or DROP).
    pub block_type: String,

    /// State persistence file path.
    pub state_path: PathBuf,

    /// Protected port (SSH default).
    pub port: u16,

    /// How often to check for expired bans, in seconds.
    pub tick_interval_secs: u64,

    /// Config file path (not serialized, set at load time).
    #[serde(skip)]
    pub config_path: Option<PathBuf>,
}

impl Default for SentinelConfig {
    fn default() -> Self {
        Self {
            max_retry: 3,
            ban_time_secs: 86400, // 24 hours
            find_time_secs: 600,  // 10 minutes
            log_path: PathBuf::from("/var/log/auth.log"),
            whitelist: vec!["127.0.0.1/8".to_string(), "::1/128".to_string()],
            chain_name: "f2b-sentinel".to_string(),
            block_type: "REJECT".to_string(),
            state_path: PathBuf::from("/var/lib/nexcore-sentinel/state.json"),
            port: 22,
            tick_interval_secs: 60,
            config_path: None,
        }
    }
}

impl SentinelConfig {
    /// Load config from a TOML file. Falls back to defaults if file doesn't exist.
    ///
    /// # Errors
    /// Returns `SentinelError::Io` if the file exists but cannot be read,
    /// or `SentinelError::Toml` if the TOML is malformed.
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            tracing::info!(
                "Config file not found at {}, using defaults",
                path.display()
            );
            return Ok(Self::default());
        }

        let content = std::fs::read_to_string(path).map_err(|e| SentinelError::Io {
            path: path.to_path_buf(),
            source: e,
        })?;

        let mut config: Self = toml::from_str(&content)?;
        config.config_path = Some(path.to_path_buf());
        config.validate()?;
        Ok(config)
    }

    /// Validate configuration values.
    ///
    /// # Errors
    /// Returns `SentinelError::Config` if any value is out of range.
    pub fn validate(&self) -> Result<()> {
        if self.max_retry == 0 {
            return Err(SentinelError::Config("max_retry must be at least 1".into()));
        }
        if self.ban_time_secs == 0 {
            return Err(SentinelError::Config(
                "ban_time_secs must be greater than 0".into(),
            ));
        }
        if self.find_time_secs == 0 {
            return Err(SentinelError::Config(
                "find_time_secs must be greater than 0".into(),
            ));
        }
        if self.chain_name.is_empty() {
            return Err(SentinelError::Config("chain_name must not be empty".into()));
        }
        let valid_actions = ["REJECT", "DROP"];
        if !valid_actions.contains(&self.block_type.as_str()) {
            return Err(SentinelError::Config(format!(
                "block_type must be one of: {valid_actions:?}"
            )));
        }
        Ok(())
    }

    /// Generate a sample TOML config string with defaults.
    #[must_use]
    pub fn sample_toml() -> String {
        let cfg = Self::default();
        // Safe: Default config is always valid TOML-serializable
        toml::to_string_pretty(&cfg).unwrap_or_default()
    }
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_matches_fail2ban() {
        let cfg = SentinelConfig::default();
        assert_eq!(cfg.max_retry, 3);
        assert_eq!(cfg.ban_time_secs, 86400);
        assert_eq!(cfg.find_time_secs, 600);
        assert_eq!(cfg.log_path, PathBuf::from("/var/log/auth.log"));
        assert_eq!(cfg.chain_name, "f2b-sentinel");
        assert_eq!(cfg.block_type, "REJECT");
        assert_eq!(cfg.port, 22);
    }

    #[test]
    fn validate_rejects_zero_retry() {
        let mut cfg = SentinelConfig::default();
        cfg.max_retry = 0;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn validate_rejects_bad_block_type() {
        let mut cfg = SentinelConfig::default();
        cfg.block_type = "ACCEPT".to_string();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn validate_accepts_defaults() {
        let cfg = SentinelConfig::default();
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn sample_toml_is_parseable() {
        let toml_str = SentinelConfig::sample_toml();
        let parsed: std::result::Result<SentinelConfig, _> = toml::from_str(&toml_str);
        assert!(parsed.is_ok());
    }

    #[test]
    fn load_nonexistent_returns_defaults() {
        let path = Path::new("/tmp/nonexistent-sentinel-config-12345.toml");
        let cfg = SentinelConfig::load(path);
        assert!(cfg.is_ok());
    }
}
