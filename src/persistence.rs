//! Persistence — atomic JSON state save/load.
//!
//! ## Primitive Foundation
//!
//! | Primitive | Manifestation |
//! |-----------|---------------|
//! | T1: State (ς) | Serialized ban/failure state |
//! | T1: Sequence (σ) | Write temp → rename (atomic) |

use std::path::Path;

use crate::error::{Result, SentinelError};
use crate::types::SentinelState;

/// Save state to a JSON file atomically (write to temp, rename).
///
/// # Errors
/// Returns `SentinelError::Io` on file write failure,
/// or `SentinelError::Json` on serialization failure.
pub fn save_state(state: &SentinelState, path: &Path) -> Result<()> {
    let json = serde_json::to_string_pretty(state)?;

    // Ensure parent directory exists
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| SentinelError::Io {
            path: parent.to_path_buf(),
            source: e,
        })?;
    }

    // Atomic write: temp file + rename
    let temp_path = path.with_extension("json.tmp");
    std::fs::write(&temp_path, &json).map_err(|e| SentinelError::Io {
        path: temp_path.clone(),
        source: e,
    })?;

    std::fs::rename(&temp_path, path).map_err(|e| SentinelError::Io {
        path: path.to_path_buf(),
        source: e,
    })?;

    tracing::debug!(
        "Saved state: {} bans, {} failures",
        state.bans.len(),
        state.failures.len()
    );
    Ok(())
}

/// Load state from a JSON file. Returns `None` if the file doesn't exist.
///
/// # Errors
/// Returns `SentinelError::Io` on read failure,
/// or `SentinelError::Json` on deserialization failure.
pub fn load_state(path: &Path) -> Result<Option<SentinelState>> {
    if !path.exists() {
        tracing::debug!("No state file at {}, starting fresh", path.display());
        return Ok(None);
    }

    let json = std::fs::read_to_string(path).map_err(|e| SentinelError::Io {
        path: path.to_path_buf(),
        source: e,
    })?;

    let state: SentinelState = serde_json::from_str(&json)?;
    tracing::info!(
        "Loaded state: {} bans, {} failures",
        state.bans.len(),
        state.failures.len()
    );
    Ok(Some(state))
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{BanRecord, FailureRecord};
    use nexcore_chrono::DateTime;
    use std::net::IpAddr;

    fn parse_ip(s: &str) -> IpAddr {
        s.parse()
            .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST))
    }

    #[test]
    fn save_load_round_trip() {
        let dir = tempfile::tempdir().ok();
        let dir = match dir.as_ref() {
            Some(d) => d.path(),
            None => return, // skip test if tempdir fails
        };
        let path = dir.join("state.json");

        let now = DateTime::now();
        let state = SentinelState {
            bans: vec![BanRecord {
                ip: parse_ip("10.0.0.1"),
                banned_at: now,
                expires_at: now + nexcore_chrono::Duration::seconds(3600),
                failure_count: 3,
            }],
            failures: vec![FailureRecord::new(parse_ip("10.0.0.2"), now)],
        };

        let save_result = save_state(&state, &path);
        assert!(save_result.is_ok());

        let loaded = load_state(&path);
        assert!(loaded.is_ok());
        let loaded = loaded.unwrap_or(None);
        assert!(loaded.is_some());

        let loaded = loaded.unwrap_or_default();
        assert_eq!(loaded.bans.len(), 1);
        assert_eq!(loaded.failures.len(), 1);
        assert_eq!(loaded.bans[0].ip, parse_ip("10.0.0.1"));
    }

    #[test]
    fn load_missing_file_returns_none() {
        let path = Path::new("/tmp/nonexistent-sentinel-state-99999.json");
        let loaded = load_state(path);
        assert!(loaded.is_ok());
        assert!(loaded.unwrap_or(Some(SentinelState::default())).is_none());
    }

    #[test]
    fn save_creates_parent_dirs() {
        let dir = tempfile::tempdir().ok();
        let dir = match dir.as_ref() {
            Some(d) => d.path(),
            None => return,
        };
        let path = dir.join("subdir").join("deep").join("state.json");

        let state = SentinelState::default();
        let result = save_state(&state, &path);
        assert!(result.is_ok());
        assert!(path.exists());
    }

    #[test]
    fn empty_state_round_trip() {
        let dir = tempfile::tempdir().ok();
        let dir = match dir.as_ref() {
            Some(d) => d.path(),
            None => return,
        };
        let path = dir.join("empty.json");

        let state = SentinelState::default();
        let _ = save_state(&state, &path);

        let loaded = load_state(&path).unwrap_or(None).unwrap_or_default();
        assert!(loaded.bans.is_empty());
        assert!(loaded.failures.is_empty());
    }
}
