//! Integration tests — tempfile-based pipeline: log → watcher → parser → tracker → MockFirewall.

use std::io::Write;
use std::net::IpAddr;
use std::sync::Arc;

use nexcore_chrono::{DateTime, Duration};
use nexcore_sentinel::config::SentinelConfig;
use nexcore_sentinel::engine::Engine;
use nexcore_sentinel::firewall::{FirewallOp, MockFirewall};

fn parse_ip(s: &str) -> IpAddr {
    s.parse()
        .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST))
}

fn test_config(state_path: std::path::PathBuf) -> SentinelConfig {
    SentinelConfig {
        max_retry: 3,
        ban_time_secs: 3600,
        find_time_secs: 600,
        state_path,
        ..SentinelConfig::default()
    }
}

#[test]
fn full_pipeline_ban_flow() {
    let dir = match tempfile::tempdir() {
        Ok(d) => d,
        Err(_) => return,
    };
    let state_path = dir.path().join("state.json");
    let config = test_config(state_path);

    let fw = Arc::new(MockFirewall::default());
    let mut engine = match Engine::new(config, fw.clone()) {
        Ok(e) => e,
        Err(_) => return,
    };

    // Simulate 3 failed password lines from the same IP
    let lines = [
        "Feb  4 14:23:01 host sshd[100]: Failed password for root from 203.0.113.50 port 22 ssh2",
        "Feb  4 14:23:02 host sshd[100]: Failed password for root from 203.0.113.50 port 22 ssh2",
        "Feb  4 14:23:03 host sshd[100]: Failed password for root from 203.0.113.50 port 22 ssh2",
    ];

    for line in &lines {
        let _ = engine.process_line(line);
    }

    // Verify the ban was issued
    let ops = fw.operations.lock().unwrap_or_else(|e| e.into_inner());
    let ban_count = ops
        .iter()
        .filter(|op| matches!(op, FirewallOp::Ban { .. }))
        .count();
    assert_eq!(ban_count, 1, "Expected exactly 1 ban");

    // Verify the correct IP was banned
    let banned_ip = ops.iter().find_map(|op| {
        if let FirewallOp::Ban { ip, .. } = op {
            Some(*ip)
        } else {
            None
        }
    });
    assert_eq!(banned_ip, Some(parse_ip("203.0.113.50")));
}

#[test]
fn different_ips_tracked_independently() {
    let dir = match tempfile::tempdir() {
        Ok(d) => d,
        Err(_) => return,
    };
    let config = test_config(dir.path().join("state.json"));

    let fw = Arc::new(MockFirewall::default());
    let mut engine = match Engine::new(config, fw.clone()) {
        Ok(e) => e,
        Err(_) => return,
    };

    // 2 failures from IP A, 2 from IP B — neither should be banned
    let lines = [
        "Feb  4 14:23:01 host sshd[100]: Failed password for root from 10.0.0.1 port 22 ssh2",
        "Feb  4 14:23:02 host sshd[100]: Failed password for root from 10.0.0.1 port 22 ssh2",
        "Feb  4 14:23:03 host sshd[100]: Failed password for admin from 10.0.0.2 port 22 ssh2",
        "Feb  4 14:23:04 host sshd[100]: Failed password for admin from 10.0.0.2 port 22 ssh2",
    ];

    for line in &lines {
        let _ = engine.process_line(line);
    }

    let ops = fw.operations.lock().unwrap_or_else(|e| e.into_inner());
    let ban_count = ops
        .iter()
        .filter(|op| matches!(op, FirewallOp::Ban { .. }))
        .count();
    assert_eq!(ban_count, 0, "No IP should be banned with only 2 failures");
}

#[test]
fn whitelisted_ip_never_banned() {
    let dir = match tempfile::tempdir() {
        Ok(d) => d,
        Err(_) => return,
    };
    let config = test_config(dir.path().join("state.json"));

    let fw = Arc::new(MockFirewall::default());
    let mut engine = match Engine::new(config, fw.clone()) {
        Ok(e) => e,
        Err(_) => return,
    };

    // 10 failures from localhost (whitelisted)
    for i in 1..=10 {
        let line = format!(
            "Feb  4 14:23:{i:02} host sshd[100]: Failed password for root from 127.0.0.1 port 22 ssh2"
        );
        let _ = engine.process_line(&line);
    }

    let ops = fw.operations.lock().unwrap_or_else(|e| e.into_inner());
    assert!(ops.is_empty(), "Whitelisted IPs should never be banned");
}

#[test]
fn invalid_user_also_triggers_ban() {
    let dir = match tempfile::tempdir() {
        Ok(d) => d,
        Err(_) => return,
    };
    let config = test_config(dir.path().join("state.json"));

    let fw = Arc::new(MockFirewall::default());
    let mut engine = match Engine::new(config, fw.clone()) {
        Ok(e) => e,
        Err(_) => return,
    };

    // Mix of Invalid user and Failed password from same IP
    let lines = [
        "Feb  4 14:23:01 host sshd[100]: Invalid user hacker from 198.51.100.10 port 55555",
        "Feb  4 14:23:02 host sshd[100]: Failed password for root from 198.51.100.10 port 22 ssh2",
        "Feb  4 14:23:03 host sshd[100]: Invalid user admin from 198.51.100.10 port 55556",
    ];

    for line in &lines {
        let _ = engine.process_line(line);
    }

    let ops = fw.operations.lock().unwrap_or_else(|e| e.into_inner());
    let ban_count = ops
        .iter()
        .filter(|op| matches!(op, FirewallOp::Ban { .. }))
        .count();
    assert_eq!(ban_count, 1);
}

#[test]
fn non_matching_lines_ignored() {
    let dir = match tempfile::tempdir() {
        Ok(d) => d,
        Err(_) => return,
    };
    let config = test_config(dir.path().join("state.json"));

    let fw = Arc::new(MockFirewall::default());
    let mut engine = match Engine::new(config, fw.clone()) {
        Ok(e) => e,
        Err(_) => return,
    };

    let lines = [
        "Feb  4 14:23:01 host sshd[100]: Accepted publickey for user from 10.0.0.1 port 22 ssh2",
        "Feb  4 14:23:02 host CRON[200]: (root) CMD (test -x /usr/sbin/anacron)",
        "",
        "Feb  4 14:23:03 host systemd[1]: Started Session 42 of user root.",
    ];

    for line in &lines {
        let result = engine.process_line(line);
        assert!(result.is_ok());
    }

    let ops = fw.operations.lock().unwrap_or_else(|e| e.into_inner());
    assert!(ops.is_empty());
}

#[test]
fn state_persistence_round_trip() {
    let dir = match tempfile::tempdir() {
        Ok(d) => d,
        Err(_) => return,
    };
    let state_path = dir.path().join("state.json");
    let mut config = test_config(state_path.clone());
    // Use a very long ban time to ensure it doesn't expire between save and load
    config.ban_time_secs = 86400; // 24 hours

    // Build state directly: create a ban record with current time
    let now = DateTime::now();
    let ban = nexcore_sentinel::types::BanRecord {
        ip: parse_ip("10.0.0.99"),
        banned_at: now,
        expires_at: now + Duration::seconds(86400),
        failure_count: 3,
    };
    let state = nexcore_sentinel::types::SentinelState {
        bans: vec![ban],
        failures: vec![],
    };

    // Save state manually
    let save_result = nexcore_sentinel::persistence::save_state(&state, &state_path);
    assert!(save_result.is_ok(), "State save should succeed");
    assert!(state_path.exists(), "State file should exist");

    // Load into engine: should restore the ban
    let fw = Arc::new(MockFirewall::default());
    let engine = match Engine::new(config, fw) {
        Ok(e) => e,
        Err(_) => return,
    };

    let stats = engine.stats();
    assert_eq!(stats.active_bans, 1, "Ban should survive restart");
}
