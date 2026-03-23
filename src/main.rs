//! nexcore-sentinel — Rust fail2ban replacement binary.
//!
//! ## Usage
//!
//! ```bash
//! nexcore-sentinel run                    # Start daemon
//! nexcore-sentinel run -c /etc/sentinel.toml  # With config
//! nexcore-sentinel status                 # Show stats
//! nexcore-sentinel list                   # List banned IPs
//! nexcore-sentinel unban 10.0.0.1         # Unban an IP
//! nexcore-sentinel sample-config          # Print sample TOML
//! ```

#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use nexcore_error::Context;
use tracing_subscriber::EnvFilter;

use nexcore_sentinel::config::SentinelConfig;
use nexcore_sentinel::engine::Engine;
use nexcore_sentinel::firewall::IptablesFirewall;

/// nexcore-sentinel: Rust-powered SSH brute-force protection.
#[derive(Parser)]
#[command(name = "nexcore-sentinel", version, about)]
struct Cli {
    /// Path to config file (TOML).
    #[arg(short, long, default_value = "/etc/nexcore-sentinel/sentinel.toml")]
    config: PathBuf,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the sentinel daemon.
    Run,
    /// Show current status.
    Status,
    /// List banned IPs.
    List,
    /// Unban a specific IP.
    Unban {
        /// IP address to unban.
        ip: IpAddr,
    },
    /// Print a sample configuration file.
    SampleConfig,
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_timer(tracing_subscriber::fmt::time::uptime())
        .init();
}

fn load_config(path: &std::path::Path) -> nexcore_error::Result<SentinelConfig> {
    SentinelConfig::load(path).context("failed to load config")
}

async fn cmd_run(config: SentinelConfig) -> nexcore_error::Result<()> {
    let firewall = Arc::new(IptablesFirewall);
    let mut engine = Engine::new(config.clone(), firewall).context("engine init")?;

    engine.init_firewall().context("firewall init")?;
    tracing::info!("Firewall chain initialized: {}", config.chain_name);

    let (tx, rx) = tokio::sync::mpsc::channel(1024);

    // Spawn watcher thread (blocking I/O)
    let log_path = config.log_path.clone();
    tokio::task::spawn_blocking(move || {
        run_watcher(log_path, tx);
    });

    // Install Ctrl+C handler for graceful shutdown
    let chain = config.chain_name.clone();
    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        tracing::info!("Shutting down...");
    });

    engine.run(rx).await.context("engine run")?;
    engine.cleanup().context("firewall cleanup")?;
    Ok(())
}

fn run_watcher(log_path: PathBuf, tx: tokio::sync::mpsc::Sender<String>) {
    let (std_tx, std_rx) = std::sync::mpsc::channel();
    let mut watcher = match nexcore_sentinel::watcher::LogWatcher::new(&log_path, std_tx) {
        Ok(w) => w,
        Err(e) => {
            tracing::error!("Failed to create watcher: {e}");
            return;
        }
    };

    // Bridge std::sync::mpsc → tokio::sync::mpsc in a separate thread
    let bridge_tx = tx.clone();
    std::thread::spawn(move || {
        for line in std_rx {
            if bridge_tx.blocking_send(line).is_err() {
                break;
            }
        }
    });

    if let Err(e) = watcher.watch_blocking() {
        tracing::error!("Watcher error: {e}");
    }
}

fn cmd_status(config: &SentinelConfig) -> nexcore_error::Result<()> {
    let firewall = Arc::new(IptablesFirewall);
    let engine = Engine::new(config.clone(), firewall).context("engine init")?;
    let stats = engine.stats();
    println!("nexcore-sentinel status:");
    println!("  Active bans:  {}", stats.active_bans);
    println!("  Tracking IPs: {}", stats.tracking);
    println!(
        "  Config:       {}",
        config
            .config_path
            .as_ref()
            .map_or("default", |p| p.to_str().unwrap_or("?"))
    );
    println!("  Chain:        {}", config.chain_name);
    println!("  Log:          {}", config.log_path.display());
    Ok(())
}

fn cmd_list(config: &SentinelConfig) -> nexcore_error::Result<()> {
    let firewall = Arc::new(IptablesFirewall);
    let engine = Engine::new(config.clone(), firewall).context("engine init")?;
    let bans = engine.list_bans();

    if bans.is_empty() {
        println!("No active bans.");
        return Ok(());
    }

    println!(
        "{:<20} {:<25} {:<25} Failures",
        "IP", "Banned At", "Expires At"
    );
    println!("{}", "-".repeat(80));
    for ban in bans {
        println!(
            "{:<20} {:<25} {:<25} {}",
            ban.ip,
            ban.banned_at
                .format("%Y-%m-%d %H:%M:%S")
                .unwrap_or_default(),
            ban.expires_at
                .format("%Y-%m-%d %H:%M:%S")
                .unwrap_or_default(),
            ban.failure_count,
        );
    }
    Ok(())
}

fn cmd_unban(config: &SentinelConfig, ip: IpAddr) -> nexcore_error::Result<()> {
    let firewall = Arc::new(IptablesFirewall);
    let mut engine = Engine::new(config.clone(), firewall).context("engine init")?;

    if engine.manual_unban(ip).context("unban")? {
        println!("Unbanned {ip}");
    } else {
        println!("{ip} was not banned");
    }
    Ok(())
}

#[tokio::main]
async fn main() -> nexcore_error::Result<()> {
    init_tracing();
    let cli = Cli::parse();
    let config = load_config(&cli.config)?;

    match cli.command {
        Commands::Run => cmd_run(config).await,
        Commands::Status => cmd_status(&config),
        Commands::List => cmd_list(&config),
        Commands::Unban { ip } => cmd_unban(&config, ip),
        Commands::SampleConfig => {
            println!("{}", SentinelConfig::sample_toml());
            Ok(())
        }
    }
}
