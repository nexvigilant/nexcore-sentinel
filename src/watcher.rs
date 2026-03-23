//! Log file watcher — notify-based tail with rotation handling.
//!
//! ## Primitive Foundation
//!
//! | Primitive | Manifestation |
//! |-----------|---------------|
//! | T1: Sequence (σ) | New lines streamed via channel |
//! | T1: State (ς) | File position, inode tracking |

use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::mpsc;

use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};

use crate::error::{Result, SentinelError};

// ── Pure helper functions (flat, max 2 levels) ─────────────────────

/// Get file length, returning 0 on any error.
fn file_len(path: &Path) -> u64 {
    std::fs::metadata(path).map(|m| m.len()).unwrap_or(0)
}

/// Open file for reading.
fn open_file(path: &Path) -> Result<std::fs::File> {
    std::fs::File::open(path).map_err(|e| SentinelError::Io {
        path: path.to_path_buf(),
        source: e,
    })
}

/// Seek a reader to a byte offset.
fn seek_reader(reader: &mut BufReader<std::fs::File>, pos: u64, path: &Path) -> Result<()> {
    reader
        .seek(SeekFrom::Start(pos))
        .map_err(|e| SentinelError::Io {
            path: path.to_path_buf(),
            source: e,
        })?;
    Ok(())
}

/// Read one line from reader. Returns bytes read (0 = EOF).
fn read_one_line(reader: &mut BufReader<std::fs::File>, buf: &mut String) -> usize {
    buf.clear();
    reader.read_line(buf).unwrap_or(0)
}

/// Send a non-empty trimmed line through the channel.
fn send_line(line: &str, tx: &mpsc::Sender<String>) -> Result<()> {
    let trimmed = line.trim_end();
    if trimmed.is_empty() {
        return Ok(());
    }
    tx.send(trimmed.to_string())
        .map_err(|_| SentinelError::Channel("receiver dropped".into()))
}

/// Check if a notify event is relevant to our watched file.
fn is_relevant_event(event: &Event, path: &Path) -> bool {
    let touches = event.paths.iter().any(|p| p == path);
    let writable = matches!(event.kind, EventKind::Modify(_) | EventKind::Create(_));
    touches && writable
}

/// Get parent directory of a path, defaulting to /var/log.
fn parent_dir(path: &Path) -> &Path {
    path.parent().unwrap_or(Path::new("/var/log"))
}

/// Detect log rotation: new file is smaller than our recorded position.
fn detect_rotation(current_len: u64, position: u64) -> bool {
    current_len < position
}

// ── LogWatcher struct ──────────────────────────────────────────────

/// Tier: T3 — Watches an auth log file and streams new lines.
pub struct LogWatcher {
    path: PathBuf,
    tx: mpsc::Sender<String>,
    position: u64,
}

impl LogWatcher {
    /// Create a new watcher. Starts at end of file (only new lines).
    pub fn new(path: &Path, tx: mpsc::Sender<String>) -> Result<Self> {
        Ok(Self {
            path: path.to_path_buf(),
            tx,
            position: file_len(path),
        })
    }

    /// Read new lines from the file since last position.
    fn read_new_lines(&mut self) -> Result<()> {
        if detect_rotation(file_len(&self.path), self.position) {
            tracing::info!("Log rotation detected, resetting to 0");
            self.position = 0;
        }

        let file = open_file(&self.path)?;
        let mut reader = BufReader::new(file);
        seek_reader(&mut reader, self.position, &self.path)?;

        self.position += self.drain_reader(&mut reader)?;
        Ok(())
    }

    /// Read all available lines from reader, sending through channel.
    fn drain_reader(&self, reader: &mut BufReader<std::fs::File>) -> Result<u64> {
        let mut bytes_total: u64 = 0;
        let mut buf = String::new();
        loop {
            let n = read_one_line(reader, &mut buf);
            if n == 0 {
                break;
            }
            bytes_total += n as u64;
            send_line(&buf, &self.tx)?;
        }
        Ok(bytes_total)
    }

    /// Start watching with notify. Blocks the calling thread.
    pub fn watch_blocking(&mut self) -> Result<()> {
        let (event_tx, event_rx) = mpsc::channel();
        let mut watcher = self.create_notify_watcher(event_tx)?;
        self.attach_watcher(&mut watcher)?;

        tracing::info!("Watching {} for changes", self.path.display());
        self.event_loop(event_rx)
    }

    /// Create a notify watcher.
    fn create_notify_watcher(
        &self,
        tx: mpsc::Sender<std::result::Result<Event, notify::Error>>,
    ) -> Result<RecommendedWatcher> {
        Watcher::new(tx, notify::Config::default())
            .map_err(|e| SentinelError::Watcher(format!("create: {e}")))
    }

    /// Attach watcher to parent directory.
    fn attach_watcher(&self, watcher: &mut RecommendedWatcher) -> Result<()> {
        let dir = parent_dir(&self.path);
        watcher
            .watch(dir, RecursiveMode::NonRecursive)
            .map_err(|e| SentinelError::Watcher(format!("watch {}: {e}", dir.display())))
    }

    /// Process notify events until channel closes.
    fn event_loop(
        &mut self,
        rx: mpsc::Receiver<std::result::Result<Event, notify::Error>>,
    ) -> Result<()> {
        for event_result in rx {
            self.handle_event(event_result)?;
        }
        Ok(())
    }

    /// Handle a single notify event.
    fn handle_event(&mut self, result: std::result::Result<Event, notify::Error>) -> Result<()> {
        let event = match result {
            Ok(e) => e,
            Err(e) => {
                tracing::warn!("Watch error: {e}");
                return Ok(());
            }
        };
        if is_relevant_event(&event, &self.path) {
            self.read_new_lines()?;
        }
        Ok(())
    }
}

/// Create a watcher with an mpsc channel, returning both ends.
pub fn create_watcher(path: &Path) -> Result<(LogWatcher, mpsc::Receiver<String>)> {
    let (tx, rx) = mpsc::channel();
    let watcher = LogWatcher::new(path, tx)?;
    Ok((watcher, rx))
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn temp_log() -> Option<(tempfile::TempDir, PathBuf)> {
        let dir = tempfile::tempdir().ok()?;
        let path = dir.path().join("test.log");
        std::fs::File::create(&path).ok()?;
        Some((dir, path))
    }

    fn append(path: &Path, text: &str) {
        let mut f = match std::fs::OpenOptions::new().append(true).open(path) {
            Ok(f) => f,
            Err(_) => return,
        };
        let _ = write!(f, "{text}");
    }

    #[test]
    fn read_new_lines_from_file() {
        let (_dir, path) = match temp_log() {
            Some(v) => v,
            None => return,
        };
        std::fs::write(&path, "initial\n").ok();

        let (tx, rx) = mpsc::channel();
        let mut w = match LogWatcher::new(&path, tx) {
            Ok(w) => w,
            Err(_) => return,
        };
        assert!(w.position > 0);

        append(&path, "line1\nline2\n");
        assert!(w.read_new_lines().is_ok());
        assert_eq!(rx.try_recv().ok().as_deref(), Some("line1"));
        assert_eq!(rx.try_recv().ok().as_deref(), Some("line2"));
    }

    #[test]
    fn detects_log_rotation() {
        let (_dir, path) = match temp_log() {
            Some(v) => v,
            None => return,
        };
        let big: String = (0..100).map(|i| format!("old {i}\n")).collect();
        std::fs::write(&path, &big).ok();

        let (tx, rx) = mpsc::channel();
        let mut w = match LogWatcher::new(&path, tx) {
            Ok(w) => w,
            Err(_) => return,
        };
        assert!(w.position > 0);

        std::fs::write(&path, "rotated\n").ok();
        assert!(w.read_new_lines().is_ok());
        assert_eq!(rx.try_recv().ok().as_deref(), Some("rotated"));
    }

    #[test]
    fn create_watcher_ok() {
        let (_dir, path) = match temp_log() {
            Some(v) => v,
            None => return,
        };
        assert!(create_watcher(&path).is_ok());
    }

    #[test]
    fn detect_rotation_logic() {
        assert!(detect_rotation(10, 100));
        assert!(!detect_rotation(100, 10));
        assert!(!detect_rotation(50, 50));
    }
}
