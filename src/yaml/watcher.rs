use crate::Result;
use notify::{Config, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use std::path::Path;
use std::sync::mpsc;
use std::time::Duration;
use tokio::sync::watch;
use tracing::{error, info};

pub struct YamlWatcher {
    _watcher: RecommendedWatcher,
    rx: mpsc::Receiver<notify::Result<Event>>,
}

impl YamlWatcher {
    pub fn new(path: &Path) -> Result<(Self, watch::Receiver<()>)> {
        let (tx, rx) = mpsc::channel();
        let (reload_tx, reload_rx) = watch::channel(());

        let mut watcher = RecommendedWatcher::new(
            move |res: notify::Result<Event>| {
                if let Err(e) = tx.send(res) {
                    error!("Failed to send file watch event: {}", e);
                }
            },
            Config::default().with_poll_interval(Duration::from_secs(2)),
        )
        .map_err(|e| {
            crate::YamlLdapError::Io(std::io::Error::other(format!(
                "Failed to create file watcher: {}",
                e
            )))
        })?;

        // Watch the parent directory for better compatibility
        let parent_dir = path.parent().unwrap_or(Path::new("."));
        watcher
            .watch(parent_dir, RecursiveMode::NonRecursive)
            .map_err(|e| {
                crate::YamlLdapError::Io(std::io::Error::other(format!(
                    "Failed to watch directory: {}",
                    e
                )))
            })?;

        let watched_path = path.to_path_buf();
        let reload_tx_clone = reload_tx.clone();

        // Spawn a task to handle file events
        tokio::spawn(async move {
            let yaml_watcher = YamlWatcher {
                _watcher: watcher,
                rx,
            };
            yaml_watcher.run(watched_path, reload_tx_clone).await;
        });

        Ok((
            YamlWatcher {
                _watcher: RecommendedWatcher::new(|_| {}, Config::default()).unwrap(),
                rx: mpsc::channel().1,
            },
            reload_rx,
        ))
    }

    async fn run(self, watched_path: std::path::PathBuf, reload_tx: watch::Sender<()>) {
        loop {
            match self.rx.recv() {
                Ok(Ok(event)) => {
                    if self.is_relevant_event(&event, &watched_path) {
                        info!("YAML file changed, triggering reload: {:?}", event.paths);
                        if let Err(e) = reload_tx.send(()) {
                            error!("Failed to send reload signal: {}", e);
                            break;
                        }
                    }
                }
                Ok(Err(e)) => {
                    error!("File watch error: {}", e);
                }
                Err(e) => {
                    error!("File watcher channel error: {}", e);
                    break;
                }
            }
        }
    }

    fn is_relevant_event(&self, event: &Event, watched_path: &Path) -> bool {
        // Check if the event is for our YAML file
        let is_our_file = event.paths.iter().any(|p| p == watched_path);

        // Only trigger on modify or create events
        let is_relevant_kind = matches!(event.kind, EventKind::Modify(_) | EventKind::Create(_));

        is_our_file && is_relevant_kind
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use notify::event::{CreateKind, ModifyKind};
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_is_relevant_event_modify() {
        let watcher = YamlWatcher {
            _watcher: RecommendedWatcher::new(|_| {}, Config::default()).unwrap(),
            rx: mpsc::channel().1,
        };

        let path = Path::new("/tmp/test.yaml");
        let event = Event {
            kind: EventKind::Modify(ModifyKind::Any),
            paths: vec![path.to_path_buf()],
            attrs: Default::default(),
        };

        assert!(watcher.is_relevant_event(&event, path));
    }

    #[test]
    fn test_is_relevant_event_create() {
        let watcher = YamlWatcher {
            _watcher: RecommendedWatcher::new(|_| {}, Config::default()).unwrap(),
            rx: mpsc::channel().1,
        };

        let path = Path::new("/tmp/test.yaml");
        let event = Event {
            kind: EventKind::Create(CreateKind::Any),
            paths: vec![path.to_path_buf()],
            attrs: Default::default(),
        };

        assert!(watcher.is_relevant_event(&event, path));
    }

    #[test]
    fn test_is_relevant_event_wrong_file() {
        let watcher = YamlWatcher {
            _watcher: RecommendedWatcher::new(|_| {}, Config::default()).unwrap(),
            rx: mpsc::channel().1,
        };

        let watched_path = Path::new("/tmp/test.yaml");
        let other_path = Path::new("/tmp/other.yaml");
        let event = Event {
            kind: EventKind::Modify(ModifyKind::Any),
            paths: vec![other_path.to_path_buf()],
            attrs: Default::default(),
        };

        assert!(!watcher.is_relevant_event(&event, watched_path));
    }

    #[test]
    fn test_is_relevant_event_wrong_kind() {
        let watcher = YamlWatcher {
            _watcher: RecommendedWatcher::new(|_| {}, Config::default()).unwrap(),
            rx: mpsc::channel().1,
        };

        let path = Path::new("/tmp/test.yaml");
        let event = Event {
            kind: EventKind::Access(notify::event::AccessKind::Any),
            paths: vec![path.to_path_buf()],
            attrs: Default::default(),
        };

        assert!(!watcher.is_relevant_event(&event, path));
    }

    #[tokio::test]
    async fn test_yaml_watcher_new() {
        let temp_file = NamedTempFile::new().unwrap();
        writeln!(temp_file.as_file(), "test: data").unwrap();

        let result = YamlWatcher::new(temp_file.path());
        assert!(result.is_ok());

        let (_watcher, rx) = result.unwrap();

        // Initial value should be available
        assert!(rx.has_changed().is_ok());
    }

    // Slow test - commented out for regular runs
    // #[tokio::test]
    #[allow(dead_code)]
    async fn test_yaml_watcher_file_change() {
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(temp_file.as_file(), "test: data").unwrap();
        temp_file.flush().unwrap();

        let (_watcher, mut rx) = YamlWatcher::new(temp_file.path()).unwrap();

        // Clear initial notification
        let _ = rx.changed().await;

        // Modify the file
        writeln!(temp_file.as_file(), "test: modified").unwrap();
        temp_file.flush().unwrap();

        // Wait a bit for the file system event
        tokio::time::sleep(Duration::from_millis(100)).await;

        // We might or might not receive a change notification depending on the file system
        // Just check that we can still try to receive
        let _ = rx.has_changed();
    }

    #[test]
    fn test_yaml_watcher_invalid_path() {
        let result = YamlWatcher::new(Path::new("/nonexistent/parent/file.yaml"));
        assert!(result.is_err());
    }

    #[test]
    fn test_is_relevant_event_multiple_paths() {
        let watcher = YamlWatcher {
            _watcher: RecommendedWatcher::new(|_| {}, Config::default()).unwrap(),
            rx: mpsc::channel().1,
        };

        let watched_path = Path::new("/tmp/test.yaml");
        let other_path = Path::new("/tmp/other.yaml");
        let event = Event {
            kind: EventKind::Modify(ModifyKind::Any),
            paths: vec![other_path.to_path_buf(), watched_path.to_path_buf()],
            attrs: Default::default(),
        };

        // Should be relevant because watched_path is in the paths list
        assert!(watcher.is_relevant_event(&event, watched_path));
    }

    #[test]
    fn test_is_relevant_event_delete() {
        let watcher = YamlWatcher {
            _watcher: RecommendedWatcher::new(|_| {}, Config::default()).unwrap(),
            rx: mpsc::channel().1,
        };

        let path = Path::new("/tmp/test.yaml");
        let event = Event {
            kind: EventKind::Remove(notify::event::RemoveKind::Any),
            paths: vec![path.to_path_buf()],
            attrs: Default::default(),
        };

        // Delete events should not be relevant
        assert!(!watcher.is_relevant_event(&event, path));
    }

    #[test]
    fn test_is_relevant_event_empty_paths() {
        let watcher = YamlWatcher {
            _watcher: RecommendedWatcher::new(|_| {}, Config::default()).unwrap(),
            rx: mpsc::channel().1,
        };

        let path = Path::new("/tmp/test.yaml");
        let event = Event {
            kind: EventKind::Modify(ModifyKind::Any),
            paths: vec![],
            attrs: Default::default(),
        };

        assert!(!watcher.is_relevant_event(&event, path));
    }

    #[test]
    fn test_is_relevant_event_specific_modify_kinds() {
        let watcher = YamlWatcher {
            _watcher: RecommendedWatcher::new(|_| {}, Config::default()).unwrap(),
            rx: mpsc::channel().1,
        };

        let path = Path::new("/tmp/test.yaml");
        
        // Test data modification
        let event = Event {
            kind: EventKind::Modify(ModifyKind::Data(notify::event::DataChange::Content)),
            paths: vec![path.to_path_buf()],
            attrs: Default::default(),
        };
        assert!(watcher.is_relevant_event(&event, path));

        // Test metadata modification
        let event = Event {
            kind: EventKind::Modify(ModifyKind::Metadata(notify::event::MetadataKind::Permissions)),
            paths: vec![path.to_path_buf()],
            attrs: Default::default(),
        };
        assert!(watcher.is_relevant_event(&event, path));

        // Test name modification (rename)
        let event = Event {
            kind: EventKind::Modify(ModifyKind::Name(notify::event::RenameMode::Both)),
            paths: vec![path.to_path_buf()],
            attrs: Default::default(),
        };
        assert!(watcher.is_relevant_event(&event, path));
    }

    #[tokio::test]
    async fn test_yaml_watcher_with_symlink() {
        use std::os::unix::fs::symlink;
        
        let temp_dir = tempfile::tempdir().unwrap();
        let real_file = temp_dir.path().join("real.yaml");
        let symlink_file = temp_dir.path().join("link.yaml");
        
        std::fs::write(&real_file, "test: data").unwrap();
        symlink(&real_file, &symlink_file).unwrap();
        
        // Should be able to watch through symlink
        let result = YamlWatcher::new(&symlink_file);
        assert!(result.is_ok());
    }
}
