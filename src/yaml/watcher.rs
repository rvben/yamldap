use crate::Result;
use notify::{Config, Event, EventKind, PollWatcher, RecursiveMode, Watcher};
use std::path::Path;
use std::time::Duration;
use tokio::sync::watch;
use tracing::{error, info};

pub struct YamlWatcher {
    _watcher: PollWatcher,
}

impl YamlWatcher {
    pub fn new(path: &Path) -> Result<(Self, watch::Receiver<()>)> {
        let metadata = std::fs::metadata(path).map_err(|error| {
            crate::YamlLdapError::Io(std::io::Error::new(
                error.kind(),
                format!(
                    "Failed to access watched YAML file {}: {error}",
                    path.display()
                ),
            ))
        })?;
        if !metadata.is_file() {
            return Err(crate::YamlLdapError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("Watched YAML path is not a file: {}", path.display()),
            )));
        }

        let (reload_tx, reload_rx) = watch::channel(());
        let watched_path = path.to_path_buf();

        let mut watcher = PollWatcher::new(
            move |res: notify::Result<Event>| match res {
                Ok(event) if Self::event_is_relevant(&event, &watched_path) => {
                    info!("YAML file changed, triggering reload: {:?}", event.paths);
                    if let Err(error) = reload_tx.send(()) {
                        error!("Failed to send reload signal: {error}");
                    }
                }
                Ok(_) => {}
                Err(error) => error!("File watch error: {error}"),
            },
            Config::default()
                .with_poll_interval(Duration::from_millis(500))
                .with_compare_contents(true),
        )
        .map_err(|e| {
            crate::YamlLdapError::Io(std::io::Error::other(format!(
                "Failed to create file watcher: {}",
                e
            )))
        })?;

        watcher
            .watch(path, RecursiveMode::NonRecursive)
            .map_err(|e| {
                crate::YamlLdapError::Io(std::io::Error::other(format!(
                    "Failed to watch directory: {}",
                    e
                )))
            })?;

        Ok((YamlWatcher { _watcher: watcher }, reload_rx))
    }

    #[cfg(test)]
    fn is_relevant_event(&self, event: &Event, watched_path: &Path) -> bool {
        Self::event_is_relevant(event, watched_path)
    }

    fn event_is_relevant(event: &Event, watched_path: &Path) -> bool {
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
            _watcher: PollWatcher::new(|_| {}, Config::default()).unwrap(),
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
            _watcher: PollWatcher::new(|_| {}, Config::default()).unwrap(),
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
            _watcher: PollWatcher::new(|_| {}, Config::default()).unwrap(),
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
            _watcher: PollWatcher::new(|_| {}, Config::default()).unwrap(),
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

    #[tokio::test]
    async fn test_yaml_watcher_file_change() {
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(temp_file.as_file(), "test: data").unwrap();
        temp_file.flush().unwrap();

        let (_watcher, mut rx) = YamlWatcher::new(temp_file.path()).unwrap();

        // Modify the file
        writeln!(temp_file.as_file(), "test: modified").unwrap();
        temp_file.flush().unwrap();

        tokio::time::timeout(Duration::from_secs(5), rx.changed())
            .await
            .expect("file watcher did not report the change")
            .expect("file watcher channel closed");
    }

    #[test]
    fn test_yaml_watcher_invalid_path() {
        let result = YamlWatcher::new(Path::new("/nonexistent/parent/file.yaml"));
        assert!(result.is_err());
    }

    #[test]
    fn test_is_relevant_event_multiple_paths() {
        let watcher = YamlWatcher {
            _watcher: PollWatcher::new(|_| {}, Config::default()).unwrap(),
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
            _watcher: PollWatcher::new(|_| {}, Config::default()).unwrap(),
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
            _watcher: PollWatcher::new(|_| {}, Config::default()).unwrap(),
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
            _watcher: PollWatcher::new(|_| {}, Config::default()).unwrap(),
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
            kind: EventKind::Modify(ModifyKind::Metadata(
                notify::event::MetadataKind::Permissions,
            )),
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
