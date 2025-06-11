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
        .map_err(|e| crate::YamlLdapError::Io(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("Failed to create file watcher: {}", e),
        )))?;
        
        // Watch the parent directory for better compatibility
        let parent_dir = path.parent().unwrap_or(Path::new("."));
        watcher
            .watch(parent_dir, RecursiveMode::NonRecursive)
            .map_err(|e| crate::YamlLdapError::Io(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Failed to watch directory: {}", e),
            )))?;
        
        let watched_path = path.to_path_buf();
        let reload_tx_clone = reload_tx.clone();
        
        // Spawn a task to handle file events
        tokio::spawn(async move {
            let yaml_watcher = YamlWatcher { _watcher: watcher, rx };
            yaml_watcher.run(watched_path, reload_tx_clone).await;
        });
        
        Ok((YamlWatcher { _watcher: RecommendedWatcher::new(|_| {}, Config::default()).unwrap(), rx: mpsc::channel().1 }, reload_rx))
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
        let is_relevant_kind = matches!(
            event.kind,
            EventKind::Modify(_) | EventKind::Create(_)
        );
        
        is_our_file && is_relevant_kind
    }
}