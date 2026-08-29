pub mod connection;
pub mod session;

use crate::config::Config;
use crate::directory::{AuthHandler, Directory};
use crate::yaml::{self, YamlWatcher};
use std::future::Future;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::{oneshot, Semaphore};
use tokio::task::{JoinHandle, JoinSet};
use tracing::{error, info, warn};

/// Runtime limits applied to each server instance.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ResourceLimits {
    pub max_connections: usize,
    pub max_blocking_operations: usize,
    pub max_password_operations: usize,
    pub max_message_bytes: usize,
    pub max_search_entries: usize,
    pub max_search_response_bytes: usize,
    pub idle_timeout: Duration,
    pub write_timeout: Duration,
    pub search_timeout: Duration,
    pub shutdown_grace: Duration,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            max_connections: 128,
            max_blocking_operations: 8,
            max_password_operations: 4,
            max_message_bytes: 1024 * 1024,
            max_search_entries: 1_000,
            max_search_response_bytes: 16 * 1024 * 1024,
            idle_timeout: Duration::from_secs(60),
            write_timeout: Duration::from_secs(10),
            search_timeout: Duration::from_secs(5),
            shutdown_grace: Duration::from_secs(5),
        }
    }
}

/// A running server that can be shut down without aborting its task.
pub struct ServerHandle {
    local_addr: SocketAddr,
    shutdown: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<crate::Result<()>>>,
}

impl ServerHandle {
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub async fn shutdown(mut self) -> crate::Result<()> {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        let task = self.task.take().ok_or_else(|| {
            crate::YamlLdapError::Directory("server task was already consumed".to_string())
        })?;
        task.await.map_err(|error| {
            crate::YamlLdapError::Directory(format!("server task failed: {error}"))
        })?
    }
}

impl Drop for ServerHandle {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct DirectoryStore(Arc<RwLock<Arc<Directory>>>);

impl DirectoryStore {
    fn new(directory: Directory) -> Self {
        Self(Arc::new(RwLock::new(Arc::new(directory))))
    }

    pub(crate) fn snapshot(&self) -> crate::Result<Arc<Directory>> {
        self.0
            .read()
            .map(|snapshot| Arc::clone(&snapshot))
            .map_err(|error| {
                crate::YamlLdapError::Directory(format!(
                    "failed to read directory snapshot: {error}"
                ))
            })
    }

    fn replace(&self, directory: Directory) -> crate::Result<()> {
        let mut snapshot = self.0.write().map_err(|error| {
            crate::YamlLdapError::Directory(format!(
                "failed to replace directory snapshot: {error}"
            ))
        })?;
        *snapshot = Arc::new(directory);
        Ok(())
    }
}

pub struct Server {
    config: Config,
    directory: DirectoryStore,
    auth_handler: Arc<AuthHandler>,
    limits: ResourceLimits,
}

impl Server {
    pub async fn new(config: Config) -> crate::Result<Self> {
        let directory = load_directory(config.yaml_file(), config.base_dn()).await?;

        info!("Loaded directory with base DN: {}", directory.base_dn);

        let auth_handler = AuthHandler::new(config.allows_anonymous_access());

        Ok(Self {
            config,
            directory: DirectoryStore::new(directory),
            auth_handler: Arc::new(auth_handler),
            limits: ResourceLimits::default(),
        })
    }

    pub fn with_resource_limits(mut self, limits: ResourceLimits) -> crate::Result<Self> {
        if limits.max_connections == 0
            || limits.max_blocking_operations == 0
            || limits.max_password_operations == 0
            || limits.max_message_bytes == 0
            || limits.max_search_entries == 0
            || limits.max_search_response_bytes == 0
        {
            return Err(crate::YamlLdapError::Config(
                "server resource limits must be greater than zero".to_string(),
            ));
        }
        self.limits = limits;
        Ok(self)
    }

    pub async fn start(self) -> crate::Result<ServerHandle> {
        let listener = TcpListener::bind(self.config.bind_address()).await?;
        let local_addr = listener.local_addr()?;
        let (shutdown, receiver) = oneshot::channel();
        let task = tokio::spawn(async move {
            self.run_with_listener_until(listener, async move {
                let _ = receiver.await;
            })
            .await
        });
        Ok(ServerHandle {
            local_addr,
            shutdown: Some(shutdown),
            task: Some(task),
        })
    }

    pub async fn run(self) -> crate::Result<()> {
        let listener = TcpListener::bind(self.config.bind_address()).await?;
        self.run_with_listener_until(listener, async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await
    }

    /// Run the server using an already-bound listener.
    ///
    /// This is useful for embedding and allows tests to bind port zero without a race.
    pub async fn run_with_listener(self, listener: TcpListener) -> crate::Result<()> {
        self.run_with_listener_until(listener, std::future::pending())
            .await
    }

    /// Run using an already-bound listener until the shutdown signal resolves.
    pub async fn run_with_listener_until<S>(
        self,
        listener: TcpListener,
        shutdown: S,
    ) -> crate::Result<()>
    where
        S: Future<Output = ()>,
    {
        tokio::pin!(shutdown);

        // Set up hot-reload if enabled
        let (_watcher_guard, mut reload_rx) = if self.config.hot_reload() {
            info!("Hot-reload enabled, watching YAML file for changes");
            let (watcher, rx) = YamlWatcher::new(self.config.yaml_file())?;
            (Some(watcher), Some(rx))
        } else {
            (None, None)
        };

        info!("LDAP server listening on {}", listener.local_addr()?);

        let connections = Arc::new(Semaphore::new(self.limits.max_connections));
        let blocking_operations = Arc::new(Semaphore::new(self.limits.max_blocking_operations));
        let password_operations = Arc::new(Semaphore::new(self.limits.max_password_operations));
        let mut tasks = JoinSet::new();

        loop {
            tokio::select! {
                biased;
                _ = &mut shutdown => {
                    info!("Shutdown requested; no longer accepting LDAP connections");
                    break;
                }
                reload = async {
                    match reload_rx.as_mut() {
                        Some(receiver) => receiver.changed().await,
                        None => std::future::pending().await,
                    }
                } => {
                    if reload.is_err() {
                        reload_rx = None;
                        continue;
                    }
                    info!("Reloading YAML directory file");
                    match load_directory(self.config.yaml_file(), self.config.base_dn()).await {
                        Ok(directory) => {
                            if let Err(error) = self.directory.replace(directory) {
                                error!("Failed to install reloaded directory: {error}");
                            } else {
                                info!("Successfully reloaded directory snapshot");
                            }
                        }
                        Err(error) => error!("Keeping previous directory after reload failure: {error}"),
                    }
                }
                accepted = listener.accept() => {
                    match accepted {
                        Ok((socket, addr)) => {
                            let permit = match Arc::clone(&connections).try_acquire_owned() {
                                Ok(permit) => permit,
                                Err(_) => {
                                    warn!("Connection limit reached; rejecting {addr}");
                                    continue;
                                }
                            };
                            info!("New connection from {addr}");
                            let directory = self.directory.clone();
                            let auth_handler = Arc::clone(&self.auth_handler);
                            let blocking_operations = Arc::clone(&blocking_operations);
                            let password_operations = Arc::clone(&password_operations);
                            let limits = self.limits.clone();
                            let ad_compat = self.config.ad_compat();
                            tasks.spawn(async move {
                                let _permit = permit;
                                if let Err(error) = connection::handle_connection(
                                    socket,
                                    directory,
                                    auth_handler,
                                    ad_compat,
                                    limits,
                                    blocking_operations,
                                    password_operations,
                                ).await {
                                    error!("Connection error from {addr}: {error}");
                                }
                            });
                        }
                        Err(error) => {
                            error!("Failed to accept connection: {error}");
                            tokio::time::sleep(Duration::from_millis(100)).await;
                        }
                    }
                }
                result = tasks.join_next(), if !tasks.is_empty() => {
                    if let Some(Err(error)) = result {
                        error!("Connection task failed: {error}");
                    }
                }
            }
        }

        let graceful = async {
            while let Some(result) = tasks.join_next().await {
                if let Err(error) = result {
                    error!("Connection task failed during shutdown: {error}");
                }
            }
        };
        if tokio::time::timeout(self.limits.shutdown_grace, graceful)
            .await
            .is_err()
        {
            warn!("Shutdown grace elapsed; aborting remaining connections");
            tasks.abort_all();
            while tasks.join_next().await.is_some() {}
        }

        info!("LDAP server stopped");
        Ok(())
    }
}

async fn load_directory(
    yaml_path: &std::path::Path,
    base_dn_override: Option<&str>,
) -> crate::Result<Directory> {
    yaml::compile_directory_file(yaml_path, base_dn_override).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::path::PathBuf;
    use tempfile::NamedTempFile;

    fn create_test_yaml_file() -> NamedTempFile {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "directory:").unwrap();
        writeln!(file, "  base_dn: dc=test,dc=com").unwrap();
        writeln!(file, "entries:").unwrap();
        writeln!(file, "  - dn: cn=test,dc=test,dc=com").unwrap();
        writeln!(file, "    objectClass: [top, person]").unwrap();
        writeln!(file, "    cn: test").unwrap();
        writeln!(file, "    sn: Test").unwrap();
        file.flush().unwrap();
        file
    }

    #[tokio::test]
    async fn test_server_new() {
        let yaml_file = create_test_yaml_file();
        let config = Config::new(yaml_file.path());

        let server = Server::new(config).await.unwrap();
        assert_eq!(
            server.directory.snapshot().unwrap().base_dn,
            "dc=test,dc=com"
        );
        assert!(!server.auth_handler.is_anonymous_allowed());
    }

    #[tokio::test]
    async fn test_server_new_with_anonymous() {
        let yaml_file = create_test_yaml_file();
        let config = Config::new(yaml_file.path()).with_anonymous_access(true);

        let server = Server::new(config).await.unwrap();
        assert!(server.auth_handler.is_anonymous_allowed());
    }

    #[tokio::test]
    async fn test_server_applies_base_dn_override() {
        let yaml_file = create_test_yaml_file();
        let config = Config::new(yaml_file.path()).with_base_dn("dc=override,dc=example");

        let server = Server::new(config).await.unwrap();

        assert_eq!(
            server.directory.snapshot().unwrap().base_dn,
            "dc=override,dc=example"
        );
        assert!(server
            .directory
            .snapshot()
            .unwrap()
            .entry_exists("cn=test,dc=override,dc=example"));
    }

    #[tokio::test]
    async fn test_server_new_invalid_yaml() {
        let config = Config::new(PathBuf::from("/nonexistent/file.yaml"));

        let result = Server::new(config).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_server_run_with_hot_reload() {
        let yaml_file = create_test_yaml_file();
        let config = Config::new(yaml_file.path())
            .with_bind_address("127.0.0.1:0".parse().unwrap())
            .with_hot_reload(true);

        let server = Server::new(config).await.unwrap();
        let handle = server.start().await.unwrap();
        tokio::net::TcpStream::connect(handle.local_addr())
            .await
            .unwrap();
        handle.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn test_server_run_without_hot_reload() {
        let yaml_file = create_test_yaml_file();
        let config = Config::new(yaml_file.path())
            .with_bind_address("127.0.0.1:0".parse().unwrap())
            .with_anonymous_access(true);

        let server = Server::new(config).await.unwrap();
        let handle = server.start().await.unwrap();
        tokio::net::TcpStream::connect(handle.local_addr())
            .await
            .unwrap();
        handle.shutdown().await.unwrap();
    }
}
