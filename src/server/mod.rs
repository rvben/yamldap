pub mod connection;
pub mod session;

use crate::config::Config;
use crate::directory::{AuthHandler, Directory};
use crate::yaml::{self, YamlWatcher};
use std::sync::{Arc, RwLock};
use tokio::net::TcpListener;
use tracing::{error, info};

pub struct Server {
    config: Config,
    directory: Arc<RwLock<Directory>>,
    auth_handler: Arc<AuthHandler>,
}

impl Server {
    pub async fn new(config: Config) -> crate::Result<Self> {
        // Load directory from YAML
        let (yaml_dir, schema) = yaml::parse_directory_file(&config.yaml_file).await?;
        let directory = Directory::from_yaml(yaml_dir, schema);
        
        info!(
            "Loaded directory with base DN: {}",
            directory.base_dn
        );
        
        let auth_handler = AuthHandler::new(config.allow_anonymous);
        
        Ok(Self {
            config,
            directory: Arc::new(RwLock::new(directory)),
            auth_handler: Arc::new(auth_handler),
        })
    }
    
    pub async fn run(self) -> crate::Result<()> {
        // Set up hot-reload if enabled
        let reload_rx = if self.config.hot_reload {
            info!("Hot-reload enabled, watching YAML file for changes");
            let (_watcher, rx) = YamlWatcher::new(&self.config.yaml_file)?;
            Some(rx)
        } else {
            None
        };
        
        // Start hot-reload handler if enabled
        if let Some(mut rx) = reload_rx {
            let yaml_path = self.config.yaml_file.clone();
            let directory = Arc::clone(&self.directory);
            
            tokio::spawn(async move {
                while rx.changed().await.is_ok() {
                    info!("Reloading YAML directory file...");
                    match yaml::parse_directory_file(&yaml_path).await {
                        Ok((yaml_dir, schema)) => {
                            let new_directory = Directory::from_yaml(yaml_dir, schema);
                            match directory.write() {
                                Ok(mut dir) => {
                                    *dir = new_directory;
                                    info!("Successfully reloaded directory");
                                }
                                Err(e) => {
                                    error!("Failed to acquire write lock for directory reload: {}", e);
                                }
                            }
                        }
                        Err(e) => {
                            error!("Failed to reload YAML file: {}", e);
                        }
                    }
                }
            });
        }
        
        let listener = TcpListener::bind(&self.config.bind_address).await?;
        
        info!(
            "LDAP server listening on {}",
            self.config.bind_address
        );
        
        loop {
            match listener.accept().await {
                Ok((socket, addr)) => {
                    info!("New connection from {}", addr);
                    
                    let directory = Arc::clone(&self.directory);
                    let auth_handler = Arc::clone(&self.auth_handler);
                    
                    tokio::spawn(async move {
                        // Create a read-only snapshot of the directory for this connection
                        let dir_snapshot = match directory.read() {
                            Ok(dir) => Arc::new(dir.clone()),
                            Err(e) => {
                                error!("Failed to read directory: {}", e);
                                return;
                            }
                        };
                        
                        if let Err(e) = connection::handle_connection(
                            socket,
                            dir_snapshot,
                            auth_handler,
                        )
                        .await
                        {
                            error!("Connection error: {}", e);
                        }
                    });
                }
                Err(e) => {
                    error!("Failed to accept connection: {}", e);
                }
            }
        }
    }
}