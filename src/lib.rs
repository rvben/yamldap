pub mod config;
pub mod crypto;
pub mod directory;
pub mod ldap;
pub mod server;
pub mod yaml;

pub use config::Config;
pub use server::Server;

#[derive(thiserror::Error, Debug)]
pub enum YamlLdapError {
    #[error("YAML parsing error: {0}")]
    YamlParse(#[from] serde_yaml::Error),

    #[error("LDAP protocol error: {0}")]
    Protocol(String),

    #[error("Directory error: {0}")]
    Directory(String),

    #[error("Authentication error: {0}")]
    Auth(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Configuration error: {0}")]
    Config(String),
}

pub type Result<T> = std::result::Result<T, YamlLdapError>;
