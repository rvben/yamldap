//! Embeddable core for the `yamldap` local LDAP test server.
//!
//! The stable surface intentionally consists of server configuration and
//! lifecycle types. Protocol, YAML, and directory implementation details are
//! available only through the opt-in `unstable-internals` feature used by this
//! repository's benchmarks and fuzz targets.

mod config;
mod crypto;
mod directory;
mod ldap;
mod server;
mod yaml;

pub use config::{CliArgs, Config};
pub use server::{ResourceLimits, Server, ServerHandle};

#[cfg(feature = "unstable-internals")]
#[doc(hidden)]
pub mod unstable {
    pub use crate::directory::storage::SearchScope as DirectorySearchScope;
    pub use crate::directory::Directory;
    pub use crate::ldap::{
        parse_ldap_filter, FilterLimits, LdapFilter, SimpleLdapCodec, DEFAULT_FILTER_LIMITS,
    };
    pub use crate::yaml::compiler::compile_directory;
    pub use crate::yaml::schema::DirectoryConfig;
    pub use crate::yaml::{YamlDirectory, YamlEntry, YamlSchema};
}

#[derive(thiserror::Error, Debug)]
#[non_exhaustive]
pub enum YamlLdapError {
    #[error("YAML parsing error: {0}")]
    YamlParse(#[from] serde_yaml_ng::Error),

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
