use clap::Parser;
use std::net::SocketAddr;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "yamldap")]
#[command(about = "A lightweight LDAP server that serves directory data from YAML files")]
#[command(version)]
pub struct CliArgs {
    /// Path to YAML directory file
    #[arg(short, long, value_name = "FILE")]
    pub file: PathBuf,

    /// Port to listen on
    #[arg(short, long, default_value = "389")]
    pub port: u16,

    /// Address to bind to
    #[arg(long, default_value = "0.0.0.0")]
    pub bind_address: String,

    /// Override base DN from YAML file
    #[arg(long)]
    pub base_dn: Option<String>,

    /// Allow anonymous bind operations
    #[arg(long)]
    pub allow_anonymous: bool,

    /// Enable hot-reloading of YAML file changes
    #[arg(long)]
    pub hot_reload: bool,

    /// Enable verbose logging
    #[arg(short, long)]
    pub verbose: bool,

    /// Set log level: debug, info, warn, error
    #[arg(long, default_value = "info")]
    pub log_level: String,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub yaml_file: PathBuf,
    pub bind_address: SocketAddr,
    pub base_dn: Option<String>,
    pub allow_anonymous: bool,
    pub hot_reload: bool,
    pub log_level: tracing::Level,
}

impl Config {
    pub fn from_cli_args(args: CliArgs) -> crate::Result<Self> {
        let bind_address = format!("{}:{}", args.bind_address, args.port)
            .parse()
            .map_err(|e| crate::YamlLdapError::Config(format!("Invalid bind address: {}", e)))?;

        let log_level = match args.log_level.to_lowercase().as_str() {
            "debug" => tracing::Level::DEBUG,
            "info" => tracing::Level::INFO,
            "warn" => tracing::Level::WARN,
            "error" => tracing::Level::ERROR,
            _ => tracing::Level::INFO,
        };

        Ok(Config {
            yaml_file: args.file,
            bind_address,
            base_dn: args.base_dn,
            allow_anonymous: args.allow_anonymous,
            hot_reload: args.hot_reload,
            log_level,
        })
    }
}