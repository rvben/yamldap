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
    #[arg(short, long, default_value = "1389")]
    pub port: u16,

    /// Address to bind to
    #[arg(long, default_value = "127.0.0.1")]
    pub bind_address: String,

    /// Acknowledge that plaintext LDAP will be reachable beyond this host
    #[arg(long)]
    pub allow_insecure_non_loopback: bool,

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

    /// Enable Active Directory compatibility mode
    #[arg(long)]
    pub ad_compat: bool,
}

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Config {
    yaml_file: PathBuf,
    bind_address: SocketAddr,
    base_dn: Option<String>,
    allow_anonymous: bool,
    hot_reload: bool,
    ad_compat: bool,
}

impl Config {
    pub fn new(yaml_file: impl Into<PathBuf>) -> Self {
        Self {
            yaml_file: yaml_file.into(),
            bind_address: SocketAddr::from(([127, 0, 0, 1], 1389)),
            base_dn: None,
            allow_anonymous: false,
            hot_reload: false,
            ad_compat: false,
        }
    }

    pub fn with_bind_address(mut self, bind_address: SocketAddr) -> Self {
        self.bind_address = bind_address;
        self
    }

    pub fn with_base_dn(mut self, base_dn: impl Into<String>) -> Self {
        self.base_dn = Some(base_dn.into());
        self
    }

    pub fn with_anonymous_access(mut self, allow_anonymous: bool) -> Self {
        self.allow_anonymous = allow_anonymous;
        self
    }

    pub fn with_hot_reload(mut self, hot_reload: bool) -> Self {
        self.hot_reload = hot_reload;
        self
    }

    pub fn with_ad_compat(mut self, ad_compat: bool) -> Self {
        self.ad_compat = ad_compat;
        self
    }

    pub fn yaml_file(&self) -> &std::path::Path {
        &self.yaml_file
    }

    pub fn bind_address(&self) -> SocketAddr {
        self.bind_address
    }

    pub fn base_dn(&self) -> Option<&str> {
        self.base_dn.as_deref()
    }

    pub fn allows_anonymous_access(&self) -> bool {
        self.allow_anonymous
    }

    pub fn hot_reload(&self) -> bool {
        self.hot_reload
    }

    pub fn ad_compat(&self) -> bool {
        self.ad_compat
    }

    pub fn from_cli_args(args: CliArgs) -> crate::Result<Self> {
        // Handle IPv6 addresses by adding brackets if needed
        let bind_address = if args.bind_address.contains(':') && !args.bind_address.starts_with('[')
        {
            format!("[{}]:{}", args.bind_address, args.port)
        } else {
            format!("{}:{}", args.bind_address, args.port)
        };

        let bind_address: SocketAddr = bind_address
            .parse()
            .map_err(|e| crate::YamlLdapError::Config(format!("Invalid bind address: {}", e)))?;

        if !bind_address.ip().is_loopback() && !args.allow_insecure_non_loopback {
            return Err(crate::YamlLdapError::Config(format!(
                "refusing to expose plaintext LDAP on {}; use \
                 --allow-insecure-non-loopback to acknowledge the risk",
                bind_address.ip()
            )));
        }

        let mut config = Config::new(args.file)
            .with_bind_address(bind_address)
            .with_anonymous_access(args.allow_anonymous)
            .with_hot_reload(args.hot_reload)
            .with_ad_compat(args.ad_compat);
        if let Some(base_dn) = args.base_dn {
            config = config.with_base_dn(base_dn);
        }
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_cli_args_default_values() {
        let args = CliArgs::parse_from(["yamldap", "-f", "test.yaml"]);
        assert_eq!(args.file, PathBuf::from("test.yaml"));
        assert_eq!(args.port, 1389);
        assert_eq!(args.bind_address, "127.0.0.1");
        assert!(!args.allow_insecure_non_loopback);
        assert_eq!(args.base_dn, None);
        assert!(!args.allow_anonymous);
        assert!(!args.hot_reload);
        assert!(!args.verbose);
        assert!(!args.ad_compat);
        assert_eq!(args.log_level, "info");
    }

    #[test]
    fn test_cli_args_custom_values() {
        let args = CliArgs::parse_from([
            "yamldap",
            "-f",
            "test.yaml",
            "-p",
            "1389",
            "--bind-address",
            "127.0.0.1",
            "--base-dn",
            "dc=example,dc=com",
            "--allow-anonymous",
            "--hot-reload",
            "-v",
            "--log-level",
            "debug",
        ]);
        assert_eq!(args.file, PathBuf::from("test.yaml"));
        assert_eq!(args.port, 1389);
        assert_eq!(args.bind_address, "127.0.0.1");
        assert!(!args.allow_insecure_non_loopback);
        assert_eq!(args.base_dn, Some("dc=example,dc=com".to_string()));
        assert!(args.allow_anonymous);
        assert!(args.hot_reload);
        assert!(args.verbose);
        assert_eq!(args.log_level, "debug");
    }

    #[test]
    fn test_config_from_cli_args_success() {
        let args = CliArgs {
            file: PathBuf::from("test.yaml"),
            port: 389,
            bind_address: "127.0.0.1".to_string(),
            allow_insecure_non_loopback: false,
            base_dn: Some("dc=example,dc=com".to_string()),
            allow_anonymous: true,
            hot_reload: true,
            verbose: false,
            log_level: "debug".to_string(),
            ad_compat: false,
        };

        let config = Config::from_cli_args(args).unwrap();
        assert_eq!(config.yaml_file, PathBuf::from("test.yaml"));
        assert_eq!(
            config.bind_address,
            SocketAddr::from_str("127.0.0.1:389").unwrap()
        );
        assert_eq!(config.base_dn, Some("dc=example,dc=com".to_string()));
        assert!(config.allow_anonymous);
        assert!(config.hot_reload);
    }

    #[test]
    fn test_config_from_cli_args_invalid_bind_address() {
        let args = CliArgs {
            file: PathBuf::from("test.yaml"),
            port: 389,
            bind_address: "invalid_address".to_string(),
            allow_insecure_non_loopback: false,
            base_dn: None,
            allow_anonymous: false,
            hot_reload: false,
            verbose: false,
            log_level: "info".to_string(),
            ad_compat: false,
        };

        let result = Config::from_cli_args(args);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, crate::YamlLdapError::Config(_)));
    }

    #[test]
    fn test_non_loopback_requires_explicit_acknowledgement() {
        let args = CliArgs {
            file: PathBuf::from("test.yaml"),
            port: 1389,
            bind_address: "0.0.0.0".to_string(),
            allow_insecure_non_loopback: false,
            base_dn: None,
            allow_anonymous: false,
            hot_reload: false,
            verbose: false,
            log_level: "info".to_string(),
            ad_compat: false,
        };

        let error = Config::from_cli_args(args).unwrap_err();
        assert!(error
            .to_string()
            .contains("refusing to expose plaintext LDAP"));
    }

    #[test]
    fn test_config_with_ipv6_address() {
        let args = CliArgs {
            file: PathBuf::from("test.yaml"),
            port: 389,
            bind_address: "::1".to_string(),
            allow_insecure_non_loopback: false,
            base_dn: None,
            allow_anonymous: false,
            hot_reload: false,
            verbose: false,
            log_level: "info".to_string(),
            ad_compat: false,
        };

        let config = Config::from_cli_args(args).unwrap();
        assert_eq!(
            config.bind_address,
            SocketAddr::from_str("[::1]:389").unwrap()
        );
    }

    #[test]
    fn test_config_with_custom_port() {
        let args = CliArgs {
            file: PathBuf::from("test.yaml"),
            port: 1389,
            bind_address: "0.0.0.0".to_string(),
            allow_insecure_non_loopback: true,
            base_dn: None,
            allow_anonymous: false,
            hot_reload: false,
            verbose: false,
            log_level: "info".to_string(),
            ad_compat: false,
        };

        let config = Config::from_cli_args(args).unwrap();
        assert_eq!(config.bind_address.port(), 1389);
    }

    #[test]
    fn test_config_clone() {
        let config = Config {
            yaml_file: PathBuf::from("test.yaml"),
            bind_address: SocketAddr::from_str("127.0.0.1:389").unwrap(),
            base_dn: Some("dc=example,dc=com".to_string()),
            allow_anonymous: true,
            hot_reload: true,
            ad_compat: false,
        };

        let cloned = config.clone();
        assert_eq!(cloned.yaml_file, config.yaml_file);
        assert_eq!(cloned.bind_address, config.bind_address);
        assert_eq!(cloned.base_dn, config.base_dn);
        assert_eq!(cloned.allow_anonymous, config.allow_anonymous);
        assert_eq!(cloned.hot_reload, config.hot_reload);
        assert_eq!(cloned.ad_compat, config.ad_compat);
    }
}
