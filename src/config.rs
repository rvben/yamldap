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

    /// Enable Active Directory compatibility mode
    #[arg(long)]
    pub ad_compat: bool,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub yaml_file: PathBuf,
    pub bind_address: SocketAddr,
    pub base_dn: Option<String>,
    pub allow_anonymous: bool,
    pub hot_reload: bool,
    pub log_level: tracing::Level,
    pub ad_compat: bool,
}

impl Config {
    pub fn from_cli_args(args: CliArgs) -> crate::Result<Self> {
        // Handle IPv6 addresses by adding brackets if needed
        let bind_address = if args.bind_address.contains(':') && !args.bind_address.starts_with('[')
        {
            format!("[{}]:{}", args.bind_address, args.port)
        } else {
            format!("{}:{}", args.bind_address, args.port)
        };

        let bind_address = bind_address
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
            ad_compat: args.ad_compat,
        })
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
        assert_eq!(args.port, 389);
        assert_eq!(args.bind_address, "0.0.0.0");
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
        assert_eq!(config.log_level, tracing::Level::DEBUG);
    }

    #[test]
    fn test_config_from_cli_args_invalid_bind_address() {
        let args = CliArgs {
            file: PathBuf::from("test.yaml"),
            port: 389,
            bind_address: "invalid_address".to_string(),
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
    fn test_config_log_level_parsing() {
        let test_cases = vec![
            ("debug", tracing::Level::DEBUG),
            ("info", tracing::Level::INFO),
            ("warn", tracing::Level::WARN),
            ("error", tracing::Level::ERROR),
            ("DEBUG", tracing::Level::DEBUG),
            ("INFO", tracing::Level::INFO),
            ("WARN", tracing::Level::WARN),
            ("ERROR", tracing::Level::ERROR),
            ("invalid", tracing::Level::INFO), // default
            ("", tracing::Level::INFO),        // default
        ];

        for (log_level_str, expected_level) in test_cases {
            let args = CliArgs {
                file: PathBuf::from("test.yaml"),
                port: 389,
                bind_address: "0.0.0.0".to_string(),
                base_dn: None,
                allow_anonymous: false,
                hot_reload: false,
                verbose: false,
                log_level: log_level_str.to_string(),
                ad_compat: false,
            };

            let config = Config::from_cli_args(args).unwrap();
            assert_eq!(config.log_level, expected_level);
        }
    }

    #[test]
    fn test_config_with_ipv6_address() {
        let args = CliArgs {
            file: PathBuf::from("test.yaml"),
            port: 389,
            bind_address: "::1".to_string(),
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
            log_level: tracing::Level::DEBUG,
            ad_compat: false,
        };

        let cloned = config.clone();
        assert_eq!(cloned.yaml_file, config.yaml_file);
        assert_eq!(cloned.bind_address, config.bind_address);
        assert_eq!(cloned.base_dn, config.base_dn);
        assert_eq!(cloned.allow_anonymous, config.allow_anonymous);
        assert_eq!(cloned.hot_reload, config.hot_reload);
        assert_eq!(cloned.log_level, config.log_level);
        assert_eq!(cloned.ad_compat, config.ad_compat);
    }
}
