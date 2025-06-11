use clap::Parser;
use tracing::Level;
use tracing_subscriber::FmtSubscriber;
use yamldap::{Config, Server};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Parse command line arguments
    let args = yamldap::config::CliArgs::parse();
    
    // Configure logging
    let log_level = if args.verbose {
        Level::DEBUG
    } else {
        match args.log_level.to_lowercase().as_str() {
            "debug" => Level::DEBUG,
            "info" => Level::INFO,
            "warn" => Level::WARN,
            "error" => Level::ERROR,
            _ => Level::INFO,
        }
    };
    
    FmtSubscriber::builder()
        .with_max_level(log_level)
        .init();
    
    // Create configuration
    let config = Config::from_cli_args(args)?;
    
    // Create and run server
    let server = Server::new(config).await?;
    server.run().await?;
    
    Ok(())
}
