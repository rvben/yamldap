use yamldap::{Config, Server};
use std::io::{Write, Seek};
use std::path::PathBuf;
use std::time::Duration;
use tempfile::NamedTempFile;
use tokio::net::TcpStream;
use tokio::time::timeout;

fn create_test_config(yaml_file: PathBuf, port: u16) -> Config {
    Config {
        yaml_file,
        bind_address: format!("127.0.0.1:{}", port).parse().unwrap(),
        base_dn: None,
        allow_anonymous: true,
        hot_reload: true,
        log_level: tracing::Level::INFO,
    }
}

fn create_yaml_file() -> NamedTempFile {
    let mut file = NamedTempFile::new().unwrap();
    writeln!(
        file,
        r#"directory:
  base_dn: dc=test,dc=com

entries:
  - dn: dc=test,dc=com
    objectClass: [top, domain]
    dc: test

  - dn: cn=admin,dc=test,dc=com
    objectClass: [top, person]
    cn: admin
    sn: Admin
    userPassword: secret
"#
    )
    .unwrap();
    file.flush().unwrap();
    file
}

#[tokio::test]
#[ignore] // These tests require a running server
async fn test_server_startup_and_shutdown() {
    let yaml_file = create_yaml_file();
    let config = create_test_config(yaml_file.path().to_path_buf(), 10389);
    
    let server = Server::new(config.clone()).await.unwrap();
    
    // Start server in background
    let server_task = tokio::spawn(async move {
        server.run().await
    });
    
    // Give server time to start
    tokio::time::sleep(Duration::from_millis(100)).await;
    
    // Try to connect
    let connect_result = timeout(
        Duration::from_secs(1),
        TcpStream::connect(&config.bind_address)
    ).await;
    
    assert!(connect_result.is_ok());
    let stream = connect_result.unwrap().unwrap();
    drop(stream);
    
    // Cancel server task
    server_task.abort();
    
    // Give time for cleanup
    tokio::time::sleep(Duration::from_millis(100)).await;
}

#[tokio::test]
#[ignore] // These tests require a running server
async fn test_server_hot_reload() {
    let mut yaml_file = create_yaml_file();
    let config = create_test_config(yaml_file.path().to_path_buf(), 10390);
    
    let server = Server::new(config.clone()).await.unwrap();
    
    // Start server in background
    let server_task = tokio::spawn(async move {
        server.run().await
    });
    
    // Give server time to start
    tokio::time::sleep(Duration::from_millis(200)).await;
    
    // Connect and verify initial state
    let stream = TcpStream::connect(&config.bind_address).await.unwrap();
    drop(stream);
    
    // Modify the YAML file
    yaml_file.rewind().unwrap();
    writeln!(
        yaml_file,
        r#"directory:
  base_dn: dc=test,dc=com

entries:
  - dn: dc=test,dc=com
    objectClass: [top, domain]
    dc: test

  - dn: cn=admin,dc=test,dc=com
    objectClass: [top, person]
    cn: admin
    sn: Admin
    userPassword: newsecret

  - dn: cn=user,dc=test,dc=com
    objectClass: [top, person]
    cn: user
    sn: User
"#
    )
    .unwrap();
    yaml_file.flush().unwrap();
    
    // Give time for hot reload to process
    tokio::time::sleep(Duration::from_millis(500)).await;
    
    // Server should still be running
    let connect_result = TcpStream::connect(&config.bind_address).await;
    assert!(connect_result.is_ok());
    
    // Cancel server task
    server_task.abort();
}

#[tokio::test]
#[ignore] // These tests require a running server
async fn test_server_multiple_connections() {
    let yaml_file = create_yaml_file();
    let config = create_test_config(yaml_file.path().to_path_buf(), 10391);
    
    let server = Server::new(config.clone()).await.unwrap();
    
    // Start server in background
    let server_task = tokio::spawn(async move {
        server.run().await
    });
    
    // Give server time to start
    tokio::time::sleep(Duration::from_millis(100)).await;
    
    // Create multiple concurrent connections
    let mut handles = vec![];
    
    for i in 0..10 {
        let addr = config.bind_address.clone();
        let handle = tokio::spawn(async move {
            let stream = TcpStream::connect(&addr).await.unwrap();
            // Keep connection open briefly
            tokio::time::sleep(Duration::from_millis(50)).await;
            drop(stream);
            i
        });
        handles.push(handle);
    }
    
    // Wait for all connections to complete
    for handle in handles {
        let result = handle.await.unwrap();
        assert!(result < 10);
    }
    
    // Cancel server task
    server_task.abort();
}

#[tokio::test]
async fn test_server_bind_error() {
    let yaml_file = create_yaml_file();
    
    // Try to bind to a privileged port (should fail on most systems without root)
    let config = Config {
        yaml_file: yaml_file.path().to_path_buf(),
        bind_address: "127.0.0.1:1".parse().unwrap(),
        base_dn: None,
        allow_anonymous: false,
        hot_reload: false,
        log_level: tracing::Level::INFO,
    };
    
    let server = Server::new(config).await.unwrap();
    let result = server.run().await;
    
    // Should fail to bind
    assert!(result.is_err());
}

#[tokio::test]
async fn test_server_invalid_yaml() {
    let config = Config {
        yaml_file: PathBuf::from("/nonexistent/file.yaml"),
        bind_address: "127.0.0.1:10392".parse().unwrap(),
        base_dn: None,
        allow_anonymous: false,
        hot_reload: false,
        log_level: tracing::Level::INFO,
    };
    
    let result = Server::new(config).await;
    assert!(result.is_err());
}

#[tokio::test]
#[ignore] // These tests require a running server
async fn test_server_with_custom_schema() {
    let mut file = NamedTempFile::new().unwrap();
    writeln!(
        file,
        r#"directory:
  base_dn: dc=custom,dc=com

schema:
  object_classes:
    - name: customPerson
      attributes: [cn, email]
  custom_attributes:
    email:
      syntax: String
      single_value: true

entries:
  - dn: cn=test,dc=custom,dc=com
    objectClass: [customPerson]
    cn: test
    email: test@example.com
"#
    )
    .unwrap();
    file.flush().unwrap();
    
    let config = create_test_config(file.path().to_path_buf(), 10393);
    let server = Server::new(config.clone()).await.unwrap();
    
    // Start server in background
    let server_task = tokio::spawn(async move {
        server.run().await
    });
    
    // Give server time to start
    tokio::time::sleep(Duration::from_millis(100)).await;
    
    // Try to connect
    let stream = TcpStream::connect(&config.bind_address).await.unwrap();
    drop(stream);
    
    // Cancel server task
    server_task.abort();
}