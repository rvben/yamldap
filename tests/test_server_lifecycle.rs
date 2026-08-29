use std::io::Write;
use std::path::PathBuf;
use tempfile::NamedTempFile;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};
use yamldap::{Config, ResourceLimits, Server};

fn create_test_config(yaml_file: PathBuf) -> Config {
    Config::new(yaml_file)
        .with_bind_address("127.0.0.1:0".parse().unwrap())
        .with_anonymous_access(true)
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
async fn server_starts_accepts_connections_and_shuts_down() {
    let yaml_file = create_yaml_file();
    let server = Server::new(create_test_config(yaml_file.path().to_path_buf()))
        .await
        .unwrap();
    let handle = server.start().await.unwrap();

    TcpStream::connect(handle.local_addr()).await.unwrap();
    handle.shutdown().await.unwrap();
}

#[tokio::test]
async fn server_owns_multiple_connection_tasks_during_shutdown() {
    let yaml_file = create_yaml_file();
    let server = Server::new(create_test_config(yaml_file.path().to_path_buf()))
        .await
        .unwrap();
    let handle = server.start().await.unwrap();

    let mut streams = Vec::new();
    for _ in 0..10 {
        streams.push(TcpStream::connect(handle.local_addr()).await.unwrap());
    }
    drop(streams);

    handle.shutdown().await.unwrap();
}

#[tokio::test]
async fn server_enforces_connection_limit_without_unbounded_tasks() {
    let yaml_file = create_yaml_file();
    let mut limits = ResourceLimits::default();
    limits.max_connections = 1;
    let server = Server::new(create_test_config(yaml_file.path().to_path_buf()))
        .await
        .unwrap()
        .with_resource_limits(limits)
        .unwrap();
    let handle = server.start().await.unwrap();

    let first = TcpStream::connect(handle.local_addr()).await.unwrap();
    let mut second = TcpStream::connect(handle.local_addr()).await.unwrap();
    let mut byte = [0_u8; 1];
    let closed = tokio::time::timeout(std::time::Duration::from_secs(1), second.read(&mut byte))
        .await
        .expect("excess connection was not handled")
        .unwrap();
    assert_eq!(closed, 0, "excess connection should be closed");
    drop(first);
    drop(second);

    handle.shutdown().await.unwrap();
}

#[tokio::test]
async fn server_reports_a_deterministic_bind_error() {
    let yaml_file = create_yaml_file();
    let occupied = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = occupied.local_addr().unwrap();
    let config = Config::new(yaml_file.path()).with_bind_address(address);
    let server = Server::new(config).await.unwrap();

    assert!(server.start().await.is_err());
}

#[tokio::test]
async fn server_rejects_a_missing_yaml_file() {
    let config = Config::new(PathBuf::from("/nonexistent/file.yaml"));
    assert!(Server::new(config).await.is_err());
}

#[tokio::test]
async fn server_starts_with_a_custom_schema() {
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

    let server = Server::new(create_test_config(file.path().to_path_buf()))
        .await
        .unwrap();
    let handle = server.start().await.unwrap();
    TcpStream::connect(handle.local_addr()).await.unwrap();
    handle.shutdown().await.unwrap();
}
