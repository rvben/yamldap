use ldap3::{LdapConnAsync, LdapError, SearchEntry, Scope};
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::time::sleep;
use yamldap::{Config, Server};

async fn start_test_server() -> (String, tokio::task::JoinHandle<()>) {
    let yaml_content = r#"
directory:
  base_dn: "dc=example,dc=com"

entries:
  - dn: "dc=example,dc=com"
    objectClass: ["top", "domain"]
    dc: "example"

  - dn: "ou=users,dc=example,dc=com"
    objectClass: ["top", "organizationalUnit"]
    ou: "users"

  - dn: "uid=john,ou=users,dc=example,dc=com"
    objectClass: ["top", "person", "inetOrgPerson"]
    uid: "john"
    cn: "John Doe"
    sn: "Doe"
    mail: "john@example.com"
    userPassword: "password123"
"#;

    // Create temporary file
    let temp_file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(temp_file.path(), yaml_content).unwrap();

    // Find available port
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);

    // Create config
    let config = Config {
        yaml_file: temp_file.path().to_path_buf(),
        bind_address: format!("127.0.0.1:{}", port).parse().unwrap(),
        base_dn: None,
        allow_anonymous: true,
        hot_reload: false,
        log_level: tracing::Level::INFO,
    };

    let server_url = format!("ldap://127.0.0.1:{}", port);

    // Create and start server
    let server = Server::new(config).await.unwrap();
    let handle = tokio::spawn(async move {
        server.run().await.ok();
    });

    // Give server time to start
    sleep(Duration::from_millis(100)).await;

    // Keep temp file alive
    Box::leak(Box::new(temp_file));

    (server_url, handle)
}

#[tokio::test]
async fn test_undefined_attribute_in_search_filter() {
    let (server_url, handle) = start_test_server().await;

    // Connect to test server
    let (conn, mut ldap) = LdapConnAsync::new(&server_url)
        .await
        .expect("connection failed");
    tokio::spawn(async move { conn.drive().await });

    // Bind anonymously
    ldap.simple_bind("", "").await.expect("bind failed");

    // Search with undefined attribute - should fail with UndefinedAttributeType error
    let result = ldap
        .search(
            "dc=example,dc=com",
            Scope::Subtree,
            "(userPrincipalName=test)",
            vec!["*"],
        )
        .await;

    // Should get an error
    assert!(result.is_err());
    let err = result.unwrap_err();
    
    match err {
        LdapError::LdapResult { result } => {
            assert_eq!(result.rc, 17); // UndefinedAttributeType
            assert!(result.text.contains("attribute type undefined"));
        }
        _ => panic!("Expected LdapResult error, got: {:?}", err),
    }

    // Unbind
    ldap.unbind().await.ok();
    handle.abort();
}

#[tokio::test]
async fn test_undefined_attribute_in_complex_filter() {
    let (server_url, handle) = start_test_server().await;

    // Connect to test server
    let (conn, mut ldap) = LdapConnAsync::new(&server_url)
        .await
        .expect("connection failed");
    tokio::spawn(async move { conn.drive().await });

    // Bind anonymously
    ldap.simple_bind("", "").await.expect("bind failed");

    // Search with AND filter containing undefined attribute
    let result = ldap
        .search(
            "dc=example,dc=com",
            Scope::Subtree,
            "(&(uid=john)(nonExistentAttr=value))",
            vec!["*"],
        )
        .await;

    // Should get an error
    assert!(result.is_err());
    let err = result.unwrap_err();
    
    match err {
        LdapError::LdapResult { result } => {
            assert_eq!(result.rc, 17); // UndefinedAttributeType
            assert!(result.text.contains("nonexistentattr")); // Note: lowercase
            assert!(result.text.contains("attribute type undefined"));
        }
        _ => panic!("Expected LdapResult error, got: {:?}", err),
    }

    // Unbind
    ldap.unbind().await.ok();
    handle.abort();
}

#[tokio::test]
async fn test_valid_attribute_search_still_works() {
    let (server_url, handle) = start_test_server().await;

    // Connect to test server
    let (conn, mut ldap) = LdapConnAsync::new(&server_url)
        .await
        .expect("connection failed");
    tokio::spawn(async move { conn.drive().await });

    // Bind anonymously
    ldap.simple_bind("", "").await.expect("bind failed");

    // Search with valid attribute - should work fine
    let (entries, _result) = ldap
        .search(
            "dc=example,dc=com",
            Scope::Subtree,
            "(uid=john)",
            vec!["*"],
        )
        .await
        .expect("search failed")
        .success()
        .expect("search failed");

    // Should find john
    assert_eq!(entries.len(), 1);
    let entry = SearchEntry::construct(entries[0].clone());
    assert_eq!(entry.dn, "uid=john,ou=users,dc=example,dc=com");

    // Unbind
    ldap.unbind().await.ok();
    handle.abort();
}

#[tokio::test]
async fn test_undefined_attribute_in_or_filter() {
    let (server_url, handle) = start_test_server().await;

    // Connect to test server
    let (conn, mut ldap) = LdapConnAsync::new(&server_url)
        .await
        .expect("connection failed");
    tokio::spawn(async move { conn.drive().await });

    // Bind anonymously
    ldap.simple_bind("", "").await.expect("bind failed");

    // Search with OR filter containing undefined attribute
    // Even though uid=john is valid, the undefined attribute should cause an error
    let result = ldap
        .search(
            "dc=example,dc=com",
            Scope::Subtree,
            "(|(uid=john)(unknownAttribute=value))",
            vec!["*"],
        )
        .await;

    // Should get an error
    assert!(result.is_err());
    let err = result.unwrap_err();
    
    match err {
        LdapError::LdapResult { result } => {
            assert_eq!(result.rc, 17); // UndefinedAttributeType
            assert!(result.text.contains("unknownattribute")); // Note: lowercase
            assert!(result.text.contains("attribute type undefined"));
        }
        _ => panic!("Expected LdapResult error, got: {:?}", err),
    }

    // Unbind
    ldap.unbind().await.ok();
    handle.abort();
}

#[tokio::test]
async fn test_undefined_attribute_in_not_filter() {
    let (server_url, handle) = start_test_server().await;

    // Connect to test server
    let (conn, mut ldap) = LdapConnAsync::new(&server_url)
        .await
        .expect("connection failed");
    tokio::spawn(async move { conn.drive().await });

    // Bind anonymously
    ldap.simple_bind("", "").await.expect("bind failed");

    // Search with NOT filter containing undefined attribute
    let result = ldap
        .search(
            "dc=example,dc=com",
            Scope::Subtree,
            "(!(missingAttribute=value))",
            vec!["*"],
        )
        .await;

    // Should get an error
    assert!(result.is_err());
    let err = result.unwrap_err();
    
    match err {
        LdapError::LdapResult { result } => {
            assert_eq!(result.rc, 17); // UndefinedAttributeType
            assert!(result.text.contains("missingattribute")); // Note: lowercase
            assert!(result.text.contains("attribute type undefined"));
        }
        _ => panic!("Expected LdapResult error, got: {:?}", err),
    }

    // Unbind
    ldap.unbind().await.ok();
    handle.abort();
}

#[tokio::test]
async fn test_present_filter_with_undefined_attribute() {
    let (server_url, handle) = start_test_server().await;

    // Connect to test server
    let (conn, mut ldap) = LdapConnAsync::new(&server_url)
        .await
        .expect("connection failed");
    tokio::spawn(async move { conn.drive().await });

    // Bind anonymously
    ldap.simple_bind("", "").await.expect("bind failed");

    // Search with present filter for undefined attribute
    let result = ldap
        .search(
            "dc=example,dc=com",
            Scope::Subtree,
            "(notDefinedAttribute=*)",
            vec!["*"],
        )
        .await;

    // Should get an error
    assert!(result.is_err());
    let err = result.unwrap_err();
    
    match err {
        LdapError::LdapResult { result } => {
            assert_eq!(result.rc, 17); // UndefinedAttributeType
            assert!(result.text.contains("notdefinedattribute")); // Note: lowercase
            assert!(result.text.contains("attribute type undefined"));
        }
        _ => panic!("Expected LdapResult error, got: {:?}", err),
    }

    // Unbind
    ldap.unbind().await.ok();
    handle.abort();
}