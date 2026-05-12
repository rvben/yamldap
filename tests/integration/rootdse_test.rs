use ldap3::{LdapConnAsync, Scope, SearchEntry};
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::time::sleep;
use yamldap::{Config, Server};

async fn start_rootdse_test_server() -> (String, tokio::task::JoinHandle<()>) {
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

  - dn: "uid=alice,ou=users,dc=example,dc=com"
    objectClass: ["top", "person", "inetOrgPerson"]
    uid: "alice"
    cn: "Alice"
    sn: "Smith"
    userPassword: "alicepass"
"#;

    let temp_file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(temp_file.path(), yaml_content).unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);

    let config = Config {
        yaml_file: temp_file.path().to_path_buf(),
        bind_address: format!("127.0.0.1:{}", port).parse().unwrap(),
        base_dn: None,
        allow_anonymous: true,
        hot_reload: false,
        log_level: tracing::Level::INFO,
    };

    let server_url = format!("ldap://127.0.0.1:{}", port);

    let server = Server::new(config).await.unwrap();
    let handle = tokio::spawn(async move {
        server.run().await.ok();
    });

    sleep(Duration::from_millis(100)).await;

    // Keep temp file alive for the lifetime of the test
    Box::leak(Box::new(temp_file));

    (server_url, handle)
}

#[tokio::test]
async fn test_rootdse_naming_contexts_populated() {
    let (server_url, handle) = start_rootdse_test_server().await;

    let (conn, mut ldap) = LdapConnAsync::new(&server_url)
        .await
        .expect("connection failed");
    tokio::spawn(async move { conn.drive().await });

    ldap.simple_bind("", "").await.expect("bind failed");

    let (entries, result) = ldap
        .search(
            "",
            Scope::Base,
            "(objectClass=*)",
            vec!["namingContexts", "supportedLDAPVersion", "vendorName"],
        )
        .await
        .expect("RootDSE search failed")
        .success()
        .expect("RootDSE search returned error");

    assert_eq!(result.rc, 0, "RootDSE search must succeed");
    assert_eq!(entries.len(), 1, "RootDSE search must return exactly one entry");

    let entry = SearchEntry::construct(entries[0].clone());
    assert_eq!(entry.dn, "", "RootDSE entry DN must be empty string");

    let naming_contexts = entry
        .attrs
        .get("namingContexts")
        .expect("namingContexts must be present in RootDSE");
    assert!(
        naming_contexts.contains(&"dc=example,dc=com".to_string()),
        "namingContexts must contain the directory base DN"
    );

    let ldap_versions = entry
        .attrs
        .get("supportedLDAPVersion")
        .expect("supportedLDAPVersion must be present in RootDSE");
    assert!(
        ldap_versions.contains(&"3".to_string()),
        "supportedLDAPVersion must include '3'"
    );

    let vendor_name = entry
        .attrs
        .get("vendorName")
        .expect("vendorName must be present in RootDSE");
    assert_eq!(
        vendor_name,
        &vec!["yamldap".to_string()],
        "vendorName must be 'yamldap'"
    );

    ldap.unbind().await.ok();
    handle.abort();
}

#[tokio::test]
async fn test_rootdse_does_not_interfere_with_normal_search() {
    let (server_url, handle) = start_rootdse_test_server().await;

    let (conn, mut ldap) = LdapConnAsync::new(&server_url)
        .await
        .expect("connection failed");
    tokio::spawn(async move { conn.drive().await });

    ldap.simple_bind("", "").await.expect("bind failed");

    // Normal subtree search from base DN must still work as before
    let (entries, result) = ldap
        .search(
            "dc=example,dc=com",
            Scope::Subtree,
            "(objectClass=*)",
            vec!["*"],
        )
        .await
        .expect("normal search failed")
        .success()
        .expect("normal search returned error");

    assert_eq!(result.rc, 0, "Normal search must succeed");
    assert!(entries.len() >= 3, "Normal search must return directory entries");

    // None of the returned entries should have an empty DN
    for raw_entry in &entries {
        let e = SearchEntry::construct(raw_entry.clone());
        assert!(!e.dn.is_empty(), "Regular directory entries must have non-empty DNs");
    }

    ldap.unbind().await.ok();
    handle.abort();
}
