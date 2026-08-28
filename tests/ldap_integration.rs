use ldap3::{LdapConnAsync, LdapError, Scope, SearchEntry};
use std::io::{Seek, Write};
use std::time::Duration;
use tempfile::NamedTempFile;
use tokio::net::TcpListener;
use yamldap::{Config, Server};

const ORIGINAL_PASSWORD: &str = "original-secret";
const ROTATED_PASSWORD: &str = "rotated-secret";
const USER_DN: &str = "uid=test,dc=example,dc=com";

struct TestServer {
    url: String,
    yaml_file: NamedTempFile,
    task: tokio::task::JoinHandle<()>,
}

impl TestServer {
    async fn start(allow_anonymous: bool, hot_reload: bool) -> Self {
        let mut yaml_file = NamedTempFile::new().unwrap();
        write_directory(&mut yaml_file, ORIGINAL_PASSWORD);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let config = Config {
            yaml_file: yaml_file.path().to_path_buf(),
            bind_address: address,
            base_dn: None,
            allow_anonymous,
            hot_reload,
            log_level: tracing::Level::INFO,
            ad_compat: false,
        };
        let server = Server::new(config).await.unwrap();
        let task = tokio::spawn(async move {
            let _ = server.run_with_listener(listener).await;
        });

        Self {
            url: format!("ldap://{address}"),
            yaml_file,
            task,
        }
    }

    async fn connect(&self) -> ldap3::Ldap {
        let (connection, ldap) = LdapConnAsync::new(&self.url).await.unwrap();
        tokio::spawn(async move { connection.drive().await });
        ldap
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn write_directory(file: &mut NamedTempFile, password: &str) {
    file.as_file_mut().set_len(0).unwrap();
    file.rewind().unwrap();
    writeln!(
        file,
        r#"directory:
  base_dn: dc=example,dc=com
entries:
  - dn: dc=example,dc=com
    objectClass: [top, domain]
    dc: example
  - dn: {USER_DN}
    objectClass: [top, person, inetOrgPerson]
    uid: test
    cn: Test User
    givenName: Test
    sn: User
    mail: test@example.com
    userPassword: {password}
"#
    )
    .unwrap();
    file.flush().unwrap();
}

fn assert_access_denied(error: LdapError) {
    match error {
        LdapError::LdapResult { result } => assert_eq!(result.rc, 50),
        other => panic!("Expected LDAP access-denied result, got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unbound_search_is_denied_and_passwords_are_never_returned() {
    let server = TestServer::start(false, false).await;
    let mut ldap = server.connect().await;

    let error = ldap
        .search(
            "dc=example,dc=com",
            Scope::Subtree,
            "(objectClass=*)",
            vec!["*"],
        )
        .await
        .unwrap()
        .success()
        .unwrap_err();
    assert_access_denied(error);

    ldap.simple_bind(USER_DN, ORIGINAL_PASSWORD)
        .await
        .unwrap()
        .success()
        .unwrap();
    let (entries, _) = ldap
        .search(
            "dc=example,dc=com",
            Scope::Subtree,
            "(objectClass=*)",
            vec!["*", "userPassword"],
        )
        .await
        .unwrap()
        .success()
        .unwrap();

    for entry in entries.into_iter().map(SearchEntry::construct) {
        assert!(entry
            .attrs
            .keys()
            .all(|name| !name.eq_ignore_ascii_case("userPassword")));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn failed_rebind_clears_the_previous_identity() {
    let server = TestServer::start(false, false).await;
    let mut ldap = server.connect().await;

    ldap.simple_bind(USER_DN, ORIGINAL_PASSWORD)
        .await
        .unwrap()
        .success()
        .unwrap();
    assert!(ldap
        .simple_bind(USER_DN, "wrong-password")
        .await
        .unwrap()
        .success()
        .is_err());

    let error = ldap
        .search(
            "dc=example,dc=com",
            Scope::Base,
            "(objectClass=*)",
            vec!["cn"],
        )
        .await
        .unwrap()
        .success()
        .unwrap_err();
    assert_access_denied(error);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn password_rotation_applies_to_an_existing_connection() {
    let mut server = TestServer::start(false, true).await;
    let mut ldap = server.connect().await;

    ldap.simple_bind(USER_DN, ORIGINAL_PASSWORD)
        .await
        .unwrap()
        .success()
        .unwrap();
    write_directory(&mut server.yaml_file, ROTATED_PASSWORD);

    let mut rotated = false;
    for _ in 0..50 {
        if ldap
            .simple_bind(USER_DN, ROTATED_PASSWORD)
            .await
            .unwrap()
            .success()
            .is_ok()
        {
            rotated = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(rotated, "hot reload did not apply the rotated password");

    assert!(ldap
        .simple_bind(USER_DN, ORIGINAL_PASSWORD)
        .await
        .unwrap()
        .success()
        .is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rootdse_reports_the_naming_context_without_polluting_directory_searches() {
    let server = TestServer::start(true, false).await;
    let mut ldap = server.connect().await;

    ldap.simple_bind("", "").await.unwrap().success().unwrap();
    let (entries, _) = ldap
        .search(
            "",
            Scope::Base,
            "(objectClass=*)",
            vec!["namingContexts", "supportedLDAPVersion", "vendorName"],
        )
        .await
        .unwrap()
        .success()
        .unwrap();

    assert_eq!(entries.len(), 1);
    let root_dse = SearchEntry::construct(entries.into_iter().next().unwrap());
    assert!(root_dse.dn.is_empty());
    assert_eq!(
        root_dse.attrs.get("namingContexts"),
        Some(&vec!["dc=example,dc=com".to_string()])
    );
    assert_eq!(
        root_dse.attrs.get("supportedLDAPVersion"),
        Some(&vec!["3".to_string()])
    );
    assert_eq!(
        root_dse.attrs.get("vendorName"),
        Some(&vec!["yamldap".to_string()])
    );

    let (entries, _) = ldap
        .search(
            "dc=example,dc=com",
            Scope::Subtree,
            "(objectClass=*)",
            vec!["*"],
        )
        .await
        .unwrap()
        .success()
        .unwrap();
    assert_eq!(entries.len(), 2);
    assert!(entries
        .into_iter()
        .map(SearchEntry::construct)
        .all(|entry| !entry.dn.is_empty()));
}
