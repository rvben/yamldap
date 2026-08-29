use ldap3::{LdapConnAsync, LdapError, Scope, SearchEntry};
use std::io::{Seek, Write};
use std::net::SocketAddr;
use std::time::Duration;
use tempfile::NamedTempFile;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use yamldap::{Config, Server, ServerHandle};

const ORIGINAL_PASSWORD: &str = "original-secret";
const ROTATED_PASSWORD: &str = "rotated-secret";
const USER_DN: &str = "uid=test,dc=example,dc=com";

struct TestServer {
    address: SocketAddr,
    url: String,
    yaml_file: NamedTempFile,
    _handle: ServerHandle,
}

impl TestServer {
    async fn start(allow_anonymous: bool, hot_reload: bool) -> Self {
        let mut yaml_file = NamedTempFile::new().unwrap();
        write_directory(&mut yaml_file, ORIGINAL_PASSWORD);

        let config = Config::new(yaml_file.path())
            .with_bind_address("127.0.0.1:0".parse().unwrap())
            .with_anonymous_access(allow_anonymous)
            .with_hot_reload(hot_reload);
        let server = Server::new(config).await.unwrap();
        let handle = server.start().await.unwrap();
        let address = handle.local_addr();

        Self {
            address,
            url: format!("ldap://{address}"),
            yaml_file,
            _handle: handle,
        }
    }

    async fn connect(&self) -> ldap3::Ldap {
        let (connection, ldap) = LdapConnAsync::new(&self.url).await.unwrap();
        tokio::spawn(async move { connection.drive().await });
        ldap
    }
}

async fn read_ldap_frame(stream: &mut TcpStream) -> Vec<u8> {
    let mut header = [0u8; 2];
    tokio::time::timeout(Duration::from_secs(2), stream.read_exact(&mut header))
        .await
        .expect("LDAP response timed out")
        .expect("failed to read LDAP response header");
    assert_eq!(header[0], 0x30, "LDAP response must be a sequence");

    let (content_length, mut frame) = if header[1] & 0x80 == 0 {
        (header[1] as usize, header.to_vec())
    } else {
        let length_octets = (header[1] & 0x7f) as usize;
        assert!((1..=4).contains(&length_octets));
        let mut encoded_length = vec![0u8; length_octets];
        stream.read_exact(&mut encoded_length).await.unwrap();
        let content_length = encoded_length
            .iter()
            .fold(0usize, |length, byte| (length << 8) | *byte as usize);
        let mut frame = header.to_vec();
        frame.extend_from_slice(&encoded_length);
        (content_length, frame)
    };

    let mut content = vec![0u8; content_length];
    tokio::time::timeout(Duration::from_secs(2), stream.read_exact(&mut content))
        .await
        .expect("LDAP response body timed out")
        .expect("failed to read LDAP response body");
    frame.extend_from_slice(&content);
    frame
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
async fn unsupported_sasl_bind_returns_an_error_and_keeps_the_connection_open() {
    let server = TestServer::start(true, false).await;
    let mut stream = TcpStream::connect(server.address).await.unwrap();

    let sasl_bind = [
        0x30, 0x18, // LDAPMessage sequence
        0x02, 0x01, 0x01, // message ID 1
        0x60, 0x13, // BindRequest
        0x02, 0x01, 0x03, // LDAP version 3
        0x04, 0x00, // empty DN
        0xa3, 0x0c, // SASL authentication choice
        0x04, 0x0a, b'G', b'S', b'S', b'-', b'S', b'P', b'N', b'E', b'G', b'O',
    ];
    stream.write_all(&sasl_bind).await.unwrap();

    let response = read_ldap_frame(&mut stream).await;
    assert!(response.contains(&0x61), "expected a BindResponse");
    assert!(
        response.windows(3).any(|bytes| bytes == [0x0a, 0x01, 0x07]),
        "expected authMethodNotSupported (7), got {response:02x?}"
    );

    let anonymous_bind = [
        0x30, 0x0c, // LDAPMessage sequence
        0x02, 0x01, 0x02, // message ID 2
        0x60, 0x07, // BindRequest
        0x02, 0x01, 0x03, // LDAP version 3
        0x04, 0x00, // empty DN
        0x80, 0x00, // empty simple credentials
    ];
    stream.write_all(&anonymous_bind).await.unwrap();

    let response = read_ldap_frame(&mut stream).await;
    assert!(
        response.windows(3).any(|bytes| bytes == [0x0a, 0x01, 0x00]),
        "expected a successful anonymous bind, got {response:02x?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unsupported_microsoft_sicily_bind_returns_an_error_and_keeps_the_connection_open() {
    let server = TestServer::start(true, false).await;
    let mut stream = TcpStream::connect(server.address).await.unwrap();

    let sicily_bind = [
        0x30, 0x0f, // LDAPMessage sequence
        0x02, 0x01, 0x01, // message ID 1
        0x60, 0x0a, // BindRequest
        0x02, 0x01, 0x03, // LDAP version 3
        0x04, 0x00, // empty DN
        0x8a, 0x03, 0x01, 0x02, 0x03, // Sicily negotiate token
    ];
    stream.write_all(&sicily_bind).await.unwrap();

    let response = read_ldap_frame(&mut stream).await;
    assert!(response.contains(&0x61), "expected a BindResponse");
    assert!(
        response.windows(3).any(|bytes| bytes == [0x0a, 0x01, 0x07]),
        "expected authMethodNotSupported (7), got {response:02x?}"
    );

    let anonymous_bind = [
        0x30, 0x0c, // LDAPMessage sequence
        0x02, 0x01, 0x02, // message ID 2
        0x60, 0x07, // BindRequest
        0x02, 0x01, 0x03, // LDAP version 3
        0x04, 0x00, // empty DN
        0x80, 0x00, // empty simple credentials
    ];
    stream.write_all(&anonymous_bind).await.unwrap();

    let response = read_ldap_frame(&mut stream).await;
    assert!(
        response.windows(3).any(|bytes| bytes == [0x0a, 0x01, 0x00]),
        "expected a successful anonymous bind, got {response:02x?}"
    );
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
