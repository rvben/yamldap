use ldap3::{LdapConn, Scope, SearchEntry};
use std::process::{Child, Command};
use std::thread;
use std::time::Duration;

struct TestServer {
    process: Child,
    port: u16,
}

impl TestServer {
    fn start() -> Self {
        let port = 13389; // Use a non-standard port for testing
        
        // Start yamldap server
        let process = Command::new("target/release/yamldap")
            .args(&["-f", "test_filter_directory.yaml", "-p", &port.to_string()])
            .spawn()
            .expect("Failed to start yamldap");
        
        // Give server time to start
        thread::sleep(Duration::from_millis(500));
        
        TestServer { process, port }
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        let _ = self.process.kill();
    }
}

#[test]
fn test_approximate_match_filter() {
    let server = TestServer::start();
    let ldap_url = format!("ldap://localhost:{}", server.port);
    
    let mut ldap = LdapConn::new(&ldap_url).expect("Failed to connect");
    
    // Test approximate match for "john" - should match "John Smith" and "Johnny Johnson"
    let (results, _res) = ldap
        .search(
            "dc=test,dc=com",
            Scope::Subtree,
            "(cn~=john)",
            vec!["cn"],
        )
        .expect("Search failed")
        .success()
        .expect("Search error");
    
    let entries: Vec<SearchEntry> = results.into_iter().map(SearchEntry::construct).collect();
    assert_eq!(entries.len(), 2);
    
    let cns: Vec<String> = entries
        .iter()
        .filter_map(|e| e.attrs.get("cn"))
        .flat_map(|v| v.iter())
        .cloned()
        .collect();
    
    assert!(cns.contains(&"John Smith".to_string()));
    assert!(cns.contains(&"Johnny Johnson".to_string()));
}

#[test]
fn test_extensible_match_filter() {
    let server = TestServer::start();
    let ldap_url = format!("ldap://localhost:{}", server.port);
    
    let mut ldap = LdapConn::new(&ldap_url).expect("Failed to connect");
    
    // Test basic extensible match
    let (results, _res) = ldap
        .search(
            "dc=test,dc=com",
            Scope::Subtree,
            "(cn:=jane doe)",
            vec!["cn"],
        )
        .expect("Search failed")
        .success()
        .expect("Search error");
    
    let entries: Vec<SearchEntry> = results.into_iter().map(SearchEntry::construct).collect();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].attrs.get("cn").unwrap()[0], "Jane Doe");
}

#[test]
fn test_extensible_match_with_dn() {
    let server = TestServer::start();
    let ldap_url = format!("ldap://localhost:{}", server.port);
    
    let mut ldap = LdapConn::new(&ldap_url).expect("Failed to connect");
    
    // Test DN component matching - should match all entries under ou=people
    let (results, _res) = ldap
        .search(
            "dc=test,dc=com",
            Scope::Subtree,
            "(:dn:=people)",
            vec!["dn"],
        )
        .expect("Search failed")
        .success()
        .expect("Search error");
    
    let entries: Vec<SearchEntry> = results.into_iter().map(SearchEntry::construct).collect();
    
    // Should match ou=people and all entries under it
    assert!(entries.len() >= 5);
    
    for entry in &entries {
        assert!(entry.dn.contains("people"));
    }
}

#[test]
fn test_escape_sequences_in_filter() {
    let server = TestServer::start();
    let ldap_url = format!("ldap://localhost:{}", server.port);
    
    let mut ldap = LdapConn::new(&ldap_url).expect("Failed to connect");
    
    // Test filter with escaped parentheses
    let (results, _res) = ldap
        .search(
            "dc=test,dc=com",
            Scope::Subtree,
            "(description=Test \\28with parens\\29)",
            vec!["cn", "description"],
        )
        .expect("Search failed")
        .success()
        .expect("Search error");
    
    let entries: Vec<SearchEntry> = results.into_iter().map(SearchEntry::construct).collect();
    assert_eq!(entries.len(), 1);
    assert_eq!(
        entries[0].attrs.get("description").unwrap()[0],
        "Test (with parens)"
    );
}

#[test]
fn test_complex_filter_with_new_types() {
    let server = TestServer::start();
    let ldap_url = format!("ldap://localhost:{}", server.port);
    
    let mut ldap = LdapConn::new(&ldap_url).expect("Failed to connect");
    
    // Complex filter combining approximate match and DN component match
    let (results, _res) = ldap
        .search(
            "dc=test,dc=com",
            Scope::Subtree,
            "(&(objectClass=person)(|(cn~=john)(:dn:=people)))",
            vec!["cn"],
        )
        .expect("Search failed")
        .success()
        .expect("Search error");
    
    let entries: Vec<SearchEntry> = results.into_iter().map(SearchEntry::construct).collect();
    
    // Should match all people (DN contains "people") including those with "john" in name
    assert!(entries.len() >= 5);
}