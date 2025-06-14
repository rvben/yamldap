use ldap3::{LdapConn, Scope, SearchEntry};
use std::process::{Child, Command};
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use tokio::sync::Barrier;

struct TestServer {
    process: Child,
    port: u16,
}

impl TestServer {
    fn start() -> Self {
        let port = 13390; // Use a different port from other tests
        
        // Start yamldap server
        let process = Command::new("target/release/yamldap")
            .args(&["-f", "examples/sample_directory.yaml", "-p", &port.to_string()])
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

#[tokio::test]
async fn test_concurrent_client_connections() {
    let server = TestServer::start();
    let ldap_url = format!("ldap://localhost:{}", server.port);
    let url = Arc::new(ldap_url);
    
    // Test 10 concurrent clients
    let num_clients = 10;
    let barrier = Arc::new(Barrier::new(num_clients));
    
    let mut handles = vec![];
    
    for client_id in 0..num_clients {
        let url = url.clone();
        let barrier = barrier.clone();
        
        let handle = tokio::spawn(async move {
            // Wait for all clients to be ready
            barrier.wait().await;
            
            // Each client performs operations
            let mut ldap = LdapConn::new(&url).expect("Failed to connect");
            
            // Bind with different users
            let user_dn = if client_id % 2 == 0 {
                "uid=jdoe,ou=users,dc=example,dc=com"
            } else {
                "cn=admin,ou=admins,dc=example,dc=com"
            };
            let password = if client_id % 2 == 0 { "password" } else { "admin" };
            
            ldap.simple_bind(user_dn, password)
                .expect("Bind failed")
                .success()
                .expect("Bind error");
            
            // Perform searches
            for i in 0..5 {
                let filter = if i % 2 == 0 {
                    "(objectClass=person)"
                } else {
                    "(objectClass=organizationalUnit)"
                };
                
                let (results, _res) = ldap
                    .search("dc=example,dc=com", Scope::Subtree, filter, vec!["dn"])
                    .expect("Search failed")
                    .success()
                    .expect("Search error");
                
                assert!(!results.is_empty());
            }
            
            // Unbind
            ldap.unbind().expect("Unbind failed");
            
            client_id
        });
        
        handles.push(handle);
    }
    
    // Wait for all clients to complete
    for handle in handles {
        let client_id = handle.await.expect("Client task failed");
        println!("Client {} completed successfully", client_id);
    }
}

#[tokio::test]
async fn test_rapid_connect_disconnect() {
    let server = TestServer::start();
    let ldap_url = format!("ldap://localhost:{}", server.port);
    
    // Rapidly connect and disconnect 50 times
    for i in 0..50 {
        let mut ldap = LdapConn::new(&ldap_url).expect("Failed to connect");
        
        // Anonymous bind
        ldap.simple_bind("", "")
            .expect("Bind failed")
            .success()
            .expect("Bind error");
        
        // Quick search
        let (results, _res) = ldap
            .search("dc=example,dc=com", Scope::Base, "(objectClass=*)", vec!["dn"])
            .expect("Search failed")
            .success()
            .expect("Search error");
        
        assert_eq!(results.len(), 1);
        
        // Disconnect
        ldap.unbind().expect("Unbind failed");
        
        if i % 10 == 0 {
            println!("Completed {} rapid connections", i + 1);
        }
    }
}

#[tokio::test]
async fn test_concurrent_searches_same_connection() {
    let server = TestServer::start();
    let ldap_url = format!("ldap://localhost:{}", server.port);
    
    let mut ldap = LdapConn::new(&ldap_url).expect("Failed to connect");
    
    // Bind once
    ldap.simple_bind("cn=admin,ou=admins,dc=example,dc=com", "admin")
        .expect("Bind failed")
        .success()
        .expect("Bind error");
    
    // Note: ldap3 doesn't support concurrent operations on same connection
    // But we can test sequential operations with different filters
    let filters = vec![
        "(uid=jdoe)",
        "(cn=admin)",
        "(objectClass=groupOfNames)",
        "(ou=users)",
        "(&(objectClass=person)(uid=jdoe))",
        "(|(uid=jdoe)(uid=rjones))",
        "(!(uid=guest))",
        "(cn~=john)",
        "(cn:=Jane Doe)",
        "(:dn:=users)",
    ];
    
    for filter in filters {
        let (results, _res) = ldap
            .search("dc=example,dc=com", Scope::Subtree, filter, vec!["dn", "cn"])
            .expect(&format!("Search failed for filter: {}", filter))
            .success()
            .expect("Search error");
        
        println!("Filter '{}' returned {} results", filter, results.len());
    }
    
    ldap.unbind().expect("Unbind failed");
}

#[test]
fn test_stress_large_result_set() {
    // This test would require a larger dataset
    // For now, we'll test with the sample directory
    let server = TestServer::start();
    let ldap_url = format!("ldap://localhost:{}", server.port);
    
    let mut ldap = LdapConn::new(&ldap_url).expect("Failed to connect");
    
    // Search for all entries
    let (results, _res) = ldap
        .search("dc=example,dc=com", Scope::Subtree, "(objectClass=*)", vec!["*"])
        .expect("Search failed")
        .success()
        .expect("Search error");
    
    // Verify we got all entries
    assert!(results.len() > 5); // Should have base, OUs, users, groups, etc.
    
    // Test with all attributes
    for result in results {
        let entry = SearchEntry::construct(result);
        println!("Entry: {} has {} attributes", entry.dn, entry.attrs.len());
    }
}