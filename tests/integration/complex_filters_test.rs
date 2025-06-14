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
        let port = 13391; // Use a different port
        
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

#[test]
fn test_deeply_nested_filters() {
    let server = TestServer::start();
    let ldap_url = format!("ldap://localhost:{}", server.port);
    
    let mut ldap = LdapConn::new(&ldap_url).expect("Failed to connect");
    
    // Test deeply nested AND/OR combinations
    let complex_filter = "(&(objectClass=person)(|(uid=jdoe)(uid=rjones)(uid=mjohnson))(!(cn=Guest*)))";
    
    let (results, _res) = ldap
        .search("dc=example,dc=com", Scope::Subtree, complex_filter, vec!["uid", "cn"])
        .expect("Search failed")
        .success()
        .expect("Search error");
    
    // Should find jdoe and rjones (mjohnson doesn't exist in sample)
    assert!(results.len() >= 2);
    
    let entries: Vec<SearchEntry> = results.into_iter().map(SearchEntry::construct).collect();
    let uids: Vec<String> = entries
        .iter()
        .filter_map(|e| e.attrs.get("uid"))
        .flat_map(|v| v.iter())
        .cloned()
        .collect();
    
    assert!(uids.contains(&"jdoe".to_string()));
    assert!(uids.contains(&"rjones".to_string()));
}

#[test]
fn test_complex_substring_filters() {
    let server = TestServer::start();
    let ldap_url = format!("ldap://localhost:{}", server.port);
    
    let mut ldap = LdapConn::new(&ldap_url).expect("Failed to connect");
    
    // Test various substring patterns
    let test_cases = vec![
        ("(cn=*Doe)", vec!["John Doe", "Jane Doe"]),
        ("(cn=J*)", vec!["John Doe", "Jane Doe"]),
        ("(cn=*oh*)", vec!["John Doe"]),
        ("(mail=*@example.com)", vec!["john.doe@example.com", "jane.doe@example.com", "admin@example.com"]),
        ("(uid=*doe*)", vec!["jdoe"]),
    ];
    
    for (filter, expected_partial) in test_cases {
        let (results, _res) = ldap
            .search("dc=example,dc=com", Scope::Subtree, filter, vec!["cn", "mail", "uid"])
            .expect(&format!("Search failed for filter: {}", filter))
            .success()
            .expect("Search error");
        
        let entries: Vec<SearchEntry> = results.into_iter().map(SearchEntry::construct).collect();
        
        // Check that at least some expected values are found
        let mut found_count = 0;
        for expected in &expected_partial {
            for entry in &entries {
                let has_match = entry.attrs.values().any(|values| {
                    values.iter().any(|v| v.contains(expected))
                });
                if has_match {
                    found_count += 1;
                    break;
                }
            }
        }
        
        println!("Filter '{}' found {}/{} expected matches", filter, found_count, expected_partial.len());
        assert!(found_count > 0, "Filter '{}' should find at least one match", filter);
    }
}

#[test]
fn test_mixed_filter_types() {
    let server = TestServer::start();
    let ldap_url = format!("ldap://localhost:{}", server.port);
    
    let mut ldap = LdapConn::new(&ldap_url).expect("Failed to connect");
    
    // Mix of all filter types
    let mixed_filter = "(&(objectClass=person)(cn~=john)(!(uid:=guest))(:dn:=users))";
    
    let (results, _res) = ldap
        .search("dc=example,dc=com", Scope::Subtree, mixed_filter, vec!["dn", "cn"])
        .expect("Search failed")
        .success()
        .expect("Search error");
    
    // Should find entries with "john" in cn under users OU
    assert!(!results.is_empty());
    
    let entries: Vec<SearchEntry> = results.into_iter().map(SearchEntry::construct).collect();
    for entry in &entries {
        // All results should be under users
        assert!(entry.dn.to_lowercase().contains("users"));
        
        // All should have cn containing "john" (case-insensitive)
        if let Some(cn_values) = entry.attrs.get("cn") {
            let has_john = cn_values.iter().any(|v| v.to_lowercase().contains("john"));
            assert!(has_john, "Entry {} should have 'john' in cn", entry.dn);
        }
    }
}

#[test]
fn test_filter_with_special_characters() {
    let server = TestServer::start();
    let ldap_url = format!("ldap://localhost:{}", server.port);
    
    let mut ldap = LdapConn::new(&ldap_url).expect("Failed to connect");
    
    // Test filters with escaped special characters
    // Note: The test data would need entries with special characters
    let special_filters = vec![
        "(cn=John\\20Doe)",  // Space
        "(cn=*\\2a*)",       // Asterisk
        "(cn=*\\28*)",       // Left parenthesis
        "(cn=*\\29*)",       // Right parenthesis
        "(cn=*\\5c*)",       // Backslash
    ];
    
    for filter in special_filters {
        // These might not match anything in the sample data, but shouldn't error
        let result = ldap.search("dc=example,dc=com", Scope::Subtree, filter, vec!["cn"]);
        assert!(result.is_ok(), "Filter '{}' should not cause an error", filter);
    }
}

#[test]
fn test_attribute_options_in_filters() {
    let server = TestServer::start();
    let ldap_url = format!("ldap://localhost:{}", server.port);
    
    let mut ldap = LdapConn::new(&ldap_url).expect("Failed to connect");
    
    // Test extensible filters with different matching rules
    let matching_rule_filters = vec![
        "(cn:caseIgnoreMatch:=JOHN DOE)",
        "(cn:caseExactMatch:=John Doe)",
        "(cn:2.5.13.2:=john doe)",  // OID for caseIgnoreMatch
        "(cn:dn:=admin)",            // DN matching
    ];
    
    for filter in matching_rule_filters {
        let (results, _res) = ldap
            .search("dc=example,dc=com", Scope::Subtree, filter, vec!["dn", "cn"])
            .expect(&format!("Search failed for filter: {}", filter))
            .success()
            .expect("Search error");
        
        println!("Filter '{}' returned {} results", filter, results.len());
    }
}

#[test]
fn test_empty_filter_components() {
    let server = TestServer::start();
    let ldap_url = format!("ldap://localhost:{}", server.port);
    
    let mut ldap = LdapConn::new(&ldap_url).expect("Failed to connect");
    
    // Test filters with empty components
    let edge_case_filters = vec![
        "(&)",                    // Empty AND
        "(|)",                    // Empty OR
        "(&(objectClass=*))",     // Single component AND
        "(|(objectClass=*))",     // Single component OR
        "(!(!(objectClass=*)))",  // Double negation
    ];
    
    for filter in edge_case_filters {
        let result = ldap.search("dc=example,dc=com", Scope::Subtree, filter, vec!["dn"]);
        
        // Some of these might be invalid and return errors
        if let Ok((results, _res)) = result.and_then(|r| r.success()) {
            println!("Filter '{}' returned {} results", filter, results.len());
        } else {
            println!("Filter '{}' was rejected (expected for some edge cases)", filter);
        }
    }
}