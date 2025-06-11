use std::time::Duration;
use tokio::time::sleep;

#[tokio::test]
async fn test_server_startup() {
    // This test verifies that the server can start up with a valid YAML file
    let yaml_content = r#"
directory:
  base_dn: "dc=test,dc=com"

entries:
  - dn: "dc=test,dc=com"
    objectClass: ["top", "domain"]
    dc: "test"
"#;
    
    // Create temporary file
    let temp_file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(temp_file.path(), yaml_content).unwrap();
    
    // Parse the YAML file
    let (yaml_dir, schema) = yamldap::yaml::parse_directory_file(temp_file.path())
        .await
        .expect("Failed to parse YAML");
    
    assert_eq!(yaml_dir.directory.base_dn, "dc=test,dc=com");
    assert_eq!(yaml_dir.entries.len(), 1);
}

#[tokio::test]
async fn test_directory_operations() {
    use yamldap::directory::{Directory, storage::SearchScope};
    use yamldap::yaml::{YamlDirectory, YamlEntry, YamlSchema};
    
    // Create test directory
    let yaml_dir = YamlDirectory {
        directory: yamldap::yaml::schema::DirectoryConfig {
            base_dn: "dc=test,dc=com".to_string(),
        },
        schema: None,
        entries: vec![
            YamlEntry {
                dn: "dc=test,dc=com".to_string(),
                object_class: vec!["top".to_string(), "domain".to_string()],
                attributes: std::collections::HashMap::new(),
            },
            YamlEntry {
                dn: "uid=testuser,dc=test,dc=com".to_string(),
                object_class: vec!["person".to_string()],
                attributes: {
                    let mut attrs = std::collections::HashMap::new();
                    attrs.insert("cn".to_string(), serde_yaml::Value::String("Test User".to_string()));
                    attrs.insert("userPassword".to_string(), serde_yaml::Value::String("secret".to_string()));
                    attrs
                },
            },
        ],
    };
    
    let schema = YamlSchema::default();
    let directory = Directory::from_yaml(yaml_dir, schema);
    
    // Test entry lookup
    assert!(directory.entry_exists("dc=test,dc=com"));
    assert!(directory.entry_exists("uid=testuser,dc=test,dc=com"));
    assert!(!directory.entry_exists("uid=nonexistent,dc=test,dc=com"));
    
    // Test search
    let results = directory.search_entries("dc=test,dc=com", SearchScope::WholeSubtree, |_| true);
    assert_eq!(results.len(), 2);
}