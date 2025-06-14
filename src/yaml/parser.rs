use super::schema::{YamlDirectory, YamlEntry, YamlSchema};
use crate::YamlLdapError;
use std::path::Path;

pub async fn parse_directory_file(path: &Path) -> crate::Result<(YamlDirectory, YamlSchema)> {
    let content = tokio::fs::read_to_string(path).await?;
    let yaml_dir: YamlDirectory = serde_yaml::from_str(&content)?;

    // Validate base DN
    if yaml_dir.directory.base_dn.is_empty() {
        return Err(YamlLdapError::Config("Base DN cannot be empty".to_string()));
    }

    // Create schema from config or use defaults
    let schema = yaml_dir
        .schema
        .as_ref()
        .map(|s| s.clone().into())
        .unwrap_or_default();

    // Validate entries
    validate_entries(&yaml_dir.entries, &schema)?;

    Ok((yaml_dir, schema))
}

fn validate_entries(entries: &[YamlEntry], schema: &YamlSchema) -> crate::Result<()> {
    for entry in entries {
        // Validate DN format
        if entry.dn.is_empty() {
            return Err(YamlLdapError::Config(
                "Entry DN cannot be empty".to_string(),
            ));
        }

        // Validate object classes
        if entry.object_class.is_empty() {
            return Err(YamlLdapError::Config(format!(
                "Entry {} must have at least one objectClass",
                entry.dn
            )));
        }

        // Validate required attributes for object classes
        for oc in &entry.object_class {
            if let Some(required_attrs) = schema.object_classes.get(oc) {
                for attr in required_attrs {
                    if !entry.attributes.contains_key(attr) {
                        return Err(YamlLdapError::Config(format!(
                            "Entry {} with objectClass {} is missing required attribute {}",
                            entry.dn, oc, attr
                        )));
                    }
                }
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[tokio::test]
    async fn test_parse_valid_directory() {
        let yaml_content = r#"
directory:
  base_dn: "dc=example,dc=com"

entries:
  - dn: "dc=example,dc=com"
    objectClass: ["top", "domain"]
    dc: "example"
"#;

        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(yaml_content.as_bytes()).unwrap();

        let result = parse_directory_file(temp_file.path()).await;
        assert!(result.is_ok());

        let (dir, _schema) = result.unwrap();
        assert_eq!(dir.directory.base_dn, "dc=example,dc=com");
        assert_eq!(dir.entries.len(), 1);
    }

    #[tokio::test]
    async fn test_parse_empty_base_dn() {
        let yaml_content = r#"
directory:
  base_dn: ""

entries: []
"#;

        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(yaml_content.as_bytes()).unwrap();

        let result = parse_directory_file(temp_file.path()).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Base DN cannot be empty"));
    }

    #[tokio::test]
    async fn test_parse_empty_entry_dn() {
        let yaml_content = r#"
directory:
  base_dn: "dc=example,dc=com"

entries:
  - dn: ""
    objectClass: ["top"]
"#;

        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(yaml_content.as_bytes()).unwrap();

        let result = parse_directory_file(temp_file.path()).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Entry DN cannot be empty"));
    }

    #[tokio::test]
    async fn test_parse_missing_object_class() {
        let yaml_content = r#"
directory:
  base_dn: "dc=example,dc=com"

entries:
  - dn: "cn=test,dc=example,dc=com"
    objectClass: []
"#;

        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(yaml_content.as_bytes()).unwrap();

        let result = parse_directory_file(temp_file.path()).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("must have at least one objectClass"));
    }

    #[tokio::test]
    async fn test_parse_missing_required_attribute() {
        let yaml_content = r#"
directory:
  base_dn: "dc=example,dc=com"

schema:
  object_classes:
    - name: "person"
      attributes: ["cn", "sn"]

entries:
  - dn: "cn=test,dc=example,dc=com"
    objectClass: ["person"]
    cn: "test"
    # Missing required attribute 'sn'
"#;

        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(yaml_content.as_bytes()).unwrap();

        let result = parse_directory_file(temp_file.path()).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("missing required attribute sn"));
    }

    #[tokio::test]
    async fn test_parse_with_custom_schema() {
        let yaml_content = r#"
directory:
  base_dn: "dc=example,dc=com"

schema:
  object_classes:
    - name: "customPerson"
      attributes: ["cn", "email"]
  custom_attributes:
    email:
      syntax: "String"
      single_value: true

entries:
  - dn: "cn=test,dc=example,dc=com"
    objectClass: ["customPerson"]
    cn: "test"
    email: "test@example.com"
"#;

        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(yaml_content.as_bytes()).unwrap();

        let result = parse_directory_file(temp_file.path()).await;
        assert!(result.is_ok());

        let (dir, schema) = result.unwrap();
        assert!(schema.object_classes.contains_key("customPerson"));
        assert!(schema.custom_attributes.contains_key("email"));
        assert_eq!(dir.entries.len(), 1);
    }

    #[tokio::test]
    async fn test_parse_invalid_yaml() {
        let yaml_content = r#"
directory:
  base_dn: "dc=example,dc=com"

entries:
  - dn: "test"
    objectClass: [invalid yaml here
"#;

        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(yaml_content.as_bytes()).unwrap();

        let result = parse_directory_file(temp_file.path()).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), YamlLdapError::YamlParse(_)));
    }

    #[tokio::test]
    async fn test_parse_file_not_found() {
        let result = parse_directory_file(Path::new("/non/existent/file.yaml")).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), YamlLdapError::Io(_)));
    }

    #[test]
    fn test_validate_entries_direct() {
        use std::collections::HashMap;

        let schema = YamlSchema::default();
        
        // Test empty entries - should succeed
        let result = validate_entries(&[], &schema);
        assert!(result.is_ok());

        // Test valid entry
        let mut attrs = HashMap::new();
        attrs.insert("cn".to_string(), serde_yaml::Value::String("test".to_string()));
        
        let entries = vec![YamlEntry {
            dn: "cn=test,dc=example,dc=com".to_string(),
            object_class: vec!["top".to_string()],
            attributes: attrs,
        }];
        
        let result = validate_entries(&entries, &schema);
        assert!(result.is_ok());
    }
}
