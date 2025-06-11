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
    use tempfile::NamedTempFile;
    use std::io::Write;

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
}