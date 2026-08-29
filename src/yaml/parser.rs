use super::schema::{SchemaConfig, YamlDirectory, YamlEntry, YamlSchema};
use crate::directory::DistinguishedName;
use crate::YamlLdapError;
use std::path::Path;

pub async fn parse_directory_file(path: &Path) -> crate::Result<(YamlDirectory, YamlSchema)> {
    let content = tokio::fs::read_to_string(path).await?;
    // Materialize a Value first: serde_yaml_ng's Mapping rejects duplicate
    // keys, while deserializing directly into HashMap-backed fields can hide
    // an earlier occurrence.
    let document: serde_yaml_ng::Value = serde_yaml_ng::from_str(&content)?;
    let yaml_dir: YamlDirectory = serde_yaml_ng::from_value(document)?;

    // Validate base DN
    if yaml_dir.directory.base_dn.is_empty() {
        return Err(YamlLdapError::Config("Base DN cannot be empty".to_string()));
    }
    let base_dn = DistinguishedName::parse(&yaml_dir.directory.base_dn)
        .map_err(|error| YamlLdapError::Config(format!("Invalid base DN: {error}")))?;
    if base_dn.is_empty() {
        return Err(YamlLdapError::Config("Base DN cannot be empty".to_string()));
    }

    // Create schema from config or use defaults
    if let Some(schema_config) = &yaml_dir.schema {
        validate_schema_config(schema_config)?;
    }
    let schema = yaml_dir.schema.clone().map(Into::into).unwrap_or_default();

    // Validate entries
    validate_entries(&yaml_dir.entries, &schema)?;

    Ok((yaml_dir, schema))
}

pub(crate) fn validate_entries(entries: &[YamlEntry], schema: &YamlSchema) -> crate::Result<()> {
    for entry in entries {
        // Validate DN format
        if entry.dn.is_empty() {
            return Err(YamlLdapError::Config(
                "Entry DN cannot be empty".to_string(),
            ));
        }
        DistinguishedName::parse(&entry.dn).map_err(|error| {
            YamlLdapError::Config(format!("Entry {} has an invalid DN: {error}", entry.dn))
        })?;

        let mut attribute_names = std::collections::HashSet::new();
        for attribute in entry.attributes.keys() {
            if !attribute_names.insert(attribute.to_ascii_lowercase()) {
                return Err(YamlLdapError::Config(format!(
                    "Entry {} contains duplicate attribute description {}",
                    entry.dn, attribute
                )));
            }
        }

        // Validate object classes
        if entry.object_class.is_empty() {
            return Err(YamlLdapError::Config(format!(
                "Entry {} must have at least one objectClass",
                entry.dn
            )));
        }
        let mut object_class_names = std::collections::HashSet::new();
        for object_class in &entry.object_class {
            if !object_class_names.insert(object_class.to_ascii_lowercase()) {
                return Err(YamlLdapError::Config(format!(
                    "Entry {} contains duplicate objectClass {}",
                    entry.dn, object_class
                )));
            }
        }

        // Validate required attributes for object classes
        for oc in &entry.object_class {
            let required_attrs = schema
                .object_classes
                .iter()
                .find(|(name, _)| name.eq_ignore_ascii_case(oc))
                .map(|(_, object_class)| &object_class.required_attributes)
                .ok_or_else(|| {
                    YamlLdapError::Config(format!(
                        "Entry {} references unknown objectClass {}",
                        entry.dn, oc
                    ))
                })?;
            for attr in required_attrs {
                if !entry
                    .attributes
                    .keys()
                    .any(|name| name.eq_ignore_ascii_case(attr))
                {
                    return Err(YamlLdapError::Config(format!(
                        "Entry {} with objectClass {} is missing required attribute {}",
                        entry.dn, oc, attr
                    )));
                }
            }
        }
    }

    Ok(())
}

fn validate_schema_config(schema: &SchemaConfig) -> crate::Result<()> {
    let mut object_classes = std::collections::HashSet::new();
    for object_class in &schema.object_classes {
        if !object_classes.insert(object_class.name.to_ascii_lowercase()) {
            return Err(YamlLdapError::Config(format!(
                "Duplicate schema objectClass identifier {}",
                object_class.name
            )));
        }
        if !object_class.attributes.is_empty()
            && (!object_class.must.is_empty() || !object_class.may.is_empty())
        {
            return Err(YamlLdapError::Config(format!(
                "Schema objectClass {} cannot combine v1 attributes with must/may",
                object_class.name
            )));
        }
        let mut attributes = std::collections::HashSet::new();
        for attribute in object_class
            .attributes
            .iter()
            .chain(&object_class.must)
            .chain(&object_class.may)
        {
            if !attributes.insert(attribute.to_ascii_lowercase()) {
                return Err(YamlLdapError::Config(format!(
                    "Schema objectClass {} contains duplicate attribute {}",
                    object_class.name, attribute
                )));
            }
        }
    }

    let mut custom_attributes = std::collections::HashSet::new();
    for (name, definition) in &schema.custom_attributes {
        if !custom_attributes.insert(name.to_ascii_lowercase()) {
            return Err(YamlLdapError::Config(format!(
                "Duplicate schema attribute identifier {name}"
            )));
        }
        let normalized = definition
            .syntax
            .to_ascii_lowercase()
            .replace(['_', '-'], "");
        if !matches!(
            normalized.as_str(),
            "string"
                | "directorystring"
                | "integer"
                | "boolean"
                | "bool"
                | "binary"
                | "octetstring"
                | "dn"
                | "distinguishedname"
                | "generalizedtime"
        ) {
            return Err(YamlLdapError::Config(format!(
                "Schema attribute {name} has unsupported syntax {}",
                definition.syntax
            )));
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
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Base DN cannot be empty"));
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
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Entry DN cannot be empty"));
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
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("must have at least one objectClass"));
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
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("missing required attribute sn"));
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
    async fn rejects_unknown_object_class() {
        let yaml_content = r#"
directory:
  base_dn: "dc=example,dc=com"
entries:
  - dn: "dc=example,dc=com"
    objectClass: [top, madeUpClass]
    dc: example
"#;
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(yaml_content.as_bytes()).unwrap();
        let error = parse_directory_file(temp_file.path()).await.unwrap_err();
        assert!(error
            .to_string()
            .contains("unknown objectClass madeUpClass"));
    }

    #[tokio::test]
    async fn rejects_case_insensitive_duplicate_schema_identifiers() {
        let yaml_content = r#"
directory:
  base_dn: "dc=example,dc=com"
schema:
  object_classes:
    - name: customPerson
      attributes: [cn]
    - name: CUSTOMPERSON
      attributes: [sn]
entries: []
"#;
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(yaml_content.as_bytes()).unwrap();
        let error = parse_directory_file(temp_file.path()).await.unwrap_err();
        assert!(error
            .to_string()
            .contains("Duplicate schema objectClass identifier"));
    }

    #[tokio::test]
    async fn rejects_unknown_fields_and_duplicate_yaml_keys() {
        for yaml_content in [
            r#"
directory:
  base_dn: "dc=example,dc=com"
  ignored: true
entries: []
"#,
            r#"
directory:
  base_dn: "dc=example,dc=com"
  base_dn: "dc=other,dc=com"
entries: []
"#,
        ] {
            let mut temp_file = NamedTempFile::new().unwrap();
            temp_file.write_all(yaml_content.as_bytes()).unwrap();
            assert!(parse_directory_file(temp_file.path()).await.is_err());
        }
    }

    #[tokio::test]
    async fn accepts_explicit_must_may_and_does_not_invent_inet_org_person_musts() {
        let yaml_content = r#"
directory:
  base_dn: "dc=example,dc=com"
schema:
  object_classes:
    - name: applicationUser
      must: [cn]
      may: [mail]
entries:
  - dn: "cn=test,dc=example,dc=com"
    objectClass: [top, person, inetOrgPerson, applicationUser]
    cn: test
    sn: User
"#;
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(yaml_content.as_bytes()).unwrap();
        let (_, schema) = parse_directory_file(temp_file.path()).await.unwrap();
        let application_user = &schema.object_classes["applicationUser"];
        assert_eq!(application_user.required_attributes, ["cn"]);
        assert_eq!(application_user.allowed_attributes, ["mail"]);
        assert!(schema.object_classes["inetOrgPerson"]
            .required_attributes
            .is_empty());
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
        attrs.insert(
            "cn".to_string(),
            serde_yaml_ng::Value::String("test".to_string()),
        );

        let entries = vec![YamlEntry {
            dn: "cn=test,dc=example,dc=com".to_string(),
            object_class: vec!["top".to_string()],
            attributes: attrs,
        }];

        let result = validate_entries(&entries, &schema);
        assert!(result.is_ok());
    }
}
