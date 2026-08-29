use super::{parse_directory_file, YamlDirectory, YamlSchema};
use crate::directory::{Directory, DistinguishedName};
use crate::YamlLdapError;
use std::path::Path;

/// Load, validate, optionally relocate, and compile a complete directory.
///
/// The returned value is ready to publish as a new immutable server snapshot;
/// no partially converted entry can escape this interface.
pub async fn compile_directory_file(
    path: &Path,
    base_dn_override: Option<&str>,
) -> crate::Result<Directory> {
    let (yaml_directory, schema) = parse_directory_file(path).await?;
    compile_directory(yaml_directory, schema, base_dn_override)
}

pub fn compile_directory(
    mut yaml_directory: YamlDirectory,
    schema: YamlSchema,
    base_dn_override: Option<&str>,
) -> crate::Result<Directory> {
    super::parser::validate_entries(&yaml_directory.entries, &schema)?;

    if let Some(override_text) = base_dn_override {
        let old_base = DistinguishedName::parse(&yaml_directory.directory.base_dn)
            .map_err(|error| YamlLdapError::Config(format!("Invalid source base DN: {error}")))?;
        let new_base = DistinguishedName::parse(override_text)
            .map_err(|error| YamlLdapError::Config(format!("Invalid base DN override: {error}")))?;
        if new_base.is_empty() {
            return Err(YamlLdapError::Config(
                "Base DN override cannot be empty".to_string(),
            ));
        }

        for entry in &mut yaml_directory.entries {
            let parsed = DistinguishedName::parse(&entry.dn).map_err(|error| {
                YamlLdapError::Config(format!("Entry {} has an invalid DN: {error}", entry.dn))
            })?;
            let is_context_root = parsed.key() == old_base.key();
            let rebased = parsed.rebase(&old_base, &new_base).ok_or_else(|| {
                YamlLdapError::Config(format!(
                    "Entry {} is outside source base DN {}",
                    entry.dn, yaml_directory.directory.base_dn
                ))
            })?;
            entry.dn = rebased.to_string();
            if is_context_root {
                update_context_root_naming_attributes(entry, &new_base)?;
            }

            for (attribute, value) in &mut entry.attributes {
                if attribute_has_dn_syntax(attribute, &schema) {
                    relocate_dn_values(value, &old_base, &new_base, attribute, &entry.dn)?;
                }
            }
        }
        yaml_directory.directory.base_dn = new_base.to_string();
    }

    Directory::try_from_yaml(yaml_directory, schema)
}

fn update_context_root_naming_attributes(
    entry: &mut super::YamlEntry,
    new_base: &DistinguishedName,
) -> crate::Result<()> {
    let rdn = new_base
        .leaf_rdn()
        .ok_or_else(|| YamlLdapError::Config("Base DN override cannot be empty".to_string()))?;
    for ava in rdn.avas() {
        let value = ava.text_value().ok_or_else(|| {
            YamlLdapError::Config(
                "BER-form AVAs are not supported in the base DN override".to_string(),
            )
        })?;
        let existing_name = entry
            .attributes
            .keys()
            .find(|name| name.eq_ignore_ascii_case(ava.attribute()))
            .cloned();
        entry.attributes.insert(
            existing_name.unwrap_or_else(|| ava.attribute().to_string()),
            serde_yaml_ng::Value::String(value.to_string()),
        );
    }
    Ok(())
}

fn attribute_has_dn_syntax(attribute: &str, schema: &YamlSchema) -> bool {
    if matches!(
        attribute.to_ascii_lowercase().as_str(),
        "member" | "memberof" | "manager"
    ) {
        return true;
    }
    schema.custom_attributes.iter().any(|(name, definition)| {
        name.eq_ignore_ascii_case(attribute)
            && matches!(
                definition
                    .syntax
                    .to_ascii_lowercase()
                    .replace(['_', '-'], "")
                    .as_str(),
                "dn" | "distinguishedname"
            )
    })
}

fn relocate_dn_values(
    value: &mut serde_yaml_ng::Value,
    old_base: &DistinguishedName,
    new_base: &DistinguishedName,
    attribute: &str,
    entry_dn: &str,
) -> crate::Result<()> {
    match value {
        serde_yaml_ng::Value::String(value) => {
            let parsed = DistinguishedName::parse(value).map_err(|error| {
                YamlLdapError::Config(format!(
                    "Entry {entry_dn} attribute {attribute} has an invalid DN value: {error}"
                ))
            })?;
            if let Some(rebased) = parsed.rebase(old_base, new_base) {
                *value = rebased.to_string();
            }
            Ok(())
        }
        serde_yaml_ng::Value::Sequence(values) => {
            for value in values {
                relocate_dn_values(value, old_base, new_base, attribute, entry_dn)?;
            }
            Ok(())
        }
        _ => Err(YamlLdapError::Config(format!(
            "Entry {entry_dn} attribute {attribute} must contain DN strings"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::directory::AttributeValue;

    fn source() -> &'static str {
        r#"
directory:
  base_dn: dc=example,dc=com
entries:
  - dn: dc=example,dc=com
    objectClass: [top, domain]
    dc: example
  - dn: ou=people,dc=example,dc=com
    objectClass: [top, organizationalUnit]
    ou: people
  - dn: "cn=Smith\\, John,ou=people,dc=example,dc=com"
    objectClass: [top, person]
    cn: "Smith, John"
    sn: Smith
  - dn: cn=group,dc=example,dc=com
    objectClass: [top, groupOfNames]
    cn: group
    member:
      - "cn=Smith\\, John,ou=people,dc=example,dc=com"
      - uid=external,dc=other,dc=org
"#
    }

    #[test]
    fn relocates_entries_and_in_context_dn_values() {
        let raw: YamlDirectory = serde_yaml_ng::from_str(source()).unwrap();
        let directory =
            compile_directory(raw, YamlSchema::default(), Some("dc=relocated,dc=internal"))
                .unwrap();

        assert_eq!(directory.base_dn, "dc=relocated,dc=internal");
        assert!(directory.entry_exists(r"cn=Smith\, John,ou=people,dc=relocated,dc=internal"));
        let group = directory
            .get_entry("cn=group,dc=relocated,dc=internal")
            .unwrap();
        let members: Vec<String> = group
            .get_attribute("member")
            .unwrap()
            .values
            .iter()
            .map(AttributeValue::as_string)
            .collect();
        assert_eq!(
            members,
            vec![
                r"cn=Smith\, John,ou=people,dc=relocated,dc=internal".to_string(),
                "uid=external,dc=other,dc=org".to_string(),
            ]
        );
    }

    #[test]
    fn rejects_entry_outside_source_base_during_relocation() {
        let mut raw: YamlDirectory = serde_yaml_ng::from_str(source()).unwrap();
        raw.entries[0].dn = "dc=other,dc=org".to_string();
        let error =
            compile_directory(raw, YamlSchema::default(), Some("dc=new,dc=org")).unwrap_err();
        assert!(error.to_string().contains("outside source base DN"));
    }

    #[test]
    fn rejects_duplicate_semantic_dns() {
        let mut raw: YamlDirectory = serde_yaml_ng::from_str(source()).unwrap();
        raw.entries.push(raw.entries[0].clone());
        raw.entries.last_mut().unwrap().dn = "DC=EXAMPLE,DC=COM".to_string();
        let error = compile_directory(raw, YamlSchema::default(), None).unwrap_err();
        assert!(error.to_string().contains("Duplicate distinguished name"));
    }

    #[test]
    fn enforces_single_valued_schema_attributes() {
        let mut raw: YamlDirectory = serde_yaml_ng::from_str(source()).unwrap();
        raw.entries[0].attributes.insert(
            "serial".to_string(),
            serde_yaml_ng::Value::Sequence(vec![
                serde_yaml_ng::Value::String("one".to_string()),
                serde_yaml_ng::Value::String("two".to_string()),
            ]),
        );
        let mut schema = YamlSchema::default();
        schema.custom_attributes.insert(
            "serial".to_string(),
            crate::yaml::schema::AttributeDef {
                syntax: "string".to_string(),
                single_value: true,
            },
        );
        let error = compile_directory(raw, schema, None).unwrap_err();
        assert!(error.to_string().contains("is single-valued"));
    }
}
