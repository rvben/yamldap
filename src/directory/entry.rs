use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use super::dn::DistinguishedName;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum AttributeSyntax {
    String,
    Integer,
    Boolean,
    Binary,
    Dn,
    GeneralizedTime,
}

#[derive(Debug, Clone, PartialEq)]
pub enum AttributeValue {
    String(String),
    Integer(i64),
    Boolean(bool),
    Binary(Vec<u8>),
    Dn(String),
    GeneralizedTime(chrono::DateTime<chrono::Utc>),
}

impl AttributeValue {
    pub fn as_string(&self) -> String {
        match self {
            AttributeValue::String(s) => s.clone(),
            AttributeValue::Integer(i) => i.to_string(),
            AttributeValue::Boolean(b) => b.to_string(),
            AttributeValue::Binary(b) => {
                base64::Engine::encode(&base64::engine::general_purpose::STANDARD, b)
            }
            AttributeValue::Dn(dn) => dn.clone(),
            AttributeValue::GeneralizedTime(dt) => dt.format("%Y%m%d%H%M%SZ").to_string(),
        }
    }

    #[cfg(any(test, feature = "unstable-internals"))]
    pub fn as_bytes(&self) -> Vec<u8> {
        match self {
            AttributeValue::String(s) => s.as_bytes().to_vec(),
            AttributeValue::Integer(i) => i.to_string().as_bytes().to_vec(),
            AttributeValue::Boolean(b) => b.to_string().as_bytes().to_vec(),
            AttributeValue::Binary(b) => b.clone(),
            AttributeValue::Dn(dn) => dn.as_bytes().to_vec(),
            AttributeValue::GeneralizedTime(dt) => {
                dt.format("%Y%m%d%H%M%SZ").to_string().as_bytes().to_vec()
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct LdapAttribute {
    pub name: String,
    pub values: Vec<AttributeValue>,
    #[cfg_attr(not(feature = "unstable-internals"), allow(dead_code))]
    pub syntax: AttributeSyntax,
}

#[derive(Debug, Clone)]
pub struct LdapEntry {
    pub dn: String,
    pub attributes: HashMap<String, LdapAttribute>,
    pub object_classes: Vec<String>,
}

impl LdapEntry {
    pub fn new(dn: String) -> Self {
        Self {
            dn,
            attributes: HashMap::new(),
            object_classes: Vec::new(),
        }
    }

    pub fn add_attribute(
        &mut self,
        name: String,
        values: Vec<AttributeValue>,
        syntax: AttributeSyntax,
    ) {
        self.attributes.insert(
            name.to_lowercase(),
            LdapAttribute {
                name,
                values,
                syntax,
            },
        );
    }

    pub fn get_attribute(&self, name: &str) -> Option<&LdapAttribute> {
        self.attributes.get(&name.to_lowercase())
    }

    pub fn has_attribute(&self, name: &str) -> bool {
        self.attributes.contains_key(&name.to_lowercase())
    }

    #[cfg(any(test, feature = "unstable-internals"))]
    pub fn matches_dn(&self, dn: &str) -> bool {
        let Ok(stored) = DistinguishedName::parse(&self.dn) else {
            return false;
        };
        let Ok(candidate) = DistinguishedName::parse(dn) else {
            return false;
        };
        stored.key() == candidate.key()
    }
}

impl From<crate::yaml::YamlEntry> for LdapEntry {
    fn from(yaml_entry: crate::yaml::YamlEntry) -> Self {
        Self::try_from_yaml(yaml_entry, &crate::yaml::YamlSchema::default())
            .expect("invalid YAML entry passed to infallible compatibility conversion")
    }
}

impl LdapEntry {
    /// Convert a YAML entry without discarding unsupported or malformed data.
    pub fn try_from_yaml(
        yaml_entry: crate::yaml::YamlEntry,
        schema: &crate::yaml::YamlSchema,
    ) -> crate::Result<Self> {
        DistinguishedName::parse(&yaml_entry.dn).map_err(|error| {
            crate::YamlLdapError::Config(format!(
                "Entry {} has an invalid DN: {error}",
                yaml_entry.dn
            ))
        })?;

        let mut entry = LdapEntry::new(yaml_entry.dn);
        entry.object_classes = yaml_entry.object_class;

        // Add objectClass as an attribute
        let oc_values: Vec<AttributeValue> = entry
            .object_classes
            .iter()
            .map(|oc| AttributeValue::String(oc.clone()))
            .collect();
        entry.add_attribute(
            "objectClass".to_string(),
            oc_values,
            AttributeSyntax::String,
        );

        // Convert other attributes
        for (name, value) in yaml_entry.attributes {
            if entry.has_attribute(&name) {
                return Err(crate::YamlLdapError::Config(format!(
                    "Entry {} contains duplicate attribute description {}",
                    entry.dn, name
                )));
            }
            let definition = schema
                .custom_attributes
                .iter()
                .find(|(defined_name, _)| defined_name.eq_ignore_ascii_case(&name))
                .map(|(_, definition)| definition);
            let declared_syntax = definition
                .map(|definition| parse_syntax(&definition.syntax))
                .transpose()
                .map_err(|message| {
                    crate::YamlLdapError::Config(format!(
                        "Entry {} attribute {}: {message}",
                        entry.dn, name
                    ))
                })?;
            let (values, syntax) = convert_yaml_values(&name, value, declared_syntax)?;
            if definition.is_some_and(|definition| definition.single_value) && values.len() != 1 {
                return Err(crate::YamlLdapError::Config(format!(
                    "Entry {} attribute {} is single-valued but has {} values",
                    entry.dn,
                    name,
                    values.len()
                )));
            }
            entry.add_attribute(name, values, syntax);
        }

        Ok(entry)
    }
}

fn parse_syntax(syntax: &str) -> Result<AttributeSyntax, String> {
    match syntax.to_ascii_lowercase().replace(['_', '-'], "").as_str() {
        "string" | "directorystring" => Ok(AttributeSyntax::String),
        "integer" => Ok(AttributeSyntax::Integer),
        "boolean" | "bool" => Ok(AttributeSyntax::Boolean),
        "binary" | "octetstring" => Ok(AttributeSyntax::Binary),
        "dn" | "distinguishedname" => Ok(AttributeSyntax::Dn),
        "generalizedtime" => Ok(AttributeSyntax::GeneralizedTime),
        _ => Err(format!("unsupported schema syntax '{syntax}'")),
    }
}

fn convert_yaml_values(
    name: &str,
    value: serde_yaml_ng::Value,
    declared_syntax: Option<AttributeSyntax>,
) -> crate::Result<(Vec<AttributeValue>, AttributeSyntax)> {
    let raw_values = match value {
        serde_yaml_ng::Value::Sequence(values) if values.is_empty() => {
            return Err(crate::YamlLdapError::Config(format!(
                "Attribute {name} must have at least one value"
            )));
        }
        serde_yaml_ng::Value::Sequence(values) => values,
        serde_yaml_ng::Value::Null => {
            return Err(crate::YamlLdapError::Config(format!(
                "Attribute {name} cannot be null"
            )));
        }
        scalar => vec![scalar],
    };

    let syntax = declared_syntax.unwrap_or_else(|| infer_syntax(name, &raw_values));
    let values = raw_values
        .into_iter()
        .enumerate()
        .map(|(index, value)| {
            convert_yaml_value(value, &syntax).map_err(|message| {
                crate::YamlLdapError::Config(format!(
                    "Attribute {name} value {}: {message}",
                    index + 1
                ))
            })
        })
        .collect::<crate::Result<Vec<_>>>()?;
    Ok((values, syntax))
}

fn infer_syntax(name: &str, values: &[serde_yaml_ng::Value]) -> AttributeSyntax {
    match name.to_ascii_lowercase().as_str() {
        "member" | "memberof" | "manager" => AttributeSyntax::Dn,
        "createtimestamp" | "modifytimestamp" => AttributeSyntax::GeneralizedTime,
        _ => match values.first() {
            Some(serde_yaml_ng::Value::Number(number)) if number.as_i64().is_some() => {
                AttributeSyntax::Integer
            }
            Some(serde_yaml_ng::Value::Bool(_)) => AttributeSyntax::Boolean,
            _ => AttributeSyntax::String,
        },
    }
}

fn convert_yaml_value(
    value: serde_yaml_ng::Value,
    syntax: &AttributeSyntax,
) -> Result<AttributeValue, String> {
    match syntax {
        AttributeSyntax::String => match value {
            serde_yaml_ng::Value::String(value) => Ok(AttributeValue::String(value)),
            serde_yaml_ng::Value::Number(value) => Ok(AttributeValue::String(value.to_string())),
            serde_yaml_ng::Value::Bool(value) => Ok(AttributeValue::String(value.to_string())),
            _ => Err("expected a scalar string, number, or boolean".to_string()),
        },
        AttributeSyntax::Integer => {
            let integer = match value {
                serde_yaml_ng::Value::Number(value) => value.as_i64(),
                serde_yaml_ng::Value::String(value) => value.parse().ok(),
                _ => None,
            }
            .ok_or_else(|| "expected a signed 64-bit integer".to_string())?;
            Ok(AttributeValue::Integer(integer))
        }
        AttributeSyntax::Boolean => {
            let boolean = match value {
                serde_yaml_ng::Value::Bool(value) => Some(value),
                serde_yaml_ng::Value::String(value) if value.eq_ignore_ascii_case("true") => {
                    Some(true)
                }
                serde_yaml_ng::Value::String(value) if value.eq_ignore_ascii_case("false") => {
                    Some(false)
                }
                _ => None,
            }
            .ok_or_else(|| "expected TRUE or FALSE".to_string())?;
            Ok(AttributeValue::Boolean(boolean))
        }
        AttributeSyntax::Binary => {
            let encoded = match value {
                serde_yaml_ng::Value::String(value) => value,
                _ => return Err("expected a base64 string".to_string()),
            };
            let bytes = base64::Engine::decode(
                &base64::engine::general_purpose::STANDARD,
                encoded.as_bytes(),
            )
            .map_err(|_| "expected valid base64".to_string())?;
            Ok(AttributeValue::Binary(bytes))
        }
        AttributeSyntax::Dn => {
            let value = match value {
                serde_yaml_ng::Value::String(value) => value,
                _ => return Err("expected an RFC 4514 DN string".to_string()),
            };
            DistinguishedName::parse(&value).map_err(|error| error.to_string())?;
            Ok(AttributeValue::Dn(value))
        }
        AttributeSyntax::GeneralizedTime => {
            let value = match value {
                serde_yaml_ng::Value::String(value) => value,
                _ => return Err("expected an LDAP generalized time string".to_string()),
            };
            let parsed = chrono::NaiveDateTime::parse_from_str(&value, "%Y%m%d%H%M%SZ")
                .map_err(|_| "expected generalized time in YYYYmmddHHMMSSZ form".to_string())?
                .and_utc();
            Ok(AttributeValue::GeneralizedTime(parsed))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn test_attribute_value_as_string() {
        assert_eq!(
            AttributeValue::String("test".to_string()).as_string(),
            "test"
        );
        assert_eq!(AttributeValue::Integer(42).as_string(), "42");
        assert_eq!(AttributeValue::Boolean(true).as_string(), "true");
        assert_eq!(AttributeValue::Boolean(false).as_string(), "false");
        assert_eq!(
            AttributeValue::Dn("cn=test,dc=example,dc=com".to_string()).as_string(),
            "cn=test,dc=example,dc=com"
        );

        let binary_data = vec![1, 2, 3, 4];
        let encoded = AttributeValue::Binary(binary_data.clone()).as_string();
        assert_eq!(
            encoded,
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &binary_data)
        );

        let dt = chrono::Utc
            .with_ymd_and_hms(2023, 12, 25, 10, 30, 0)
            .unwrap();
        assert_eq!(
            AttributeValue::GeneralizedTime(dt).as_string(),
            "20231225103000Z"
        );
    }

    #[test]
    fn test_attribute_value_as_bytes() {
        assert_eq!(
            AttributeValue::String("test".to_string()).as_bytes(),
            b"test".to_vec()
        );
        assert_eq!(AttributeValue::Integer(42).as_bytes(), b"42".to_vec());
        assert_eq!(AttributeValue::Boolean(true).as_bytes(), b"true".to_vec());
        assert_eq!(AttributeValue::Boolean(false).as_bytes(), b"false".to_vec());
        assert_eq!(
            AttributeValue::Dn("cn=test".to_string()).as_bytes(),
            b"cn=test".to_vec()
        );

        let binary_data = vec![1, 2, 3, 4];
        assert_eq!(
            AttributeValue::Binary(binary_data.clone()).as_bytes(),
            binary_data
        );

        let dt = chrono::Utc
            .with_ymd_and_hms(2023, 12, 25, 10, 30, 0)
            .unwrap();
        assert_eq!(
            AttributeValue::GeneralizedTime(dt).as_bytes(),
            b"20231225103000Z".to_vec()
        );
    }

    #[test]
    fn test_ldap_entry_new() {
        let entry = LdapEntry::new("cn=test,dc=example,dc=com".to_string());
        assert_eq!(entry.dn, "cn=test,dc=example,dc=com");
        assert!(entry.attributes.is_empty());
        assert!(entry.object_classes.is_empty());
    }

    #[test]
    fn test_ldap_entry_add_attribute() {
        let mut entry = LdapEntry::new("cn=test,dc=example,dc=com".to_string());

        entry.add_attribute(
            "cn".to_string(),
            vec![AttributeValue::String("test".to_string())],
            AttributeSyntax::String,
        );

        assert_eq!(entry.attributes.len(), 1);
        assert!(entry.has_attribute("cn"));
        assert!(entry.has_attribute("CN")); // Case insensitive

        let attr = entry.get_attribute("cn").unwrap();
        assert_eq!(attr.name, "cn");
        assert_eq!(attr.values.len(), 1);
        match &attr.values[0] {
            AttributeValue::String(s) => assert_eq!(s, "test"),
            _ => panic!("Expected string value"),
        }
    }

    #[test]
    fn test_ldap_entry_get_attribute_case_insensitive() {
        let mut entry = LdapEntry::new("cn=test,dc=example,dc=com".to_string());

        entry.add_attribute(
            "userPassword".to_string(),
            vec![AttributeValue::String("secret".to_string())],
            AttributeSyntax::String,
        );

        assert!(entry.get_attribute("userPassword").is_some());
        assert!(entry.get_attribute("userpassword").is_some());
        assert!(entry.get_attribute("USERPASSWORD").is_some());
        assert!(entry.get_attribute("UserPassword").is_some());
    }

    #[test]
    fn test_ldap_entry_matches_dn() {
        let entry = LdapEntry::new("cn=Test User,dc=Example,dc=Com".to_string());

        assert!(entry.matches_dn("cn=Test User,dc=Example,dc=Com"));
        assert!(entry.matches_dn("cn=test user,dc=example,dc=com")); // Case insensitive
        assert!(entry.matches_dn("CN=TEST USER,DC=EXAMPLE,DC=COM"));
        assert!(!entry.matches_dn("cn=Other User,dc=Example,dc=Com"));
    }

    #[test]
    fn test_ldap_entry_from_yaml_entry_simple() {
        let yaml_entry = crate::yaml::YamlEntry {
            dn: "cn=test,dc=example,dc=com".to_string(),
            object_class: vec!["person".to_string(), "top".to_string()],
            attributes: [
                (
                    "cn".to_string(),
                    serde_yaml_ng::Value::String("test".to_string()),
                ),
                (
                    "sn".to_string(),
                    serde_yaml_ng::Value::String("User".to_string()),
                ),
                (
                    "uid".to_string(),
                    serde_yaml_ng::Value::Number(serde_yaml_ng::Number::from(12345)),
                ),
                ("active".to_string(), serde_yaml_ng::Value::Bool(true)),
            ]
            .into_iter()
            .collect(),
        };

        let entry: LdapEntry = yaml_entry.into();

        assert_eq!(entry.dn, "cn=test,dc=example,dc=com");
        assert_eq!(entry.object_classes, vec!["person", "top"]);

        // Check objectClass attribute
        let oc_attr = entry.get_attribute("objectClass").unwrap();
        assert_eq!(oc_attr.values.len(), 2);

        // Check other attributes
        assert!(entry.has_attribute("cn"));
        assert!(entry.has_attribute("sn"));
        assert!(entry.has_attribute("uid"));
        assert!(entry.has_attribute("active"));

        match &entry.get_attribute("uid").unwrap().values[0] {
            AttributeValue::Integer(i) => assert_eq!(*i, 12345),
            _ => panic!("Expected integer value"),
        }

        match &entry.get_attribute("active").unwrap().values[0] {
            AttributeValue::Boolean(b) => assert!(*b),
            _ => panic!("Expected boolean value"),
        }
    }

    #[test]
    fn test_ldap_entry_from_yaml_entry_with_sequences() {
        let yaml_entry = crate::yaml::YamlEntry {
            dn: "cn=test,dc=example,dc=com".to_string(),
            object_class: vec!["groupOfNames".to_string()],
            attributes: [
                (
                    "cn".to_string(),
                    serde_yaml_ng::Value::String("test".to_string()),
                ),
                (
                    "member".to_string(),
                    serde_yaml_ng::Value::Sequence(vec![
                        serde_yaml_ng::Value::String("cn=user1,dc=example,dc=com".to_string()),
                        serde_yaml_ng::Value::String("cn=user2,dc=example,dc=com".to_string()),
                        serde_yaml_ng::Value::Number(serde_yaml_ng::Number::from(123)), // Invalid mixed type
                    ]),
                ),
            ]
            .into_iter()
            .collect(),
        };

        let error =
            LdapEntry::try_from_yaml(yaml_entry, &crate::yaml::YamlSchema::default()).unwrap_err();
        assert!(error.to_string().contains("expected an RFC 4514 DN string"));
    }

    #[test]
    fn test_ldap_entry_from_yaml_entry_with_float() {
        let yaml_entry = crate::yaml::YamlEntry {
            dn: "cn=test,dc=example,dc=com".to_string(),
            object_class: vec!["top".to_string()],
            attributes: [(
                "score".to_string(),
                serde_yaml_ng::Value::Number(serde_yaml_ng::Number::from(1.25)),
            )]
            .into_iter()
            .collect(),
        };

        let entry: LdapEntry = yaml_entry.into();

        let score_attr = entry.get_attribute("score").unwrap();
        match &score_attr.values[0] {
            AttributeValue::String(s) => assert_eq!(s, "1.25"),
            _ => panic!("Expected string value for float"),
        }
    }

    #[test]
    fn test_ldap_entry_from_yaml_empty_values() {
        let yaml_entry = crate::yaml::YamlEntry {
            dn: "cn=test,dc=example,dc=com".to_string(),
            object_class: vec!["top".to_string()],
            attributes: [
                ("empty".to_string(), serde_yaml_ng::Value::Null),
                (
                    "emptySeq".to_string(),
                    serde_yaml_ng::Value::Sequence(vec![]),
                ),
            ]
            .into_iter()
            .collect(),
        };

        let error =
            LdapEntry::try_from_yaml(yaml_entry, &crate::yaml::YamlSchema::default()).unwrap_err();
        assert!(
            error.to_string().contains("cannot be null")
                || error.to_string().contains("must have at least one value")
        );
    }

    #[test]
    fn test_attribute_value_equality() {
        assert_eq!(
            AttributeValue::String("test".to_string()),
            AttributeValue::String("test".to_string())
        );
        assert_ne!(
            AttributeValue::String("test".to_string()),
            AttributeValue::String("other".to_string())
        );

        assert_eq!(AttributeValue::Integer(42), AttributeValue::Integer(42));
        assert_ne!(AttributeValue::Integer(42), AttributeValue::Integer(43));

        assert_eq!(AttributeValue::Boolean(true), AttributeValue::Boolean(true));
        assert_ne!(
            AttributeValue::Boolean(true),
            AttributeValue::Boolean(false)
        );

        assert_eq!(
            AttributeValue::Binary(vec![1, 2, 3]),
            AttributeValue::Binary(vec![1, 2, 3])
        );
        assert_ne!(
            AttributeValue::Binary(vec![1, 2, 3]),
            AttributeValue::Binary(vec![1, 2, 4])
        );
    }

    #[test]
    fn test_attribute_syntax_equality() {
        assert_eq!(AttributeSyntax::String, AttributeSyntax::String);
        assert_ne!(AttributeSyntax::String, AttributeSyntax::Integer);
        assert_eq!(
            AttributeSyntax::GeneralizedTime,
            AttributeSyntax::GeneralizedTime
        );
    }

    #[test]
    fn test_ldap_entry_with_empty_attributes() {
        let mut entry = LdapEntry::new("cn=test,dc=example,dc=com".to_string());

        // Add attribute with empty string value
        entry.add_attribute(
            "description".to_string(),
            vec![AttributeValue::String(String::new())],
            AttributeSyntax::String,
        );

        assert!(entry.has_attribute("description"));
        let attr = entry.get_attribute("description").unwrap();
        assert_eq!(attr.values.len(), 1);
        assert_eq!(attr.values[0].as_string(), "");
    }

    #[test]
    fn test_ldap_entry_with_empty_dn() {
        let entry = LdapEntry::new(String::new());
        assert_eq!(entry.dn, "");
        assert!(entry.attributes.is_empty());

        // Empty DN should still work with matches_dn
        assert!(entry.matches_dn(""));
        assert!(!entry.matches_dn("cn=test"));
    }

    #[test]
    fn test_ldap_entry_with_very_long_dn() {
        // Test with a very long DN (common in deep organizational structures)
        let long_dn = "cn=user,ou=level1,ou=level2,ou=level3,ou=level4,ou=level5,\
             ou=level6,ou=level7,ou=level8,ou=level9,ou=level10,\
             dc=very-long-domain-name-example,dc=com"
            .to_string();
        let entry = LdapEntry::new(long_dn.clone());
        assert_eq!(entry.dn, long_dn);
        assert!(entry.matches_dn(&long_dn));
    }

    #[test]
    fn test_ldap_entry_with_special_chars_in_dn() {
        // Test DN with special characters that need escaping
        let special_dn = r#"cn=John\, Doe,ou=Sales\+Marketing,dc=example,dc=com"#;
        let entry = LdapEntry::new(special_dn.to_string());
        assert_eq!(entry.dn, special_dn);

        // Should match case-insensitively
        assert!(entry.matches_dn(r#"CN=John\, Doe,OU=Sales\+Marketing,DC=example,DC=com"#));
    }

    #[test]
    fn test_ldap_entry_with_unicode_dn() {
        // Test DN with Unicode characters
        let unicode_dn = "cn=用户,ou=组织,dc=例子,dc=com";
        let entry = LdapEntry::new(unicode_dn.to_string());
        assert_eq!(entry.dn, unicode_dn);
        assert!(entry.matches_dn(unicode_dn));
    }

    #[test]
    fn test_ldap_entry_with_many_attributes() {
        let mut entry = LdapEntry::new("cn=test,dc=example,dc=com".to_string());

        // Add many attributes
        for i in 0..100 {
            entry.add_attribute(
                format!("attr{}", i),
                vec![AttributeValue::String(format!("value{}", i))],
                AttributeSyntax::String,
            );
        }

        assert_eq!(entry.attributes.len(), 100);

        // Check all attributes exist
        for i in 0..100 {
            assert!(entry.has_attribute(&format!("attr{}", i)));
            let attr = entry.get_attribute(&format!("attr{}", i)).unwrap();
            assert_eq!(attr.values[0].as_string(), format!("value{}", i));
        }
    }

    #[test]
    fn test_ldap_entry_attribute_with_many_values() {
        let mut entry = LdapEntry::new("cn=test,dc=example,dc=com".to_string());

        // Add attribute with many values
        let values: Vec<AttributeValue> = (0..1000)
            .map(|i| AttributeValue::String(format!("value{}", i)))
            .collect();

        entry.add_attribute("multivalue".to_string(), values, AttributeSyntax::String);

        let attr = entry.get_attribute("multivalue").unwrap();
        assert_eq!(attr.values.len(), 1000);

        // Check a few values
        assert_eq!(attr.values[0].as_string(), "value0");
        assert_eq!(attr.values[500].as_string(), "value500");
        assert_eq!(attr.values[999].as_string(), "value999");
    }

    #[test]
    fn test_ldap_entry_binary_attribute_edge_cases() {
        let mut entry = LdapEntry::new("cn=test,dc=example,dc=com".to_string());

        // Empty binary
        entry.add_attribute(
            "empty".to_string(),
            vec![AttributeValue::Binary(vec![])],
            AttributeSyntax::Binary,
        );

        // Large binary
        let large_binary = vec![0u8; 10000];
        entry.add_attribute(
            "large".to_string(),
            vec![AttributeValue::Binary(large_binary.clone())],
            AttributeSyntax::Binary,
        );

        // Binary with all possible byte values
        let all_bytes: Vec<u8> = (0..=255).collect();
        entry.add_attribute(
            "allbytes".to_string(),
            vec![AttributeValue::Binary(all_bytes.clone())],
            AttributeSyntax::Binary,
        );

        // Verify they're stored correctly
        let empty_bytes: &[u8] = &[];
        assert_eq!(
            entry.get_attribute("empty").unwrap().values[0].as_bytes(),
            empty_bytes
        );
        assert_eq!(
            entry.get_attribute("large").unwrap().values[0].as_bytes(),
            large_binary.as_slice()
        );
        assert_eq!(
            entry.get_attribute("allbytes").unwrap().values[0].as_bytes(),
            all_bytes.as_slice()
        );
    }
}
