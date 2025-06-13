use serde::{Deserialize, Serialize};
use std::collections::HashMap;

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

    pub fn matches_dn(&self, dn: &str) -> bool {
        self.dn.eq_ignore_ascii_case(dn)
    }
}

impl From<crate::yaml::YamlEntry> for LdapEntry {
    fn from(yaml_entry: crate::yaml::YamlEntry) -> Self {
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
            let values = match value {
                serde_yaml::Value::String(s) => vec![AttributeValue::String(s)],
                serde_yaml::Value::Number(n) => {
                    if let Some(i) = n.as_i64() {
                        vec![AttributeValue::Integer(i)]
                    } else {
                        vec![AttributeValue::String(n.to_string())]
                    }
                }
                serde_yaml::Value::Bool(b) => vec![AttributeValue::Boolean(b)],
                serde_yaml::Value::Sequence(seq) => seq
                    .into_iter()
                    .filter_map(|v| match v {
                        serde_yaml::Value::String(s) => Some(AttributeValue::String(s)),
                        _ => None,
                    })
                    .collect(),
                _ => vec![],
            };

            if !values.is_empty() {
                // Guess syntax based on attribute name or value type
                let syntax = guess_attribute_syntax(&name, &values[0]);
                entry.add_attribute(name, values, syntax);
            }
        }

        entry
    }
}

fn guess_attribute_syntax(name: &str, value: &AttributeValue) -> AttributeSyntax {
    match name.to_lowercase().as_str() {
        "member" | "memberof" | "manager" => AttributeSyntax::Dn,
        "createtimestamp" | "modifytimestamp" => AttributeSyntax::GeneralizedTime,
        _ => match value {
            AttributeValue::Integer(_) => AttributeSyntax::Integer,
            AttributeValue::Boolean(_) => AttributeSyntax::Boolean,
            _ => AttributeSyntax::String,
        },
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
                    serde_yaml::Value::String("test".to_string()),
                ),
                (
                    "sn".to_string(),
                    serde_yaml::Value::String("User".to_string()),
                ),
                (
                    "uid".to_string(),
                    serde_yaml::Value::Number(serde_yaml::Number::from(12345)),
                ),
                ("active".to_string(), serde_yaml::Value::Bool(true)),
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
                    serde_yaml::Value::String("test".to_string()),
                ),
                (
                    "member".to_string(),
                    serde_yaml::Value::Sequence(vec![
                        serde_yaml::Value::String("cn=user1,dc=example,dc=com".to_string()),
                        serde_yaml::Value::String("cn=user2,dc=example,dc=com".to_string()),
                        serde_yaml::Value::Number(serde_yaml::Number::from(123)), // Non-string, should be filtered
                    ]),
                ),
            ]
            .into_iter()
            .collect(),
        };

        let entry: LdapEntry = yaml_entry.into();

        let member_attr = entry.get_attribute("member").unwrap();
        assert_eq!(member_attr.values.len(), 2); // Only the two string values
        match &member_attr.syntax {
            AttributeSyntax::Dn => {}
            _ => panic!("Expected DN syntax for member attribute"),
        }
    }

    #[test]
    fn test_ldap_entry_from_yaml_entry_with_float() {
        let yaml_entry = crate::yaml::YamlEntry {
            dn: "cn=test,dc=example,dc=com".to_string(),
            object_class: vec!["top".to_string()],
            attributes: [(
                "score".to_string(),
                serde_yaml::Value::Number(serde_yaml::Number::from(3.14)),
            )]
            .into_iter()
            .collect(),
        };

        let entry: LdapEntry = yaml_entry.into();

        let score_attr = entry.get_attribute("score").unwrap();
        match &score_attr.values[0] {
            AttributeValue::String(s) => assert_eq!(s, "3.14"),
            _ => panic!("Expected string value for float"),
        }
    }

    #[test]
    fn test_guess_attribute_syntax() {
        // Test DN attributes
        assert!(matches!(
            guess_attribute_syntax("member", &AttributeValue::String("test".to_string())),
            AttributeSyntax::Dn
        ));
        assert!(matches!(
            guess_attribute_syntax("memberOf", &AttributeValue::String("test".to_string())),
            AttributeSyntax::Dn
        ));
        assert!(matches!(
            guess_attribute_syntax("manager", &AttributeValue::String("test".to_string())),
            AttributeSyntax::Dn
        ));

        // Test timestamp attributes
        assert!(matches!(
            guess_attribute_syntax(
                "createTimestamp",
                &AttributeValue::String("test".to_string())
            ),
            AttributeSyntax::GeneralizedTime
        ));
        assert!(matches!(
            guess_attribute_syntax(
                "modifyTimestamp",
                &AttributeValue::String("test".to_string())
            ),
            AttributeSyntax::GeneralizedTime
        ));

        // Test value-based syntax guessing
        assert!(matches!(
            guess_attribute_syntax("someAttr", &AttributeValue::Integer(42)),
            AttributeSyntax::Integer
        ));
        assert!(matches!(
            guess_attribute_syntax("someAttr", &AttributeValue::Boolean(true)),
            AttributeSyntax::Boolean
        ));
        assert!(matches!(
            guess_attribute_syntax("someAttr", &AttributeValue::String("test".to_string())),
            AttributeSyntax::String
        ));
    }

    #[test]
    fn test_ldap_entry_from_yaml_empty_values() {
        let yaml_entry = crate::yaml::YamlEntry {
            dn: "cn=test,dc=example,dc=com".to_string(),
            object_class: vec!["top".to_string()],
            attributes: [
                ("empty".to_string(), serde_yaml::Value::Null),
                ("emptySeq".to_string(), serde_yaml::Value::Sequence(vec![])),
            ]
            .into_iter()
            .collect(),
        };

        let entry: LdapEntry = yaml_entry.into();

        // Empty values should not create attributes
        assert!(!entry.has_attribute("empty"));
        assert!(!entry.has_attribute("emptySeq"));

        // Only objectClass should be present
        assert_eq!(entry.attributes.len(), 1);
        assert!(entry.has_attribute("objectClass"));
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
}
