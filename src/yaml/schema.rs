use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct YamlDirectory {
    pub directory: DirectoryConfig,
    #[serde(default)]
    pub schema: Option<SchemaConfig>,
    pub entries: Vec<YamlEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryConfig {
    pub base_dn: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SchemaConfig {
    #[serde(default)]
    pub object_classes: Vec<ObjectClassDef>,
    #[serde(default)]
    pub custom_attributes: HashMap<String, AttributeDef>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectClassDef {
    pub name: String,
    /// V1 compatibility: every listed attribute is required.
    #[serde(default)]
    pub attributes: Vec<String>,
    /// V2-style explicit required attributes.
    #[serde(default)]
    pub must: Vec<String>,
    /// V2-style explicit optional attributes.
    #[serde(default)]
    pub may: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttributeDef {
    pub syntax: String,
    #[serde(default)]
    pub single_value: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YamlEntry {
    pub dn: String,
    #[serde(rename = "objectClass")]
    pub object_class: Vec<String>,
    #[serde(flatten)]
    pub attributes: HashMap<String, serde_yaml_ng::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct YamlSchema {
    pub object_classes: HashMap<String, ObjectClassSchema>,
    pub custom_attributes: HashMap<String, AttributeDef>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectClassSchema {
    pub required_attributes: Vec<String>,
    pub allowed_attributes: Vec<String>,
}

impl From<SchemaConfig> for YamlSchema {
    fn from(config: SchemaConfig) -> Self {
        // V1 schema blocks extend the built-ins. A same-named definition is
        // an intentional override; unrelated built-ins remain available.
        let mut schema = YamlSchema::default();
        for oc in config.object_classes {
            if let Some(existing_name) = schema
                .object_classes
                .keys()
                .find(|name| name.eq_ignore_ascii_case(&oc.name))
                .cloned()
            {
                schema.object_classes.remove(&existing_name);
            }
            let (required_attributes, allowed_attributes) = if oc.attributes.is_empty() {
                (oc.must, oc.may)
            } else {
                (oc.attributes, Vec::new())
            };
            schema.object_classes.insert(
                oc.name,
                ObjectClassSchema {
                    required_attributes,
                    allowed_attributes,
                },
            );
        }
        schema.custom_attributes = config.custom_attributes;
        schema
    }
}

impl YamlSchema {
    /// Get all known attributes from the schema
    #[cfg(any(test, feature = "unstable-internals"))]
    pub fn get_all_known_attributes(&self) -> std::collections::HashSet<String> {
        let mut attributes = std::collections::HashSet::new();

        // Add standard LDAP attributes that are always available
        attributes.insert("objectclass".to_string());
        attributes.insert("dn".to_string());

        // Add attributes from all object classes
        for object_class in self.object_classes.values() {
            for attr in object_class
                .required_attributes
                .iter()
                .chain(&object_class.allowed_attributes)
            {
                attributes.insert(attr.to_lowercase());
            }
        }

        // Add custom attributes
        for attr_name in self.custom_attributes.keys() {
            attributes.insert(attr_name.to_lowercase());
        }

        attributes
    }
}

impl Default for YamlSchema {
    fn default() -> Self {
        let mut object_classes = HashMap::new();

        // Add standard LDAP object classes
        object_classes.insert("top".to_string(), object_class(&[], &[]));
        object_classes.insert("domain".to_string(), object_class(&["dc"], &[]));
        object_classes.insert(
            "organizationalUnit".to_string(),
            object_class(&["ou"], &["description"]),
        );
        object_classes.insert(
            "person".to_string(),
            object_class(&["cn", "sn"], &["userPassword"]),
        );
        object_classes.insert(
            "inetOrgPerson".to_string(),
            object_class(&[], &["uid", "mail", "givenName", "userPassword"]),
        );
        object_classes.insert(
            "groupOfNames".to_string(),
            object_class(&["cn", "member"], &["description"]),
        );

        YamlSchema {
            object_classes,
            custom_attributes: HashMap::new(),
        }
    }
}

fn object_class(required: &[&str], allowed: &[&str]) -> ObjectClassSchema {
    ObjectClassSchema {
        required_attributes: required.iter().map(|name| (*name).to_string()).collect(),
        allowed_attributes: allowed.iter().map(|name| (*name).to_string()).collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_schema_config_to_yaml_schema() {
        let mut custom_attrs = HashMap::new();
        custom_attrs.insert(
            "employeeNumber".to_string(),
            AttributeDef {
                syntax: "String".to_string(),
                single_value: true,
            },
        );
        custom_attrs.insert(
            "department".to_string(),
            AttributeDef {
                syntax: "String".to_string(),
                single_value: false,
            },
        );

        let schema_config = SchemaConfig {
            object_classes: vec![
                ObjectClassDef {
                    name: "customPerson".to_string(),
                    attributes: vec!["cn".to_string(), "employeeNumber".to_string()],
                    must: vec![],
                    may: vec![],
                },
                ObjectClassDef {
                    name: "organizationalPerson".to_string(),
                    attributes: vec!["title".to_string(), "department".to_string()],
                    must: vec![],
                    may: vec![],
                },
            ],
            custom_attributes: custom_attrs,
        };

        let yaml_schema: YamlSchema = schema_config.into();

        // Verify object classes were converted
        assert!(yaml_schema.object_classes.len() >= 2);
        assert!(yaml_schema.object_classes.contains_key("customPerson"));
        assert!(yaml_schema
            .object_classes
            .contains_key("organizationalPerson"));

        // Verify attributes for each object class
        let custom_person_attrs = &yaml_schema.object_classes["customPerson"];
        assert_eq!(custom_person_attrs.required_attributes.len(), 2);
        assert!(custom_person_attrs
            .required_attributes
            .contains(&"cn".to_string()));
        assert!(custom_person_attrs
            .required_attributes
            .contains(&"employeeNumber".to_string()));

        let org_person_attrs = &yaml_schema.object_classes["organizationalPerson"];
        assert_eq!(org_person_attrs.required_attributes.len(), 2);
        assert!(org_person_attrs
            .required_attributes
            .contains(&"title".to_string()));
        assert!(org_person_attrs
            .required_attributes
            .contains(&"department".to_string()));

        // Verify custom attributes
        assert_eq!(yaml_schema.custom_attributes.len(), 2);
        assert!(yaml_schema.custom_attributes.contains_key("employeeNumber"));
        assert!(yaml_schema.custom_attributes.contains_key("department"));

        let emp_num_attr = &yaml_schema.custom_attributes["employeeNumber"];
        assert_eq!(emp_num_attr.syntax, "String");
        assert!(emp_num_attr.single_value);

        let dept_attr = &yaml_schema.custom_attributes["department"];
        assert_eq!(dept_attr.syntax, "String");
        assert!(!dept_attr.single_value);
    }

    #[test]
    fn test_yaml_schema_default() {
        let schema = YamlSchema::default();

        // Verify standard object classes are present
        assert!(schema.object_classes.contains_key("top"));
        assert!(schema.object_classes.contains_key("domain"));
        assert!(schema.object_classes.contains_key("organizationalUnit"));
        assert!(schema.object_classes.contains_key("person"));
        assert!(schema.object_classes.contains_key("inetOrgPerson"));
        assert!(schema.object_classes.contains_key("groupOfNames"));

        // Verify some key attributes
        let person_attrs = &schema.object_classes["person"];
        assert!(person_attrs.required_attributes.contains(&"cn".to_string()));
        assert!(person_attrs.required_attributes.contains(&"sn".to_string()));

        let inet_org_attrs = &schema.object_classes["inetOrgPerson"];
        assert!(inet_org_attrs.required_attributes.is_empty());
        assert!(inet_org_attrs
            .allowed_attributes
            .contains(&"uid".to_string()));
        assert!(inet_org_attrs
            .allowed_attributes
            .contains(&"mail".to_string()));
        assert!(inet_org_attrs
            .allowed_attributes
            .contains(&"userPassword".to_string()));

        // Verify no custom attributes by default
        assert!(schema.custom_attributes.is_empty());
    }

    #[test]
    fn test_empty_schema_config() {
        let schema_config = SchemaConfig {
            object_classes: vec![],
            custom_attributes: HashMap::new(),
        };

        let yaml_schema: YamlSchema = schema_config.into();

        assert!(yaml_schema.object_classes.contains_key("top"));
        assert!(yaml_schema.object_classes.contains_key("person"));
        assert!(yaml_schema.custom_attributes.is_empty());
    }
}
