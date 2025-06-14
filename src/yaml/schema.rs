use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YamlDirectory {
    pub directory: DirectoryConfig,
    #[serde(default)]
    pub schema: Option<SchemaConfig>,
    pub entries: Vec<YamlEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirectoryConfig {
    pub base_dn: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchemaConfig {
    #[serde(default)]
    pub object_classes: Vec<ObjectClassDef>,
    #[serde(default)]
    pub custom_attributes: HashMap<String, AttributeDef>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectClassDef {
    pub name: String,
    pub attributes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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
    pub attributes: HashMap<String, serde_yaml::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YamlSchema {
    pub object_classes: HashMap<String, Vec<String>>,
    pub custom_attributes: HashMap<String, AttributeDef>,
}

impl From<SchemaConfig> for YamlSchema {
    fn from(config: SchemaConfig) -> Self {
        let mut object_classes = HashMap::new();
        for oc in config.object_classes {
            object_classes.insert(oc.name, oc.attributes);
        }

        YamlSchema {
            object_classes,
            custom_attributes: config.custom_attributes,
        }
    }
}

impl Default for YamlSchema {
    fn default() -> Self {
        let mut object_classes = HashMap::new();

        // Add standard LDAP object classes
        object_classes.insert("top".to_string(), vec![]);
        object_classes.insert("domain".to_string(), vec!["dc".to_string()]);
        object_classes.insert("organizationalUnit".to_string(), vec!["ou".to_string()]);
        object_classes.insert(
            "person".to_string(),
            vec!["cn".to_string(), "sn".to_string()],
        );
        object_classes.insert(
            "inetOrgPerson".to_string(),
            vec![
                "uid".to_string(),
                "mail".to_string(),
                "givenName".to_string(),
                "userPassword".to_string(),
            ],
        );
        object_classes.insert(
            "groupOfNames".to_string(),
            vec!["cn".to_string(), "member".to_string()],
        );

        YamlSchema {
            object_classes,
            custom_attributes: HashMap::new(),
        }
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
                },
                ObjectClassDef {
                    name: "organizationalPerson".to_string(),
                    attributes: vec!["title".to_string(), "department".to_string()],
                },
            ],
            custom_attributes: custom_attrs,
        };

        let yaml_schema: YamlSchema = schema_config.into();

        // Verify object classes were converted
        assert_eq!(yaml_schema.object_classes.len(), 2);
        assert!(yaml_schema.object_classes.contains_key("customPerson"));
        assert!(yaml_schema.object_classes.contains_key("organizationalPerson"));

        // Verify attributes for each object class
        let custom_person_attrs = &yaml_schema.object_classes["customPerson"];
        assert_eq!(custom_person_attrs.len(), 2);
        assert!(custom_person_attrs.contains(&"cn".to_string()));
        assert!(custom_person_attrs.contains(&"employeeNumber".to_string()));

        let org_person_attrs = &yaml_schema.object_classes["organizationalPerson"];
        assert_eq!(org_person_attrs.len(), 2);
        assert!(org_person_attrs.contains(&"title".to_string()));
        assert!(org_person_attrs.contains(&"department".to_string()));

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
        assert!(person_attrs.contains(&"cn".to_string()));
        assert!(person_attrs.contains(&"sn".to_string()));

        let inet_org_attrs = &schema.object_classes["inetOrgPerson"];
        assert!(inet_org_attrs.contains(&"uid".to_string()));
        assert!(inet_org_attrs.contains(&"mail".to_string()));
        assert!(inet_org_attrs.contains(&"userPassword".to_string()));

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

        assert!(yaml_schema.object_classes.is_empty());
        assert!(yaml_schema.custom_attributes.is_empty());
    }
}
