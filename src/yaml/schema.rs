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
