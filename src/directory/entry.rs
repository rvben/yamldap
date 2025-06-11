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
            AttributeValue::Binary(b) => base64::Engine::encode(&base64::engine::general_purpose::STANDARD, b),
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
    
    pub fn add_attribute(&mut self, name: String, values: Vec<AttributeValue>, syntax: AttributeSyntax) {
        self.attributes.insert(
            name.to_lowercase(),
            LdapAttribute { name, values, syntax },
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