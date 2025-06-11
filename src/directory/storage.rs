use super::entry::LdapEntry;
use super::index::{AttributeIndex, ObjectClassIndex};
use crate::yaml::{YamlDirectory, YamlSchema};
use dashmap::DashMap;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct Directory {
    pub base_dn: String,
    entries: Arc<DashMap<String, LdapEntry>>,
    pub schema: YamlSchema,
    // Indexes for fast lookups
    uid_index: AttributeIndex,
    cn_index: AttributeIndex,
    objectclass_index: ObjectClassIndex,
}

impl Directory {
    pub fn new(base_dn: String, schema: YamlSchema) -> Self {
        Self {
            base_dn,
            entries: Arc::new(DashMap::new()),
            schema,
            uid_index: AttributeIndex::new(),
            cn_index: AttributeIndex::new(),
            objectclass_index: ObjectClassIndex::new(),
        }
    }

    pub fn from_yaml(yaml_dir: YamlDirectory, schema: YamlSchema) -> Self {
        let dir = Self::new(yaml_dir.directory.base_dn, schema);

        for yaml_entry in yaml_dir.entries {
            let entry: LdapEntry = yaml_entry.into();
            dir.add_entry(entry);
        }

        dir
    }

    pub fn add_entry(&self, entry: LdapEntry) {
        let dn_lower = entry.dn.to_lowercase();

        // Update indexes
        if let Some(uid_attr) = entry.get_attribute("uid") {
            for value in &uid_attr.values {
                self.uid_index.insert("uid", &value.as_string(), &dn_lower);
            }
        }

        if let Some(cn_attr) = entry.get_attribute("cn") {
            for value in &cn_attr.values {
                self.cn_index.insert("cn", &value.as_string(), &dn_lower);
            }
        }

        for oc in &entry.object_classes {
            self.objectclass_index.insert(oc, &dn_lower);
        }

        self.entries.insert(dn_lower, entry);
    }

    pub fn get_entry(&self, dn: &str) -> Option<LdapEntry> {
        self.entries.get(&dn.to_lowercase()).map(|e| e.clone())
    }

    pub fn search_entries<F>(&self, base_dn: &str, scope: SearchScope, filter: F) -> Vec<LdapEntry>
    where
        F: Fn(&LdapEntry) -> bool,
    {
        let base_dn_lower = base_dn.to_lowercase();
        let mut results = Vec::new();

        for entry in self.entries.iter() {
            let entry_dn_lower = entry.key().to_lowercase();

            // Check if entry is in scope
            let in_scope = match scope {
                SearchScope::BaseObject => entry_dn_lower == base_dn_lower,
                SearchScope::SingleLevel => {
                    entry_dn_lower != base_dn_lower
                        && is_direct_child(&entry_dn_lower, &base_dn_lower)
                }
                SearchScope::WholeSubtree => {
                    entry_dn_lower == base_dn_lower
                        || is_descendant(&entry_dn_lower, &base_dn_lower)
                }
            };

            if in_scope && filter(&entry) {
                results.push(entry.clone());
            }
        }

        results
    }

    pub fn entry_exists(&self, dn: &str) -> bool {
        self.entries.contains_key(&dn.to_lowercase())
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SearchScope {
    BaseObject,
    SingleLevel,
    WholeSubtree,
}

fn is_direct_child(child_dn: &str, parent_dn: &str) -> bool {
    if !child_dn.ends_with(parent_dn) {
        return false;
    }

    let prefix = &child_dn[..child_dn.len() - parent_dn.len()];
    if prefix.is_empty() {
        return false;
    }

    // Remove trailing comma if present
    let prefix = prefix.trim_end_matches(',');

    // Check if there's only one RDN component
    !prefix.contains(',')
}

fn is_descendant(child_dn: &str, parent_dn: &str) -> bool {
    child_dn.ends_with(parent_dn) && child_dn.len() > parent_dn.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_direct_child() {
        assert!(is_direct_child(
            "uid=john,ou=users,dc=example,dc=com",
            "ou=users,dc=example,dc=com"
        ));

        assert!(!is_direct_child(
            "uid=john,ou=admins,ou=users,dc=example,dc=com",
            "ou=users,dc=example,dc=com"
        ));

        assert!(!is_direct_child(
            "ou=users,dc=example,dc=com",
            "ou=users,dc=example,dc=com"
        ));
    }

    #[test]
    fn test_is_descendant() {
        assert!(is_descendant(
            "uid=john,ou=users,dc=example,dc=com",
            "dc=example,dc=com"
        ));

        assert!(is_descendant(
            "uid=john,ou=admins,ou=users,dc=example,dc=com",
            "dc=example,dc=com"
        ));

        assert!(!is_descendant("dc=example,dc=com", "dc=example,dc=com"));
    }
}
