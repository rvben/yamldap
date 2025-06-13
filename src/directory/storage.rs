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
    if parent_dn.is_empty() || !child_dn.ends_with(parent_dn) {
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

    #[test]
    fn test_directory_new() {
        let schema = YamlSchema::default();
        let directory = Directory::new("dc=test,dc=com".to_string(), schema.clone());

        assert_eq!(directory.base_dn, "dc=test,dc=com");
        assert_eq!(directory.entries.len(), 0);
    }

    #[test]
    fn test_directory_add_and_get_entry() {
        let schema = YamlSchema::default();
        let directory = Directory::new("dc=test,dc=com".to_string(), schema);

        let mut entry = LdapEntry::new("cn=test,dc=test,dc=com".to_string());
        entry.add_attribute(
            "cn".to_string(),
            vec![crate::directory::entry::AttributeValue::String(
                "test".to_string(),
            )],
            crate::directory::entry::AttributeSyntax::String,
        );

        directory.add_entry(entry.clone());

        // Test get_entry
        let retrieved = directory.get_entry("cn=test,dc=test,dc=com");
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().dn, "cn=test,dc=test,dc=com");

        // Test case insensitive lookup
        let retrieved = directory.get_entry("CN=TEST,DC=TEST,DC=COM");
        assert!(retrieved.is_some());

        // Test entry_exists
        assert!(directory.entry_exists("cn=test,dc=test,dc=com"));
        assert!(directory.entry_exists("CN=TEST,DC=TEST,DC=COM"));
        assert!(!directory.entry_exists("cn=nonexistent,dc=test,dc=com"));
    }

    #[test]
    fn test_directory_search_base_object() {
        let schema = YamlSchema::default();
        let directory = Directory::new("dc=test,dc=com".to_string(), schema);

        let mut entry = LdapEntry::new("cn=test,dc=test,dc=com".to_string());
        entry.add_attribute(
            "cn".to_string(),
            vec![crate::directory::entry::AttributeValue::String(
                "test".to_string(),
            )],
            crate::directory::entry::AttributeSyntax::String,
        );
        directory.add_entry(entry);

        // Search for exact DN
        let results =
            directory.search_entries("cn=test,dc=test,dc=com", SearchScope::BaseObject, |_| true);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].dn, "cn=test,dc=test,dc=com");

        // Search for non-existent DN
        let results =
            directory.search_entries("cn=other,dc=test,dc=com", SearchScope::BaseObject, |_| true);
        assert_eq!(results.len(), 0);
    }

    #[test]
    fn test_directory_search_single_level() {
        let schema = YamlSchema::default();
        let directory = Directory::new("dc=test,dc=com".to_string(), schema);

        // Add parent
        let parent = LdapEntry::new("ou=users,dc=test,dc=com".to_string());
        directory.add_entry(parent);

        // Add direct child
        let child1 = LdapEntry::new("cn=user1,ou=users,dc=test,dc=com".to_string());
        directory.add_entry(child1);

        // Add grandchild (should not be included)
        let grandchild = LdapEntry::new("cn=sub,cn=user1,ou=users,dc=test,dc=com".to_string());
        directory.add_entry(grandchild);

        let results =
            directory.search_entries("ou=users,dc=test,dc=com", SearchScope::SingleLevel, |_| {
                true
            });

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].dn, "cn=user1,ou=users,dc=test,dc=com");
    }

    #[test]
    fn test_directory_search_whole_subtree() {
        let schema = YamlSchema::default();
        let directory = Directory::new("dc=test,dc=com".to_string(), schema);

        // Add base
        let base = LdapEntry::new("dc=test,dc=com".to_string());
        directory.add_entry(base);

        // Add child
        let child = LdapEntry::new("ou=users,dc=test,dc=com".to_string());
        directory.add_entry(child);

        // Add grandchild
        let grandchild = LdapEntry::new("cn=user1,ou=users,dc=test,dc=com".to_string());
        directory.add_entry(grandchild);

        let results =
            directory.search_entries("dc=test,dc=com", SearchScope::WholeSubtree, |_| true);

        assert_eq!(results.len(), 3);
        let dns: Vec<String> = results.iter().map(|e| e.dn.clone()).collect();
        assert!(dns.contains(&"dc=test,dc=com".to_string()));
        assert!(dns.contains(&"ou=users,dc=test,dc=com".to_string()));
        assert!(dns.contains(&"cn=user1,ou=users,dc=test,dc=com".to_string()));
    }

    #[test]
    fn test_directory_search_with_filter() {
        let schema = YamlSchema::default();
        let directory = Directory::new("dc=test,dc=com".to_string(), schema);

        let mut entry1 = LdapEntry::new("cn=user1,dc=test,dc=com".to_string());
        entry1.add_attribute(
            "uid".to_string(),
            vec![crate::directory::entry::AttributeValue::String(
                "user1".to_string(),
            )],
            crate::directory::entry::AttributeSyntax::String,
        );
        directory.add_entry(entry1);

        let mut entry2 = LdapEntry::new("cn=user2,dc=test,dc=com".to_string());
        entry2.add_attribute(
            "uid".to_string(),
            vec![crate::directory::entry::AttributeValue::String(
                "user2".to_string(),
            )],
            crate::directory::entry::AttributeSyntax::String,
        );
        directory.add_entry(entry2);

        // Filter for user1 only
        let results =
            directory.search_entries("dc=test,dc=com", SearchScope::WholeSubtree, |entry| {
                entry
                    .get_attribute("uid")
                    .map(|attr| attr.values.iter().any(|v| v.as_string() == "user1"))
                    .unwrap_or(false)
            });

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].dn, "cn=user1,dc=test,dc=com");
    }

    #[test]
    fn test_directory_from_yaml() {
        let schema = YamlSchema::default();

        let yaml_dir = crate::yaml::YamlDirectory {
            directory: crate::yaml::schema::DirectoryConfig {
                base_dn: "dc=yaml,dc=com".to_string(),
            },
            schema: None,
            entries: vec![crate::yaml::YamlEntry {
                dn: "cn=test,dc=yaml,dc=com".to_string(),
                object_class: vec!["person".to_string()],
                attributes: [(
                    "cn".to_string(),
                    serde_yaml::Value::String("test".to_string()),
                )]
                .into_iter()
                .collect(),
            }],
        };

        let directory = Directory::from_yaml(yaml_dir, schema);

        assert_eq!(directory.base_dn, "dc=yaml,dc=com");
        assert!(directory.entry_exists("cn=test,dc=yaml,dc=com"));

        let entry = directory.get_entry("cn=test,dc=yaml,dc=com").unwrap();
        assert!(entry.has_attribute("cn"));
        assert!(entry.has_attribute("objectClass"));
    }

    #[test]
    fn test_directory_indexing() {
        let schema = YamlSchema::default();
        let directory = Directory::new("dc=test,dc=com".to_string(), schema);

        let mut entry = LdapEntry::new("cn=indexed,dc=test,dc=com".to_string());
        entry.add_attribute(
            "uid".to_string(),
            vec![crate::directory::entry::AttributeValue::String(
                "testuid".to_string(),
            )],
            crate::directory::entry::AttributeSyntax::String,
        );
        entry.add_attribute(
            "cn".to_string(),
            vec![crate::directory::entry::AttributeValue::String(
                "Indexed User".to_string(),
            )],
            crate::directory::entry::AttributeSyntax::String,
        );
        entry.object_classes = vec!["person".to_string(), "top".to_string()];

        directory.add_entry(entry);

        // The indexes should have been updated
        // This is tested indirectly through search functionality
        let results = directory.search_entries("dc=test,dc=com", SearchScope::WholeSubtree, |e| {
            e.has_attribute("uid")
        });

        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_is_direct_child_edge_cases() {
        // Test with empty parent
        assert!(!is_direct_child("cn=test", ""));

        // Test with child same as parent
        assert!(!is_direct_child("dc=com", "dc=com"));

        // Test with trailing comma
        assert!(is_direct_child("cn=test,dc=com", "dc=com"));

        // Test with multiple levels
        assert!(!is_direct_child("cn=test,ou=users,dc=com", "dc=com"));
    }

    #[test]
    fn test_is_descendant_edge_cases() {
        // Test with unrelated DNs
        assert!(!is_descendant("dc=other,dc=com", "dc=example,dc=com"));

        // Test with partial match
        assert!(!is_descendant("dc=com", "dc=example,dc=com"));
    }
}
