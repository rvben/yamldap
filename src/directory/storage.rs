use super::dn::{attribute_types_equivalent, naming_values_equal};
use super::entry::LdapEntry;
use super::{DistinguishedName, DnKey};
use crate::yaml::{YamlDirectory, YamlSchema};
use std::collections::HashMap;
use std::time::{Duration, Instant};

#[derive(Debug)]
pub struct SearchEntriesResult {
    pub entries: Vec<LdapEntry>,
    pub size_limit_exceeded: bool,
    pub time_limit_exceeded: bool,
}

#[derive(Debug, Clone)]
pub struct Directory {
    pub base_dn: String,
    entries: HashMap<DnKey, LdapEntry>,
    #[cfg_attr(not(feature = "unstable-internals"), allow(dead_code))]
    pub schema: YamlSchema,
}

impl Directory {
    fn empty(base_dn: String, schema: YamlSchema) -> Self {
        Self {
            base_dn,
            entries: HashMap::new(),
            schema,
        }
    }

    #[cfg(test)]
    pub(crate) fn new(base_dn: String, schema: YamlSchema) -> Self {
        Self::empty(base_dn, schema)
    }

    #[cfg(test)]
    pub(crate) fn from_yaml(yaml_dir: YamlDirectory, schema: YamlSchema) -> Self {
        Self::try_from_yaml(yaml_dir, schema)
            .expect("invalid YAML directory passed to infallible compatibility conversion")
    }

    pub(crate) fn try_from_yaml(
        yaml_dir: YamlDirectory,
        schema: YamlSchema,
    ) -> crate::Result<Self> {
        let base_dn = DistinguishedName::parse(&yaml_dir.directory.base_dn)
            .map_err(|error| crate::YamlLdapError::Config(format!("Invalid base DN: {error}")))?;
        if base_dn.is_empty() {
            return Err(crate::YamlLdapError::Config(
                "Base DN cannot be empty".to_string(),
            ));
        }
        let mut dir = Self::empty(yaml_dir.directory.base_dn, schema.clone());

        for yaml_entry in yaml_dir.entries {
            let entry = LdapEntry::try_from_yaml(yaml_entry, &schema)?;
            let parsed_dn = DistinguishedName::parse(&entry.dn).map_err(|error| {
                crate::YamlLdapError::Config(format!(
                    "Entry {} has an invalid DN: {error}",
                    entry.dn
                ))
            })?;
            if !parsed_dn.is_equal_to_or_descendant_of(&base_dn) {
                return Err(crate::YamlLdapError::Config(format!(
                    "Entry {} is outside base DN {}",
                    entry.dn, dir.base_dn
                )));
            }
            validate_rdn_values(&entry, &parsed_dn)?;
            dir.insert_entry(entry)?;
        }

        Ok(dir)
    }

    #[cfg(test)]
    pub(crate) fn add_entry(&mut self, entry: LdapEntry) {
        self.insert_entry(entry)
            .expect("invalid entry passed to infallible compatibility insertion");
    }

    fn insert_entry(&mut self, entry: LdapEntry) -> crate::Result<()> {
        let parsed_dn = DistinguishedName::parse(&entry.dn).map_err(|error| {
            crate::YamlLdapError::Directory(format!("Invalid entry DN {}: {error}", entry.dn))
        })?;
        let dn_key = parsed_dn.key();
        if self.entries.contains_key(&dn_key) {
            return Err(crate::YamlLdapError::Directory(format!(
                "Duplicate distinguished name: {}",
                entry.dn
            )));
        }
        self.entries.insert(dn_key, entry);
        Ok(())
    }

    pub fn get_entry(&self, dn: &str) -> Option<LdapEntry> {
        let key = DistinguishedName::parse(dn).ok()?.key();
        self.entries.get(&key).cloned()
    }

    #[cfg(any(test, feature = "unstable-internals"))]
    pub fn search_entries<F>(&self, base_dn: &str, scope: SearchScope, filter: F) -> Vec<LdapEntry>
    where
        F: Fn(&LdapEntry) -> bool,
    {
        self.search_entries_with_limits(base_dn, scope, filter, None, None)
            .entries
    }

    pub fn search_entries_with_limits<F>(
        &self,
        base_dn: &str,
        scope: SearchScope,
        filter: F,
        size_limit: Option<usize>,
        time_limit: Option<Duration>,
    ) -> SearchEntriesResult
    where
        F: Fn(&LdapEntry) -> bool,
    {
        let Ok(base_dn) = DistinguishedName::parse(base_dn) else {
            return SearchEntriesResult {
                entries: Vec::new(),
                size_limit_exceeded: false,
                time_limit_exceeded: false,
            };
        };
        let base_key = base_dn.key();
        let mut results = Vec::new();
        let started_at = Instant::now();
        let mut size_limit_exceeded = false;
        let mut time_limit_exceeded = false;

        for (entry_key, entry) in &self.entries {
            if time_limit.is_some_and(|limit| started_at.elapsed() >= limit) {
                time_limit_exceeded = true;
                break;
            }

            let Ok(entry_dn) = DistinguishedName::parse(&entry.dn) else {
                continue;
            };
            // Check if entry is in scope
            let in_scope = match scope {
                SearchScope::BaseObject => entry_key == &base_key,
                SearchScope::SingleLevel => entry_dn.is_direct_child_of(&base_dn),
                SearchScope::WholeSubtree => {
                    entry_key == &base_key || entry_dn.is_descendant_of(&base_dn)
                }
            };

            if in_scope && filter(entry) {
                if size_limit.is_some_and(|limit| results.len() >= limit) {
                    size_limit_exceeded = true;
                    break;
                }
                results.push(entry.clone());
            }
        }

        SearchEntriesResult {
            entries: results,
            size_limit_exceeded,
            time_limit_exceeded,
        }
    }

    #[cfg(any(test, feature = "unstable-internals"))]
    pub fn entry_exists(&self, dn: &str) -> bool {
        DistinguishedName::parse(dn)
            .map(|dn| self.entries.contains_key(&dn.key()))
            .unwrap_or(false)
    }

    /// Get all attributes that exist in any entry in the directory
    pub fn get_all_existing_attributes(&self) -> std::collections::HashSet<String> {
        let mut attributes = std::collections::HashSet::new();

        // Always include standard attributes
        attributes.insert("objectclass".to_string());
        attributes.insert("dn".to_string());

        // Collect attributes from all entries
        for entry in self.entries.values() {
            for attr_name in entry.attributes.keys() {
                attributes.insert(attr_name.to_lowercase());
            }
        }

        attributes
    }
}

fn validate_rdn_values(entry: &LdapEntry, dn: &DistinguishedName) -> crate::Result<()> {
    let Some(rdn) = dn.leaf_rdn() else {
        return Err(crate::YamlLdapError::Config(
            "Directory entries cannot use the empty DN".to_string(),
        ));
    };
    for ava in rdn.avas() {
        let Some(expected) = ava.text_value() else {
            // BER-form AVAs need schema-specific decoding. They remain valid DN
            // syntax but cannot be checked against the YAML lexical values here.
            continue;
        };
        let attribute = entry
            .attributes
            .values()
            .find(|attribute| attribute_types_equivalent(&attribute.name, ava.attribute()))
            .ok_or_else(|| {
                crate::YamlLdapError::Config(format!(
                    "Entry {} is missing RDN attribute {}",
                    entry.dn,
                    ava.attribute()
                ))
            })?;
        if !attribute
            .values
            .iter()
            .any(|value| naming_values_equal(&value.as_string(), expected))
        {
            return Err(crate::YamlLdapError::Config(format!(
                "Entry {} RDN value for {} is not present in the entry",
                entry.dn,
                ava.attribute()
            )));
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SearchScope {
    BaseObject,
    SingleLevel,
    WholeSubtree,
}

#[cfg(test)]
fn is_direct_child(child_dn: &str, parent_dn: &str) -> bool {
    let Ok(child) = DistinguishedName::parse(child_dn) else {
        return false;
    };
    let Ok(parent) = DistinguishedName::parse(parent_dn) else {
        return false;
    };
    !parent.is_empty() && child.is_direct_child_of(&parent)
}

#[cfg(test)]
fn is_descendant(child_dn: &str, parent_dn: &str) -> bool {
    let Ok(child) = DistinguishedName::parse(child_dn) else {
        return false;
    };
    let Ok(parent) = DistinguishedName::parse(parent_dn) else {
        return false;
    };
    child.is_descendant_of(&parent)
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

        // A suffix inside the preceding RDN value is not a DN boundary.
        assert!(!is_direct_child(
            "uid=john,description=ou=users,dc=example,dc=com",
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

        // A suffix inside the preceding RDN value is not a DN boundary.
        assert!(!is_descendant(
            "uid=john,description=dc=example,dc=com",
            "dc=example,dc=com"
        ));
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
        let mut directory = Directory::new("dc=test,dc=com".to_string(), schema);

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
        let mut directory = Directory::new("dc=test,dc=com".to_string(), schema);

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
        let mut directory = Directory::new("dc=test,dc=com".to_string(), schema);

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
        let mut directory = Directory::new("dc=test,dc=com".to_string(), schema);

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
        let mut directory = Directory::new("dc=test,dc=com".to_string(), schema);

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
    fn test_directory_search_reports_expired_time_limit() {
        let mut directory = Directory::new("dc=test,dc=com".to_string(), YamlSchema::default());
        directory.add_entry(LdapEntry::new("dc=test,dc=com".to_string()));

        let result = directory.search_entries_with_limits(
            "dc=test,dc=com",
            SearchScope::WholeSubtree,
            |_| true,
            None,
            Some(Duration::ZERO),
        );

        assert!(result.entries.is_empty());
        assert!(result.time_limit_exceeded);
        assert!(!result.size_limit_exceeded);
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
                    serde_yaml_ng::Value::String("test".to_string()),
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
        let mut directory = Directory::new("dc=test,dc=com".to_string(), schema);

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
    }

    #[test]
    fn test_from_yaml() {
        use crate::yaml::schema::YamlDirectory;
        use std::collections::HashMap;

        // Create a YAML directory structure
        let yaml_dir = YamlDirectory {
            directory: crate::yaml::schema::DirectoryConfig {
                base_dn: "dc=example,dc=com".to_string(),
            },
            schema: None,
            entries: vec![
                crate::yaml::YamlEntry {
                    dn: "dc=example,dc=com".to_string(),
                    object_class: vec!["dcObject".to_string(), "organization".to_string()],
                    attributes: {
                        let mut attrs = HashMap::new();
                        attrs.insert(
                            "dc".to_string(),
                            serde_yaml_ng::Value::String("example".to_string()),
                        );
                        attrs
                    },
                },
                crate::yaml::YamlEntry {
                    dn: "cn=admin,dc=example,dc=com".to_string(),
                    object_class: vec!["person".to_string()],
                    attributes: {
                        let mut attrs = HashMap::new();
                        attrs.insert(
                            "cn".to_string(),
                            serde_yaml_ng::Value::String("admin".to_string()),
                        );
                        attrs
                    },
                },
            ],
        };

        let schema = YamlSchema::default();
        let directory = Directory::from_yaml(yaml_dir, schema);

        // Verify the base DN
        assert_eq!(directory.base_dn, "dc=example,dc=com");

        // Verify entries were added
        assert!(directory.entry_exists("dc=example,dc=com"));
        assert!(directory.entry_exists("cn=admin,dc=example,dc=com"));

        // Verify entry content
        let admin_entry = directory.get_entry("cn=admin,dc=example,dc=com").unwrap();
        assert_eq!(admin_entry.dn, "cn=admin,dc=example,dc=com");
        assert!(admin_entry.has_attribute("cn"));
        assert!(admin_entry.has_attribute("objectClass"));
    }

    #[test]
    fn test_entry_exists() {
        let schema = YamlSchema::default();
        let mut directory = Directory::new("dc=test,dc=com".to_string(), schema);

        // Initially no entries
        assert!(!directory.entry_exists("cn=test,dc=test,dc=com"));

        // Add an entry
        let mut entry = LdapEntry::new("cn=test,dc=test,dc=com".to_string());
        entry.add_attribute(
            "cn".to_string(),
            vec![crate::directory::entry::AttributeValue::String(
                "test".to_string(),
            )],
            crate::directory::entry::AttributeSyntax::String,
        );
        directory.add_entry(entry);

        // Now it should exist
        assert!(directory.entry_exists("cn=test,dc=test,dc=com"));

        // Test case insensitive
        assert!(directory.entry_exists("CN=TEST,DC=TEST,DC=COM"));
        assert!(directory.entry_exists("cn=Test,dc=Test,dc=Com"));

        // Non-existent entry
        assert!(!directory.entry_exists("cn=nonexistent,dc=test,dc=com"));

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

    #[test]
    fn escaped_comma_is_one_rdn_for_scope() {
        assert!(is_direct_child(
            r"cn=Smith\, John,ou=people,dc=example,dc=com",
            "ou=people,dc=example,dc=com"
        ));
        assert!(is_descendant(
            r"cn=Smith\, John,ou=people,dc=example,dc=com",
            "dc=example,dc=com"
        ));
    }

    #[test]
    fn lookup_uses_semantic_dn_identity() {
        let mut directory = Directory::new("dc=example,dc=com".to_string(), YamlSchema::default());
        let mut entry = LdapEntry::new("OU=Sales+CN=J. Smith,DC=example,DC=com".to_string());
        entry.add_attribute(
            "cn".to_string(),
            vec![crate::directory::AttributeValue::String(
                "J. Smith".to_string(),
            )],
            crate::directory::AttributeSyntax::String,
        );
        directory.add_entry(entry);

        assert!(directory
            .entry_exists("cn=j. smith+ou=sales,0.9.2342.19200300.100.1.25=example,dc=com"));
    }

    #[tokio::test]
    async fn test_directory_concurrent_reads() {
        use std::sync::Arc;
        use tokio::task::JoinSet;

        let schema = YamlSchema::default();
        let mut directory = Directory::new("dc=test,dc=com".to_string(), schema);
        for i in 0..15 {
            let mut entry = LdapEntry::new(format!("cn=user{},dc=test,dc=com", i));
            entry.add_attribute(
                "cn".to_string(),
                vec![crate::directory::entry::AttributeValue::String(format!(
                    "user{}",
                    i
                ))],
                crate::directory::entry::AttributeSyntax::String,
            );
            directory.add_entry(entry);
        }
        let directory = Arc::new(directory);
        let mut tasks = JoinSet::new();

        for _ in 0..5 {
            let dir = Arc::clone(&directory);
            tasks.spawn(async move {
                for i in 0..15 {
                    let entry = dir.get_entry(&format!("cn=user{},dc=test,dc=com", i));
                    assert!(entry.is_some());
                }
            });
        }

        while let Some(result) = tasks.join_next().await {
            assert!(result.is_ok());
        }
    }

    #[test]
    fn test_directory_search_concurrent() {
        use std::sync::Arc;
        use std::thread;

        let schema = YamlSchema::default();
        let mut directory = Directory::new("dc=test,dc=com".to_string(), schema);

        // Add some initial entries
        for i in 0..100 {
            let mut entry = LdapEntry::new(format!("cn=user{},dc=test,dc=com", i));
            entry.add_attribute(
                "cn".to_string(),
                vec![crate::directory::entry::AttributeValue::String(format!(
                    "user{}",
                    i
                ))],
                crate::directory::entry::AttributeSyntax::String,
            );
            entry.add_attribute(
                "uid".to_string(),
                vec![crate::directory::entry::AttributeValue::String(format!(
                    "uid{}",
                    i
                ))],
                crate::directory::entry::AttributeSyntax::String,
            );
            if i % 2 == 0 {
                entry.add_attribute(
                    "department".to_string(),
                    vec![crate::directory::entry::AttributeValue::String(
                        "engineering".to_string(),
                    )],
                    crate::directory::entry::AttributeSyntax::String,
                );
            }
            directory.add_entry(entry);
        }
        let directory = Arc::new(directory);

        // Concurrent searches
        let mut handles = vec![];

        for _ in 0..10 {
            let dir = Arc::clone(&directory);
            let handle = thread::spawn(move || {
                // Search for all entries
                let results =
                    dir.search_entries("dc=test,dc=com", SearchScope::WholeSubtree, |_| true);
                assert_eq!(results.len(), 100);

                // Search for entries with department
                let results =
                    dir.search_entries("dc=test,dc=com", SearchScope::WholeSubtree, |entry| {
                        entry.has_attribute("department")
                    });
                assert_eq!(results.len(), 50);

                // Search single level
                let results =
                    dir.search_entries("dc=test,dc=com", SearchScope::SingleLevel, |_| true);
                assert_eq!(results.len(), 100);
            });
            handles.push(handle);
        }

        // Wait for all threads
        for handle in handles {
            handle.join().unwrap();
        }
    }
}
