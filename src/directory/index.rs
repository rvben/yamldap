use dashmap::DashMap;
use std::sync::Arc;

/// Index for fast attribute lookups
#[derive(Debug, Clone)]
pub struct AttributeIndex {
    // Maps attribute=value to set of DNs
    index: Arc<DashMap<String, Vec<String>>>,
}

impl Default for AttributeIndex {
    fn default() -> Self {
        Self {
            index: Arc::new(DashMap::new()),
        }
    }
}

impl AttributeIndex {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&self, attr_name: &str, value: &str, dn: &str) {
        let key = format!("{}={}", attr_name.to_lowercase(), value.to_lowercase());
        self.index.entry(key).or_default().push(dn.to_string());
    }

    pub fn find(&self, attr_name: &str, value: &str) -> Option<Vec<String>> {
        let key = format!("{}={}", attr_name.to_lowercase(), value.to_lowercase());
        self.index.get(&key).map(|v| v.clone())
    }

    pub fn clear(&self) {
        self.index.clear();
    }
}

/// Object class index for fast object class lookups
#[derive(Debug, Clone)]
pub struct ObjectClassIndex {
    // Maps objectClass to set of DNs
    index: Arc<DashMap<String, Vec<String>>>,
}

impl Default for ObjectClassIndex {
    fn default() -> Self {
        Self {
            index: Arc::new(DashMap::new()),
        }
    }
}

impl ObjectClassIndex {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&self, object_class: &str, dn: &str) {
        self.index
            .entry(object_class.to_lowercase())
            .or_default()
            .push(dn.to_string());
    }

    pub fn find(&self, object_class: &str) -> Option<Vec<String>> {
        self.index
            .get(&object_class.to_lowercase())
            .map(|v| v.clone())
    }

    pub fn clear(&self) {
        self.index.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_attribute_index_new() {
        let index = AttributeIndex::new();
        assert_eq!(index.index.len(), 0);
    }

    #[test]
    fn test_attribute_index_default() {
        let index = AttributeIndex::default();
        assert_eq!(index.index.len(), 0);
    }

    #[test]
    fn test_attribute_index_insert_and_find() {
        let index = AttributeIndex::new();
        
        // Insert a single value
        index.insert("cn", "test", "cn=test,dc=example,dc=com");
        
        // Find the value
        let results = index.find("cn", "test");
        assert!(results.is_some());
        assert_eq!(results.unwrap(), vec!["cn=test,dc=example,dc=com"]);
        
        // Insert another DN with the same attribute value
        index.insert("cn", "test", "cn=test,ou=users,dc=example,dc=com");
        
        // Should find both DNs
        let results = index.find("cn", "test");
        assert!(results.is_some());
        let dns = results.unwrap();
        assert_eq!(dns.len(), 2);
        assert!(dns.contains(&"cn=test,dc=example,dc=com".to_string()));
        assert!(dns.contains(&"cn=test,ou=users,dc=example,dc=com".to_string()));
    }

    #[test]
    fn test_attribute_index_case_insensitive() {
        let index = AttributeIndex::new();
        
        // Insert with mixed case
        index.insert("CN", "Test User", "cn=test,dc=example,dc=com");
        
        // Find with different case
        let results = index.find("cn", "test user");
        assert!(results.is_some());
        assert_eq!(results.unwrap(), vec!["cn=test,dc=example,dc=com"]);
        
        // Find with original case
        let results = index.find("CN", "Test User");
        assert!(results.is_some());
        assert_eq!(results.unwrap(), vec!["cn=test,dc=example,dc=com"]);
    }

    #[test]
    fn test_attribute_index_not_found() {
        let index = AttributeIndex::new();
        
        index.insert("cn", "test", "cn=test,dc=example,dc=com");
        
        // Try to find non-existent value
        let results = index.find("cn", "nonexistent");
        assert!(results.is_none());
        
        // Try to find non-existent attribute
        let results = index.find("sn", "test");
        assert!(results.is_none());
    }

    #[test]
    fn test_attribute_index_clear() {
        let index = AttributeIndex::new();
        
        index.insert("cn", "test1", "cn=test1,dc=example,dc=com");
        index.insert("cn", "test2", "cn=test2,dc=example,dc=com");
        index.insert("sn", "user", "cn=test1,dc=example,dc=com");
        
        assert!(index.find("cn", "test1").is_some());
        assert!(index.find("cn", "test2").is_some());
        assert!(index.find("sn", "user").is_some());
        
        index.clear();
        
        assert!(index.find("cn", "test1").is_none());
        assert!(index.find("cn", "test2").is_none());
        assert!(index.find("sn", "user").is_none());
        assert_eq!(index.index.len(), 0);
    }

    #[test]
    fn test_attribute_index_clone() {
        let index = AttributeIndex::new();
        index.insert("cn", "test", "cn=test,dc=example,dc=com");
        
        let cloned = index.clone();
        
        // Verify the clone has the same data
        let results = cloned.find("cn", "test");
        assert!(results.is_some());
        assert_eq!(results.unwrap(), vec!["cn=test,dc=example,dc=com"]);
        
        // Modify the clone and verify it doesn't affect the original
        cloned.insert("cn", "test", "cn=test2,dc=example,dc=com");
        
        let clone_results = cloned.find("cn", "test").unwrap();
        assert_eq!(clone_results.len(), 2);
        
        let original_results = index.find("cn", "test").unwrap();
        assert_eq!(original_results.len(), 2); // Should also be 2 because Arc is shared
    }

    #[test]
    fn test_object_class_index_new() {
        let index = ObjectClassIndex::new();
        assert_eq!(index.index.len(), 0);
    }

    #[test]
    fn test_object_class_index_default() {
        let index = ObjectClassIndex::default();
        assert_eq!(index.index.len(), 0);
    }

    #[test]
    fn test_object_class_index_insert_and_find() {
        let index = ObjectClassIndex::new();
        
        // Insert a single DN
        index.insert("person", "cn=test,dc=example,dc=com");
        
        // Find by object class
        let results = index.find("person");
        assert!(results.is_some());
        assert_eq!(results.unwrap(), vec!["cn=test,dc=example,dc=com"]);
        
        // Insert another DN with the same object class
        index.insert("person", "cn=test2,dc=example,dc=com");
        
        // Should find both DNs
        let results = index.find("person");
        assert!(results.is_some());
        let dns = results.unwrap();
        assert_eq!(dns.len(), 2);
        assert!(dns.contains(&"cn=test,dc=example,dc=com".to_string()));
        assert!(dns.contains(&"cn=test2,dc=example,dc=com".to_string()));
    }

    #[test]
    fn test_object_class_index_case_insensitive() {
        let index = ObjectClassIndex::new();
        
        // Insert with mixed case
        index.insert("Person", "cn=test,dc=example,dc=com");
        
        // Find with different case
        let results = index.find("person");
        assert!(results.is_some());
        assert_eq!(results.unwrap(), vec!["cn=test,dc=example,dc=com"]);
        
        // Find with uppercase
        let results = index.find("PERSON");
        assert!(results.is_some());
        assert_eq!(results.unwrap(), vec!["cn=test,dc=example,dc=com"]);
    }

    #[test]
    fn test_object_class_index_not_found() {
        let index = ObjectClassIndex::new();
        
        index.insert("person", "cn=test,dc=example,dc=com");
        
        // Try to find non-existent object class
        let results = index.find("group");
        assert!(results.is_none());
    }

    #[test]
    fn test_object_class_index_clear() {
        let index = ObjectClassIndex::new();
        
        index.insert("person", "cn=test1,dc=example,dc=com");
        index.insert("person", "cn=test2,dc=example,dc=com");
        index.insert("group", "cn=admins,dc=example,dc=com");
        
        assert!(index.find("person").is_some());
        assert!(index.find("group").is_some());
        
        index.clear();
        
        assert!(index.find("person").is_none());
        assert!(index.find("group").is_none());
        assert_eq!(index.index.len(), 0);
    }

    #[test]
    fn test_object_class_index_clone() {
        let index = ObjectClassIndex::new();
        index.insert("person", "cn=test,dc=example,dc=com");
        
        let cloned = index.clone();
        
        // Verify the clone has the same data
        let results = cloned.find("person");
        assert!(results.is_some());
        assert_eq!(results.unwrap(), vec!["cn=test,dc=example,dc=com"]);
        
        // Both should see the same updates due to Arc
        cloned.insert("person", "cn=test2,dc=example,dc=com");
        
        let clone_results = cloned.find("person").unwrap();
        assert_eq!(clone_results.len(), 2);
        
        let original_results = index.find("person").unwrap();
        assert_eq!(original_results.len(), 2);
    }

    #[test]
    fn test_attribute_index_special_characters() {
        let index = AttributeIndex::new();
        
        // Test with special characters in values
        index.insert("email", "test@example.com", "cn=test,dc=example,dc=com");
        index.insert("description", "Line 1\nLine 2", "cn=test,dc=example,dc=com");
        index.insert("cn", "O'Brien", "cn=O'Brien,dc=example,dc=com");
        
        assert!(index.find("email", "test@example.com").is_some());
        assert!(index.find("description", "Line 1\nLine 2").is_some());
        assert!(index.find("cn", "O'Brien").is_some());
    }

    #[test]
    fn test_object_class_index_multiple_classes() {
        let index = ObjectClassIndex::new();
        
        let dn = "cn=test,dc=example,dc=com";
        
        // A single entry can have multiple object classes
        index.insert("top", dn);
        index.insert("person", dn);
        index.insert("organizationalPerson", dn);
        
        // Should be findable by any of its object classes
        assert_eq!(index.find("top").unwrap(), vec![dn]);
        assert_eq!(index.find("person").unwrap(), vec![dn]);
        assert_eq!(index.find("organizationalPerson").unwrap(), vec![dn]);
    }
}
