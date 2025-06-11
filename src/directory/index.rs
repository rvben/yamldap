use dashmap::DashMap;
use std::sync::Arc;

/// Index for fast attribute lookups
#[derive(Debug, Clone)]
pub struct AttributeIndex {
    // Maps attribute=value to set of DNs
    index: Arc<DashMap<String, Vec<String>>>,
}

impl AttributeIndex {
    pub fn new() -> Self {
        Self {
            index: Arc::new(DashMap::new()),
        }
    }
    
    pub fn insert(&self, attr_name: &str, value: &str, dn: &str) {
        let key = format!("{}={}", attr_name.to_lowercase(), value.to_lowercase());
        self.index
            .entry(key)
            .or_insert_with(Vec::new)
            .push(dn.to_string());
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

impl ObjectClassIndex {
    pub fn new() -> Self {
        Self {
            index: Arc::new(DashMap::new()),
        }
    }
    
    pub fn insert(&self, object_class: &str, dn: &str) {
        self.index
            .entry(object_class.to_lowercase())
            .or_insert_with(Vec::new)
            .push(dn.to_string());
    }
    
    pub fn find(&self, object_class: &str) -> Option<Vec<String>> {
        self.index.get(&object_class.to_lowercase()).map(|v| v.clone())
    }
    
    pub fn clear(&self) {
        self.index.clear();
    }
}