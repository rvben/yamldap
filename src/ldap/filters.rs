use crate::directory::entry::LdapEntry;
use regex::Regex;

#[derive(Debug, Clone, PartialEq)]
pub enum LdapFilter {
    Present(String),                    // (attr=*)
    Equality(String, String),           // (attr=value)
    Substring(String, SubstringFilter), // (attr=*value*)
    GreaterOrEqual(String, String),     // (attr>=value)
    LessOrEqual(String, String),        // (attr<=value)
    And(Vec<LdapFilter>),               // (&(filter1)(filter2))
    Or(Vec<LdapFilter>),                // (|(filter1)(filter2))
    Not(Box<LdapFilter>),               // (!(filter))
}

#[derive(Debug, Clone, PartialEq)]
pub struct SubstringFilter {
    pub initial: Option<String>,
    pub any: Vec<String>,
    pub final_: Option<String>,
}

impl LdapFilter {
    pub fn matches(&self, entry: &LdapEntry) -> bool {
        match self {
            LdapFilter::Present(attr) => entry.has_attribute(attr),

            LdapFilter::Equality(attr, value) => {
                if let Some(attribute) = entry.get_attribute(attr) {
                    attribute
                        .values
                        .iter()
                        .any(|v| v.as_string().eq_ignore_ascii_case(value))
                } else {
                    false
                }
            }

            LdapFilter::Substring(attr, substring) => {
                if let Some(attribute) = entry.get_attribute(attr) {
                    attribute
                        .values
                        .iter()
                        .any(|v| substring.matches(&v.as_string()))
                } else {
                    false
                }
            }

            LdapFilter::GreaterOrEqual(attr, value) => {
                if let Some(attribute) = entry.get_attribute(attr) {
                    attribute.values.iter().any(|v| v.as_string() >= *value)
                } else {
                    false
                }
            }

            LdapFilter::LessOrEqual(attr, value) => {
                if let Some(attribute) = entry.get_attribute(attr) {
                    attribute.values.iter().any(|v| v.as_string() <= *value)
                } else {
                    false
                }
            }

            LdapFilter::And(filters) => filters.iter().all(|f| f.matches(entry)),

            LdapFilter::Or(filters) => filters.iter().any(|f| f.matches(entry)),

            LdapFilter::Not(filter) => !filter.matches(entry),
        }
    }
}

impl SubstringFilter {
    pub fn matches(&self, value: &str) -> bool {
        let mut pattern = String::new();

        if let Some(initial) = &self.initial {
            pattern.push_str(&regex::escape(initial));
        } else {
            pattern.push_str(".*");
        }

        for any in &self.any {
            pattern.push_str(".*");
            pattern.push_str(&regex::escape(any));
        }

        if let Some(final_) = &self.final_ {
            pattern.push_str(".*");
            pattern.push_str(&regex::escape(final_));
        } else {
            pattern.push_str(".*");
        }

        if let Ok(re) = Regex::new(&format!("(?i)^{}$", pattern)) {
            re.is_match(value)
        } else {
            false
        }
    }
}

// Simple parser for LDAP filters
pub fn parse_ldap_filter(filter_str: &str) -> crate::Result<LdapFilter> {
    let filter_str = filter_str.trim();

    if filter_str.is_empty() {
        return Err(crate::YamlLdapError::Protocol(
            "Empty filter string".to_string(),
        ));
    }

    // For now, implement a basic parser for common cases
    // A full implementation would need a proper LDAP filter parser

    // Check for presence filter: (attr=*)
    if filter_str.ends_with("=*)") && filter_str.starts_with('(') {
        let attr = filter_str[1..filter_str.len() - 3].to_string();
        return Ok(LdapFilter::Present(attr));
    }

    // Check for equality filter: (attr=value)
    if let Some(eq_pos) = filter_str.find('=') {
        if filter_str.starts_with('(') && filter_str.ends_with(')') {
            let attr = filter_str[1..eq_pos].to_string();
            let value = filter_str[eq_pos + 1..filter_str.len() - 1].to_string();

            // Check for substring filter
            if value.contains('*') && value != "*" {
                let parts: Vec<&str> = value.split('*').collect();
                let substring = SubstringFilter {
                    initial: if parts[0].is_empty() {
                        None
                    } else {
                        Some(parts[0].to_string())
                    },
                    any: parts[1..parts.len() - 1]
                        .iter()
                        .map(|s| s.to_string())
                        .collect(),
                    final_: if parts[parts.len() - 1].is_empty() {
                        None
                    } else {
                        Some(parts[parts.len() - 1].to_string())
                    },
                };
                return Ok(LdapFilter::Substring(attr, substring));
            }

            return Ok(LdapFilter::Equality(attr, value));
        }
    }

    // If we get here, the filter is not properly formatted
    Err(crate::YamlLdapError::Protocol(
        "Invalid filter format".to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_substring_filter() {
        let filter = SubstringFilter {
            initial: Some("john".to_string()),
            any: vec![],
            final_: None,
        };
        assert!(filter.matches("john"));
        assert!(filter.matches("johnny"));
        assert!(!filter.matches("ajohn"));

        let filter = SubstringFilter {
            initial: None,
            any: vec!["smith".to_string()],
            final_: None,
        };
        assert!(filter.matches("smith"));
        assert!(filter.matches("john smith"));
        assert!(filter.matches("smithsonian"));
    }

    #[test]
    fn test_parse_filter() {
        let filter = parse_ldap_filter("(cn=*)").unwrap();
        assert_eq!(filter, LdapFilter::Present("cn".to_string()));

        let filter = parse_ldap_filter("(uid=john)").unwrap();
        assert_eq!(
            filter,
            LdapFilter::Equality("uid".to_string(), "john".to_string())
        );
    }
}
