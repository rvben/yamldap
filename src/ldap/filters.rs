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

    // Check if filter is wrapped in parentheses
    if !filter_str.starts_with('(') || !filter_str.ends_with(')') {
        return Err(crate::YamlLdapError::Protocol(
            "Filter must be wrapped in parentheses".to_string(),
        ));
    }

    // Remove outer parentheses
    let inner = &filter_str[1..filter_str.len() - 1];

    // Check for composite filters
    if inner.starts_with('&') {
        // AND filter: (&(filter1)(filter2)...)
        let filters = parse_composite_filters(&inner[1..])?;
        return Ok(LdapFilter::And(filters));
    } else if inner.starts_with('|') {
        // OR filter: (|(filter1)(filter2)...)
        let filters = parse_composite_filters(&inner[1..])?;
        return Ok(LdapFilter::Or(filters));
    } else if inner.starts_with('!') {
        // NOT filter: (!(filter))
        let filter = parse_ldap_filter(&inner[1..])?;
        return Ok(LdapFilter::Not(Box::new(filter)));
    }

    // Check for presence filter: (attr=*)
    if inner.ends_with("=*") {
        let attr = inner[..inner.len() - 2].to_string();
        return Ok(LdapFilter::Present(attr));
    }

    // Check for comparison filters
    if let Some(eq_pos) = inner.find('=') {
        let attr = inner[..eq_pos].to_string();
        let value = inner[eq_pos + 1..].to_string();

        // Check for substring filter
        if value.contains('*') {
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
    } else if let Some(ge_pos) = inner.find(">=") {
        let attr = inner[..ge_pos].to_string();
        let value = inner[ge_pos + 2..].to_string();
        return Ok(LdapFilter::GreaterOrEqual(attr, value));
    } else if let Some(le_pos) = inner.find("<=") {
        let attr = inner[..le_pos].to_string();
        let value = inner[le_pos + 2..].to_string();
        return Ok(LdapFilter::LessOrEqual(attr, value));
    }

    Err(crate::YamlLdapError::Protocol(
        format!("Invalid filter format: {}", filter_str),
    ))
}

// Helper function to parse composite filters
fn parse_composite_filters(s: &str) -> crate::Result<Vec<LdapFilter>> {
    let mut filters = Vec::new();
    let mut depth = 0;
    let mut start = 0;

    for (i, ch) in s.chars().enumerate() {
        match ch {
            '(' => {
                if depth == 0 {
                    start = i;
                }
                depth += 1;
            }
            ')' => {
                depth -= 1;
                if depth == 0 {
                    let filter_str = &s[start..=i];
                    filters.push(parse_ldap_filter(filter_str)?);
                }
            }
            _ => {}
        }
    }

    if depth != 0 {
        return Err(crate::YamlLdapError::Protocol(
            "Unbalanced parentheses in filter".to_string(),
        ));
    }

    Ok(filters)
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

    #[test]
    fn test_parse_and_filter() {
        let filter = parse_ldap_filter("(&(objectClass=person)(uid=admin))").unwrap();
        match filter {
            LdapFilter::And(filters) => {
                assert_eq!(filters.len(), 2);
                assert_eq!(
                    filters[0],
                    LdapFilter::Equality("objectClass".to_string(), "person".to_string())
                );
                assert_eq!(
                    filters[1],
                    LdapFilter::Equality("uid".to_string(), "admin".to_string())
                );
            }
            _ => panic!("Expected AND filter"),
        }
    }

    #[test]
    fn test_parse_or_filter() {
        let filter = parse_ldap_filter("(|(uid=user1)(uid=user2))").unwrap();
        match filter {
            LdapFilter::Or(filters) => {
                assert_eq!(filters.len(), 2);
                assert_eq!(
                    filters[0],
                    LdapFilter::Equality("uid".to_string(), "user1".to_string())
                );
                assert_eq!(
                    filters[1],
                    LdapFilter::Equality("uid".to_string(), "user2".to_string())
                );
            }
            _ => panic!("Expected OR filter"),
        }
    }

    #[test]
    fn test_parse_not_filter() {
        let filter = parse_ldap_filter("(!(uid=admin))").unwrap();
        match filter {
            LdapFilter::Not(inner) => {
                assert_eq!(
                    *inner,
                    LdapFilter::Equality("uid".to_string(), "admin".to_string())
                );
            }
            _ => panic!("Expected NOT filter"),
        }
    }

    #[test]
    fn test_parse_nested_filters() {
        let filter = parse_ldap_filter("(&(objectClass=person)(|(uid=user1)(uid=user2)))").unwrap();
        match filter {
            LdapFilter::And(filters) => {
                assert_eq!(filters.len(), 2);
                assert_eq!(
                    filters[0],
                    LdapFilter::Equality("objectClass".to_string(), "person".to_string())
                );
                match &filters[1] {
                    LdapFilter::Or(or_filters) => {
                        assert_eq!(or_filters.len(), 2);
                    }
                    _ => panic!("Expected nested OR filter"),
                }
            }
            _ => panic!("Expected AND filter"),
        }
    }

    #[test]
    fn test_filter_evaluation() {
        use crate::directory::entry::{LdapEntry, AttributeValue, AttributeSyntax};
        
        let mut entry = LdapEntry::new("cn=test,dc=example,dc=com".to_string());
        entry.add_attribute(
            "uid".to_string(),
            vec![AttributeValue::String("testuser".to_string())],
            AttributeSyntax::String,
        );
        entry.add_attribute(
            "objectClass".to_string(),
            vec![AttributeValue::String("person".to_string())],
            AttributeSyntax::String,
        );

        // Test AND filter
        let filter = parse_ldap_filter("(&(objectClass=person)(uid=testuser))").unwrap();
        assert!(filter.matches(&entry));

        let filter = parse_ldap_filter("(&(objectClass=person)(uid=wronguser))").unwrap();
        assert!(!filter.matches(&entry));

        // Test OR filter
        let filter = parse_ldap_filter("(|(uid=testuser)(uid=otheruser))").unwrap();
        assert!(filter.matches(&entry));

        let filter = parse_ldap_filter("(|(uid=wronguser)(uid=otheruser))").unwrap();
        assert!(!filter.matches(&entry));

        // Test NOT filter
        let filter = parse_ldap_filter("(!(uid=wronguser))").unwrap();
        assert!(filter.matches(&entry));

        let filter = parse_ldap_filter("(!(uid=testuser))").unwrap();
        assert!(!filter.matches(&entry));
    }
}
