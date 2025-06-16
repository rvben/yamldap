use super::filters::{LdapFilter, SubstringFilter};
use std::collections::HashSet;

/// Transform a filter to be Active Directory compatible
pub fn transform_filter_for_ad(filter: LdapFilter) -> LdapFilter {
    match filter {
        LdapFilter::Equality(attr, value) => {
            if attr.eq_ignore_ascii_case("objectClass") && value.eq_ignore_ascii_case("user") {
                // Transform objectClass=user to also match inetOrgPerson
                LdapFilter::Or(vec![
                    LdapFilter::Equality(attr.clone(), value),
                    LdapFilter::Equality(attr, "inetOrgPerson".to_string()),
                ])
            } else if attr.eq_ignore_ascii_case("userPrincipalName") {
                // Transform userPrincipalName to also check uid and mail
                LdapFilter::Or(vec![
                    LdapFilter::Equality(attr, value.clone()),
                    LdapFilter::Equality("uid".to_string(), extract_username(&value)),
                    LdapFilter::Equality("mail".to_string(), value),
                ])
            } else {
                LdapFilter::Equality(attr, value)
            }
        }
        LdapFilter::Substring(attr, substring) => {
            if attr.eq_ignore_ascii_case("userPrincipalName") {
                // For substring searches on userPrincipalName, also search uid and mail
                LdapFilter::Or(vec![
                    LdapFilter::Substring(attr, substring.clone()),
                    LdapFilter::Substring("uid".to_string(), transform_substring_for_uid(&substring)),
                    LdapFilter::Substring("mail".to_string(), substring),
                ])
            } else {
                LdapFilter::Substring(attr, substring)
            }
        }
        LdapFilter::And(filters) => {
            LdapFilter::And(filters.into_iter().map(transform_filter_for_ad).collect())
        }
        LdapFilter::Or(filters) => {
            LdapFilter::Or(filters.into_iter().map(transform_filter_for_ad).collect())
        }
        LdapFilter::Not(filter) => LdapFilter::Not(Box::new(transform_filter_for_ad(*filter))),
        // Other filter types remain unchanged
        _ => filter,
    }
}

/// Transform attributes that should be present in AD but map to OpenLDAP equivalents
pub fn transform_undefined_attributes(attributes: &HashSet<String>) -> HashSet<String> {
    let mut transformed = attributes.clone();
    
    // If userPrincipalName is requested but not present, don't consider it undefined
    // since we'll map it to uid/mail
    transformed.remove("userprincipalname");
    
    // objectClass transformations are handled differently, so we don't need to remove "user"
    
    transformed
}

/// Extract username from userPrincipalName (e.g., "user@domain.com" -> "user")
fn extract_username(upn: &str) -> String {
    upn.split('@').next().unwrap_or(upn).to_string()
}

/// Transform substring filter for uid (remove domain part if present)
fn transform_substring_for_uid(substring: &SubstringFilter) -> SubstringFilter {
    SubstringFilter {
        initial: substring.initial.as_ref().map(|s| extract_username(s)),
        any: substring.any.iter().map(|s| extract_username(s)).collect(),
        final_: substring.final_.as_ref().map(|s| extract_username(s)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transform_objectclass_user() {
        let filter = LdapFilter::Equality("objectClass".to_string(), "user".to_string());
        let transformed = transform_filter_for_ad(filter);
        
        match transformed {
            LdapFilter::Or(filters) => {
                assert_eq!(filters.len(), 2);
                assert!(matches!(&filters[0], LdapFilter::Equality(attr, val) 
                    if attr == "objectClass" && val == "user"));
                assert!(matches!(&filters[1], LdapFilter::Equality(attr, val) 
                    if attr == "objectClass" && val == "inetOrgPerson"));
            }
            _ => panic!("Expected OR filter"),
        }
    }

    #[test]
    fn test_transform_userprincipalname() {
        let filter = LdapFilter::Equality("userPrincipalName".to_string(), "user@example.com".to_string());
        let transformed = transform_filter_for_ad(filter);
        
        match transformed {
            LdapFilter::Or(filters) => {
                assert_eq!(filters.len(), 3);
                // Should check userPrincipalName, uid (without domain), and mail
                assert!(matches!(&filters[0], LdapFilter::Equality(attr, val) 
                    if attr == "userPrincipalName" && val == "user@example.com"));
                assert!(matches!(&filters[1], LdapFilter::Equality(attr, val) 
                    if attr == "uid" && val == "user"));
                assert!(matches!(&filters[2], LdapFilter::Equality(attr, val) 
                    if attr == "mail" && val == "user@example.com"));
            }
            _ => panic!("Expected OR filter"),
        }
    }

    #[test]
    fn test_transform_and_filter() {
        let filter = LdapFilter::And(vec![
            LdapFilter::Equality("objectClass".to_string(), "user".to_string()),
            LdapFilter::Equality("cn".to_string(), "test".to_string()),
        ]);
        let transformed = transform_filter_for_ad(filter);
        
        match transformed {
            LdapFilter::And(filters) => {
                assert_eq!(filters.len(), 2);
                // First should be transformed objectClass
                assert!(matches!(&filters[0], LdapFilter::Or(_)));
                // Second should be unchanged cn
                assert!(matches!(&filters[1], LdapFilter::Equality(attr, val) 
                    if attr == "cn" && val == "test"));
            }
            _ => panic!("Expected AND filter"),
        }
    }

    #[test]
    fn test_extract_username() {
        assert_eq!(extract_username("user@example.com"), "user");
        assert_eq!(extract_username("user"), "user");
        assert_eq!(extract_username("user@domain@weird"), "user");
    }
}