use super::bind::handle_bind_request;
use super::filters::parse_ldap_filter;
use super::protocol::*;
use crate::directory::{storage::SearchScope as DirSearchScope, AuthHandler, Directory};
use std::collections::HashMap;

#[derive(Debug)]
pub enum LdapOperation {
    Bind {
        version: u8,
        dn: String,
        auth: BindAuthentication,
    },
    Unbind,
    Search {
        base_dn: String,
        scope: SearchScope,
        filter: String,
        attributes: Vec<String>,
    },
    Compare {
        dn: String,
        attribute: String,
        value: String,
    },
    Abandon {
        message_id: LdapMessageId,
    },
    Extended {
        name: String,
        value: Option<Vec<u8>>,
    },
}

pub fn handle_operation(
    message_id: LdapMessageId,
    operation: LdapOperation,
    directory: &Directory,
    auth_handler: &AuthHandler,
    _is_authenticated: bool,
) -> Vec<LdapMessage> {
    match operation {
        LdapOperation::Bind {
            version: _,
            dn,
            auth,
        } => {
            vec![handle_bind_request(
                message_id,
                dn,
                auth,
                directory,
                auth_handler,
            )]
        }

        LdapOperation::Unbind => {
            // No response for unbind
            vec![]
        }

        LdapOperation::Search {
            base_dn,
            scope,
            filter,
            attributes,
        } => {
            let mut responses = Vec::new();

            // Parse the filter
            let ldap_filter = match parse_ldap_filter(&filter) {
                Ok(f) => f,
                Err(e) => {
                    responses.push(LdapMessage {
                        message_id,
                        protocol_op: LdapProtocolOp::SearchResultDone {
                            result: LdapResult::error(
                                LdapResultCode::ProtocolError,
                                format!("Invalid filter: {}", e),
                            ),
                        },
                    });
                    return responses;
                }
            };

            // Convert scope
            let dir_scope = match scope {
                SearchScope::BaseObject => DirSearchScope::BaseObject,
                SearchScope::SingleLevel => DirSearchScope::SingleLevel,
                SearchScope::WholeSubtree => DirSearchScope::WholeSubtree,
            };

            // Perform search
            let entries =
                directory.search_entries(&base_dn, dir_scope, |entry| ldap_filter.matches(entry));

            // Return search results
            for entry in entries {
                let mut attrs = HashMap::new();

                // If specific attributes requested, filter them
                let attr_names: Vec<String> = if attributes.is_empty() {
                    entry.attributes.keys().cloned().collect()
                } else {
                    attributes.clone()
                };

                for attr_name in attr_names {
                    if let Some(attr) = entry.get_attribute(&attr_name) {
                        let values: Vec<String> =
                            attr.values.iter().map(|v| v.as_string()).collect();
                        attrs.insert(attr.name.clone(), values);
                    }
                }

                responses.push(LdapMessage {
                    message_id,
                    protocol_op: LdapProtocolOp::SearchResultEntry {
                        dn: entry.dn.clone(),
                        attributes: attrs,
                    },
                });
            }

            // Send SearchResultDone
            responses.push(LdapMessage {
                message_id,
                protocol_op: LdapProtocolOp::SearchResultDone {
                    result: LdapResult::success(),
                },
            });

            responses
        }

        LdapOperation::Compare {
            dn,
            attribute,
            value,
        } => {
            let result = if let Some(entry) = directory.get_entry(&dn) {
                if let Some(attr) = entry.get_attribute(&attribute) {
                    let matches = attr
                        .values
                        .iter()
                        .any(|v| v.as_string().eq_ignore_ascii_case(&value));

                    if matches {
                        LdapResult {
                            result_code: LdapResultCode::CompareTrue,
                            matched_dn: dn,
                            diagnostic_message: String::new(),
                        }
                    } else {
                        LdapResult {
                            result_code: LdapResultCode::CompareFalse,
                            matched_dn: dn,
                            diagnostic_message: String::new(),
                        }
                    }
                } else {
                    LdapResult::error(
                        LdapResultCode::NoSuchAttribute,
                        format!("Attribute {} not found", attribute),
                    )
                }
            } else {
                LdapResult::error(
                    LdapResultCode::NoSuchObject,
                    format!("Entry {} not found", dn),
                )
            };

            vec![LdapMessage {
                message_id,
                protocol_op: LdapProtocolOp::CompareResponse { result },
            }]
        }

        LdapOperation::Abandon {
            message_id: abandon_id,
        } => {
            // According to RFC 4511, there is no response to an abandon operation
            // Just log it and return empty response
            tracing::debug!("Received abandon request for message ID: {}", abandon_id);
            // Return empty vector - no response is sent for abandon
            vec![]
        }

        LdapOperation::Extended { name, value: _ } => {
            // Handle Extended operations
            tracing::debug!("Received extended request with OID: {}", name);

            // StartTLS OID: 1.3.6.1.4.1.1466.20037
            const START_TLS_OID: &str = "1.3.6.1.4.1.1466.20037";

            let result = if name == START_TLS_OID {
                // For now, we don't support StartTLS - return unavailable
                LdapResult::error(
                    LdapResultCode::Unavailable,
                    "StartTLS is not supported in this implementation".to_string(),
                )
            } else {
                // Unknown extended operation
                LdapResult::error(
                    LdapResultCode::UnwillingToPerform,
                    format!("Unsupported extended operation: {}", name),
                )
            };

            vec![LdapMessage {
                message_id,
                protocol_op: LdapProtocolOp::ExtendedResponse {
                    result,
                    name: Some(name),
                    value: None,
                },
            }]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::directory::entry::{AttributeSyntax, AttributeValue, LdapEntry};

    fn create_test_directory() -> Directory {
        let schema = crate::yaml::YamlSchema::default();
        let directory = Directory::new("dc=example,dc=com".to_string(), schema);

        // Add test users
        let mut user1 = LdapEntry::new("cn=user1,ou=users,dc=example,dc=com".to_string());
        user1.add_attribute(
            "cn".to_string(),
            vec![AttributeValue::String("user1".to_string())],
            AttributeSyntax::String,
        );
        user1.add_attribute(
            "uid".to_string(),
            vec![AttributeValue::String("user1".to_string())],
            AttributeSyntax::String,
        );
        user1.add_attribute(
            "userPassword".to_string(),
            vec![AttributeValue::String("password1".to_string())],
            AttributeSyntax::String,
        );
        user1.add_attribute(
            "mail".to_string(),
            vec![AttributeValue::String("user1@example.com".to_string())],
            AttributeSyntax::String,
        );
        user1.object_classes = vec!["person".to_string(), "top".to_string()];
        user1.add_attribute(
            "objectClass".to_string(),
            vec![
                AttributeValue::String("person".to_string()),
                AttributeValue::String("top".to_string()),
            ],
            AttributeSyntax::String,
        );
        directory.add_entry(user1);

        let mut user2 = LdapEntry::new("cn=user2,ou=users,dc=example,dc=com".to_string());
        user2.add_attribute(
            "cn".to_string(),
            vec![AttributeValue::String("user2".to_string())],
            AttributeSyntax::String,
        );
        user2.add_attribute(
            "uid".to_string(),
            vec![AttributeValue::String("user2".to_string())],
            AttributeSyntax::String,
        );
        user2.object_classes = vec!["person".to_string()];
        user2.add_attribute(
            "objectClass".to_string(),
            vec![AttributeValue::String("person".to_string())],
            AttributeSyntax::String,
        );
        directory.add_entry(user2);

        // Add OU entry
        let mut ou = LdapEntry::new("ou=users,dc=example,dc=com".to_string());
        ou.add_attribute(
            "ou".to_string(),
            vec![AttributeValue::String("users".to_string())],
            AttributeSyntax::String,
        );
        ou.object_classes = vec!["organizationalUnit".to_string()];
        ou.add_attribute(
            "objectClass".to_string(),
            vec![AttributeValue::String("organizationalUnit".to_string())],
            AttributeSyntax::String,
        );
        directory.add_entry(ou);

        // Add base DN entry
        let mut base = LdapEntry::new("dc=example,dc=com".to_string());
        base.object_classes = vec!["top".to_string(), "domain".to_string()];
        base.add_attribute(
            "objectClass".to_string(),
            vec![
                AttributeValue::String("top".to_string()),
                AttributeValue::String("domain".to_string()),
            ],
            AttributeSyntax::String,
        );
        base.add_attribute(
            "dc".to_string(),
            vec![AttributeValue::String("example".to_string())],
            AttributeSyntax::String,
        );
        directory.add_entry(base);

        directory
    }

    #[test]
    fn test_handle_bind_operation() {
        let directory = create_test_directory();
        let auth_handler = AuthHandler::new(false);

        let operation = LdapOperation::Bind {
            version: 3,
            dn: "cn=user1,ou=users,dc=example,dc=com".to_string(),
            auth: BindAuthentication::Simple("password1".to_string()),
        };

        let responses = handle_operation(1, operation, &directory, &auth_handler, false);

        assert_eq!(responses.len(), 1);
        match &responses[0].protocol_op {
            LdapProtocolOp::BindResponse { result } => {
                assert_eq!(result.result_code, LdapResultCode::Success);
            }
            _ => panic!("Expected BindResponse"),
        }
    }

    #[test]
    fn test_handle_unbind_operation() {
        let directory = create_test_directory();
        let auth_handler = AuthHandler::new(false);

        let operation = LdapOperation::Unbind;

        let responses = handle_operation(1, operation, &directory, &auth_handler, true);

        // Unbind should return no responses
        assert_eq!(responses.len(), 0);
    }

    #[test]
    fn test_handle_search_operation_base_scope() {
        let directory = create_test_directory();
        let auth_handler = AuthHandler::new(false);

        let operation = LdapOperation::Search {
            base_dn: "cn=user1,ou=users,dc=example,dc=com".to_string(),
            scope: SearchScope::BaseObject,
            filter: "(objectClass=*)".to_string(),
            attributes: vec![],
        };

        let responses = handle_operation(1, operation, &directory, &auth_handler, true);

        // Should have 2 responses: 1 entry + done
        assert_eq!(responses.len(), 2);

        match &responses[0].protocol_op {
            LdapProtocolOp::SearchResultEntry { dn, attributes } => {
                assert_eq!(dn, "cn=user1,ou=users,dc=example,dc=com");
                assert!(attributes.contains_key("cn"));
                assert!(attributes.contains_key("uid"));
                assert!(attributes.contains_key("mail"));
            }
            _ => panic!("Expected SearchResultEntry"),
        }

        match &responses[1].protocol_op {
            LdapProtocolOp::SearchResultDone { result } => {
                assert_eq!(result.result_code, LdapResultCode::Success);
            }
            _ => panic!("Expected SearchResultDone"),
        }
    }

    #[test]
    fn test_handle_search_operation_single_level() {
        let directory = create_test_directory();
        let auth_handler = AuthHandler::new(false);

        let operation = LdapOperation::Search {
            base_dn: "ou=users,dc=example,dc=com".to_string(),
            scope: SearchScope::SingleLevel,
            filter: "(objectClass=person)".to_string(),
            attributes: vec!["cn".to_string(), "uid".to_string()],
        };

        let responses = handle_operation(1, operation, &directory, &auth_handler, true);

        // Should have 3 responses: 2 entries + done
        assert_eq!(responses.len(), 3);

        // Check that we got both users
        let entry_dns: Vec<&str> = responses[0..2]
            .iter()
            .filter_map(|r| match &r.protocol_op {
                LdapProtocolOp::SearchResultEntry { dn, .. } => Some(dn.as_str()),
                _ => None,
            })
            .collect();

        assert!(entry_dns.contains(&"cn=user1,ou=users,dc=example,dc=com"));
        assert!(entry_dns.contains(&"cn=user2,ou=users,dc=example,dc=com"));

        // Check that only requested attributes are returned
        match &responses[0].protocol_op {
            LdapProtocolOp::SearchResultEntry { attributes, .. } => {
                assert!(attributes.contains_key("cn"));
                assert!(attributes.contains_key("uid"));
                assert!(!attributes.contains_key("mail")); // Not requested
            }
            _ => panic!("Expected SearchResultEntry"),
        }
    }

    #[test]
    fn test_handle_search_operation_subtree() {
        let directory = create_test_directory();
        let auth_handler = AuthHandler::new(false);

        let operation = LdapOperation::Search {
            base_dn: "dc=example,dc=com".to_string(),
            scope: SearchScope::WholeSubtree,
            filter: "(objectClass=*)".to_string(), // Get all entries
            attributes: vec![],
        };

        let responses = handle_operation(1, operation, &directory, &auth_handler, true);

        // Should have 5 responses: 4 entries (2 users + 1 OU + 1 base) + done
        assert_eq!(responses.len(), 5);

        match &responses[4].protocol_op {
            LdapProtocolOp::SearchResultDone { result } => {
                assert_eq!(result.result_code, LdapResultCode::Success);
            }
            _ => panic!("Expected SearchResultDone"),
        }
    }

    #[test]
    fn test_handle_search_operation_invalid_filter() {
        let directory = create_test_directory();
        let auth_handler = AuthHandler::new(false);

        let operation = LdapOperation::Search {
            base_dn: "dc=example,dc=com".to_string(),
            scope: SearchScope::BaseObject,
            filter: "invalid filter".to_string(), // No parentheses at all
            attributes: vec![],
        };

        let responses = handle_operation(1, operation, &directory, &auth_handler, true);

        assert_eq!(responses.len(), 1);
        match &responses[0].protocol_op {
            LdapProtocolOp::SearchResultDone { result } => {
                assert_eq!(result.result_code, LdapResultCode::ProtocolError);
                assert!(result.diagnostic_message.contains("Invalid filter"));
            }
            _ => panic!("Expected SearchResultDone with error"),
        }
    }

    #[test]
    fn test_handle_compare_operation_match() {
        let directory = create_test_directory();
        let auth_handler = AuthHandler::new(false);

        let operation = LdapOperation::Compare {
            dn: "cn=user1,ou=users,dc=example,dc=com".to_string(),
            attribute: "uid".to_string(),
            value: "user1".to_string(),
        };

        let responses = handle_operation(1, operation, &directory, &auth_handler, true);

        assert_eq!(responses.len(), 1);
        match &responses[0].protocol_op {
            LdapProtocolOp::CompareResponse { result } => {
                assert_eq!(result.result_code, LdapResultCode::CompareTrue);
            }
            _ => panic!("Expected CompareResponse"),
        }
    }

    #[test]
    fn test_handle_compare_operation_no_match() {
        let directory = create_test_directory();
        let auth_handler = AuthHandler::new(false);

        let operation = LdapOperation::Compare {
            dn: "cn=user1,ou=users,dc=example,dc=com".to_string(),
            attribute: "uid".to_string(),
            value: "user2".to_string(),
        };

        let responses = handle_operation(1, operation, &directory, &auth_handler, true);

        assert_eq!(responses.len(), 1);
        match &responses[0].protocol_op {
            LdapProtocolOp::CompareResponse { result } => {
                assert_eq!(result.result_code, LdapResultCode::CompareFalse);
            }
            _ => panic!("Expected CompareResponse"),
        }
    }

    #[test]
    fn test_handle_compare_operation_case_insensitive() {
        let directory = create_test_directory();
        let auth_handler = AuthHandler::new(false);

        let operation = LdapOperation::Compare {
            dn: "cn=user1,ou=users,dc=example,dc=com".to_string(),
            attribute: "mail".to_string(),
            value: "USER1@EXAMPLE.COM".to_string(), // Different case
        };

        let responses = handle_operation(1, operation, &directory, &auth_handler, true);

        assert_eq!(responses.len(), 1);
        match &responses[0].protocol_op {
            LdapProtocolOp::CompareResponse { result } => {
                assert_eq!(result.result_code, LdapResultCode::CompareTrue);
            }
            _ => panic!("Expected CompareResponse"),
        }
    }

    #[test]
    fn test_handle_compare_operation_no_such_attribute() {
        let directory = create_test_directory();
        let auth_handler = AuthHandler::new(false);

        let operation = LdapOperation::Compare {
            dn: "cn=user1,ou=users,dc=example,dc=com".to_string(),
            attribute: "nonexistent".to_string(),
            value: "value".to_string(),
        };

        let responses = handle_operation(1, operation, &directory, &auth_handler, true);

        assert_eq!(responses.len(), 1);
        match &responses[0].protocol_op {
            LdapProtocolOp::CompareResponse { result } => {
                assert_eq!(result.result_code, LdapResultCode::NoSuchAttribute);
                assert!(result
                    .diagnostic_message
                    .contains("Attribute nonexistent not found"));
            }
            _ => panic!("Expected CompareResponse"),
        }
    }

    #[test]
    fn test_handle_compare_operation_no_such_object() {
        let directory = create_test_directory();
        let auth_handler = AuthHandler::new(false);

        let operation = LdapOperation::Compare {
            dn: "cn=nonexistent,dc=example,dc=com".to_string(),
            attribute: "uid".to_string(),
            value: "value".to_string(),
        };

        let responses = handle_operation(1, operation, &directory, &auth_handler, true);

        assert_eq!(responses.len(), 1);
        match &responses[0].protocol_op {
            LdapProtocolOp::CompareResponse { result } => {
                assert_eq!(result.result_code, LdapResultCode::NoSuchObject);
                assert!(result
                    .diagnostic_message
                    .contains("Entry cn=nonexistent,dc=example,dc=com not found"));
            }
            _ => panic!("Expected CompareResponse"),
        }
    }

    #[test]
    fn test_message_id_preserved() {
        let directory = create_test_directory();
        let auth_handler = AuthHandler::new(false);

        let message_id = 42;
        let operation = LdapOperation::Search {
            base_dn: "dc=example,dc=com".to_string(),
            scope: SearchScope::BaseObject,
            filter: "(objectClass=*)".to_string(),
            attributes: vec![],
        };

        let responses = handle_operation(message_id, operation, &directory, &auth_handler, true);

        // All responses should have the same message ID
        for response in responses {
            assert_eq!(response.message_id, message_id);
        }
    }

    #[test]
    fn test_search_with_specific_filter() {
        let directory = create_test_directory();
        let auth_handler = AuthHandler::new(false);

        let operation = LdapOperation::Search {
            base_dn: "dc=example,dc=com".to_string(),
            scope: SearchScope::WholeSubtree,
            filter: "(uid=user1)".to_string(), // Simple filter since complex ones aren't parsed
            attributes: vec![],
        };

        let responses = handle_operation(1, operation, &directory, &auth_handler, true);

        // Should find only user1
        assert_eq!(responses.len(), 2); // 1 entry + done

        match &responses[0].protocol_op {
            LdapProtocolOp::SearchResultEntry { dn, .. } => {
                assert_eq!(dn, "cn=user1,ou=users,dc=example,dc=com");
            }
            _ => panic!("Expected SearchResultEntry"),
        }
    }

    #[test]
    fn test_search_preserves_dn_case() {
        let schema = crate::yaml::YamlSchema::default();
        let directory = Directory::new("dc=test,dc=com".to_string(), schema);

        // Add entry with uppercase components
        let mut entry = LdapEntry::new("cn=User,ou=NXP,dc=Test,dc=Com".to_string());
        entry.add_attribute(
            "objectClass".to_string(),
            vec![AttributeValue::String("person".to_string())],
            AttributeSyntax::String,
        );
        entry.add_attribute(
            "cn".to_string(),
            vec![AttributeValue::String("User".to_string())],
            AttributeSyntax::String,
        );
        directory.add_entry(entry);

        let auth_handler = AuthHandler::new(false);
        let operation = LdapOperation::Search {
            base_dn: "dc=test,dc=com".to_string(), // lowercase search
            scope: SearchScope::WholeSubtree,
            filter: "(cn=user)".to_string(), // lowercase filter
            attributes: vec![],
        };

        let responses = handle_operation(1, operation, &directory, &auth_handler, false);

        // Should find 2 responses: SearchResultEntry and SearchResultDone
        assert_eq!(responses.len(), 2);

        // Check that DN case is preserved
        match &responses[0].protocol_op {
            LdapProtocolOp::SearchResultEntry { dn, .. } => {
                assert_eq!(dn, "cn=User,ou=NXP,dc=Test,dc=Com"); // Original case preserved
            }
            _ => panic!("Expected SearchResultEntry"),
        }
    }

    #[test]
    fn test_search_returns_only_matching_entries() {
        let directory = create_test_directory();
        let auth_handler = AuthHandler::new(false);

        // Test 1: Search for specific uid - should return only that user
        let operation = LdapOperation::Search {
            base_dn: "ou=users,dc=example,dc=com".to_string(),
            scope: SearchScope::WholeSubtree,
            filter: "(uid=user1)".to_string(),
            attributes: vec!["uid".to_string(), "cn".to_string()],
        };

        let responses = handle_operation(1, operation, &directory, &auth_handler, true);

        // Count actual entries (exclude SearchResultDone)
        let entry_count = responses
            .iter()
            .filter(|r| matches!(r.protocol_op, LdapProtocolOp::SearchResultEntry { .. }))
            .count();

        assert_eq!(
            entry_count, 1,
            "Should return exactly 1 user with uid=user1"
        );

        // Verify it's the right user
        match &responses[0].protocol_op {
            LdapProtocolOp::SearchResultEntry { dn, attributes } => {
                assert_eq!(dn, "cn=user1,ou=users,dc=example,dc=com");
                assert!(attributes.contains_key("uid"));
                assert_eq!(attributes.get("uid").unwrap()[0], "user1");
            }
            _ => panic!("Expected SearchResultEntry"),
        }
    }

    #[test]
    fn test_search_base_scope_returns_only_base() {
        let directory = create_test_directory();
        let auth_handler = AuthHandler::new(false);

        // Search with BASE scope should return only the specified DN
        let operation = LdapOperation::Search {
            base_dn: "cn=user1,ou=users,dc=example,dc=com".to_string(),
            scope: SearchScope::BaseObject,
            filter: "(objectClass=*)".to_string(),
            attributes: vec![],
        };

        let responses = handle_operation(1, operation, &directory, &auth_handler, true);

        let entry_count = responses
            .iter()
            .filter(|r| matches!(r.protocol_op, LdapProtocolOp::SearchResultEntry { .. }))
            .count();

        assert_eq!(entry_count, 1, "BASE scope should return exactly 1 entry");

        match &responses[0].protocol_op {
            LdapProtocolOp::SearchResultEntry { dn, .. } => {
                assert_eq!(
                    dn, "cn=user1,ou=users,dc=example,dc=com",
                    "BASE scope should return only the base DN"
                );
            }
            _ => panic!("Expected SearchResultEntry"),
        }
    }

    #[test]
    fn test_search_returns_empty_for_no_matches() {
        let directory = create_test_directory();
        let auth_handler = AuthHandler::new(false);

        // Search for non-existent uid
        let operation = LdapOperation::Search {
            base_dn: "dc=example,dc=com".to_string(),
            scope: SearchScope::WholeSubtree,
            filter: "(uid=nonexistent)".to_string(),
            attributes: vec![],
        };

        let responses = handle_operation(1, operation, &directory, &auth_handler, true);

        assert_eq!(responses.len(), 1, "Should only have SearchResultDone");

        match &responses[0].protocol_op {
            LdapProtocolOp::SearchResultDone { result } => {
                assert_eq!(result.result_code, LdapResultCode::Success);
            }
            _ => panic!("Expected only SearchResultDone"),
        }
    }

    #[test]
    fn test_search_onelevel_scope() {
        let directory = create_test_directory();
        let auth_handler = AuthHandler::new(false);

        // Search with ONELEVEL scope from dc=example,dc=com
        let operation = LdapOperation::Search {
            base_dn: "dc=example,dc=com".to_string(),
            scope: SearchScope::SingleLevel,
            filter: "(objectClass=*)".to_string(),
            attributes: vec!["ou".to_string()],
        };

        let responses = handle_operation(1, operation, &directory, &auth_handler, true);

        let entries: Vec<&str> = responses
            .iter()
            .filter_map(|r| match &r.protocol_op {
                LdapProtocolOp::SearchResultEntry { dn, .. } => Some(dn.as_str()),
                _ => None,
            })
            .collect();

        assert_eq!(entries.len(), 1, "ONELEVEL from base should find 1 OU");
        assert_eq!(entries[0], "ou=users,dc=example,dc=com");
    }

    #[test]
    fn test_search_and_filter() {
        let directory = create_test_directory();
        let auth_handler = AuthHandler::new(false);

        // Test AND filter: (&(objectClass=person)(uid=user1))
        let operation = LdapOperation::Search {
            base_dn: "dc=example,dc=com".to_string(),
            scope: SearchScope::WholeSubtree,
            filter: "(&(objectClass=person)(uid=user1))".to_string(),
            attributes: vec![],
        };

        let responses = handle_operation(1, operation, &directory, &auth_handler, true);

        let entries: Vec<&str> = responses
            .iter()
            .filter_map(|r| match &r.protocol_op {
                LdapProtocolOp::SearchResultEntry { dn, .. } => Some(dn.as_str()),
                _ => None,
            })
            .collect();

        // Should find only user1 (not user2, and not non-person entries)
        assert_eq!(entries.len(), 1, "AND filter should return exactly 1 match");
        assert_eq!(entries[0], "cn=user1,ou=users,dc=example,dc=com");
    }

    #[test]
    fn test_abandon_operation() {
        let directory = create_test_directory();
        let auth_handler = AuthHandler::new(false);

        // Test abandon operation - it should return no responses
        let operation = LdapOperation::Abandon { message_id: 5 };

        let responses = handle_operation(1, operation, &directory, &auth_handler, true);

        // Abandon operation should return empty response (no response is sent)
        assert_eq!(
            responses.len(),
            0,
            "Abandon operation should return no response"
        );
    }

    #[test]
    fn test_extended_operation_start_tls() {
        let directory = create_test_directory();
        let auth_handler = AuthHandler::new(false);

        // Test StartTLS extended operation
        let operation = LdapOperation::Extended {
            name: "1.3.6.1.4.1.1466.20037".to_string(),
            value: None,
        };

        let responses = handle_operation(1, operation, &directory, &auth_handler, true);

        assert_eq!(
            responses.len(),
            1,
            "Extended operation should return one response"
        );

        match &responses[0].protocol_op {
            LdapProtocolOp::ExtendedResponse {
                result,
                name,
                value,
            } => {
                assert_eq!(result.result_code, LdapResultCode::Unavailable);
                assert!(result
                    .diagnostic_message
                    .contains("StartTLS is not supported"));
                assert_eq!(name.as_ref().unwrap(), "1.3.6.1.4.1.1466.20037");
                assert!(value.is_none());
            }
            _ => panic!("Expected ExtendedResponse"),
        }
    }

    #[test]
    fn test_extended_operation_unknown() {
        let directory = create_test_directory();
        let auth_handler = AuthHandler::new(false);

        // Test unknown extended operation
        let operation = LdapOperation::Extended {
            name: "1.2.3.4.5".to_string(),
            value: Some(vec![0x01, 0x02, 0x03]),
        };

        let responses = handle_operation(1, operation, &directory, &auth_handler, true);

        assert_eq!(
            responses.len(),
            1,
            "Extended operation should return one response"
        );

        match &responses[0].protocol_op {
            LdapProtocolOp::ExtendedResponse {
                result,
                name,
                value,
            } => {
                assert_eq!(result.result_code, LdapResultCode::UnwillingToPerform);
                assert!(result
                    .diagnostic_message
                    .contains("Unsupported extended operation"));
                assert_eq!(name.as_ref().unwrap(), "1.2.3.4.5");
                assert!(value.is_none());
            }
            _ => panic!("Expected ExtendedResponse"),
        }
    }
}
