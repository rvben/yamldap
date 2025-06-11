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
}

pub fn handle_operation(
    message_id: LdapMessageId,
    operation: LdapOperation,
    directory: &Directory,
    auth_handler: &AuthHandler,
    _is_authenticated: bool,
) -> Vec<LdapMessage> {
    match operation {
        LdapOperation::Bind { version: _, dn, auth } => {
            vec![handle_bind_request(message_id, dn, auth, directory, auth_handler)]
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
            let entries = directory.search_entries(&base_dn, dir_scope, |entry| {
                ldap_filter.matches(entry)
            });
            
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
                        let values: Vec<String> = attr.values.iter()
                            .map(|v| v.as_string())
                            .collect();
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
                    let matches = attr.values.iter().any(|v| {
                        v.as_string().eq_ignore_ascii_case(&value)
                    });
                    
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
    }
}