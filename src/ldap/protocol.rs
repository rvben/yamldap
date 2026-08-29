use std::collections::HashMap;
use std::fmt;

use super::filters::LdapFilter;

pub type LdapMessageId = u32;

#[derive(Debug, Clone, PartialEq)]
pub struct LdapRequestMessage {
    pub message_id: LdapMessageId,
    pub protocol_op: LdapRequest,
}

#[derive(Debug, Clone, PartialEq)]
// These names intentionally mirror the LDAP ASN.1 protocol operation names.
#[allow(clippy::enum_variant_names)]
pub enum LdapRequest {
    BindRequest {
        version: u8,
        dn: String,
        authentication: BindAuthentication,
    },
    UnbindRequest,
    SearchRequest {
        base_dn: String,
        scope: SearchScope,
        deref_aliases: DerefAliases,
        size_limit: u32,
        time_limit: u32,
        types_only: bool,
        filter: LdapFilter,
        attributes: Vec<String>,
    },
    CompareRequest {
        dn: String,
        attribute: String,
        value: String,
    },
    AbandonRequest {
        message_id: LdapMessageId,
    },
    ExtendedRequest {
        name: String,
        value: Option<Vec<u8>>,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub struct LdapResponseMessage {
    pub message_id: LdapMessageId,
    pub protocol_op: LdapResponse,
}

#[derive(Debug, Clone, PartialEq)]
// These names intentionally mirror the LDAP ASN.1 protocol operation names.
#[allow(clippy::enum_variant_names)]
pub enum LdapResponse {
    BindResponse {
        result: LdapResult,
    },
    SearchResultEntry {
        dn: String,
        attributes: HashMap<String, Vec<String>>,
    },
    SearchResultDone {
        result: LdapResult,
    },
    CompareResponse {
        result: LdapResult,
    },
    ExtendedResponse {
        result: LdapResult,
        name: Option<String>,   // OID
        value: Option<Vec<u8>>, // Optional value
    },
}

#[derive(Clone, PartialEq)]
pub enum BindAuthentication {
    Simple(String), // password
    Anonymous,
    Sasl {
        mechanism: String,
        credentials: Option<Vec<u8>>,
    },
    Sicily {
        tag: u8,
        credentials: Vec<u8>,
    },
}

impl fmt::Debug for BindAuthentication {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Simple(_) => formatter
                .debug_tuple("Simple")
                .field(&"<redacted>")
                .finish(),
            Self::Anonymous => formatter.write_str("Anonymous"),
            Self::Sasl {
                mechanism,
                credentials,
            } => formatter
                .debug_struct("Sasl")
                .field("mechanism", mechanism)
                .field("credentials", &credentials.as_ref().map(|_| "<redacted>"))
                .finish(),
            Self::Sicily {
                tag,
                credentials: _,
            } => formatter
                .debug_struct("Sicily")
                .field("tag", &format_args!("0x{tag:02x}"))
                .field("credentials", &"<redacted>")
                .finish(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SearchScope {
    BaseObject = 0,
    SingleLevel = 1,
    WholeSubtree = 2,
}

#[derive(Debug, Clone, Copy, PartialEq)]
// These names intentionally mirror RFC 4511's derefAliases enumeration.
#[allow(clippy::enum_variant_names)]
pub enum DerefAliases {
    NeverDerefAliases = 0,
    DerefInSearching = 1,
    DerefFindingBaseObj = 2,
    DerefAlways = 3,
}

#[derive(Debug, Clone, PartialEq)]
pub struct LdapResult {
    pub result_code: LdapResultCode,
    pub matched_dn: String,
    pub diagnostic_message: String,
}

#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u8)]
// Keep the complete LDAP result-code vocabulary available for protocol work.
#[allow(dead_code)]
pub enum LdapResultCode {
    Success = 0,
    OperationsError = 1,
    ProtocolError = 2,
    TimeLimitExceeded = 3,
    SizeLimitExceeded = 4,
    CompareFalse = 5,
    CompareTrue = 6,
    AuthMethodNotSupported = 7,
    StrongerAuthRequired = 8,
    NoSuchAttribute = 16,
    UndefinedAttributeType = 17,
    InappropriateMatching = 18,
    ConstraintViolation = 19,
    AttributeOrValueExists = 20,
    InvalidAttributeSyntax = 21,
    NoSuchObject = 32,
    AliasProblem = 33,
    InvalidDNSyntax = 34,
    InvalidCredentials = 49,
    InsufficientAccessRights = 50,
    Busy = 51,
    Unavailable = 52,
    UnwillingToPerform = 53,
    LoopDetect = 54,
    NamingViolation = 64,
    ObjectClassViolation = 65,
    NotAllowedOnNonLeaf = 66,
    NotAllowedOnRDN = 67,
    EntryAlreadyExists = 68,
    ObjectClassModsProhibited = 69,
    Other = 80,
}

impl LdapResult {
    pub fn success() -> Self {
        Self {
            result_code: LdapResultCode::Success,
            matched_dn: String::new(),
            diagnostic_message: String::new(),
        }
    }

    pub fn error(code: LdapResultCode, message: String) -> Self {
        Self {
            result_code: code,
            matched_dn: String::new(),
            diagnostic_message: message,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ldap_result_success() {
        let result = LdapResult::success();
        assert_eq!(result.result_code, LdapResultCode::Success);
        assert_eq!(result.matched_dn, "");
        assert_eq!(result.diagnostic_message, "");
    }

    #[test]
    fn test_ldap_result_error() {
        let result = LdapResult::error(
            LdapResultCode::InvalidDNSyntax,
            "Invalid DN format".to_string(),
        );
        assert_eq!(result.result_code, LdapResultCode::InvalidDNSyntax);
        assert_eq!(result.matched_dn, "");
        assert_eq!(result.diagnostic_message, "Invalid DN format");
    }

    #[test]
    fn test_search_scope_values() {
        assert_eq!(SearchScope::BaseObject as u8, 0);
        assert_eq!(SearchScope::SingleLevel as u8, 1);
        assert_eq!(SearchScope::WholeSubtree as u8, 2);
    }

    #[test]
    fn test_deref_aliases_values() {
        assert_eq!(DerefAliases::NeverDerefAliases as u8, 0);
        assert_eq!(DerefAliases::DerefInSearching as u8, 1);
        assert_eq!(DerefAliases::DerefFindingBaseObj as u8, 2);
        assert_eq!(DerefAliases::DerefAlways as u8, 3);
    }

    #[test]
    fn test_ldap_result_code_values() {
        assert_eq!(LdapResultCode::Success as u8, 0);
        assert_eq!(LdapResultCode::OperationsError as u8, 1);
        assert_eq!(LdapResultCode::ProtocolError as u8, 2);
        assert_eq!(LdapResultCode::CompareFalse as u8, 5);
        assert_eq!(LdapResultCode::CompareTrue as u8, 6);
        assert_eq!(LdapResultCode::NoSuchAttribute as u8, 16);
        assert_eq!(LdapResultCode::NoSuchObject as u8, 32);
        assert_eq!(LdapResultCode::InvalidDNSyntax as u8, 34);
        assert_eq!(LdapResultCode::InvalidCredentials as u8, 49);
        assert_eq!(LdapResultCode::InsufficientAccessRights as u8, 50);
        assert_eq!(LdapResultCode::Other as u8, 80);
    }

    #[test]
    fn test_bind_authentication_variants() {
        let simple = BindAuthentication::Simple("password".to_string());
        match simple {
            BindAuthentication::Simple(pwd) => assert_eq!(pwd, "password"),
            _ => panic!("Expected Simple authentication"),
        }

        let anon = BindAuthentication::Anonymous;
        match anon {
            BindAuthentication::Anonymous => {}
            _ => panic!("Expected Anonymous authentication"),
        }

        let sasl = BindAuthentication::Sasl {
            mechanism: "GSS-SPNEGO".to_string(),
            credentials: Some(vec![1, 2, 3]),
        };
        match sasl {
            BindAuthentication::Sasl {
                mechanism,
                credentials,
            } => {
                assert_eq!(mechanism, "GSS-SPNEGO");
                assert_eq!(credentials, Some(vec![1, 2, 3]));
            }
            _ => panic!("Expected SASL authentication"),
        }

        let sicily = BindAuthentication::Sicily {
            tag: 0x8a,
            credentials: vec![1, 2, 3],
        };
        match sicily {
            BindAuthentication::Sicily { tag, credentials } => {
                assert_eq!(tag, 0x8a);
                assert_eq!(credentials, vec![1, 2, 3]);
            }
            _ => panic!("Expected Sicily authentication"),
        }
    }

    #[test]
    fn test_bind_authentication_debug_redacts_credentials() {
        let simple = BindAuthentication::Simple("simple-secret".to_string());
        let sasl = BindAuthentication::Sasl {
            mechanism: "GSS-SPNEGO".to_string(),
            credentials: Some(b"sasl-secret".to_vec()),
        };
        let sicily = BindAuthentication::Sicily {
            tag: 0x8a,
            credentials: b"sicily-secret".to_vec(),
        };

        let simple_debug = format!("{simple:?}");
        let sasl_debug = format!("{sasl:?}");
        let sicily_debug = format!("{sicily:?}");

        assert!(!simple_debug.contains("simple-secret"));
        assert!(simple_debug.contains("<redacted>"));
        assert!(!sasl_debug.contains("sasl-secret"));
        assert!(sasl_debug.contains("GSS-SPNEGO"));
        assert!(sasl_debug.contains("<redacted>"));
        assert!(!sicily_debug.contains("sicily-secret"));
        assert!(sicily_debug.contains("0x8a"));
        assert!(sicily_debug.contains("<redacted>"));
    }

    #[test]
    fn test_ldap_message_structure() {
        let msg = LdapRequestMessage {
            message_id: 42,
            protocol_op: LdapRequest::UnbindRequest,
        };
        assert_eq!(msg.message_id, 42);
        match msg.protocol_op {
            LdapRequest::UnbindRequest => {}
            _ => panic!("Expected UnbindRequest"),
        }
    }

    #[test]
    fn test_ldap_protocol_op_bind_request() {
        let op = LdapRequest::BindRequest {
            version: 3,
            dn: "cn=admin,dc=example,dc=com".to_string(),
            authentication: BindAuthentication::Simple("secret".to_string()),
        };

        match op {
            LdapRequest::BindRequest {
                version,
                dn,
                authentication,
            } => {
                assert_eq!(version, 3);
                assert_eq!(dn, "cn=admin,dc=example,dc=com");
                match authentication {
                    BindAuthentication::Simple(pwd) => assert_eq!(pwd, "secret"),
                    _ => panic!("Expected Simple authentication"),
                }
            }
            _ => panic!("Expected BindRequest"),
        }
    }

    #[test]
    fn test_ldap_protocol_op_search_request() {
        let op = LdapRequest::SearchRequest {
            base_dn: "dc=example,dc=com".to_string(),
            scope: SearchScope::WholeSubtree,
            deref_aliases: DerefAliases::NeverDerefAliases,
            size_limit: 100,
            time_limit: 60,
            types_only: false,
            filter: LdapFilter::Present("objectClass".to_string()),
            attributes: vec!["cn".to_string(), "mail".to_string()],
        };

        match op {
            LdapRequest::SearchRequest {
                base_dn,
                scope,
                deref_aliases,
                size_limit,
                time_limit,
                types_only,
                filter,
                attributes,
            } => {
                assert_eq!(base_dn, "dc=example,dc=com");
                assert_eq!(scope, SearchScope::WholeSubtree);
                assert_eq!(deref_aliases, DerefAliases::NeverDerefAliases);
                assert_eq!(size_limit, 100);
                assert_eq!(time_limit, 60);
                assert!(!types_only);
                assert_eq!(filter, LdapFilter::Present("objectClass".to_string()));
                assert_eq!(attributes, vec!["cn", "mail"]);
            }
            _ => panic!("Expected SearchRequest"),
        }
    }

    #[test]
    fn test_ldap_protocol_op_search_result_entry() {
        let mut attrs = HashMap::new();
        attrs.insert("cn".to_string(), vec!["John Doe".to_string()]);
        attrs.insert("mail".to_string(), vec!["john@example.com".to_string()]);

        let op = LdapResponse::SearchResultEntry {
            dn: "cn=John Doe,dc=example,dc=com".to_string(),
            attributes: attrs.clone(),
        };

        match op {
            LdapResponse::SearchResultEntry { dn, attributes } => {
                assert_eq!(dn, "cn=John Doe,dc=example,dc=com");
                assert_eq!(attributes, attrs);
            }
            _ => panic!("Expected SearchResultEntry"),
        }
    }

    #[test]
    fn test_ldap_protocol_op_compare_request() {
        let op = LdapRequest::CompareRequest {
            dn: "cn=user,dc=example,dc=com".to_string(),
            attribute: "userPassword".to_string(),
            value: "secret".to_string(),
        };

        match op {
            LdapRequest::CompareRequest {
                dn,
                attribute,
                value,
            } => {
                assert_eq!(dn, "cn=user,dc=example,dc=com");
                assert_eq!(attribute, "userPassword");
                assert_eq!(value, "secret");
            }
            _ => panic!("Expected CompareRequest"),
        }
    }

    #[test]
    fn test_equality_traits() {
        let result1 = LdapResult::success();
        let result2 = LdapResult::success();
        assert_eq!(result1, result2);

        let result3 = LdapResult::error(LdapResultCode::NoSuchObject, "Not found".to_string());
        assert_ne!(result1, result3);

        let msg1 = LdapRequestMessage {
            message_id: 1,
            protocol_op: LdapRequest::UnbindRequest,
        };
        let msg2 = LdapRequestMessage {
            message_id: 1,
            protocol_op: LdapRequest::UnbindRequest,
        };
        assert_eq!(msg1, msg2);
    }

    #[test]
    fn test_clone_traits() {
        let result = LdapResult::success();
        let result_clone = result.clone();
        assert_eq!(result, result_clone);

        let msg = LdapResponseMessage {
            message_id: 42,
            protocol_op: LdapResponse::BindResponse {
                result: LdapResult::success(),
            },
        };
        let msg_clone = msg.clone();
        assert_eq!(msg, msg_clone);
    }
}
