#[derive(Debug, Default)]
pub struct LdapSession {
    pub is_authenticated: bool,
    pub bound_dn: Option<String>,
    pub anonymous: bool,
}

impl LdapSession {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn bind(&mut self, dn: String) {
        self.is_authenticated = true;
        self.anonymous = dn.is_empty();
        self.bound_dn = if dn.is_empty() { None } else { Some(dn) };
    }

    pub fn unbind(&mut self) {
        self.is_authenticated = false;
        self.anonymous = false;
        self.bound_dn = None;
    }

    pub fn is_bound(&self) -> bool {
        self.is_authenticated
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_new() {
        let session = LdapSession::new();
        assert!(!session.is_authenticated);
        assert!(session.bound_dn.is_none());
        assert!(!session.anonymous);
        assert!(!session.is_bound());
    }

    #[test]
    fn test_session_bind_with_dn() {
        let mut session = LdapSession::new();
        session.bind("cn=admin,dc=example,dc=com".to_string());
        
        assert!(session.is_authenticated);
        assert_eq!(session.bound_dn, Some("cn=admin,dc=example,dc=com".to_string()));
        assert!(!session.anonymous);
        assert!(session.is_bound());
    }

    #[test]
    fn test_session_bind_anonymous() {
        let mut session = LdapSession::new();
        session.bind("".to_string());
        
        assert!(session.is_authenticated);
        assert!(session.bound_dn.is_none());
        assert!(session.anonymous);
        assert!(session.is_bound());
    }

    #[test]
    fn test_session_unbind() {
        let mut session = LdapSession::new();
        session.bind("cn=admin,dc=example,dc=com".to_string());
        
        // Verify bound state
        assert!(session.is_bound());
        
        // Unbind
        session.unbind();
        
        assert!(!session.is_authenticated);
        assert!(session.bound_dn.is_none());
        assert!(!session.anonymous);
        assert!(!session.is_bound());
    }

    #[test]
    fn test_session_rebind() {
        let mut session = LdapSession::new();
        
        // First bind
        session.bind("cn=user1,dc=example,dc=com".to_string());
        assert_eq!(session.bound_dn, Some("cn=user1,dc=example,dc=com".to_string()));
        
        // Rebind as different user
        session.bind("cn=user2,dc=example,dc=com".to_string());
        assert_eq!(session.bound_dn, Some("cn=user2,dc=example,dc=com".to_string()));
        assert!(session.is_authenticated);
        assert!(!session.anonymous);
    }

    #[test]
    fn test_session_default() {
        let session: LdapSession = Default::default();
        assert!(!session.is_authenticated);
        assert!(session.bound_dn.is_none());
        assert!(!session.anonymous);
    }
}
