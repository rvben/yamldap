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