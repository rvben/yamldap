# yamldap

A lightweight LDAP server that serves directory data from YAML files, designed for local development and testing.

## Features

- 🚀 **Quick Setup** - Define your LDAP directory in a simple YAML file
- 🔐 **Authentication** - Support for multiple password formats (plain, SHA, SSHA, bcrypt)
- 🔍 **LDAP Operations** - Bind, search, and compare operations
- 🛠️ **Development Friendly** - Perfect for testing LDAP integrations locally
- 🐳 **Docker Support** - Run in containers with provided Dockerfile
- ⚡ **Lightweight** - Minimal resource usage, fast startup

## Installation

### From Source
```bash
cargo install --path .
```

### Using Docker
```bash
docker build -t yamldap .
docker run -p 389:389 -v $(pwd)/examples/sample_directory.yaml:/data/directory.yaml yamldap
```

### Using Docker Compose
```bash
docker-compose up
```

## Quick Start

1. Create a YAML file defining your directory:
```yaml
directory:
  base_dn: "dc=example,dc=com"

entries:
  - dn: "dc=example,dc=com"
    objectClass: ["top", "domain"]
    dc: "example"
    
  - dn: "ou=users,dc=example,dc=com"
    objectClass: ["top", "organizationalUnit"]
    ou: "users"
    
  - dn: "uid=john,ou=users,dc=example,dc=com"
    objectClass: ["top", "person", "inetOrgPerson"]
    uid: "john"
    cn: "John Doe"
    sn: "Doe"
    mail: "john@example.com"
    userPassword: "secret123"
```

2. Start the server:
```bash
# On a non-privileged port
yamldap -f directory.yaml --port 3389

# Or with Docker
docker run -p 389:389 -v $(pwd)/directory.yaml:/data/directory.yaml yamldap
```

3. Test with LDAP tools:
```bash
# Search all entries
ldapsearch -x -H ldap://localhost:3389 -b "dc=example,dc=com" "(objectClass=*)"

# Authenticate and search
ldapsearch -x -H ldap://localhost:3389 \
  -D "uid=john,ou=users,dc=example,dc=com" \
  -w secret123 \
  -b "dc=example,dc=com" "(uid=john)"
```

## Command Line Options

```
yamldap [OPTIONS]

Options:
  -f, --file <FILE>          Path to YAML directory file
  -p, --port <PORT>          Port to listen on [default: 389]
      --bind-address <ADDR>  Address to bind to [default: 0.0.0.0]
      --allow-anonymous      Allow anonymous bind operations
  -v, --verbose              Enable verbose logging
      --log-level <LEVEL>    Set log level: debug, info, warn, error [default: info]
  -h, --help                 Print help
```

## YAML Directory Format

### Basic Structure
```yaml
directory:
  base_dn: "dc=example,dc=com"  # Required: Base DN for the directory

entries:                         # List of directory entries
  - dn: "..."                   # Distinguished Name
    objectClass: [...]          # Object classes
    attribute: value            # Attributes and values
```

### Password Formats
```yaml
# Plain text (for testing only!)
userPassword: "plaintext"

# SHA hash
userPassword: "{SHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g="

# Salted SHA
userPassword: "{SSHA}DkMTwBl+a/3DfY+MTDTrcd5kMT8dpDkE"

# Bcrypt
userPassword: "$2b$10$..."
```

### Complete Example
See [examples/sample_directory.yaml](examples/sample_directory.yaml) for a full example with users, groups, and organizational units.

## Testing Scripts

### Python Test Script
```bash
./test_ldap.py
```

### Shell Test Script
```bash
./test_basic.sh
```

## Integration Examples

### Python
```python
import ldap

conn = ldap.initialize("ldap://localhost:389")
conn.simple_bind_s("uid=john,ou=users,dc=example,dc=com", "password")
results = conn.search_s("dc=example,dc=com", ldap.SCOPE_SUBTREE, "(uid=john)")
```

### Node.js
```javascript
const ldap = require('ldapjs');
const client = ldap.createClient({ url: 'ldap://localhost:389' });

client.bind('uid=john,ou=users,dc=example,dc=com', 'password', (err) => {
  // Authenticated
});
```

### Java/Spring
```java
@Bean
public LdapContextSource contextSource() {
    LdapContextSource contextSource = new LdapContextSource();
    contextSource.setUrl("ldap://localhost:389");
    contextSource.setBase("dc=example,dc=com");
    contextSource.setUserDn("uid=john,ou=users,dc=example,dc=com");
    contextSource.setPassword("password");
    return contextSource;
}
```

## Development

### Running Tests
```bash
cargo test
```

### Building Release
```bash
cargo build --release
```

### Code Formatting
```bash
cargo fmt
cargo clippy
```

## Limitations

- Read-only operations (no add/modify/delete support yet)
- Basic LDAP v3 protocol support
- Limited search filter syntax
- No referral or alias support
- No TLS/SSL support yet

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is dual-licensed under MIT OR Apache-2.0