# yamldap

<div align="center">
  <img src="https://raw.githubusercontent.com/rvben/yamldap/main/assets/logo.png" alt="yamldap logo" width="400">

  **A lightweight LDAP server that serves directory data from YAML files**

  [![Crates.io](https://img.shields.io/crates/v/yamldap.svg)](https://crates.io/crates/yamldap)
  [![Documentation](https://docs.rs/yamldap/badge.svg)](https://docs.rs/yamldap)
  [![License](https://img.shields.io/crates/l/yamldap.svg)](https://github.com/rvben/yamldap#license)
  [![Build Status](https://img.shields.io/github/workflow/status/rvben/yamldap/CI)](https://github.com/rvben/yamldap/actions)
</div>

---

A lightweight LDAP server that serves directory data from YAML files, designed for local development and testing.

## Features

- 🚀 **Quick Setup** - Define your LDAP directory in a simple YAML file
- 🔐 **Authentication** - Support for multiple password formats (plain, SHA, SSHA, bcrypt)
- 🔍 **LDAP Operations** - Bind, search, compare, abandon, and extended operations
- 🛠️ **Development Friendly** - Perfect for testing LDAP integrations locally
- 🐳 **Docker Support** - Run in containers with provided Dockerfile
- ⚡ **Lightweight** - Minimal resource usage, fast startup
- 🎯 **Advanced Filters** - Full LDAP filter support including approximate and extensible match

## Installation

### From Crates.io
```bash
cargo install yamldap
```

### From Binary Releases
Download pre-built binaries from the [GitHub Releases](https://github.com/rvben/yamldap/releases) page for:
- Linux (x86_64, aarch64)
- macOS (x86_64, aarch64)
- Windows (x86_64)

### From Source
```bash
git clone https://github.com/rvben/yamldap
cd yamldap
cargo install --path .
```

### Using Docker

Pull from GitHub Container Registry:
```bash
# Pull the latest version (multi-platform: linux/amd64, linux/arm64)
docker pull ghcr.io/rvben/yamldap:latest

# Or pull a specific version
docker pull ghcr.io/rvben/yamldap:0.0.1

# Run with your YAML directory file
docker run -p 389:389 -v $(pwd)/directory.yaml:/data/directory.yaml ghcr.io/rvben/yamldap:latest -f /data/directory.yaml
```

Or build locally:
```bash
docker build -t yamldap .
docker run -p 389:389 -v $(pwd)/examples/sample_directory.yaml:/data/directory.yaml yamldap:latest -f /data/directory.yaml
```

### Using Docker Compose

Using pre-built images from registry:
```bash
docker compose -f compose.registry.yml up
```

Or build and run locally:
```bash
docker compose up
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

# Or with Docker from registry
docker run -p 389:389 -v $(pwd)/directory.yaml:/data/directory.yaml ghcr.io/rvben/yamldap:latest -f /data/directory.yaml

# Or with anonymous bind enabled
docker run -p 389:389 -v $(pwd)/directory.yaml:/data/directory.yaml ghcr.io/rvben/yamldap:latest -f /data/directory.yaml --allow-anonymous
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

## LDAP Filter Support

yamldap supports comprehensive LDAP filter syntax including:

### Basic Filters
- **Equality**: `(uid=john)`
- **Presence**: `(mail=*)`
- **Substring**: `(cn=*smith*)`, `(cn=john*)`, `(cn=*doe)`
- **Greater/Less**: `(age>=18)`, `(created<=20240101)`

### Boolean Operators
- **AND**: `(&(objectClass=person)(uid=admin))`
- **OR**: `(|(uid=john)(uid=jane))`
- **NOT**: `(!(uid=guest))`

### Advanced Filters
- **Approximate Match**: `(cn~=john)` - Fuzzy matching
- **Extensible Match**: 
  - Simple: `(cn:=John Doe)`
  - With matching rule: `(cn:caseExactMatch:=John Doe)`
  - DN components: `(:dn:=users)` - Matches entries with "users" in their DN
  - Combined: `(cn:dn:caseIgnoreMatch:=admin)`

### Escape Sequences
Special characters can be escaped in filter values:
- `\28` for `(`
- `\29` for `)`
- `\2a` for `*`
- `\5c` for `\`
- `\00` for NULL

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

### Django with django-auth-ldap
```python
# settings.py
import ldap
from django_auth_ldap.config import LDAPSearch, GroupOfNamesType

AUTH_LDAP_SERVER_URI = "ldap://yamldap:389"
AUTH_LDAP_BIND_DN = "cn=admin,dc=example,dc=com"
AUTH_LDAP_BIND_PASSWORD = "admin"

AUTH_LDAP_USER_SEARCH = LDAPSearch(
    "dc=example,dc=com",
    ldap.SCOPE_SUBTREE,
    "(uid=%(user)s)",
)

AUTH_LDAP_GROUP_SEARCH = LDAPSearch(
    "ou=groups,dc=example,dc=com",
    ldap.SCOPE_SUBTREE,
    "(objectClass=groupOfNames)",
)

AUTH_LDAP_GROUP_TYPE = GroupOfNamesType()
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
# Run all tests
cargo test

# Run with coverage report
make coverage

# Check test coverage percentage
make coverage-check

# Run benchmarks
make bench
```

### Building
```bash
# Build release version
cargo build --release

# Build Docker image (3.99MB scratch image)
make docker-build
```

### Code Quality
```bash
# Format code
cargo fmt

# Run linter
cargo clippy

# Run all CI checks
make ci
```

### Testing & Coverage

The project includes comprehensive unit tests with near 100% code coverage:
- 250+ unit and integration tests covering all major components
- Complete error path and edge case coverage
- Concurrent operation and thread safety tests
- Integration tests for full server lifecycle
- Performance benchmarks with Criterion
- Test coverage reporting via cargo-tarpaulin

Run `make help` to see all available Make targets.

### Fuzz Testing

yamldap includes fuzz testing to ensure robustness against malformed input:

```bash
# Install cargo-fuzz
cargo install cargo-fuzz

# Run fuzz tests (requires nightly Rust)
cd fuzz
cargo +nightly fuzz run fuzz_ldap_decoder      # Fuzz the LDAP decoder
cargo +nightly fuzz run fuzz_ldap_filter_parser # Fuzz the filter parser
cargo +nightly fuzz run fuzz_ldap_structured    # Fuzz with structured input
```

See [fuzz/README.md](fuzz/README.md) for detailed fuzzing instructions.

## Limitations

- Read-only operations (no add/modify/delete support yet)
- Basic LDAP v3 protocol support
- No referral or alias support
- No built-in TLS/SSL support (see below)

## TLS/SSL Support

yamldap intentionally does not include built-in TLS support to maintain its core value: simplicity. For local development and testing, TLS is rarely needed. When TLS is required, you can easily add it using a reverse proxy:

### Using stunnel
```bash
# stunnel.conf
[ldaps]
accept = 636
connect = 127.0.0.1:389
cert = /path/to/certificate.pem
```

### Using nginx
```nginx
stream {
    server {
        listen 636 ssl;
        proxy_pass localhost:389;
        ssl_certificate /path/to/cert.pem;
        ssl_certificate_key /path/to/key.pem;
    }
}
```

This approach keeps yamldap simple while allowing TLS when needed for production-like testing.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is dual-licensed under MIT OR Apache-2.0