# yamldap

<p align="center">
  <img src="assets/logo.png" alt="yamldap Folded Directory logo" width="260">
</p>

<h3 align="center">YAML in, LDAP out.</h3>

<p align="center"><strong>A lightweight LDAP server that serves directory data from YAML files</strong></p>

<p align="center">
  <a href="https://crates.io/crates/yamldap"><img src="https://img.shields.io/crates/v/yamldap.svg" alt="Crates.io"></a>
  <a href="https://docs.rs/yamldap"><img src="https://docs.rs/yamldap/badge.svg" alt="Documentation"></a>
  <a href="https://github.com/rvben/yamldap#license"><img src="https://img.shields.io/crates/l/yamldap.svg" alt="License"></a>
  <a href="https://github.com/rvben/yamldap/actions/workflows/ci.yml"><img src="https://github.com/rvben/yamldap/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
</p>

---

A lightweight LDAP server that serves directory data from YAML files, designed for local development and testing.

## Features

- 🚀 **Quick Setup** - Define your LDAP directory in a simple YAML file
- 🔐 **Authentication** - Support for multiple password formats (plain, SHA, SSHA, bcrypt)
- 🔍 **LDAP Operations** - Bind, unbind, search, compare, and selected extended operations
- 🛠️ **Development Friendly** - Perfect for testing LDAP integrations locally
- 🐳 **Docker Support** - Run in containers with provided Dockerfile
- ⚡ **Lightweight** - Minimal resource usage, fast startup
- 🎯 **Structural Filters** - BER filters remain typed through evaluation, with bounded complexity

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
docker run --read-only --cap-drop ALL --security-opt no-new-privileges \
  -p 127.0.0.1:1389:1389 \
  -v "$(pwd)/directory.yaml:/data/directory.yaml:ro" \
  ghcr.io/rvben/yamldap:latest \
  -f /data/directory.yaml --bind-address 0.0.0.0 --port 1389 \
  --allow-insecure-non-loopback
```

Or build locally:
```bash
docker build -t yamldap .
docker run --read-only --cap-drop ALL --security-opt no-new-privileges \
  -p 127.0.0.1:1389:1389 \
  -v "$(pwd)/examples/sample_directory.yaml:/data/directory.yaml:ro" \
  yamldap:latest -f /data/directory.yaml --bind-address 0.0.0.0 \
  --port 1389 --allow-insecure-non-loopback
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
    givenName: "John"
    sn: "Doe"
    mail: "john@example.com"
    userPassword: "secret123"
```

2. Start the server:
```bash
# Defaults to the loopback-only, non-privileged address 127.0.0.1:1389
yamldap -f directory.yaml

# Or with Docker from registry
docker compose up

# Or with anonymous bind enabled
docker compose run --service-ports yamldap \
  -f /data/directory.yaml --bind-address 0.0.0.0 --port 1389 \
  --allow-insecure-non-loopback --allow-anonymous
```

3. Test with LDAP tools:
```bash
# Search all entries
ldapsearch -x -H ldap://localhost:1389 -b "dc=example,dc=com" "(objectClass=*)"

# Authenticate and search
ldapsearch -x -H ldap://localhost:1389 \
  -D "uid=john,ou=users,dc=example,dc=com" \
  -w secret123 \
  -b "dc=example,dc=com" "(uid=john)"
```

## Command Line Options

```
yamldap [OPTIONS]

Options:
  -f, --file <FILE>           Path to YAML directory file
  -p, --port <PORT>                    Port to listen on [default: 1389]
      --bind-address <ADDR>            Address to bind to [default: 127.0.0.1]
      --allow-insecure-non-loopback    Acknowledge non-loopback plaintext LDAP exposure
      --base-dn <DN>                   Relocate the YAML directory to a new base DN
      --allow-anonymous       Allow anonymous bind operations
      --hot-reload            Enable hot-reloading of YAML file changes
  -v, --verbose               Enable verbose logging
      --log-level <LEVEL>     Set log level: debug, info, warn, error [default: info]
      --ad-compat             Enable Active Directory schema/filter mappings
  -h, --help                  Print help
```

## YAML Directory Format

YAML is compiled and validated before it becomes visible to clients. Invalid
DNs, duplicate semantic DNs, entries outside the base, unsupported value
types, schema cardinality violations, and inconsistent RDN values fail the
load. A failed hot reload leaves the previous complete snapshot active.

`--base-dn` relocates entry DNs and in-tree values of DN-valued attributes;
external DN references remain unchanged. RootDSE, bind, search, and returned
DNs therefore describe the same relocated tree.

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
userPassword: "{SHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g="  # SHA hash of "password"

# Salted SHA
userPassword: "{SSHA}DkMTwBl+a/3DfY+MTDTrcd5kMT8dpDkE"

# Bcrypt
userPassword: "$2b$10$..."
```

### Complete Example
See [examples/sample_directory.yaml](examples/sample_directory.yaml) for a full example with users, groups, and organizational units.

## LDAP Filter Support

yamldap supports the following bounded LDAP filter forms:

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
  - DN attributes: `(ou:dn:=users)` - Matches entries whose DN has an `ou=users` component
  - Combined: `(cn:dn:caseIgnoreMatch:=admin)`

Unknown matching rules are rejected rather than assigned guessed semantics.
Filter nesting and total node counts are bounded for both BER input and the
text parser. Assertion values are never included in request logs.

## Protocol capabilities

| Capability | Status |
|---|---|
| LDAP v3 simple and anonymous bind | Supported |
| Base, one-level, and subtree search | Supported |
| Compare and Unbind | Supported |
| RootDSE discovery | Supported |
| Search size/time and server resource limits | Supported |
| Hot reload with atomic snapshots | Supported |
| Abandon cancellation | Not currently supported |
| SASL, Kerberos, NTLM, and Sicily authentication | Not supported; an LDAP error is returned |
| Aliases, referrals, controls, paging, Add/Modify/Delete | Not supported |
| TLS/StartTLS | Not built in |

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

### PowerShell (`System.DirectoryServices`)

`DirectoryEntry` uses secure authentication by default on modern .NET. yamldap supports LDAP simple binds and anonymous access, but it does not implement Kerberos, NTLM, or SASL. Select anonymous authentication explicitly when the server runs with `--allow-anonymous`:

```powershell
$authentication = [System.DirectoryServices.AuthenticationTypes]::Anonymous `
    -bor [System.DirectoryServices.AuthenticationTypes]::FastBind `
    -bor [System.DirectoryServices.AuthenticationTypes]::ServerBind

$searchRoot = [System.DirectoryServices.DirectoryEntry]::new(
    "LDAP://localhost:11389/dc=example,dc=com",
    $null,
    $null,
    $authentication
)

$searcher = [System.DirectoryServices.DirectorySearcher]::new($searchRoot)
$searcher.Filter = "(objectClass=*)"
$searcher.SearchScope = [System.DirectoryServices.SearchScope]::Subtree
$searcher.ClientTimeout = [TimeSpan]::FromSeconds(10)
$results = $searcher.FindAll()
```

`FastBind` keeps ADSI on its generic LDAP interfaces and avoids Active Directory schema discovery. `ServerBind` tells ADSI that the hostname in the path is a specific server. Neither flag enables Active Directory-only behavior.

For a simple authenticated bind, pass a bind DN and password and omit `Anonymous`:

```powershell
$authentication = [System.DirectoryServices.AuthenticationTypes]::FastBind `
    -bor [System.DirectoryServices.AuthenticationTypes]::ServerBind

$searchRoot = [System.DirectoryServices.DirectoryEntry]::new(
    "LDAP://localhost:11389/dc=example,dc=com",
    "uid=john,ou=users,dc=example,dc=com",
    "secret123",
    $authentication
)
```

The optional `--ad-compat` server flag maps selected Active Directory-style filters and attributes onto the YAML directory. It is not full Active Directory emulation and is not required for a generic subtree search.

### Python
```python
import ldap

conn = ldap.initialize("ldap://localhost:1389")
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
const client = ldap.createClient({ url: 'ldap://localhost:1389' });

client.bind('uid=john,ou=users,dc=example,dc=com', 'password', (err) => {
  // Authenticated
});
```

### Java/Spring
```java
@Bean
public LdapContextSource contextSource() {
    LdapContextSource contextSource = new LdapContextSource();
    contextSource.setUrl("ldap://localhost:1389");
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

# Build the locked, non-root container image
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

The repository includes unit, protocol, integration, lifecycle, hot-reload,
property-style, and fuzz tests. CI runs formatting, strict Clippy, tests across
Linux/macOS/Windows, warning-free rustdoc, fuzz-target compilation, package
verification, and dependency policy checks. Coverage is reported as measured
output; the project does not claim a percentage that CI has not produced.

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
- Simple and anonymous binds only; no SASL, Kerberos, or NTLM authentication
- No referral or alias support
- No paged-results or other LDAP controls
- No built-in TLS/SSL support (see below)
- Abandon requests are decoded but cannot cancel an in-flight search yet

## TLS/SSL Support

yamldap is a local development and testing server and does not include TLS.
The default loopback bind protects against accidental LAN exposure. Do not
send production credentials over plaintext LDAP. For an isolated test setup
that requires TLS, terminate it with a locally controlled proxy:

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

Dependency updates are maintained with weekly policy-constrained upd pull
requests and separate daily security remediation. See the
[dependency-maintenance guide](docs/dependencies.md) for policy, credentials,
and local commands.

## Releasing

Vership manages version bumps, changelog promotion, release commits, tags, pushes, and verification. The tag-triggered GitHub Actions workflow builds and publishes the release artifacts. See [the release runbook](docs/releases.md).

## License

This project is dual-licensed under MIT OR Apache-2.0
