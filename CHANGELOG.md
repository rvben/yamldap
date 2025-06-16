# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.1] - 2025-06-16

### Fixed
- **OpenLDAP Compatibility**: Search filters with undefined attributes now return `UndefinedAttributeType` error (code 17) instead of silently returning 0 results
  - Matches OpenLDAP's behavior for better compatibility with existing LDAP client code
  - Enables exception-based fallback patterns used for Active Directory/OpenLDAP compatibility
  - Added comprehensive tests for undefined attribute handling

### Changed
- Search operations now validate all attributes referenced in filters before executing the search
- Added methods to collect and validate attributes from both schema and existing entries

## [0.1.0] - 2025-06-14

### Added
- **Comprehensive Test Coverage**: Achieved near 100% test coverage with 250+ tests
  - Added 50+ new test functions covering all error paths and edge cases
  - Integration tests for full server lifecycle
  - Concurrent operation and thread safety tests
  - Fuzz testing infrastructure for robustness
- **Enhanced Error Handling**: All error paths now have proper test coverage
- **Improved Filter Support**: Fixed and tested all LDAP filter edge cases
- **Password Security Tests**: Comprehensive testing for all password hash formats
- **YAML Parser Validation**: Complete test coverage for YAML parsing and validation errors
- **File Watcher Tests**: Full coverage for hot-reload functionality
- **Server Tests**: Integration tests for server startup, shutdown, and concurrent connections

### Changed
- Improved LDAP filter parser to be more lenient with syntax (matching real-world LDAP servers)
- Enhanced test organization with separate test modules for each component
- Better error messages throughout the codebase

### Fixed
- UTF-8 boundary handling in LDAP filter parser (found via fuzzing)
- Buffer overrun protection in LDAP protocol decoder (found via fuzzing)
- Various edge cases in filter parsing and evaluation

### Security
- Added comprehensive fuzz testing to catch potential security issues
- Fixed buffer boundary checks in protocol decoder
- Enhanced input validation throughout the codebase

## [0.0.10] - 2025-06-13

### Added
- Enhanced LDAP filter support with two new filter types:
  - Approximate match filters `(attr~=value)` for fuzzy matching
  - Extensible match filters `(attr:=value)`, `(attr:dn:=value)`, `(attr:matchingRule:=value)`
- Support for LDAP filter escape sequences (e.g., `\28` for `(`, `\2a` for `*`)
- Common matching rules support: caseIgnoreMatch (2.5.13.2), caseExactMatch (2.5.13.5)
- DN component matching with `:dn:` modifier in extensible filters
- Protocol decoder support for approximate match (tag 0xA8) and extensible match (tag 0xA9) filters
- Comprehensive test coverage for all new filter types

### Changed
- Improved filter parser to handle escaped characters in filter values
- Enhanced protocol decoder to properly parse complex extensible match filters

### Fixed
- Filter values now properly handle escape sequences according to RFC 4515

## [0.0.9] - 2025-06-13

### Fixed
- Added support for LDAP Abandon Request operation (tag 0x50) to prevent connection drops with django-auth-ldap

### Added
- Implemented LDAP Abandon Request handling (RFC 4511 Section 4.11)
- Implemented LDAP Extended Request/Response operations (tags 0x77/0x78) for future extensibility
- Added proper response for StartTLS Extended operation (returns unavailable)
- Added comprehensive tests for Abandon and Extended operation functionality

## [0.0.8] - 2025-06-13

### Fixed
- Added support for LDAP Compare operation (tag 0x6e) which was causing Django LDAP authentication to fail

### Added
- Implemented LDAP Compare Request/Response handling in SimpleLdapCodec
- Added comprehensive tests for Compare operation functionality

## [0.0.7] - 2025-06-13

### Fixed
- Simplified Docker image publishing in GitHub workflow to resolve persistent 403 errors
- Removed problematic docker/build-push-action in favor of direct docker commands
- Fixed multi-arch image creation by building and pushing platform-specific images first

### Changed
- Refactored GitHub workflow to use simple docker build/push with manifest creation
- Cleaned up Makefile by removing obsolete Docker targets
- Updated docker-push-multiarch target to better support local testing with .env file

### Added
- Created .env.example file documenting GitHub PAT token configuration
- Added docker-inspect-multiarch target for verifying multi-architecture images

## [0.0.6] - 2025-06-13

### Fixed
- Fixed GitHub Container Registry push errors by adding proper image labels
- Added package initialization step to ensure registry package exists
- Resolved 403 errors by linking Docker images to the repository with org.opencontainers.image.source label

### Changed
- Simplified Docker push approach back to using docker/build-push-action
- Disabled SBOM generation in addition to provenance
- Added comprehensive image labels for proper registry integration

### Added
- Instructions for using Personal Access Tokens for local Docker registry testing

## [0.0.5] - 2025-06-13

### Fixed
- Reworked Docker image building to push platform-specific images before creating multi-arch manifest
- Added registry access verification step to debug authentication issues
- Fixed step ordering to ensure version extraction happens before registry operations

### Changed
- Split multi-platform Docker build into separate platform builds followed by manifest creation
- Added explicit buildx commands for better control over the build process

## [0.0.4] - 2025-06-13

### Fixed
- Fixed Docker image push authentication errors by disabling provenance attestations
- Resolved 403 Forbidden errors when pushing multi-arch images to GitHub Container Registry

### Changed
- Updated GitHub workflow to set `provenance: false` for Docker builds with pre-built binaries

## [0.0.3] - 2025-06-13

### Changed
- Optimized Docker release process to use pre-built binaries instead of compiling during image creation
- Simplified Docker image publishing to create multi-arch images directly without intermediate architecture-specific tags
- Docker images are now built from binary artifacts, significantly reducing CI/CD pipeline time

### Added
- Dynamic Dockerfile generation during release process for efficient multi-arch builds
- .dockerignore file to optimize Docker build context

## [0.0.2] - 2025-06-13

### Fixed
- Fixed critical DN attribute type case sensitivity issue that incorrectly rejected uppercase DNs
- Fixed LDAP search filtering that was returning all entries regardless of filter criteria
- Fixed incorrect LDAP error code (34 - InvalidDNSyntax) being returned instead of (49 - InvalidCredentials) for authentication failures
- Fixed search request parsing to properly handle filters instead of hardcoding (objectClass=*)
- Fixed clippy warnings about manual string stripping

### Added
- Comprehensive tests for DN case insensitivity
- Support for composite LDAP filters (AND, OR, NOT)
- Support for substring filters in LDAP searches
- Tests verifying correct LDAP error codes are returned

### Changed
- Enhanced LDAP filter parser to support nested and complex filter expressions
- Improved SimpleLdapCodec to properly parse search request filters from ASN.1

## [0.0.1] - 2025-06-11

### Added
- Initial release of yamldap
- LDAP v3 protocol support for basic operations
- YAML-based directory configuration
- Support for bind, search, and compare operations
- Multiple password formats: plain, SHA, SSHA, bcrypt
- Docker support with minimal 3.99MB scratch image
- Hot reload functionality for YAML files
- Comprehensive test suite with 148 unit tests
- Performance benchmarks
- Command-line interface with configurable options
- Anonymous bind support
- Case-insensitive DN and attribute matching
- Basic LDAP filter support
- Integration test scripts in Python and Shell

### Features
- 🚀 Lightning-fast performance with in-memory storage
- 🔐 Multiple authentication methods
- 🐳 Docker and Docker Compose support
- 📝 Simple YAML configuration format
- 🔄 Hot reload for development
- 🧪 Extensive test coverage (~63%)

### Known Limitations
- Read-only operations (no add/modify/delete support yet)
- Basic LDAP v3 protocol support
- Limited search filter syntax
- No referral or alias support
- No TLS/SSL support yet

[0.1.0]: https://github.com/rvben/yamldap/releases/tag/v0.1.0
[0.0.10]: https://github.com/rvben/yamldap/releases/tag/v0.0.10
[0.0.9]: https://github.com/rvben/yamldap/releases/tag/v0.0.9
[0.0.8]: https://github.com/rvben/yamldap/releases/tag/v0.0.8
[0.0.7]: https://github.com/rvben/yamldap/releases/tag/v0.0.7
[0.0.6]: https://github.com/rvben/yamldap/releases/tag/v0.0.6
[0.0.5]: https://github.com/rvben/yamldap/releases/tag/v0.0.5
[0.0.4]: https://github.com/rvben/yamldap/releases/tag/v0.0.4
[0.0.3]: https://github.com/rvben/yamldap/releases/tag/v0.0.3
[0.0.2]: https://github.com/rvben/yamldap/releases/tag/v0.0.2
[0.0.1]: https://github.com/rvben/yamldap/releases/tag/v0.0.1