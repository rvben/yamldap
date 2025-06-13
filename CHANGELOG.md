# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

[0.0.1]: https://github.com/rvben/yamldap/releases/tag/v0.0.1