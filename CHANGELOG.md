# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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