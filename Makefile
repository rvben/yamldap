.PHONY: all audit build build-target build-all-targets check ci clean docs-check \
	docker-build docker-buildx docker-compose-registry docker-compose-up docker-login \
	docker-push docker-push-dockerhub docker-run docker-setup docker-stop fmt fmt-check \
	help lint package-check publish-crate publish-crate-dry release release-check \
	release-extra-checks release-lint run test test-integration test-ldap test-unit

RELEASE_LEVEL ?= patch

# Default target
all: build

# Build the project in release mode
build:
	cargo build --locked --release

# Build for a specific target
build-target:
	@if [ -z "$(TARGET)" ]; then echo "Usage: make build-target TARGET=x86_64-unknown-linux-gnu"; exit 1; fi
	@echo "Building for target: $(TARGET)"
	cargo build --locked --release --target $(TARGET)

# Build all release targets
build-all-targets:
	@echo "Building for all targets..."
	@$(MAKE) build-target TARGET=x86_64-unknown-linux-gnu || echo "Skipping Linux x64 build - cross-compilation not available"
	@$(MAKE) build-target TARGET=aarch64-unknown-linux-gnu || echo "Skipping Linux ARM64 build - cross-compilation not available"
	@$(MAKE) build-target TARGET=x86_64-pc-windows-msvc || echo "Skipping Windows build on non-Windows host"
	@$(MAKE) build-target TARGET=x86_64-apple-darwin || echo "Skipping macOS x64 build on non-macOS host"
	@$(MAKE) build-target TARGET=aarch64-apple-darwin || echo "Skipping macOS ARM build on non-macOS host"

# Run all tests
test:
	cargo test --locked --all-targets --all-features -- --nocapture

# Run unit tests only
test-unit:
	cargo test --locked --lib --all-features -- --nocapture

# Run integration tests only
test-integration:
	cargo test --locked --test '*' --all-features -- --nocapture

# Run tests with coverage
coverage:
	cargo tarpaulin --out Html --output-dir coverage --all-features --verbose

# Run tests with coverage and open report
coverage-open: coverage
	open coverage/tarpaulin-report.html || xdg-open coverage/tarpaulin-report.html

# Check coverage percentage
coverage-check:
	cargo tarpaulin --all-features --print-summary

# Run benchmarks
bench:
	cargo bench

# Clean build artifacts
clean:
	cargo clean
	rm -rf target/
	rm -rf docker-context/

# Run the server locally
run:
	cargo run --locked -- -f examples/sample_directory.yaml --allow-anonymous

# Build Docker image (local, current platform only)
docker-build:
	docker build -t yamldap:latest .

# Setup Docker buildx for multi-platform builds
docker-setup:
	@if ! docker buildx ls | grep -q yamldap-builder; then \
		docker buildx create --name yamldap-builder --driver docker-container --bootstrap || true; \
	fi
	docker buildx use yamldap-builder
	docker buildx inspect --bootstrap

# Build multi-platform Docker image using buildx
docker-buildx: docker-setup
	docker buildx build --platform linux/amd64,linux/arm64 -t yamldap:latest .


# Login to GitHub Container Registry
docker-login:
	@if [ -z "$$GITHUB_TOKEN" ]; then echo "Error: GITHUB_TOKEN not set"; exit 1; fi
	@echo "$$GITHUB_TOKEN" | docker login ghcr.io -u $$GITHUB_ACTOR --password-stdin

# Push multi-platform image to GitHub Container Registry
docker-push: docker-login docker-setup
	@if [ -z "$(VERSION)" ]; then echo "Usage: make docker-push VERSION=0.1.0"; exit 1; fi
	docker buildx build --platform linux/amd64,linux/arm64 \
		-t ghcr.io/rvben/yamldap:$(VERSION) \
		-t ghcr.io/rvben/yamldap:latest \
		--push .

# Push multi-platform image to Docker Hub
docker-push-dockerhub: docker-setup
	@if [ -z "$(VERSION)" ]; then echo "Usage: make docker-push-dockerhub VERSION=0.1.0"; exit 1; fi
	docker buildx build --platform linux/amd64,linux/arm64 \
		-t docker.io/rvben/yamldap:$(VERSION) \
		-t docker.io/rvben/yamldap:latest \
		--push .

# Run with Docker
docker-run:
	docker run -d --name yamldap --read-only --cap-drop ALL \
		--security-opt no-new-privileges \
		-p 127.0.0.1:1389:1389 \
		-v $$(pwd)/examples/sample_directory.yaml:/data/directory.yaml:ro \
		yamldap:latest -f /data/directory.yaml --bind-address 0.0.0.0 \
		--port 1389 --allow-insecure-non-loopback

# Run with Docker Compose (local build)
docker-compose-up:
	docker compose up -d

# Run with Docker Compose (from registry)
docker-compose-registry:
	docker compose -f compose.registry.yml up -d

# Stop Docker containers
docker-stop:
	docker stop yamldap && docker rm yamldap || true
	docker compose down || true


# Deploy secrets to GitHub
gh-secrets:
	@if [ ! -f .env ]; then \
		echo "Error: .env file not found. Copy .env.example to .env and fill in your values."; \
		exit 1; \
	fi
	@echo "Loading environment variables from .env..."
	@export $$(grep -v '^#' .env | xargs) && \
		gh secret set DOCKER_USERNAME --body "$$DOCKER_USERNAME" && \
		echo "✓ Set DOCKER_USERNAME" && \
		gh secret set DOCKER_PASSWORD --body "$$DOCKER_PASSWORD" && \
		echo "✓ Set DOCKER_PASSWORD"
	@echo "GitHub secrets deployed successfully!"

# Run linting
lint:
	cargo clippy --locked --all-targets --all-features -- -D warnings

# Format code
fmt:
	cargo fmt --all
	cargo fmt --manifest-path fuzz/Cargo.toml

# Check formatting
fmt-check:
	cargo fmt --all -- --check
	cargo fmt --manifest-path fuzz/Cargo.toml -- --check

# Type check
check:
	cargo check --locked --all-targets --all-features
	cargo check --locked --manifest-path fuzz/Cargo.toml --bins

# Build documentation with warnings treated as errors.
docs-check:
	RUSTDOCFLAGS="-D warnings" cargo doc --locked --no-deps --all-features

# Verify the exact package Cargo would upload.
package-check:
	cargo publish --locked --dry-run

# Check the locked dependency graph against the RustSec advisory database.
audit:
	@command -v cargo-audit >/dev/null || { echo "cargo-audit is required: cargo install cargo-audit --locked"; exit 1; }
	@command -v cargo-deny >/dev/null || { echo "cargo-deny is required: cargo install cargo-deny --locked"; exit 1; }
	cargo audit --deny warnings
	cargo audit --deny warnings --file fuzz/Cargo.lock
	cargo deny --locked check
	cargo deny --locked --manifest-path fuzz/Cargo.toml check

# Run the same checks enforced by CI.
ci: fmt-check check lint test docs-check package-check audit

# Test with LDAP client
test-ldap:
	@echo "Testing LDAP server..."
	python3 test_ldap.py

# Publish to crates.io
publish-crate:
	@if [ -z "$$CARGO_REGISTRY_TOKEN" ]; then echo "Error: CARGO_REGISTRY_TOKEN not set"; exit 1; fi
	cargo publish --locked

# Dry run publish to crates.io
publish-crate-dry:
	cargo publish --locked --dry-run

# Checks Vership runs before changing release state.
release-lint: fmt-check lint

release-extra-checks: docs-check package-check audit

# Preview release readiness without changing repository state.
release-check:
	@command -v vership >/dev/null || { echo "Vership is required: cargo install vership"; exit 1; }
	vership preflight --output text

# Bump, commit, tag, and push. The tag triggers the publishing workflow.
release:
	@command -v vership >/dev/null || { echo "Vership is required: cargo install vership"; exit 1; }
	vership bump $(RELEASE_LEVEL) --output text

# Help target
help:
	@echo "Available targets:"
	@echo ""
	@echo "Building:"
	@echo "  make build                 - Build the project in release mode"
	@echo "  make build-target TARGET=  - Build for a specific target"
	@echo "  make build-all-targets     - Build for all supported targets"
	@echo ""
	@echo "Testing:"
	@echo "  make test                  - Run all tests"
	@echo "  make test-unit            - Run unit tests only"
	@echo "  make test-integration     - Run integration tests only"
	@echo "  make coverage             - Run tests with coverage report"
	@echo "  make coverage-open        - Run coverage and open HTML report"
	@echo "  make coverage-check       - Check coverage percentage"
	@echo "  make bench                - Run benchmarks"
	@echo "  make test-ldap            - Test with LDAP client"
	@echo ""
	@echo "Code Quality:"
	@echo "  make lint                 - Run linting with clippy"
	@echo "  make fmt                  - Format code"
	@echo "  make fmt-check            - Check code formatting"
	@echo "  make check                - Type check the code"
	@echo "  make docs-check           - Build docs with warnings denied"
	@echo "  make package-check        - Dry-run the locked crate package"
	@echo "  make audit                - Audit locked dependencies with RustSec"
	@echo "  make ci                   - Run all CI checks"
	@echo ""
	@echo "Docker:"
	@echo "  make docker-build         - Build Docker image (current platform)"
	@echo "  make docker-buildx        - Build multi-platform image"
	@echo "  make docker-push VERSION= - Push multi-platform image"
	@echo "  make docker-run           - Run with Docker"
	@echo "  make docker-compose-up    - Run with Docker Compose"
	@echo "  make docker-stop          - Stop Docker containers"
	@echo ""
	@echo "Release:"
	@echo "  make release-check        - Run Vership preflight checks"
	@echo "  make release RELEASE_LEVEL=patch - Bump, tag, and push with Vership"
	@echo "  make publish-crate        - Publish to crates.io"
	@echo "  make publish-crate-dry    - Dry run crates.io publish"
	@echo ""
	@echo "Other:"
	@echo "  make run                  - Run the server locally"
	@echo "  make clean                - Clean build artifacts"
	@echo "  make help                 - Show this help message"
