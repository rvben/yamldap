.PHONY: all build test bench clean run docker-build docker-run help

# Default target
all: build

# Build the project in release mode
build:
	cargo build --release

# Build for a specific target
build-target:
	@if [ -z "$(TARGET)" ]; then echo "Usage: make build-target TARGET=x86_64-unknown-linux-gnu"; exit 1; fi
	@echo "Building for target: $(TARGET)"
	cargo build --release --target $(TARGET)

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
	cargo test --all-features -- --nocapture

# Run unit tests only
test-unit:
	cargo test --lib --all-features -- --nocapture

# Run integration tests only
test-integration:
	cargo test --test '*' --all-features -- --nocapture

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
	cargo run -- -f examples/sample_directory.yaml --allow-anonymous

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

# Build multi-platform Docker image from pre-built binaries (for releases)
docker-buildx-release: docker-setup
	@if [ ! -f "target/x86_64-unknown-linux-gnu/release/yamldap" ] || [ ! -f "target/aarch64-unknown-linux-gnu/release/yamldap" ]; then \
		echo "Error: Pre-built binaries not found. Run 'make build-all-targets' first"; \
		exit 1; \
	fi
	@mkdir -p docker-context
	@cp target/x86_64-unknown-linux-gnu/release/yamldap docker-context/yamldap-amd64
	@cp target/aarch64-unknown-linux-gnu/release/yamldap docker-context/yamldap-arm64
	@chmod +x docker-context/yamldap-*
	@echo "FROM scratch" > docker-context/Dockerfile
	@echo "ARG TARGETARCH" >> docker-context/Dockerfile
	@echo "COPY yamldap-\$${TARGETARCH} /yamldap" >> docker-context/Dockerfile
	@echo "EXPOSE 389" >> docker-context/Dockerfile
	@echo "ENTRYPOINT [\"/yamldap\"]" >> docker-context/Dockerfile
	docker buildx build --platform linux/amd64,linux/arm64 -t yamldap:latest docker-context/

# Login to GitHub Container Registry
docker-login:
	@if [ -z "$$GITHUB_TOKEN" ]; then echo "Error: GITHUB_TOKEN not set"; exit 1; fi
	@echo "$$GITHUB_TOKEN" | docker login ghcr.io -u $$GITHUB_ACTOR --password-stdin

# Push multi-platform image to GitHub Container Registry
docker-push: docker-login docker-buildx
	@if [ -z "$(VERSION)" ]; then echo "Usage: make docker-push VERSION=0.1.0"; exit 1; fi
	docker buildx build --platform linux/amd64,linux/arm64 \
		-t ghcr.io/rvben/yamldap:$(VERSION) \
		-t ghcr.io/rvben/yamldap:latest \
		--push .

# Push multi-platform release image (from pre-built binaries)
docker-push-release: docker-login
	@if [ -z "$(VERSION)" ]; then echo "Usage: make docker-push-release VERSION=0.1.0"; exit 1; fi
	@if [ ! -f "target/x86_64-unknown-linux-gnu/release/yamldap" ] || [ ! -f "target/aarch64-unknown-linux-gnu/release/yamldap" ]; then \
		echo "Error: Pre-built binaries not found. Run 'make build-all-targets' first"; \
		exit 1; \
	fi
	@mkdir -p docker-context
	@cp target/x86_64-unknown-linux-gnu/release/yamldap docker-context/yamldap-amd64
	@cp target/aarch64-unknown-linux-gnu/release/yamldap docker-context/yamldap-arm64
	@chmod +x docker-context/yamldap-*
	@echo "FROM scratch" > docker-context/Dockerfile
	@echo "ARG TARGETARCH" >> docker-context/Dockerfile
	@echo "COPY yamldap-\$${TARGETARCH} /yamldap" >> docker-context/Dockerfile
	@echo "EXPOSE 389" >> docker-context/Dockerfile
	@echo "ENTRYPOINT [\"/yamldap\"]" >> docker-context/Dockerfile
	docker buildx build --platform linux/amd64,linux/arm64 \
		-t ghcr.io/rvben/yamldap:$(VERSION) \
		-t ghcr.io/rvben/yamldap:latest \
		--push docker-context/

# Run with Docker
docker-run:
	docker run -d --name yamldap -p 389:389 -v $$(pwd)/examples/sample_directory.yaml:/data/directory.yaml yamldap:latest -f /data/directory.yaml --allow-anonymous

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

# Run linting
lint:
	cargo clippy -- -D warnings

# Format code
fmt:
	cargo fmt

# Check formatting
fmt-check:
	cargo fmt -- --check

# Type check
check:
	cargo check --all-features

# Run all CI checks (format, lint, type check, test)
ci: fmt-check check lint test

# Test with LDAP client
test-ldap:
	@echo "Testing LDAP server..."
	@python3 test_ldap.py || true

# Publish to crates.io
publish-crate:
	@if [ -z "$$CRATES_IO_TOKEN" ]; then echo "Error: CRATES_IO_TOKEN not set"; exit 1; fi
	cargo publish --token $$CRATES_IO_TOKEN

# Dry run publish to crates.io
publish-crate-dry:
	cargo publish --dry-run

# Release preparation
release-prep:
	@if [ -f scripts/prepare-release.sh ]; then \
		./scripts/prepare-release.sh; \
	else \
		echo "Release preparation script not found"; \
	fi

# Check if ready for release
release-check:
	@echo "Checking release readiness..."
	@echo ""
	@echo "1. Running tests..."
	@cargo test --quiet
	@echo "✓ Tests passed"
	@echo ""
	@echo "2. Checking formatting..."
	@cargo fmt -- --check
	@echo "✓ Code is formatted"
	@echo ""
	@echo "3. Running clippy..."
	@cargo clippy -- -D warnings
	@echo "✓ No clippy warnings"
	@echo ""
	@echo "4. Checking documentation..."
	@cargo doc --no-deps --quiet
	@echo "✓ Documentation builds"
	@echo ""
	@echo "5. Dry-run crates.io publish..."
	@cargo publish --dry-run --allow-dirty
	@echo "✓ Package is ready for crates.io"
	@echo ""
	@echo "✅ All checks passed! Ready for release."
	@echo ""
	@echo "Next steps:"
	@echo "  1. Run 'make release-prep' to prepare the release"
	@echo "  2. Push the tag to trigger the release workflow"

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
	@echo "  make ci                   - Run all CI checks"
	@echo ""
	@echo "Docker:"
	@echo "  make docker-build         - Build Docker image (current platform)"
	@echo "  make docker-buildx        - Build multi-platform image"
	@echo "  make docker-buildx-release - Build multi-platform from binaries"
	@echo "  make docker-push VERSION= - Push multi-platform image"
	@echo "  make docker-push-release VERSION= - Push release image"
	@echo "  make docker-run           - Run with Docker"
	@echo "  make docker-compose-up    - Run with Docker Compose"
	@echo "  make docker-stop          - Stop Docker containers"
	@echo ""
	@echo "Release:"
	@echo "  make release-check        - Check if ready for release"
	@echo "  make release-prep         - Prepare a new release"
	@echo "  make publish-crate        - Publish to crates.io"
	@echo "  make publish-crate-dry    - Dry run crates.io publish"
	@echo ""
	@echo "Other:"
	@echo "  make run                  - Run the server locally"
	@echo "  make clean                - Clean build artifacts"
	@echo "  make help                 - Show this help message"