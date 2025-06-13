.PHONY: all build test bench clean run docker-build docker-run help

# Default target
all: build

# Build the project in release mode
build:
	cargo build --release

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
	open coverage/tarpaulin-report.html

# Check coverage percentage
coverage-check:
	cargo tarpaulin --all-features

# Run benchmarks
bench:
	cargo bench

# Clean build artifacts
clean:
	cargo clean
	rm -rf target/

# Run the server locally
run:
	cargo run -- -f examples/sample_directory.yaml --allow-anonymous

# Build Docker image (local, current platform only)
docker-build:
	docker build -t yamldap:latest .

# Build Docker image for multiple platforms (requires buildx)
docker-buildx:
	docker buildx build --platform linux/amd64,linux/arm64 -t yamldap:latest .

# Build and push to GitHub Container Registry
docker-push: docker-login
	@if [ -z "$(VERSION)" ]; then echo "Usage: make docker-push VERSION=0.0.1"; exit 1; fi
	docker buildx build --platform linux/amd64 \
		-t ghcr.io/rvben/yamldap:$(VERSION) \
		-t ghcr.io/rvben/yamldap:latest \
		--push .

# Build and push multi-platform to GitHub Container Registry
docker-push-multiplatform: docker-login
	@if [ -z "$(VERSION)" ]; then echo "Usage: make docker-push-multiplatform VERSION=0.0.1"; exit 1; fi
	docker buildx build --platform linux/amd64,linux/arm64 \
		-t ghcr.io/rvben/yamldap:$(VERSION) \
		-t ghcr.io/rvben/yamldap:latest \
		--push .

# Login to GitHub Container Registry
docker-login:
	@echo "Logging into GitHub Container Registry..."
	@echo "$$GITHUB_TOKEN" | docker login ghcr.io -u rvben --password-stdin

# Setup Docker buildx for multi-platform builds
docker-setup:
	docker buildx create --name yamldap-builder --use || true
	docker buildx inspect --bootstrap

# Run with Docker
docker-run:
	docker run -d --name yamldap -p 389:389 -v $(PWD)/examples/sample_directory.yaml:/data/directory.yaml yamldap:latest -f /data/directory.yaml --allow-anonymous

# Run with Docker Compose (local build)
docker-compose-up:
	docker compose up -d

# Run with Docker Compose (from registry)
docker-compose-registry:
	docker compose -f compose.registry.yml up -d

# Stop Docker container
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

# Run all checks (format, lint, type check, test)
ci: fmt-check check lint test

# Test with LDAP client
test-ldap:
	@echo "Testing LDAP server..."
	@./test_ldap.py || true

# Create a new patch release
release-patch:
	@echo "Creating a new patch release..."
	@# Get current version from Cargo.toml
	@CURRENT_VERSION=$$(grep '^version = ' Cargo.toml | head -1 | cut -d'"' -f2); \
	echo "Current version: $$CURRENT_VERSION"; \
	# Split version into parts
	MAJOR=$$(echo $$CURRENT_VERSION | cut -d. -f1); \
	MINOR=$$(echo $$CURRENT_VERSION | cut -d. -f2); \
	PATCH=$$(echo $$CURRENT_VERSION | cut -d. -f3); \
	# Increment patch version
	NEW_PATCH=$$((PATCH + 1)); \
	NEW_VERSION="$$MAJOR.$$MINOR.$$NEW_PATCH"; \
	echo "New version: $$NEW_VERSION"; \
	# Update Cargo.toml
	sed -i.bak "s/^version = \"$$CURRENT_VERSION\"/version = \"$$NEW_VERSION\"/" Cargo.toml && rm Cargo.toml.bak; \
	# Update Cargo.lock
	cargo update -p yamldap; \
	# Commit changes
	git add Cargo.toml Cargo.lock; \
	git commit -m "chore: bump version to $$NEW_VERSION"; \
	# Create and push tag
	git tag -a "v$$NEW_VERSION" -m "Release v$$NEW_VERSION"; \
	echo ""; \
	echo "Release v$$NEW_VERSION created successfully!"; \
	echo ""; \
	echo "To push the release:"; \
	echo "  git push origin main"; \
	echo "  git push origin v$$NEW_VERSION"; \
	echo ""; \
	echo "To publish to crates.io:"; \
	echo "  cargo publish"; \
	echo ""; \
	echo "To build and push Docker images:"; \
	echo "  make docker-push VERSION=$$NEW_VERSION"; \
	echo "  make docker-push-multiplatform VERSION=$$NEW_VERSION"

# Help target
help:
	@echo "Available targets:"
	@echo "  make build          - Build the project in release mode"
	@echo "  make test           - Run all tests"
	@echo "  make test-unit      - Run unit tests only"
	@echo "  make test-integration - Run integration tests only"
	@echo "  make coverage       - Run tests with coverage report"
	@echo "  make coverage-open  - Run coverage and open HTML report"
	@echo "  make coverage-check - Check coverage percentage"
	@echo "  make bench          - Run benchmarks"
	@echo "  make clean          - Clean build artifacts"
	@echo "  make run            - Run the server locally"
	@echo "  make docker-build   - Build Docker image (local, current platform)"
	@echo "  make docker-buildx  - Build Docker image for multiple platforms"
	@echo "  make docker-push VERSION=x.x.x - Build and push to ghcr.io (AMD64)"
	@echo "  make docker-push-multiplatform VERSION=x.x.x - Push multi-arch to ghcr.io"
	@echo "  make docker-setup   - Setup Docker buildx for multi-platform builds"
	@echo "  make docker-run     - Run with Docker"
	@echo "  make docker-compose-up - Run with Docker Compose (local build)"
	@echo "  make docker-compose-registry - Run with Docker Compose (from registry)"
	@echo "  make docker-stop    - Stop Docker containers"
	@echo "  make test-ldap      - Test with LDAP client"
	@echo "  make lint           - Run linting with clippy"
	@echo "  make fmt            - Format code"
	@echo "  make fmt-check      - Check code formatting"
	@echo "  make check          - Type check the code"
	@echo "  make ci             - Run all checks (format, lint, type check, test)"
	@echo "  make release-patch  - Create a new patch release (increments version)"
	@echo "  make help           - Show this help message"