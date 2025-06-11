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

# Build Docker image
docker-build:
	docker compose build

# Run with Docker
docker-run:
	docker compose up -d

# Stop Docker containers
docker-stop:
	docker compose down

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
	@echo "  make docker-build   - Build Docker image"
	@echo "  make docker-run     - Run with Docker"
	@echo "  make docker-stop    - Stop Docker containers"
	@echo "  make lint           - Run linting with clippy"
	@echo "  make fmt            - Format code"
	@echo "  make fmt-check      - Check code formatting"
	@echo "  make check          - Type check the code"
	@echo "  make ci             - Run all checks (format, lint, type check, test)"
	@echo "  make help           - Show this help message"