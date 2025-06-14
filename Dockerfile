# Multi-stage Dockerfile for yamldap
# This builds the binary from source for multi-platform support

# Build stage
FROM rust:1.87 AS builder

# Install musl tools for static linking
RUN apt-get update && \
    apt-get install -y musl-tools && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY src ./src

# Detect target platform and build accordingly
ARG TARGETPLATFORM
RUN case "$TARGETPLATFORM" in \
        "linux/amd64") RUST_TARGET="x86_64-unknown-linux-musl" ;; \
        "linux/arm64") RUST_TARGET="aarch64-unknown-linux-musl" ;; \
        *) echo "Unsupported platform: $TARGETPLATFORM" && exit 1 ;; \
    esac && \
    rustup target add $RUST_TARGET && \
    RUSTFLAGS='-C target-feature=+crt-static' cargo build --release --target $RUST_TARGET && \
    cp target/$RUST_TARGET/release/yamldap /yamldap

# Runtime stage - using scratch (empty image)
FROM scratch

# Copy only the binary
COPY --from=builder /yamldap /yamldap

# Default to port 389 (standard LDAP port)
EXPOSE 389

# The binary is the entrypoint
ENTRYPOINT ["/yamldap"]