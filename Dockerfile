# Build stage
FROM rust:1.87 as builder

# Install musl tools for static linking
RUN apt-get update && \
    apt-get install -y musl-tools && \
    rustup target add x86_64-unknown-linux-musl && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY src ./src

# Build a fully static binary for x86_64
RUN RUSTFLAGS='-C target-feature=+crt-static' cargo build --release --target x86_64-unknown-linux-musl

# Runtime stage - using scratch (empty image)
FROM scratch

# Copy only the binary
COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/yamldap /yamldap

# Default to port 389 (standard LDAP port)
EXPOSE 389

# The binary is the entrypoint
ENTRYPOINT ["/yamldap"]