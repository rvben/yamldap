# Build stage
FROM rust:1.87 as builder

WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY src ./src

RUN cargo build --release

# Runtime stage
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/yamldap /usr/local/bin/yamldap

# Create directory for YAML files
RUN mkdir -p /data

# Default to port 389 (standard LDAP port)
EXPOSE 389

# Run as non-root user
RUN useradd -m -u 1000 yamldap
USER yamldap

# Default command expects a YAML file to be mounted at /data/directory.yaml
CMD ["yamldap", "-f", "/data/directory.yaml"]