# Build stage
FROM rust:1.85-slim-bookworm AS builder

WORKDIR /usr/src/kagi
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY migrations ./migrations

# Build the full binary with server feature
RUN cargo build --release --locked

# Runtime stage
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates sqlite3 wget && rm -rf /var/lib/apt/lists/*

# Create a non-root user
RUN useradd -m -u 1000 -s /bin/bash kagi

WORKDIR /home/kagi

# Copy the binary from the builder stage
COPY --from=builder /usr/src/kagi/target/release/kagi /usr/local/bin/kagi

# Ensure the binary is executable
RUN chmod +x /usr/local/bin/kagi

# Create directories for data and server key
RUN mkdir -p /home/kagi/data /home/kagi/server && chown -R kagi:kagi /home/kagi

USER kagi

EXPOSE 8787

ENV KAGI_HOME=/home/kagi/data

# Default: bind on all interfaces so the container is reachable
CMD ["kagi", "serve", "--bind", "0.0.0.0:8787", "--db", "/home/kagi/data/kagi.db", "--key-file", "/home/kagi/server/server.key.json", "--allow-insecure-http"]
