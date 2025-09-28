# Stage 1: Build the Rust app
FROM rust:1.90-slim-bookworm AS builder

# Install dependencies for building
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/app

# Copy Cargo files and cache dependencies
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release

# Stage 2: Create runtime image
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    libssl3 \
    libpq5 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy the compiled binary
COPY --from=builder /usr/src/app/target/release/wallet-service /usr/local/bin/wallet-service

# Run as non-root user
RUN useradd -m -u 1000 appuser
USER appuser

# Expose the Axum server port
EXPOSE 3000

# Environment variables
ENV RUST_LOG=debug
ENV DATABASE_URL=postgres://wallet_user:wallet_pass@postgres:5432/wallet
ENV JWT_SECRET=your-secure-jwt-secret

CMD ["wallet-service"]
