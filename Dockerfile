# Use Rust base image
FROM rust:1.90 as builder

# Set working directory
WORKDIR /app

# Copy Cargo.toml and Cargo.lock
COPY Cargo.toml Cargo.lock ./

# Copy source code
COPY src ./src

# Build the application
RUN cargo build

# Final stage
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y libssl3 ca-certificates && rm -rf /var/lib/apt/lists/*

# Copy the binary from builder
COPY --from=builder /app/target/release/walletserviceauth /usr/local/bin/walletserviceauth

# Create file db
RUN mkdir -p /data && chmod 777 /data

# Set environment variables (optional, e.g., for JWT_SECRET)
ENV JWT_SECRET=supersecretkey
ENV RUST_LOG=info

# Expose port
EXPOSE 3000

# Run the application
CMD ["walletserviceauth"]
