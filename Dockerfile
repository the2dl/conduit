# Multi-stage build for Linux containers
# For local macOS testing, just run the binaries directly
FROM rust:1.93-bookworm AS builder

RUN apt-get update && apt-get install -y \
    cmake \
    libclang-dev \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .

RUN cargo build --release --bin conduit-proxy --bin conduit-api

# Proxy image
FROM debian:bookworm-slim AS proxy
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/conduit-proxy /usr/local/bin/
ENTRYPOINT ["conduit-proxy"]

# API image
FROM debian:bookworm-slim AS api
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/conduit-api /usr/local/bin/
ENTRYPOINT ["conduit-api"]
