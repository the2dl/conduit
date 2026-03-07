# Installation

## Prerequisites

- **Rust toolchain** (stable) — install via [rustup](https://rustup.rs/)
- **cmake** and **libclang-dev** — required for BoringSSL compilation
- **Dragonfly** (or Redis) — used for policy storage, logs, and coordination

### macOS

```sh
brew install cmake llvm
```

### Ubuntu/Debian

```sh
apt install cmake libclang-dev build-essential
```

## Build from source

```sh
git clone https://github.com/dan/conduit-proxy.git
cd conduit-proxy
cargo build --release
```

This produces two binaries:

- `target/release/conduit-proxy` — the forward proxy
- `target/release/conduit-api` — the management API

## Run Dragonfly

The easiest way to get Dragonfly running is with the included Docker Compose file:

```sh
docker compose up -d
```

This starts Dragonfly on port `6380`.

## Verify

```sh
./target/release/conduit-proxy --help
```
