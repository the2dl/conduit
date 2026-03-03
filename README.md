# conduit

MITM proxy built on Cloudflare's [Pingora](https://github.com/cloudflare/pingora) framework.

## Quick start

### Prerequisites

- Rust toolchain (stable)
- cmake, libclang-dev (for BoringSSL build)
- [Dragonfly](https://www.dragonflydb.io/) (Redis-compatible) — or use the provided docker-compose

### Run Dragonfly

```sh
docker compose up -d
```

### Build & run

```sh
cargo build --release
./target/release/conduit-proxy   # listens on :8888 by default
./target/release/conduit-api     # management API on :8443
```

### Configuration

conduit reads `conduit.toml` by default. Override with the `CONDUIT_CONFIG` env var:

```sh
CONDUIT_CONFIG=/etc/conduit/conduit.toml ./target/release/conduit-proxy
```

See `conduit.toml` for all available options.

## Crates

| Crate | Description |
|-------|-------------|
| `conduit-common` | Shared types, config, CA, Redis helpers |
| `conduit-proxy` | Pingora-based MITM proxy |
| `conduit-api` | Axum management API |

## UI

The SvelteKit management UI lives in `conduit-ui/`.

```sh
cd conduit-ui
npm install
npm run build   # static build output goes to conduit-ui/build/
npm run dev      # dev server
```

## Docker

```sh
docker build --target proxy -t conduit-proxy .
docker build --target api -t conduit-api .
```

## License

Proprietary.
