# Conduit Proxy

Conduit is a forward MITM (man-in-the-middle) proxy built on Cloudflare's [Pingora](https://github.com/cloudflare/pingora) framework. It intercepts, inspects, and enforces policy on HTTP/HTTPS traffic passing through your network.

## What it does

- **TLS interception** — Decrypts CONNECT tunnels to inspect full request URLs and response bodies, or runs in passthrough mode for privacy-first deployments.
- **Policy enforcement** — Domain allow/block lists, category-based filtering, and user-level rules managed via API and stored in Dragonfly (Redis-compatible).
- **Threat detection** — Multi-tier pipeline: fast heuristics, ML model scoring, content inspection, optional LLM analysis, and domain reputation tracking.
- **Data Loss Prevention** — Regex-based scanning for sensitive data (SSN, credit cards, API keys) with configurable actions (log, block, redact).
- **Operational hardening** — Rate limiting, connection limits, DNS caching, HTTP response caching, load balancing, Prometheus metrics.

## Components

| Component | Description |
|-----------|-------------|
| `conduit-proxy` | Pingora-based forward proxy (the main binary) |
| `conduit-api` | Axum REST API for policy management, logs, and node orchestration |
| `conduit-common` | Shared types, configuration, CA utilities, Redis helpers |
| `conduit-ui` | SvelteKit web dashboard for managing rules and viewing logs |

## How it works

Clients configure Conduit as their HTTP proxy. Plain HTTP requests flow through directly. For HTTPS, clients send a `CONNECT` request; Conduit establishes a TLS tunnel with dynamic certificate generation, allowing it to inspect the decrypted traffic before forwarding to the upstream server.

All policy rules, logs, and state are stored in Dragonfly for fast access and multi-node coordination.
