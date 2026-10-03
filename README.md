# Conduit Security Gateway

> High-performance MITM forward proxy, threat prevention engine, and security gateway built on Cloudflare's [Pingora](https://github.com/cloudflare/pingora) framework with native **Valkey** datastore support.

---

## Overview

Conduit is an enterprise-grade local and edge security gateway designed for endpoints, developer workstations, and cloud clusters. It intercepts, inspects, and enforces security policies across all outbound HTTP/HTTPS traffic with sub-millisecond latency.

### Key Capabilities

- **Pingora-Powered Proxy**: Built on Cloudflare's async Pingora engine with dynamic per-domain TLS certificate generation, HTTP/1.1 & HTTP/2 downstream support, and response caching.
- **Native Valkey Datastore**: Zero Docker required. Uses [Valkey](https://valkey.io/) (the open-source BSD-3-Clause Redis continuation under the Linux Foundation) on standard port `6379`, with transparent compatibility for Redis and Dragonfly.
- **Multi-Distribution Turnkey Installer**: One-command automated installation for **Arch Linux**, **Debian / Ubuntu**, **Fedora / RHEL**, and **Omarchy**.
- **Host Egress Firewall Lockdown**: Kernel-level `nftables` or `iptables` lockdown enforcing that all outbound ports 80/443 on the machine must route through Conduit—preventing bypass by rogue scripts or malware.
- **Multi-Tier Threat Detection**:
  - **Bloom Filters**: Instant lookup against 1.5M+ malicious URLs/domains from URLhaus, OpenPhish, ThreatFox, and Hagezi TIF.
  - **Heuristics & DGA Detection**: Shannon entropy calculations, suspicious TLD risk scoring, and SSO phishing mimicry analysis.
  - **Package Threat Scanner**: Deep payload inspection detecting dropper scripts, reverse shells, and credential scrapers in `npm`, `pip`, and `cargo` packages.
  - **IP Reputation**: IPv4/IPv6 CIDR blocklist matching.
- **Data Loss Prevention (DLP)**: Real-time request inspection scanning for leaked AWS keys, GitHub PATs, private keys, Discord webhooks, PyPI/npm tokens, and custom regex rules with domain allowlists.
- **Automated Domain Categorization**: Background categorization engine with parallel HTML title/meta pre-fetch probes and local agent grounding (`agy`, `codex`, `claude`, or rule-based UT1 database).
- **Modern SvelteKit Dashboard**: Web UI on `:8443` featuring live traffic charts, policy builders, category management, DLP inspectors, and multi-node clustering.
- **Omarchy Desktop Widget**: Native status bar widget for Omarchy Linux displaying live throughput, proxy status, and prevention toggles.

---

## Turnkey Installation

Conduit includes a turnkey installer script (`scripts/install.sh`) that detects your Linux distribution, installs native dependencies and Valkey, compiles the SvelteKit UI and release binaries, sets up hardened systemd services, seeds category/threat datasets, and generates & trusts the Root CA.

### One-Command Turnkey Profiles

#### 1. Standard Linux (Arch Linux, Debian/Ubuntu, Fedora/RHEL)
Installs Conduit as a production system daemon under `/usr/local/bin` and `/etc/conduit` (unprivileged `conduit` user), starts native Valkey, trusts the Root CA, routes shell traffic via `/etc/profile.d/conduit.sh`, and applies egress firewall lockdown:

```bash
git clone https://github.com/the2dl/conduit.git
cd conduit
sudo ./scripts/install.sh --all
```

#### 2. Omarchy Linux
Installs everything in `--all` plus the native Omarchy desktop status bar widget:

```bash
git clone https://github.com/the2dl/conduit.git
cd conduit
sudo ./scripts/install.sh --all-omarchy
```

#### 3. User-Level Service (Desktop / Development)
Installs as a systemd user service in your current environment without requiring root:

```bash
./scripts/install.sh --user
```

---

### Installer CLI Reference

```
Usage:
  ./scripts/install.sh [OPTIONS]

Turnkey Profiles:
  --all            Full install: system daemon, Valkey, UI, CA trust, system proxy, & firewall lockdown
  --all-omarchy    Full install + Omarchy desktop bar widget plugin

Modular Options:
  --system         Install as system-wide daemon in /usr/local/bin & /etc/conduit (requires sudo)
  --user           Install as user-level service in ~/.config/systemd/user (default for non-root)
  --trust-ca       Install Conduit root CA into OS certificate trust store (requires sudo)
  --system-proxy   Install /etc/profile.d/conduit.sh to route shell traffic (requires sudo)
  --firewall       Lock down host egress firewall (nftables/iptables) to enforce proxying (requires sudo)
  --omarchy        Install and enable the Conduit desktop bar widget plugin for Omarchy
  --skip-build     Skip compiling release binaries and UI (if already built)
  --skip-deps      Skip package manager dependency installation
  --skip-seed      Skip threat feeds and category dataset seeding
  -y, --yes        Non-interactive mode (proceed without prompts)
  -h, --help       Show this help message
```

---

## Supported Environments & Datastores

### Linux Distributions

| Distribution | Package Manager | System Service Packages | Datastore Service |
|---|---|---|---|
| **Arch Linux** / Manjaro / Omarchy | `pacman` | `base-devel cmake perl pkgconf openssl nodejs npm valkey` | `valkey.service` |
| **Debian / Ubuntu** | `apt-get` | `build-essential cmake perl pkg-config libssl-dev nodejs npm curl ca-certificates valkey` *(or `redis-server`)* | `valkey.service` / `redis-server.service` |
| **Fedora / RHEL / Rocky** | `dnf` | `@development-tools cmake perl openssl-devel nodejs npm valkey` | `valkey.service` |

### Datastores

Conduit communicates using standard Redis RESP protocol and natively supports:
- **Valkey** (`:6379`) — *Default & Recommended*
- **Redis** (`:6379`) — *Fully supported fallback*
- **Dragonfly** (`:6379` or `:6380`) — *Fully supported*

---

## Feature Guides & Configuration

Conduit reads `/etc/conduit/conduit.toml` (system mode) or `./conduit.toml` (user mode). See [`conduit.example.toml`](conduit.example.toml) for annotated options.

### 1. TLS Interception (MITM)
To decrypt and inspect HTTPS traffic (required for DLP, package scanning, and full URL heuristics):
1. In `conduit.toml`:
   ```toml
   tls_intercept = true
   ```
2. Trust the Root CA in your system trust store:
   ```bash
   sudo ./scripts/install.sh --trust-ca
   ```
   *(Or import `ca/ca.pem` into Firefox/Chrome/OS keychain manually).*

### 2. Host Egress Firewall Lockdown
Prevent rogue scripts, malware, or misconfigured processes from bypassing the proxy:
```bash
# Enable lockdown (blocks direct 80/443 for non-proxy users)
sudo ./scripts/setup-firewall.sh --enable

# Check lockdown status
sudo ./scripts/setup-firewall.sh --status

# Disable lockdown
sudo ./scripts/setup-firewall.sh --disable
```

### 3. Automated Domain Categorization
Conduit captures uncategorized domains on the fly, probes the site's `<title>` and `<meta name="description">` in parallel, and runs automated classification:
- **Agents supported**: `agy` (Antigravity CLI), `codex`, `claude`, or `"none"` (heuristic UT1 rule sync).
- Configure in the UI under **Settings → Auto-Categorization**, or via API:
  ```bash
  curl -X POST http://localhost:8443/api/v1/config \
    -H "Content-Type: application/json" \
    -d '{"auto_categorize_enabled":"true","auto_categorize_agent":"agy"}'
  ```

### 4. Prevention Mode (Enforcement vs. Audit)
- In **Audit mode** (`prevention_mode = false`), threat scores and DLP violations are logged and alerted on without blocking.
- In **Prevention mode** (`prevention_mode = true`), threats exceeding threshold scores are blocked with a custom HTML block page.
- Toggle instantly in the Management UI dashboard or via API:
  ```bash
  curl -X POST http://localhost:8443/api/v1/config \
    -H "Content-Type: application/json" \
    -d '{"prevention_mode":"true","threat_block_threshold":"0.7"}'
  ```

### 5. Data Loss Prevention (DLP)
Inspect outbound request bodies for sensitive secrets:
```toml
[dlp]
enabled = true
max_scan_size = 1048576          # 1MB scan limit
action = "block"                   # "log", "block", or "redact"
allowed_domains = [
    "*.pkg.dev",
    "*.docker.pkg.dev",
]
```

### 6. Shell Proxy Routing
To quickly toggle proxying in your current shell:
```bash
# Enable
source ./scripts/env.sh

# Disable
source ./scripts/unenv.sh
```

---

## Operating & Management

### Management UI
Visit **[http://localhost:8443](http://localhost:8443)** for the SvelteKit dashboard:
- **Live Traffic**: Real-time throughput, status codes, and active tunnels.
- **Policies**: Allow/block lists, user-specific rules, and category filters.
- **Threat Intelligence**: Bloom filter entry counts, threat feed refresh toggles, and signal scores.
- **DLP**: Secret detection logs and custom regex pattern management.
- **Cluster Nodes**: Multi-node health, latency, and synchronization.

### CLI Controller (`conduit-ctl`)
Conduit includes `scripts/conduit-ctl.sh` (installed to `/usr/local/bin/conduit-ctl` in system mode):
```bash
conduit-ctl status     # Inspect systemd units, Valkey status, proxy & API health
conduit-ctl restart    # Gracefully restart proxy and API
conduit-ctl stop       # Stop proxy and API
conduit-ctl start      # Start services
```

### Systemd Service Management
- **System mode**:
  ```bash
  sudo systemctl status conduit.target conduit-proxy conduit-api
  sudo journalctl -u conduit-proxy -f
  ```
- **User mode**:
  ```bash
  systemctl --user status conduit.target conduit-proxy conduit-api
  tail -f logs/proxy.log
  ```

---

## Project Structure

```
├── conduit/
│   ├── conduit-common/     # Shared configuration, CA generation, Redis keys, utilities
│   ├── conduit-proxy/      # Pingora MITM proxy, TLS cert cache, threat & DLP pipeline
│   ├── conduit-api/        # Axum REST API, SvelteKit UI static file server, threat scheduler
│   └── conduit-mock/       # Upstream mock server for end-to-end integration tests
├── conduit-ui/             # Modern SvelteKit management dashboard
├── deploy/
│   ├── systemd/
│   │   ├── system/         # Production systemd units (/etc/systemd/system)
│   │   └── user/           # User systemd units (~/.config/systemd/user)
│   ├── omarchy/            # Native Omarchy desktop bar widget plugin
│   └── k8s/                # Kubernetes deployment manifests
├── docs/                   # mdBook architectural and user documentation
└── scripts/
    ├── install.sh          # Multi-distro turnkey installer script
    ├── conduit-ctl.sh      # Service controller and health inspector
    ├── setup-firewall.sh   # Host egress firewall lockdown utility
    ├── seed-dragonfly.sh   # Threat feeds and UT1 dataset datastore loader
    ├── env.sh              # Shell environment proxy activator
    └── unenv.sh            # Shell environment proxy deactivator
```

---

## License

Conduit is licensed under the [Apache License, Version 2.0](LICENSE).
