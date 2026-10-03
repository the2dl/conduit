# Installation

## Turnkey Native Installation (Recommended)

Conduit includes a turnkey installer script (`scripts/install.sh`) that detects your Linux distribution (**Arch Linux**, **Debian/Ubuntu**, **Fedora/RHEL**), installs native dependencies and the **Valkey** datastore, compiles the SvelteKit UI and release binaries, and sets up systemd services.

### One-Command Turnkey Profiles

#### 1. Standard Linux (Production)
Installs Conduit as a production system daemon under `/usr/local/bin` and `/etc/conduit` (unprivileged `conduit` user), starts native Valkey, trusts the Root CA, routes shell traffic via `/etc/profile.d/conduit.sh`, and applies egress firewall lockdown:

```sh
git clone https://github.com/the2dl/conduit.git
cd conduit
sudo ./scripts/install.sh --all
```

#### 2. Omarchy Linux
Installs everything in `--all` plus the native Omarchy desktop status bar widget:

```sh
git clone https://github.com/the2dl/conduit.git
cd conduit
sudo ./scripts/install.sh --all-omarchy
```

#### 3. User Service Installation (Local / Desktop)

Installs as a user-level systemd service (`~/.config/systemd/user`) in your current environment:

```sh
./scripts/install.sh --user
```

### Installer Options

| Flag | Description |
|---|---|
| `--all` | Full install: system daemon, Valkey, UI, CA trust, system proxy, & firewall lockdown |
| `--all-omarchy` | Full install + Omarchy desktop bar widget plugin |
| `--system` | Install system-wide daemons and config under `/etc/conduit` (requires sudo) |
| `--user` | Install systemd user services under `~/.config/systemd/user` |
| `--trust-ca` | Install and trust Conduit root CA into OS certificate store |
| `--system-proxy` | Configure `/etc/profile.d/conduit.sh` to route all shells through Conduit |
| `--firewall` | Lock down host egress firewall (nftables/iptables) to prevent proxy bypass |
| `--omarchy` | Install and enable Conduit desktop status bar widget plugin for Omarchy |
| `--skip-build` | Skip building release binaries and UI (if already built) |
| `--skip-deps` | Skip package manager dependency installation |
| `--skip-seed` | Skip initial threat feeds and category database seeding |
| `-y, --yes` | Run non-interactively without prompts |

---

## Manual Prerequisites & Building

If you prefer to install manually without the automated script:

- **Rust toolchain** (stable) — install via [rustup](https://rustup.rs/)
- **cmake**, **perl**, and build essentials — required for BoringSSL compilation
- **Node.js** and **npm** — required for the SvelteKit management UI
- **Valkey** (or Redis/Dragonfly) — high-performance in-memory datastore on port `6379`

### Distribution Packages

- **Arch Linux:** `sudo pacman -S --needed base-devel cmake perl nodejs npm valkey`
- **Ubuntu/Debian:** `sudo apt install -y build-essential cmake perl pkg-config libssl-dev nodejs npm valkey` (or `valkey-server` / `redis-server`)
- **Fedora/RHEL:** `sudo dnf install -y @development-tools cmake perl openssl-devel nodejs npm valkey`

### Build from Source

```sh
# Build UI dashboard
cd conduit-ui
npm install && npm run build
cd ..

# Build release binaries
cargo build --release --bin conduit-api --bin conduit-proxy
```

This produces:
- `target/release/conduit-proxy` — the Pingora MITM forward proxy
- `target/release/conduit-api` — the management REST API and UI host

### Start Valkey

```sh
sudo systemctl enable --now valkey
```

### Verify

```sh
./scripts/conduit-ctl.sh status
```
