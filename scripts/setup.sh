#!/usr/bin/env bash
# setup.sh — Turnkey installer and bootstrap for Conduit on a clean machine
#
# Usage:
#   ./scripts/setup.sh [OPTIONS]
#
# Options:
#   --trust-ca       Install Conduit root CA into OS trust store (requires sudo)
#   --system-proxy   Install system-wide proxy settings in /etc/profile.d (requires sudo)
#   --firewall       Lock down host firewall to prevent bypassing Conduit (requires sudo)
#   --skip-build     Skip building release binaries and UI if already compiled
#   --skip-seed      Skip threat feeds and domain category dataset seeding
#   -h, --help       Show this help message

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$ROOT_DIR"

TRUST_CA=false
SYSTEM_PROXY=false
ENABLE_FIREWALL=false
SKIP_BUILD=false
SKIP_SEED=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --trust-ca) TRUST_CA=true; shift ;;
    --system-proxy) SYSTEM_PROXY=true; shift ;;
    --firewall|--lockdown) ENABLE_FIREWALL=true; shift ;;
    --skip-build) SKIP_BUILD=true; shift ;;
    --skip-seed) SKIP_SEED=true; shift ;;
    -h|--help)
      cat << 'EOF'
Usage:
  ./scripts/setup.sh [OPTIONS]

Options:
  --trust-ca       Install Conduit root CA into OS trust store (requires sudo)
  --system-proxy   Install system-wide proxy settings in /etc/profile.d (requires sudo)
  --firewall       Lock down host firewall to prevent bypassing Conduit (requires sudo)
  --skip-build     Skip building release binaries and UI if already compiled
  --skip-seed      Skip threat feeds and domain category dataset seeding
  -h, --help       Show this help message
EOF
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      exit 1
      ;;
  esac
done

echo "=========================================================="
echo "          Conduit Security Gateway Setup"
echo "=========================================================="
echo "Working directory: $ROOT_DIR"
echo "User: $USER (UID: $(id -u))"
echo ""

# ── 1. Check Prerequisites ───────────────────────────────────────────
echo "--- 1. Checking Prerequisites ---"

MISSING_DEPS=()
check_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    MISSING_DEPS+=("$1")
  fi
}

check_cmd docker
check_cmd cargo
check_cmd rustc
check_cmd node
check_cmd npm
check_cmd cmake
check_cmd make
check_cmd perl

if [ ${#MISSING_DEPS[@]} -gt 0 ]; then
  echo "Missing required system dependencies: ${MISSING_DEPS[*]}" >&2
  echo ""
  echo "Please install them using your package manager:"
  echo "  Ubuntu/Debian: sudo apt update && sudo apt install -y build-essential cmake perl pkg-config libssl-dev nodejs npm"
  echo "  Arch Linux:    sudo pacman -S --needed base-devel cmake perl nodejs npm"
  echo "  Fedora:        sudo dnf install -y @development-tools cmake perl nodejs npm"
  echo "  Rust toolchain: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
  exit 1
fi

if ! docker info >/dev/null 2>&1; then
  echo "Error: Docker daemon is not running or current user cannot access Docker socket." >&2
  echo "Ensure Docker is started: sudo systemctl start docker"
  echo "Ensure your user is in the docker group: sudo usermod -aG docker $USER"
  exit 1
fi

echo "  All build and runtime dependencies detected."

# ── 2. Initialize Directories and Configuration ─────────────────────
echo ""
echo "--- 2. Initializing Configuration ---"
mkdir -p "$ROOT_DIR/logs" "$ROOT_DIR/ca" "$HOME/.config/systemd/user"

if [ ! -f "$ROOT_DIR/conduit.toml" ]; then
  echo "  Creating conduit.toml from conduit.example.toml..."
  cp "$ROOT_DIR/conduit.example.toml" "$ROOT_DIR/conduit.toml"
  # Uncomment default CA paths
  sed -i 's|^# ca_cert_path = .*|ca_cert_path = "ca/ca.pem"|' "$ROOT_DIR/conduit.toml"
  sed -i 's|^# ca_key_path = .*|ca_key_path = "ca/ca-key.pem"|' "$ROOT_DIR/conduit.toml"
else
  echo "  conduit.toml already exists."
fi

# ── 3. Start Datastore (Dragonfly) ───────────────────────────────────
echo ""
echo "--- 3. Starting Dragonfly Datastore ---"
docker compose up -d dragonfly

echo -n "  Waiting for Dragonfly on :6380..."
for i in {1..30}; do
  if docker exec conduit-dragonfly redis-cli -p 6379 ping 2>/dev/null | grep -q PONG; then
    echo " online."
    break
  fi
  sleep 0.5
  if [ "$i" -eq 30 ]; then
    echo " TIMEOUT waiting for Dragonfly." >&2
    exit 1
  fi
done

# Initialize localhost IP map in Dragonfly
docker exec conduit-dragonfly redis-cli -p 6379 HSET cleargate:ip_map 127.0.0.1 "$USER" >/dev/null 2>&1 || true

# ── 4. Build Frontend UI ─────────────────────────────────────────────
if [ "$SKIP_BUILD" = false ]; then
  echo ""
  echo "--- 4. Building Conduit UI ---"
  (
    cd "$ROOT_DIR/conduit-ui"
    if [ ! -d "node_modules" ]; then
      npm install --silent
    fi
    npm run build
  )
  echo "  UI build complete."

  # ── 5. Build Backend Binaries ───────────────────────────────────────
  echo ""
  echo "--- 5. Building Release Binaries (conduit-api, conduit-proxy) ---"
  cargo build --release --bin conduit-api --bin conduit-proxy
  echo "  Rust binaries compiled."
else
  echo ""
  echo "--- Skipping compilation (--skip-build) ---"
fi

# ── 6. Install Systemd User Services ─────────────────────────────────
echo ""
echo "--- 6. Configuring Systemd User Services ---"
mkdir -p "$HOME/.config/systemd/user"
cp "$ROOT_DIR/deploy/systemd/"* "$HOME/.config/systemd/user/"

systemctl --user daemon-reload
systemctl --user enable conduit.target
systemctl --user restart conduit-dragonfly conduit-api conduit-proxy
echo "  Systemd user services enabled and started."

echo -n "  Waiting for API on :8443..."
for i in {1..40}; do
  if curl -sf http://127.0.0.1:8443/api/v1/health >/dev/null 2>&1; then
    echo " healthy."
    break
  fi
  sleep 0.5
  if [ "$i" -eq 40 ]; then
    echo " Warning: API health check timed out. Checking logs..."
    tail -n 20 "$ROOT_DIR/logs/api.log" || true
  fi
done

# ── 7. Seed Dragonfly Dataset ────────────────────────────────────────
if [ "$SKIP_SEED" = false ]; then
  echo ""
  echo "--- 7. Seeding Dragonfly Data ---"
  "$ROOT_DIR/scripts/seed-dragonfly.sh"
else
  echo ""
  echo "--- Skipping datastore seeding (--skip-seed) ---"
fi

# ── 8. Root CA Certificate Export & Trust Store ──────────────────────
echo ""
echo "--- 8. Root CA Certificate ---"
mkdir -p "$ROOT_DIR/ca"
curl -sf http://127.0.0.1:8443/api/v1/ca/cert -o "$ROOT_DIR/ca/ca.pem" || true

if [ "$TRUST_CA" = true ]; then
  echo "  Installing Conduit Root CA into system trust store..."
  if command -v update-ca-certificates >/dev/null 2>&1; then
    # Debian / Ubuntu
    sudo cp "$ROOT_DIR/ca/ca.pem" /usr/local/share/ca-certificates/conduit-ca.crt
    sudo update-ca-certificates
    echo "  Installed via update-ca-certificates."
  elif command -v trust >/dev/null 2>&1; then
    # Arch Linux / generic p11-kit
    sudo cp "$ROOT_DIR/ca/ca.pem" /etc/ca-certificates/trust-source/anchors/conduit-ca.crt
    sudo trust extract-compat
    echo "  Installed via trust extract-compat."
  elif command -v update-ca-trust >/dev/null 2>&1; then
    # Fedora / RHEL
    sudo cp "$ROOT_DIR/ca/ca.pem" /etc/pki/ca-trust/source/anchors/conduit-ca.crt
    sudo update-ca-trust
    echo "  Installed via update-ca-trust."
  else
    echo "  Warning: Unable to detect system CA trust utility. Please install ca/ca.pem manually."
  fi
else
  echo "  CA saved to $ROOT_DIR/ca/ca.pem."
  echo "  To trust system-wide, re-run with: ./scripts/setup.sh --trust-ca"
fi

# ── 9. Shell & System Proxy Environment ──────────────────────────────
echo ""
echo "--- 9. Shell Environment Helper ---"
chmod +x "$ROOT_DIR/scripts/env.sh" "$ROOT_DIR/scripts/unenv.sh" "$ROOT_DIR/scripts/conduit-ctl.sh"

if [ "$SYSTEM_PROXY" = true ]; then
  echo "  Installing /etc/profile.d/conduit.sh for system-wide shell proxying..."
  sudo ln -sf "$ROOT_DIR/scripts/env.sh" /etc/profile.d/conduit.sh
  echo "  System-wide profile installed."
else
  echo "  To route your current shell through Conduit: source ./scripts/env.sh"
  echo "  To install system-wide across all shells, re-run with: ./scripts/setup.sh --system-proxy"
fi

# ── 10. Optional Egress Firewall Lockdown ────────────────────────────
if [ "$ENABLE_FIREWALL" = true ]; then
  echo ""
  echo "--- 10. Egress Firewall Lockdown ---"
  sudo "$ROOT_DIR/scripts/setup-firewall.sh" --enable "$USER"
fi

echo ""
echo "=========================================================="
echo "            Conduit Setup Complete!"
echo "=========================================================="
echo "  Management UI:    http://localhost:8443"
echo "  HTTP/HTTPS Proxy: http://127.0.0.1:8888"
echo "  Prometheus Stats: http://localhost:9091"
echo ""
echo "  Quick Commands:"
echo "    ./scripts/conduit-ctl.sh status   Check status of all components"
echo "    source ./scripts/env.sh           Enable proxy in current shell"
echo "    source ./scripts/unenv.sh         Disable proxy in current shell"
echo "    sudo ./scripts/setup-firewall.sh  Toggle host egress firewall lockdown"
echo "=========================================================="
