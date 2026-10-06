#!/usr/bin/env bash
# install.sh — Turnkey Native Installer for Conduit Security Gateway
# Supports: Arch Linux, Debian/Ubuntu, Fedora/RHEL
# Datastore: Native Valkey (with fallback to Redis)
#
# Usage:
#   ./scripts/install.sh [OPTIONS]
#
# Options:
#   --system         Install as a hardened systemd system service under /etc/conduit
#                    and /usr/local/bin with unprivileged 'conduit' user (requires sudo)
#   --user           Install as a systemd user service in ~/.config/systemd/user
#   --trust-ca       Install Conduit root CA into OS certificate trust store (requires sudo)
#   --system-proxy   Install /etc/profile.d/conduit.sh to route all shell traffic (requires sudo)
#   --firewall       Lock down host firewall to prevent bypassing Conduit (requires sudo)
#   --skip-build     Skip compiling release binaries and UI (use existing build)
#   --skip-deps      Skip installing distro packages
#   --skip-seed      Skip threat feeds and domain category dataset seeding
#   -y, --yes        Non-interactive mode (accept all defaults)
#   -h, --help       Show this help message

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$ROOT_DIR"

# ── Defaults ───────────────────────────────────────────────────────────
INSTALL_MODE="auto" # 'system' or 'user'
TRUST_CA=false
SYSTEM_PROXY=false
ENABLE_FIREWALL=false
ENABLE_OMARCHY=false
SKIP_BUILD=false
SKIP_DEPS=false
SKIP_SEED=false
NON_INTERACTIVE=false

# ── Argument Parsing ───────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --all)
      INSTALL_MODE="system"
      TRUST_CA=true
      SYSTEM_PROXY=true
      ENABLE_FIREWALL=true
      shift
      ;;
    --all-omarchy)
      INSTALL_MODE="system"
      TRUST_CA=true
      SYSTEM_PROXY=true
      ENABLE_FIREWALL=true
      ENABLE_OMARCHY=true
      shift
      ;;
    --system) INSTALL_MODE="system"; shift ;;
    --user) INSTALL_MODE="user"; shift ;;
    --trust-ca) TRUST_CA=true; shift ;;
    --system-proxy) SYSTEM_PROXY=true; shift ;;
    --firewall|--lockdown) ENABLE_FIREWALL=true; shift ;;
    --omarchy) ENABLE_OMARCHY=true; shift ;;
    --fix|--repair)
      exec "$SCRIPT_DIR/fix.sh" "$@"
      ;;
    --disable)
      exec "$SCRIPT_DIR/uninstall.sh" --disable
      ;;
    --uninstall|--purge)
      exec "$SCRIPT_DIR/uninstall.sh" --purge
      ;;
    --skip-build) SKIP_BUILD=true; shift ;;
    --skip-deps) SKIP_DEPS=true; shift ;;
    --skip-seed) SKIP_SEED=true; shift ;;
    -y|--yes) NON_INTERACTIVE=true; shift ;;
    -h|--help)
      cat << 'EOF'
Conduit Security Gateway — Native Linux Installer

Usage:
  ./scripts/install.sh [OPTIONS]

Turnkey Profiles:
  --all            Full install: system daemon, Valkey, UI, CA trust, system proxy, & firewall lockdown
  --all-omarchy    Full install + Omarchy desktop bar widget plugin

Lifecycle Controls:
  --fix            Audit installation, detect configuration gaps, and self-repair (no rebuild)
  --disable        Cleanly disable all proxy routing, firewall, and services (zero ghost state)
  --uninstall      Purge all installed binaries, configs, systemd services, and root CAs

Modular Options:
  --system         Install as system-wide daemon in /usr/local/bin & /etc/conduit (requires sudo)
  --user           Install as user-level service in ~/.config/systemd/user (default for non-root)
  --trust-ca       Install Conduit root CA into OS certificate trust store (requires sudo)
  --system-proxy   Install /etc/profile.d/conduit.sh to route shell traffic (requires sudo)
  --firewall       Lock down host egress firewall (nftables/iptables) to enforce proxying (requires sudo)
  --omarchy        Install and enable the Conduit desktop bar widget plugin for Omarchy
  --skip-build     Skip compiling release binaries and UI
  --skip-deps      Skip package manager dependency installation
  --skip-seed      Skip threat feeds and category dataset seeding
  -y, --yes        Non-interactive mode (proceed without prompts)
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

# Resolve install mode if auto
if [ "$INSTALL_MODE" = "auto" ]; then
  if [ "$(id -u)" -eq 0 ]; then
    INSTALL_MODE="system"
  else
    INSTALL_MODE="user"
  fi
fi

# Determine sudo command
SUDO=""
if [ "$(id -u)" -ne 0 ]; then
  if command -v sudo >/dev/null 2>&1; then
    SUDO="sudo"
  else
    echo "Error: sudo is required for system configuration steps." >&2
    exit 1
  fi
fi

# Detect calling user
REAL_USER="${SUDO_USER:-$USER}"
REAL_HOME="$(eval echo "~$REAL_USER")"

# If invoked via sudo, ensure source repository files belong to the invoking user
if [ "$(id -u)" -eq 0 ] && [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ]; then
  chown -R "$REAL_USER:$REAL_USER" "$ROOT_DIR"
fi

# Helper to run build commands as the normal user (not root) with clean rustc environment
run_build() {
  if [ "$(id -u)" -eq 0 ] && [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ]; then
    sudo -u "$REAL_USER" env "HOME=$REAL_HOME" "PATH=$PATH" "RUSTC_WRAPPER=" "$@"
  else
    env "RUSTC_WRAPPER=" "$@"
  fi
}

echo "=========================================================="
echo "       Conduit Security Gateway — Native Installer        "
echo "=========================================================="
echo "Source root:   $ROOT_DIR"
echo "Install mode:  $INSTALL_MODE"
echo "Target user:   $REAL_USER"
echo ""

# ── 1. OS & Package Manager Detection ─────────────────────────────────
echo "--- 1. Detecting Linux Distribution ---"

DISTRO="unknown"
PKG_MGR="unknown"

if [ -f /etc/os-release ]; then
  # shellcheck source=/dev/null
  . /etc/os-release
  DISTRO_ID="${ID:-unknown}"
  DISTRO_LIKE="${ID_LIKE:-}"
else
  DISTRO_ID="unknown"
  DISTRO_LIKE=""
fi

case "$DISTRO_ID" in
  arch|manjaro|endeavouros|garuda|cachyos|artix)
    DISTRO="arch"
    PKG_MGR="pacman"
    ;;
  debian|ubuntu|linuxmint|pop|elementary|raspbian)
    DISTRO="debian"
    PKG_MGR="apt"
    ;;
  fedora|rhel|centos|rocky|almalinux|ol)
    DISTRO="fedora"
    PKG_MGR="dnf"
    ;;
  *)
    if [[ "$DISTRO_LIKE" == *"arch"* ]]; then
      DISTRO="arch"
      PKG_MGR="pacman"
    elif [[ "$DISTRO_LIKE" == *"debian"* || "$DISTRO_LIKE" == *"ubuntu"* ]]; then
      DISTRO="debian"
      PKG_MGR="apt"
    elif [[ "$DISTRO_LIKE" == *"fedora"* || "$DISTRO_LIKE" == *"rhel"* ]]; then
      DISTRO="fedora"
      PKG_MGR="dnf"
    elif command -v pacman >/dev/null 2>&1; then
      DISTRO="arch"
      PKG_MGR="pacman"
    elif command -v apt-get >/dev/null 2>&1; then
      DISTRO="debian"
      PKG_MGR="apt"
    elif command -v dnf >/dev/null 2>&1; then
      DISTRO="fedora"
      PKG_MGR="dnf"
    fi
    ;;
esac

echo "  Distribution: $DISTRO ($DISTRO_ID)"
echo "  Package Tool: $PKG_MGR"

# ── 2. Install Distro Dependencies & Valkey ───────────────────────────
if [ "$SKIP_DEPS" = false ]; then
  echo ""
  echo "--- 2. Installing System Dependencies & Valkey ---"

  case "$DISTRO" in
    arch)
      echo "  Installing Arch packages (base-devel, cmake, perl, nodejs, npm, valkey)..."
      $SUDO pacman -S --needed --noconfirm base-devel cmake perl pkgconf openssl nodejs npm valkey
      ;;
    debian)
      echo "  Updating apt index and installing build dependencies..."
      $SUDO apt-get update -y
      $SUDO apt-get install -y build-essential cmake perl pkg-config libssl-dev nodejs npm curl ca-certificates

      # Check for valkey vs redis-server in Debian/Ubuntu repos
      if apt-cache show valkey >/dev/null 2>&1; then
        echo "  Installing native 'valkey' package..."
        $SUDO apt-get install -y valkey
      elif apt-cache show valkey-server >/dev/null 2>&1; then
        echo "  Installing native 'valkey-server' package..."
        $SUDO apt-get install -y valkey-server
      else
        echo "  Notice: 'valkey' package not found in current apt repos. Installing 'redis-server' (BSD compatible)..."
        $SUDO apt-get install -y redis-server
      fi
      ;;
    fedora)
      echo "  Installing Fedora packages (@development-tools, cmake, perl, nodejs, npm, valkey)..."
      $SUDO dnf install -y @development-tools cmake perl openssl-devel nodejs npm valkey
      ;;
    *)
      echo "  Warning: Unrecognized distro family '$DISTRO'. Skipping automated package installation."
      echo "  Ensure cmake, perl, nodejs, npm, and valkey/redis are installed."
      ;;
  esac
else
  echo ""
  echo "--- Skipping package manager dependency installation (--skip-deps) ---"
fi

# ── 3. Check / Install Rust Toolchain ─────────────────────────────────
echo ""
echo "--- 3. Verifying Rust Toolchain ---"

if ! command -v cargo >/dev/null 2>&1 || ! command -v rustc >/dev/null 2>&1; then
  if [ -f "$HOME/.cargo/env" ]; then
    # shellcheck source=/dev/null
    . "$HOME/.cargo/env"
  elif [ -f "$REAL_HOME/.cargo/env" ]; then
    # shellcheck source=/dev/null
    . "$REAL_HOME/.cargo/env"
  fi
fi

if ! command -v cargo >/dev/null 2>&1 || ! command -v rustc >/dev/null 2>&1; then
  echo "  Rust toolchain not found. Installing via rustup..."
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
  # shellcheck source=/dev/null
  . "$HOME/.cargo/env"
fi

echo "  Cargo version: $(cargo --version)"
echo "  Rustc version: $(rustc --version)"

# ── 4. Start & Enable Valkey / Datastore Service ───────────────────────
echo ""
echo "--- 4. Configuring Valkey Datastore on Dedicated Port 6380 ---"

# Configure native Valkey / Redis to listen on port 6380 (avoids collision with standard Redis / NanoSIEM on 6379)
for conf in /etc/valkey/valkey.conf /etc/valkey.conf /etc/redis/redis.conf /etc/redis.conf; do
  if [ -f "$conf" ]; then
    echo "  Configuring $conf to listen on dedicated port 6380..."
    $SUDO sed -i 's|^port [0-9]\+|port 6380|' "$conf"
    $SUDO sed -i 's|^#\? \?bind .*|bind 127.0.0.1 ::1|' "$conf"
  fi
done

DATASTORE_SVC=""
for svc in valkey valkey-server redis redis-server; do
  if systemctl list-unit-files "$svc.service" 2>/dev/null | grep -q "$svc.service"; then
    DATASTORE_SVC="$svc"
    break
  fi
done

if [ -n "$DATASTORE_SVC" ]; then
  echo "  Enabling and restarting $DATASTORE_SVC.service on port 6380..."
  $SUDO systemctl reset-failed "$DATASTORE_SVC.service" 2>/dev/null || true
  $SUDO systemctl restart "$DATASTORE_SVC.service" 2>/dev/null || $SUDO systemctl enable --now "$DATASTORE_SVC.service" 2>/dev/null || true
else
  echo "  Warning: No native valkey/redis systemd service unit found. Checking port 6380..."
fi

# Verify port 6380 connectivity
echo -n "  Verifying datastore response on :6380..."
PORT_OK=false
for i in {1..30}; do
  if command -v valkey-cli >/dev/null 2>&1 && valkey-cli -p 6380 ping 2>/dev/null | grep -q PONG; then
    PORT_OK=true
    break
  elif command -v redis-cli >/dev/null 2>&1 && redis-cli -p 6380 ping 2>/dev/null | grep -q PONG; then
    PORT_OK=true
    break
  elif (echo > /dev/tcp/127.0.0.1/6380) 2>/dev/null; then
    PORT_OK=true
    break
  fi
  sleep 0.5
done

if [ "$PORT_OK" = true ]; then
  echo " online."
else
  echo " warning: Port 6380 not responding yet. Proceeding with installation..."
fi

# ── 5. Compile Conduit UI & Release Binaries ──────────────────────────
if [ "$SKIP_BUILD" = false ]; then
  echo ""
  echo "--- 5. Building Conduit Frontend UI ---"
  (
    cd "$ROOT_DIR/conduit-ui"
    if [ ! -d "node_modules" ]; then
      echo "  Running npm install..."
      run_build npm install --silent
    fi
    echo "  Compiling SvelteKit dashboard..."
    run_build npm run build
  )
  echo "  UI build complete."

  echo ""
  echo "--- 6. Compiling Rust Binaries (conduit-api, conduit-proxy) ---"
  (
    cd "$ROOT_DIR"
    run_build cargo build --config 'build.rustc-wrapper=""' --release --bin conduit-api --bin conduit-proxy
  )
  echo "  Release binaries compiled successfully."
else
  echo ""
  echo "--- Skipping compilation (--skip-build) ---"
fi

# ── 6. Installation (System or User) ──────────────────────────────────
if [ "$INSTALL_MODE" = "system" ]; then
  echo ""
  echo "--- 7. Installing Conduit as System Service ---"

  # Create dedicated conduit system user/group
  if ! getent group conduit >/dev/null 2>&1; then
    echo "  Creating system group 'conduit'..."
    $SUDO groupadd -r conduit
  fi

  if ! getent passwd conduit >/dev/null 2>&1; then
    echo "  Creating system user 'conduit'..."
    $SUDO useradd -r -g conduit -d /var/lib/conduit -s /usr/sbin/nologin -c "Conduit Security Gateway" conduit
  fi

  # Create directories
  echo "  Creating system directories (/etc/conduit, /var/lib/conduit, /var/log/conduit)..."
  $SUDO mkdir -p /usr/local/bin /etc/conduit /etc/conduit/ca /var/lib/conduit /var/lib/conduit/ui /var/log/conduit

  # Stop running services before updating binaries to prevent "Text file busy"
  $SUDO systemctl stop conduit-proxy.service conduit-api.service 2>/dev/null || true

  # Copy binaries
  echo "  Installing binaries to /usr/local/bin..."
  $SUDO install -m 755 "$ROOT_DIR/target/release/conduit-api" /usr/local/bin/conduit-api
  $SUDO install -m 755 "$ROOT_DIR/target/release/conduit-proxy" /usr/local/bin/conduit-proxy
  $SUDO install -m 755 "$ROOT_DIR/scripts/conduit-ctl.sh" /usr/local/bin/conduit-ctl

  # Copy UI build
  echo "  Installing UI dashboard to /var/lib/conduit/ui..."
  $SUDO cp -r "$ROOT_DIR/conduit-ui/build/"* /var/lib/conduit/ui/

  CONFIG_SRC="$ROOT_DIR/conduit.example.toml"
  if [ -f "$ROOT_DIR/conduit.toml" ]; then
    CONFIG_SRC="$ROOT_DIR/conduit.toml"
  fi

  # Install configuration if missing
  if [ ! -f /etc/conduit/conduit.toml ]; then
    echo "  Installing configuration from $(basename "$CONFIG_SRC") to /etc/conduit/conduit.toml..."
    $SUDO cp "$CONFIG_SRC" /etc/conduit/conduit.toml
    $SUDO sed -i 's|^#\? \?ca_cert_path = .*|ca_cert_path = "/etc/conduit/ca/ca.pem"|' /etc/conduit/conduit.toml
    $SUDO sed -i 's|^#\? \?ca_key_path = .*|ca_key_path = "/etc/conduit/ca/ca-key.pem"|' /etc/conduit/conduit.toml
    $SUDO sed -i 's|^#\? \?ui_dir = .*|ui_dir = "/var/lib/conduit/ui"|' /etc/conduit/conduit.toml
    if ! grep -q "^ui_dir =" /etc/conduit/conduit.toml; then
      echo 'ui_dir = "/var/lib/conduit/ui"' | $SUDO tee -a /etc/conduit/conduit.toml >/dev/null
    fi
  else
    echo "  Preserving existing /etc/conduit/conduit.toml."
    if ! grep -q "tld_protection" /etc/conduit/conduit.toml 2>/dev/null && [ -f "$ROOT_DIR/conduit.toml" ]; then
      echo "  Syncing TLD & POST protection settings into /etc/conduit/conduit.toml..."
      $SUDO cp "$ROOT_DIR/conduit.toml" /etc/conduit/conduit.toml
      $SUDO sed -i 's|^#\? \?ca_cert_path = .*|ca_cert_path = "/etc/conduit/ca/ca.pem"|' /etc/conduit/conduit.toml
      $SUDO sed -i 's|^#\? \?ca_key_path = .*|ca_key_path = "/etc/conduit/ca/ca-key.pem"|' /etc/conduit/conduit.toml
      $SUDO sed -i 's|^#\? \?ui_dir = .*|ui_dir = "/var/lib/conduit/ui"|' /etc/conduit/conduit.toml
    fi
  fi

  # Ensure CA directory exists and seed existing Root CA if present
  $SUDO mkdir -p /etc/conduit/ca
  if [ -f "$ROOT_DIR/ca/ca.pem" ] && [ -f "$ROOT_DIR/ca/ca-key.pem" ]; then
    echo "  Seeding existing Root CA into /etc/conduit/ca/..."
    $SUDO cp "$ROOT_DIR/ca/ca.pem" /etc/conduit/ca/ca.pem
    $SUDO cp "$ROOT_DIR/ca/ca-key.pem" /etc/conduit/ca/ca-key.pem
  fi

  # Set secure permissions: public ca.pem world-readable (644), ca private key restricted (600)
  echo "  Setting ownership and permissions for 'conduit' user..."
  $SUDO chown -R conduit:conduit /etc/conduit /var/lib/conduit /var/log/conduit
  $SUDO chmod 755 /etc/conduit
  $SUDO chmod 755 /etc/conduit/ca
  $SUDO chmod 644 /etc/conduit/ca/ca.pem 2>/dev/null || true
  $SUDO chmod 600 /etc/conduit/ca/*key* 2>/dev/null || true
  $SUDO chmod 755 /var/lib/conduit

  # Install systemd unit files
  echo "  Installing systemd system units (/etc/systemd/system/)..."
  $SUDO cp "$ROOT_DIR/deploy/systemd/system/"* /etc/systemd/system/
  if [ -n "${REAL_USER:-}" ] && [ "$REAL_USER" != "root" ]; then
    $SUDO sed -i "s|^User=.*|User=$REAL_USER|" /etc/systemd/system/conduit-api.service
    $SUDO sed -i "s|^Group=.*|Group=$(id -gn "$REAL_USER")|" /etc/systemd/system/conduit-api.service
    $SUDO sed -i "s|^Environment=HOME=.*|Environment=HOME=$REAL_HOME|" /etc/systemd/system/conduit-api.service
    $SUDO sed -i "s|^Environment=USER=.*|Environment=USER=$REAL_USER|" /etc/systemd/system/conduit-api.service
    $SUDO sed -i "s|^Environment=PATH=.*|Environment=PATH=$REAL_HOME/.local/share/mise/shims:$REAL_HOME/.local/bin:/usr/local/bin:/usr/bin:/bin|" /etc/systemd/system/conduit-api.service
    $SUDO sed -i "s|^ReadWritePaths=.*|ReadWritePaths=/var/lib/conduit /var/log/conduit /etc/conduit $REAL_HOME|" /etc/systemd/system/conduit-api.service
  fi
  $SUDO systemctl daemon-reload
  $SUDO systemctl enable conduit-api.service conduit-proxy.service conduit.target
  $SUDO systemctl restart conduit-api.service conduit-proxy.service conduit.target

  echo "  Systemd system services enabled and restarted."

else
  echo ""
  echo "--- 7. Installing Conduit as User Service ---"

  mkdir -p "$ROOT_DIR/logs" "$ROOT_DIR/ca" "$HOME/.config/systemd/user"

  if [ ! -f "$ROOT_DIR/conduit.toml" ]; then
    echo "  Creating local conduit.toml from example..."
    cp "$ROOT_DIR/conduit.example.toml" "$ROOT_DIR/conduit.toml"
    sed -i 's|^# ca_cert_path = .*|ca_cert_path = "ca/ca.pem"|' "$ROOT_DIR/conduit.toml"
    sed -i 's|^# ca_key_path = .*|ca_key_path = "ca/ca-key.pem"|' "$ROOT_DIR/conduit.toml"
    sed -i 's|^# ui_dir = .*|ui_dir = "./conduit-ui/build"|' "$ROOT_DIR/conduit.toml"
    if ! grep -q "^ui_dir =" "$ROOT_DIR/conduit.toml"; then
      echo 'ui_dir = "./conduit-ui/build"' >> "$ROOT_DIR/conduit.toml"
    fi
  fi

  cp "$ROOT_DIR/deploy/systemd/user/"* "$HOME/.config/systemd/user/"
  systemctl --user daemon-reload
  systemctl --user enable --now conduit-api.service conduit-proxy.service conduit.target
  echo "  Systemd user services enabled and started."
fi

# ── 8. Health Check ───────────────────────────────────────────────────
echo ""
echo "--- 8. Verifying Service Health ---"
echo -n "  Waiting for Conduit API on :8443..."
API_READY=false
for i in {1..40}; do
  if curl -sf http://127.0.0.1:8443/api/v1/health >/dev/null 2>&1; then
    API_READY=true
    break
  fi
  sleep 0.5
done

if [ "$API_READY" = true ]; then
  echo " healthy."
  curl -s http://127.0.0.1:8443/api/v1/health | head -n1
  echo ""
else
  echo " warning: API did not respond within 20 seconds. Check logs with 'conduit-ctl status'."
fi

echo -n "  Waiting for Conduit Proxy on :8888..."
PROXY_READY=false
for i in {1..40}; do
  if (echo > /dev/tcp/127.0.0.1/8888) 2>/dev/null || nc -z 127.0.0.1 8888 2>/dev/null; then
    PROXY_READY=true
    break
  fi
  sleep 0.5
done

if [ "$PROXY_READY" = true ]; then
  echo " online."
else
  echo " warning: Proxy did not respond on :8888 within 20 seconds."
fi

if [ "$API_READY" != true ] || [ "$PROXY_READY" != true ]; then
  echo ""
  echo "========================================================"
  echo " WARNING: Conduit services are not fully operational yet!"
  echo " API (8443):   $([ "$API_READY" = true ] && echo "ONLINE" || echo "FAILED")"
  echo " Proxy (8888): $([ "$PROXY_READY" = true ] && echo "ONLINE" || echo "FAILED")"
  echo ""
  echo " Recent service logs:"
  journalctl -u conduit-api.service -u conduit-proxy.service --no-pager -n 15 2>/dev/null || true
  echo ""
  echo " Disabling system-wide proxy activation to prevent network outage."
  echo " Direct internet access remains unaffected."
  echo "========================================================"
  SYSTEM_PROXY=false
fi

# ── 9. Datastore Seeding ──────────────────────────────────────────────
if [ "$SKIP_SEED" = false ]; then
  echo ""
  echo "--- 9. Seeding Datastore (Threat Feeds & Categories) ---"
  export CONDUIT_USER="$REAL_USER"
  "$ROOT_DIR/scripts/seed-dragonfly.sh"
else
  echo ""
  echo "--- Skipping dataset seeding (--skip-seed) ---"
fi

# ── 10. Root CA Certificate Export & OS Trust ─────────────────────────
echo ""
echo "--- 10. Root CA Certificate Setup ---"
CA_PEM=""
if [ "$INSTALL_MODE" = "system" ]; then
  CA_PEM="/etc/conduit/ca/ca.pem"
else
  CA_PEM="$ROOT_DIR/ca/ca.pem"
  mkdir -p "$ROOT_DIR/ca"
  curl -sf http://127.0.0.1:8443/api/v1/ca/cert -o "$CA_PEM" 2>/dev/null || true
fi

if [ "$TRUST_CA" = true ]; then
  echo "  Installing Conduit Root CA into system trust store..."
  if [ ! -f "$CA_PEM" ] || [ ! -s "$CA_PEM" ]; then
    # Try fetching from API
    curl -sf http://127.0.0.1:8443/api/v1/ca/cert -o /tmp/conduit-ca.pem 2>/dev/null || true
    CA_SOURCE="/tmp/conduit-ca.pem"
  else
    CA_SOURCE="$CA_PEM"
  fi

  if [ -f "$CA_SOURCE" ] && [ -s "$CA_SOURCE" ]; then
    if [ "$INSTALL_MODE" = "system" ] && [ -f "/etc/conduit/ca/ca.pem" ]; then
      $SUDO chmod 755 /etc/conduit /etc/conduit/ca 2>/dev/null || true
      $SUDO chmod 644 /etc/conduit/ca/ca.pem 2>/dev/null || true
      $SUDO chmod 600 /etc/conduit/ca/*key* 2>/dev/null || true
    fi
    if command -v update-ca-certificates >/dev/null 2>&1; then
      # Debian / Ubuntu
      $SUDO cp "$CA_SOURCE" /usr/local/share/ca-certificates/conduit-ca.crt
      $SUDO update-ca-certificates
      echo "  Installed into Debian/Ubuntu trust store via update-ca-certificates."
    elif command -v trust >/dev/null 2>&1; then
      # Arch Linux
      $SUDO cp "$CA_SOURCE" /etc/ca-certificates/trust-source/anchors/conduit-ca.crt
      $SUDO trust extract-compat
      echo "  Installed into Arch Linux trust store via trust extract-compat."
    elif command -v update-ca-trust >/dev/null 2>&1; then
      # Fedora / RHEL
      $SUDO cp "$CA_SOURCE" /etc/pki/ca-trust/source/anchors/conduit-ca.crt
      $SUDO update-ca-trust
      echo "  Installed into Fedora/RHEL trust store via update-ca-trust."
    fi

    # Generate combined CA bundle (system roots + Conduit CA) so CLI tools
    # that override their trust store can verify both intercepted and bypassed domains
    SYSTEM_CA_BUNDLE=""
    for f in /etc/ssl/certs/ca-certificates.crt /etc/pki/tls/certs/ca-bundle.crt /etc/ssl/ca-bundle.pem /etc/ssl/cert.pem; do
      if [ -f "$f" ]; then
        SYSTEM_CA_BUNDLE="$f"
        break
      fi
    done
    if [ -n "$SYSTEM_CA_BUNDLE" ]; then
      cat "$SYSTEM_CA_BUNDLE" "$CA_SOURCE" | $SUDO tee /etc/conduit/ca/ca-bundle.pem >/dev/null 2>&1 || true
      $SUDO chmod 644 /etc/conduit/ca/ca-bundle.pem 2>/dev/null || true
      echo "  Generated combined CA bundle at /etc/conduit/ca/ca-bundle.pem."
    fi

    # Also update user NSS database for Chrome / Chromium if present
    USER_NSSDB="$REAL_HOME/.pki/nssdb"
    if command -v certutil >/dev/null 2>&1 && [ -d "$USER_NSSDB" ]; then
      if [ "$EUID" -eq 0 ] && [ -n "${SUDO_USER:-}" ]; then
        sudo -u "$REAL_USER" certutil -d "sql:$USER_NSSDB" -D -n "Conduit Root CA" >/dev/null 2>&1 || true
        sudo -u "$REAL_USER" certutil -d "sql:$USER_NSSDB" -A -t "C,," -n "Conduit Root CA" -i "$CA_SOURCE" >/dev/null 2>&1 || true
      else
        certutil -d "sql:$USER_NSSDB" -D -n "Conduit Root CA" >/dev/null 2>&1 || true
        certutil -d "sql:$USER_NSSDB" -A -t "C,," -n "Conduit Root CA" -i "$CA_SOURCE" >/dev/null 2>&1 || true
      fi
      echo "  Installed into user Chrome/NSS trust database ($USER_NSSDB)."
    fi

    # Configure Firefox / LibreWolf / Zen Enterprise Policies for Root CA trust
    echo "  Configuring Firefox enterprise policy for Root CA trust..."
    $SUDO mkdir -p /etc/firefox/policies
    cat << 'EOF' | $SUDO tee /etc/firefox/policies/policies.json >/dev/null
{
  "policies": {
    "Certificates": {
      "Install": [
        "/etc/conduit/ca/ca.pem"
      ]
    },
    "Preferences": {
      "security.enterprise_roots.enabled": true
    }
  }
}
EOF
    $SUDO chmod 644 /etc/firefox/policies/policies.json
    for fork in librewolf zen waterfox floorp; do
      if [ -d "/etc/$fork" ] || command -v "$fork" >/dev/null 2>&1; then
        $SUDO mkdir -p "/etc/$fork/policies"
        $SUDO cp /etc/firefox/policies/policies.json "/etc/$fork/policies/policies.json" 2>/dev/null || true
      fi
    done
    echo "  Firefox enterprise policy installed (/etc/firefox/policies/policies.json)."

    # Configure Java Keystore (cacerts) if keytool is available
    if command -v keytool >/dev/null 2>&1; then
      JAVA_CACERTS=""
      for cand in "${JAVA_HOME:-}/lib/security/cacerts" "${JAVA_HOME:-}/jre/lib/security/cacerts" \
                  /etc/ssl/certs/java/cacerts /usr/lib/jvm/default-runtime/lib/security/cacerts \
                  /usr/lib/jvm/default/lib/security/cacerts; do
        if [ -f "$cand" ]; then
          JAVA_CACERTS="$cand"
          break
        fi
      done
      if [ -z "$JAVA_CACERTS" ]; then
        JAVA_CACERTS=$(find /usr/lib/jvm -name "cacerts" 2>/dev/null | head -n1 || true)
      fi
      if [ -n "$JAVA_CACERTS" ]; then
        $SUDO keytool -delete -alias conduit-ca -keystore "$JAVA_CACERTS" -storepass changeit >/dev/null 2>&1 || true
        if $SUDO keytool -importcert -trustcacerts -noprompt -alias conduit-ca -keystore "$JAVA_CACERTS" -storepass changeit -file "$CA_SOURCE" >/dev/null 2>&1; then
          echo "  Root CA installed into Java keystore ($JAVA_CACERTS)."
        fi
      fi
    fi

    rm -f /tmp/conduit-ca.pem
  else
    echo "  Warning: Could not obtain CA certificate to install."
  fi
else
  echo "  CA Certificate available at: $CA_PEM"
  echo "  To install and trust system-wide: sudo $0 --trust-ca"
fi

# ── 11. Shell & System Proxy Environment ──────────────────────────────
echo ""
echo "--- 11. Shell Environment Helper ---"
chmod +x "$ROOT_DIR/scripts/env.sh" "$ROOT_DIR/scripts/unenv.sh" "$ROOT_DIR/scripts/conduit-ctl.sh"

if [ "$SYSTEM_PROXY" = true ]; then
  echo "  Installing /etc/profile.d/conduit.sh for system-wide shell proxying..."
  cat << 'EOF' | $SUDO tee /etc/profile.d/conduit.sh >/dev/null
# Conduit Security Gateway Shell Proxy Environment
export http_proxy="http://127.0.0.1:8888"
export https_proxy="http://127.0.0.1:8888"
export HTTP_PROXY="http://127.0.0.1:8888"
export HTTPS_PROXY="http://127.0.0.1:8888"
export ALL_PROXY="http://127.0.0.1:8888"
export NO_PROXY="localhost,127.0.0.1,::1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,169.254.0.0/16,.local,.internal,.svc,.cluster.local"
export no_proxy="localhost,127.0.0.1,::1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,169.254.0.0/16,.local,.internal,.svc,.cluster.local"

# CA Certificates for developer runtimes & CLIs (Node, Python, Git, OpenSSL, AWS)
# Prefer combined bundle or system trust bundle (which includes Conduit CA + public internet roots).
# This allows bypassed/allowlisted domains (e.g. *.googleapis.com, *.google.com) to verify
# alongside Conduit-intercepted traffic.
CA_BUNDLE="/etc/conduit/ca/ca-bundle.pem"
if [ ! -f "$CA_BUNDLE" ]; then
    for f in /etc/ssl/certs/ca-certificates.crt /etc/pki/tls/certs/ca-bundle.crt /etc/ssl/ca-bundle.pem /etc/ssl/cert.pem; do
        if [ -f "$f" ]; then
            CA_BUNDLE="$f"
            break
        fi
    done
fi
[ ! -f "$CA_BUNDLE" ] && CA_BUNDLE="/etc/conduit/ca/ca.pem"

export CURL_CA_BUNDLE="$CA_BUNDLE"
export SSL_CERT_FILE="$CA_BUNDLE"
export REQUESTS_CA_BUNDLE="$CA_BUNDLE"
export NODE_EXTRA_CA_CERTS="/etc/conduit/ca/ca.pem"
export GIT_SSL_CAINFO="$CA_BUNDLE"
export CODEX_CA_CERTIFICATE="$CA_BUNDLE"
export AWS_CA_BUNDLE="$CA_BUNDLE"

# Node.js built-in fetch (undici) proxy support (Node 20.18+, 22.1+, 24+)
if command -v node >/dev/null 2>&1 && node --use-env-proxy -e 'process.exit(0)' 2>/dev/null; then
    case " ${NODE_OPTIONS:-} " in
        *" --use-env-proxy "*) ;;
        *) export NODE_OPTIONS="${NODE_OPTIONS:+$NODE_OPTIONS }--use-env-proxy" ;;
    esac
fi
EOF
  $SUDO chmod 644 /etc/profile.d/conduit.sh
  echo "  /etc/profile.d/conduit.sh installed."

  # Ensure user shell configuration files (~/.bashrc, ~/.zshrc) source Conduit proxy
  for rc in "$REAL_HOME/.bashrc" "$REAL_HOME/.zshrc"; do
    if [ -f "$rc" ]; then
      sed -i '/# Conduit Security Gateway Shell Proxy Environment/,/^[[:space:]]*fi[[:space:]]*$/d' "$rc" 2>/dev/null || true
      if ! grep -q "conduit proxy" "$rc" && ! grep -q "/etc/profile.d/conduit.sh" "$rc" && ! grep -q "scripts/env.sh" "$rc"; then
        cat >> "$rc" << 'EOF'

# >>> conduit proxy >>>
if [ -f /etc/profile.d/conduit.sh ]; then
  . /etc/profile.d/conduit.sh
fi
# <<< conduit proxy <<<
EOF
        if [ "$(id -u)" -eq 0 ] && [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ]; then
          chown "$REAL_USER:$REAL_USER" "$rc"
        fi
        echo "  Conduit proxy environment added to $(basename "$rc")."
      fi
    fi
  done

  # Configure user environment defaults for GUI apps and Wayland/systemd session
  echo "  Configuring user desktop session and browser proxy flags..."
  mkdir -p "$REAL_HOME/.config/environment.d"
  ENV_CA_BUNDLE="/etc/conduit/ca/ca-bundle.pem"
  if [ ! -f "$ENV_CA_BUNDLE" ]; then
    for f in /etc/ssl/certs/ca-certificates.crt /etc/pki/tls/certs/ca-bundle.crt /etc/ssl/ca-bundle.pem /etc/ssl/cert.pem; do
      if [ -f "$f" ]; then
        ENV_CA_BUNDLE="$f"
        break
      fi
    done
  fi
  [ ! -f "$ENV_CA_BUNDLE" ] && ENV_CA_BUNDLE="/etc/conduit/ca/ca.pem"

  cat << EOF > "$REAL_HOME/.config/environment.d/conduit.conf"
# Conduit Security Gateway User Environment
http_proxy=http://127.0.0.1:8888
https_proxy=http://127.0.0.1:8888
HTTP_PROXY=http://127.0.0.1:8888
HTTPS_PROXY=http://127.0.0.1:8888
ALL_PROXY=http://127.0.0.1:8888
no_proxy=localhost,127.0.0.1,::1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,169.254.0.0/16,.local,.internal,.svc,.cluster.local
NO_PROXY=localhost,127.0.0.1,::1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,169.254.0.0/16,.local,.internal,.svc,.cluster.local
CURL_CA_BUNDLE=$ENV_CA_BUNDLE
SSL_CERT_FILE=$ENV_CA_BUNDLE
REQUESTS_CA_BUNDLE=$ENV_CA_BUNDLE
NODE_EXTRA_CA_CERTS=/etc/conduit/ca/ca.pem
GIT_SSL_CAINFO=$ENV_CA_BUNDLE
CODEX_CA_CERTIFICATE=$ENV_CA_BUNDLE
AWS_CA_BUNDLE=$ENV_CA_BUNDLE
NODE_OPTIONS=--use-env-proxy
EOF
  if [ "$(id -u)" -eq 0 ] && [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ]; then
    chown -R "$REAL_USER:$REAL_USER" "$REAL_HOME/.config/environment.d"
  fi

  # Configure Chrome / Chromium browser proxy flags
  for flag_file in "$REAL_HOME/.config/chrome-flags.conf" "$REAL_HOME/.config/chromium-flags.conf" "$REAL_HOME/.config/google-chrome-flags.conf"; do
    if [ -f "$flag_file" ] || [ "$(basename "$flag_file")" = "chrome-flags.conf" ]; then
      sed -i '/--proxy-server=/d' "$flag_file" 2>/dev/null || true
      sed -i '/--proxy-bypass-list=/d' "$flag_file" 2>/dev/null || true
      sed -i '/# Conduit MITM Proxy/d' "$flag_file" 2>/dev/null || true
      cat >> "$flag_file" << 'EOF'

# Conduit MITM Proxy
--proxy-server=http://127.0.0.1:8888
--proxy-bypass-list=*.local;10.0.0.0/8;172.16.0.0/12;192.168.0.0/16;169.254.0.0/16
EOF
      if [ "$(id -u)" -eq 0 ] && [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ]; then
        chown "$REAL_USER:$REAL_USER" "$flag_file"
      fi
    fi
  done

  # Propagate into live systemd user and D-Bus session
  SET_ENV_CMD='
    CA_BUNDLE="/etc/conduit/ca/ca-bundle.pem"
    if [ ! -f "$CA_BUNDLE" ]; then
      for f in /etc/ssl/certs/ca-certificates.crt /etc/pki/tls/certs/ca-bundle.crt /etc/ssl/ca-bundle.pem /etc/ssl/cert.pem; do
        if [ -f "$f" ]; then
          CA_BUNDLE="$f"
          break
        fi
      done
    fi
    [ ! -f "$CA_BUNDLE" ] && CA_BUNDLE="/etc/conduit/ca/ca.pem"
    for v in http_proxy="http://127.0.0.1:8888" https_proxy="http://127.0.0.1:8888" \
             HTTP_PROXY="http://127.0.0.1:8888" HTTPS_PROXY="http://127.0.0.1:8888" \
             ALL_PROXY="http://127.0.0.1:8888" \
             no_proxy="localhost,127.0.0.1,::1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,169.254.0.0/16,.local,.internal,.svc,.cluster.local" \
             NO_PROXY="localhost,127.0.0.1,::1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,169.254.0.0/16,.local,.internal,.svc,.cluster.local" \
             CURL_CA_BUNDLE="$CA_BUNDLE" SSL_CERT_FILE="$CA_BUNDLE" \
             REQUESTS_CA_BUNDLE="$CA_BUNDLE" NODE_EXTRA_CA_CERTS="/etc/conduit/ca/ca.pem" \
             GIT_SSL_CAINFO="$CA_BUNDLE" CODEX_CA_CERTIFICATE="$CA_BUNDLE" \
             AWS_CA_BUNDLE="$CA_BUNDLE" NODE_OPTIONS="--use-env-proxy"; do
      systemctl --user set-environment "$v" 2>/dev/null || true
    done
    if command -v dbus-update-activation-environment >/dev/null 2>&1; then
      dbus-update-activation-environment --systemd \
        http_proxy https_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY no_proxy NO_PROXY \
        CURL_CA_BUNDLE SSL_CERT_FILE REQUESTS_CA_BUNDLE NODE_EXTRA_CA_CERTS GIT_SSL_CAINFO CODEX_CA_CERTIFICATE AWS_CA_BUNDLE NODE_OPTIONS 2>/dev/null || true
    fi
  '
  if [ "$EUID" -eq 0 ] && [ -n "${SUDO_USER:-}" ]; then
    REAL_UID=$(id -u "$REAL_USER" 2>/dev/null || true)
    USER_RUNTIME_DIR="/run/user/$REAL_UID"
    sudo -u "$REAL_USER" env "XDG_RUNTIME_DIR=$USER_RUNTIME_DIR" "DBUS_SESSION_BUS_ADDRESS=unix:path=$USER_RUNTIME_DIR/bus" bash -c "$SET_ENV_CMD" 2>/dev/null || true
  else
    bash -c "$SET_ENV_CMD" 2>/dev/null || true
  fi
  echo "  User desktop session environment configured."

  # Configure Docker daemon proxy (systemd drop-in) if Docker or containerd is installed
  if command -v docker >/dev/null 2>&1 || [ -d /etc/docker ] || systemctl list-unit-files docker.service >/dev/null 2>&1; then
    echo "  Configuring Docker daemon proxy..."
    $SUDO mkdir -p /etc/systemd/system/docker.service.d
    cat << 'EOF' | $SUDO tee /etc/systemd/system/docker.service.d/http-proxy.conf >/dev/null
[Service]
Environment="HTTP_PROXY=http://127.0.0.1:8888"
Environment="HTTPS_PROXY=http://127.0.0.1:8888"
Environment="http_proxy=http://127.0.0.1:8888"
Environment="https_proxy=http://127.0.0.1:8888"
Environment="NO_PROXY=localhost,127.0.0.1,::1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,169.254.0.0/16,.local,.internal,.svc,.cluster.local"
Environment="no_proxy=localhost,127.0.0.1,::1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,169.254.0.0/16,.local,.internal,.svc,.cluster.local"
EOF
    $SUDO chmod 644 /etc/systemd/system/docker.service.d/http-proxy.conf

    if systemctl list-unit-files containerd.service >/dev/null 2>&1 || command -v containerd >/dev/null 2>&1; then
      $SUDO mkdir -p /etc/systemd/system/containerd.service.d
      cat << 'EOF' | $SUDO tee /etc/systemd/system/containerd.service.d/http-proxy.conf >/dev/null
[Service]
Environment="HTTP_PROXY=http://127.0.0.1:8888"
Environment="HTTPS_PROXY=http://127.0.0.1:8888"
Environment="http_proxy=http://127.0.0.1:8888"
Environment="https_proxy=http://127.0.0.1:8888"
Environment="NO_PROXY=localhost,127.0.0.1,::1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,169.254.0.0/16,.local,.internal,.svc,.cluster.local"
Environment="no_proxy=localhost,127.0.0.1,::1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,169.254.0.0/16,.local,.internal,.svc,.cluster.local"
EOF
      $SUDO chmod 644 /etc/systemd/system/containerd.service.d/http-proxy.conf
    fi

    $SUDO systemctl daemon-reload
    if systemctl is-active docker >/dev/null 2>&1; then
      echo "  Restarting docker service to apply proxy configuration..."
      $SUDO systemctl restart docker 2>/dev/null || true
    fi
    echo "  Docker daemon proxy configured (/etc/systemd/system/docker.service.d/http-proxy.conf)."
  fi

  # Configure Sudo environment preservation for proxy variables
  echo "  Configuring sudoers proxy environment preservation (/etc/sudoers.d/conduit-proxy)..."
  TMP_SUDOERS=$(mktemp)
  cat << 'EOF' > "$TMP_SUDOERS"
# Conduit Security Gateway Proxy Environment Preservation
Defaults env_keep += "http_proxy https_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY no_proxy NO_PROXY"
Defaults env_keep += "CURL_CA_BUNDLE SSL_CERT_FILE REQUESTS_CA_BUNDLE NODE_EXTRA_CA_CERTS GIT_SSL_CAINFO CODEX_CA_CERTIFICATE AWS_CA_BUNDLE NODE_OPTIONS"
EOF
  if command -v visudo >/dev/null 2>&1 && visudo -cf "$TMP_SUDOERS" >/dev/null 2>&1; then
    $SUDO cp "$TMP_SUDOERS" /etc/sudoers.d/conduit-proxy
    $SUDO chmod 440 /etc/sudoers.d/conduit-proxy
    echo "  /etc/sudoers.d/conduit-proxy installed."
  fi
  rm -f "$TMP_SUDOERS"

  # Configure APT proxy drop-in if Debian/Ubuntu
  if [ "$DISTRO" = "debian" ] || [ -d /etc/apt/apt.conf.d ]; then
    echo "  Configuring APT proxy (/etc/apt/apt.conf.d/99conduit-proxy)..."
    cat << 'EOF' | $SUDO tee /etc/apt/apt.conf.d/99conduit-proxy >/dev/null
Acquire::http::Proxy "http://127.0.0.1:8888";
Acquire::https::Proxy "http://127.0.0.1:8888";
EOF
    $SUDO chmod 644 /etc/apt/apt.conf.d/99conduit-proxy
  fi
else
  echo "  To route your current shell: source ./scripts/env.sh"
  echo "  To install system-wide across all shells and daemons: sudo $0 --system-proxy"
fi

# ── 12. Host Egress Firewall Lockdown ─────────────────────────────────
if [ "$ENABLE_FIREWALL" = true ]; then
  echo ""
  echo "--- 12. Egress Firewall Lockdown ---"
  TARGET_PROXY_USER="conduit"
  if [ "$INSTALL_MODE" = "user" ]; then
    TARGET_PROXY_USER="$REAL_USER"
  fi
  echo "  Enforcing firewall lockdown for proxy user '$TARGET_PROXY_USER'..."
  $SUDO "$ROOT_DIR/scripts/setup-firewall.sh" --enable "$TARGET_PROXY_USER"
fi

# ── 13. Omarchy Desktop Plugin ────────────────────────────────────────
if [ "$ENABLE_OMARCHY" = true ]; then
  echo ""
  echo "--- 13. Installing Omarchy Desktop Plugin ---"
  OMARCHY_DIR="$REAL_HOME/.config/omarchy"
  PLUGIN_SRC="$ROOT_DIR/deploy/omarchy/io.github.the2dl.conduit"
  PLUGIN_DEST="$OMARCHY_DIR/plugins/io.github.the2dl.conduit"

  if [ ! -d "$PLUGIN_SRC" ]; then
    echo "  Warning: Omarchy plugin source not found at $PLUGIN_SRC"
  else
    echo "  Installing plugin to $PLUGIN_DEST..."
    mkdir -p "$OMARCHY_DIR/plugins"
    rm -rf "$PLUGIN_DEST"
    cp -r "$PLUGIN_SRC" "$PLUGIN_DEST"
    chmod +x "$PLUGIN_DEST/poll.sh"

    if [ "$(id -u)" -eq 0 ] && [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ]; then
      chown -R "$REAL_USER:$REAL_USER" "$PLUGIN_DEST"
    fi

    if command -v omarchy >/dev/null 2>&1; then
      echo "  Enabling Conduit plugin on Omarchy bar..."
      run_build omarchy plugin enable io.github.the2dl.conduit right 2>/dev/null || true
      if command -v omarchy-shell >/dev/null 2>&1; then
        run_build omarchy-shell shell rescanPlugins 2>/dev/null || true
      fi
      echo "  Omarchy plugin enabled on status bar."
    else
      echo "  Plugin installed to $PLUGIN_DEST."
    fi
  fi
fi

# ── 14. Summary ───────────────────────────────────────────────────────
echo ""
echo "=========================================================="
echo "          Conduit Installation Complete!                  "
echo "=========================================================="
echo "  Mode:             $INSTALL_MODE"
echo "  Management UI:    http://localhost:8443"
echo "  HTTP/HTTPS Proxy: http://127.0.0.1:8888"
echo "  Datastore:        Valkey on 127.0.0.1:6380"
echo "  Prometheus Stats: http://localhost:9091"
if [ "$ENABLE_OMARCHY" = true ]; then
  echo "  Omarchy Widget:   Enabled (bar -> right)"
fi
echo ""
echo "  Useful Commands:"
if [ "$INSTALL_MODE" = "system" ]; then
  echo "    conduit-ctl status              Check status of all components"
  echo "    sudo systemctl restart conduit  Restart Conduit services"
  echo "    sudo journalctl -u conduit-proxy -f View proxy logs"
else
  echo "    ./scripts/conduit-ctl.sh status Check status of all components"
  echo "    systemctl --user restart conduit.target Restart Conduit"
  echo "    tail -f logs/proxy.log          View proxy logs"
fi
if [ "$ENABLE_OMARCHY" = false ] && [ -d "$REAL_HOME/.config/omarchy" ]; then
  echo "    omarchy plugin enable io.github.the2dl.conduit (or re-run with --omarchy)"
fi
echo "    source ./scripts/env.sh         Enable proxy in current shell"
echo "    source ./scripts/unenv.sh       Disable proxy in current shell"
echo ""
echo "  Note: Running terminal shells do not automatically inherit updated environment variables."
echo "  To activate immediately in THIS terminal window, run:"
echo "    source ~/.bashrc"
echo "  (or open a new terminal window / tab)."
echo "=========================================================="
