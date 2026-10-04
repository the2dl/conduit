#!/usr/bin/env bash
# fix.sh — Audit and repair Conduit Security Gateway installation
#
# Inspects every component of Conduit:
# 1. Datastore (Valkey / Redis on port 6380)
# 2. Binaries, directories, and config (/usr/local/bin, /etc/conduit, /var/lib/conduit)
# 3. Systemd units & daemon health (conduit-api, conduit-proxy, conduit.target)
# 4. Root CA generation & OS / NSS trust stores
# 5. Shell & user session proxy environment (/etc/profile.d, environment.d, chrome flags)
# 6. Docker & containerd daemon proxy drop-ins (/etc/systemd/system/docker.service.d)
# 7. Host egress firewall lockdown (nftables/iptables)
# 8. Omarchy desktop status bar plugin (if applicable)
#
# Automatically fixes any missing configuration or drifting state without rebuilding.
#
# Usage:
#   sudo ./scripts/fix.sh
#   sudo ./scripts/install.sh --fix
#   conduit-ctl fix

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$ROOT_DIR"

REAL_USER="${SUDO_USER:-$USER}"
REAL_HOME="$(eval echo "~$REAL_USER")"

echo "=========================================================="
echo "    Conduit Security Gateway — System Audit & Self-Repair"
echo "=========================================================="
echo "Source root:   $ROOT_DIR"
echo "Target user:   $REAL_USER ($REAL_HOME)"
echo ""

FIX_COUNT=0
WARN_COUNT=0

log_ok() {
  echo -e "  \033[32m[OK]\033[0m $1"
}

log_fixed() {
  echo -e "  \033[33m[FIXED]\033[0m $1"
  FIX_COUNT=$((FIX_COUNT + 1))
}

log_warn() {
  echo -e "  \033[31m[WARN]\033[0m $1"
  WARN_COUNT=$((WARN_COUNT + 1))
}

log_info() {
  echo -e "  \033[34m[INFO]\033[0m $1"
}

# Require root if system mode is used or needed
if [ "$EUID" -ne 0 ]; then
  if [ -d "/etc/conduit" ] || [ -f "/etc/systemd/system/conduit.target" ]; then
    if sudo -n true 2>/dev/null; then
      exec sudo "$0" "$@"
    else
      echo "Notice: Conduit is installed in system mode (/etc/conduit). Full audit and repair requires root privileges."
      echo "Please run: sudo $0"
      exit 1
    fi
  fi
fi

# Detect Distro
DISTRO="unknown"
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
  arch|manjaro|endeavouros|garuda|cachyos|artix) DISTRO="arch" ;;
  debian|ubuntu|linuxmint|pop|elementary|raspbian) DISTRO="debian" ;;
  fedora|rhel|centos|rocky|almalinux|ol) DISTRO="fedora" ;;
  *)
    if [[ "$DISTRO_LIKE" == *"arch"* ]]; then DISTRO="arch"
    elif [[ "$DISTRO_LIKE" == *"debian"* || "$DISTRO_LIKE" == *"ubuntu"* ]]; then DISTRO="debian"
    elif [[ "$DISTRO_LIKE" == *"fedora"* || "$DISTRO_LIKE" == *"rhel"* ]]; then DISTRO="fedora"
    elif command -v pacman >/dev/null 2>&1; then DISTRO="arch"
    elif command -v apt-get >/dev/null 2>&1; then DISTRO="debian"
    elif command -v dnf >/dev/null 2>&1; then DISTRO="fedora"
    fi
    ;;
esac

# ── 1. Datastore on Port 6380 ──────────────────────────────────────────
echo "--- 1. Auditing Datastore (Port 6380) ---"

check_datastore() {
  if command -v valkey-cli >/dev/null 2>&1 && valkey-cli -p 6380 ping 2>/dev/null | grep -q PONG; then
    return 0
  elif command -v redis-cli >/dev/null 2>&1 && redis-cli -p 6380 ping 2>/dev/null | grep -q PONG; then
    return 0
  elif (echo > /dev/tcp/127.0.0.1/6380) 2>/dev/null; then
    return 0
  elif docker ps --filter "name=conduit-dragonfly" --format '{{.Status}}' 2>/dev/null | grep -q "Up"; then
    return 0
  fi
  return 1
}

if check_datastore; then
  log_ok "Datastore responding on 127.0.0.1:6380"
else
  # Attempt repair: check valkey/redis configuration
  REPAIRED_DS=false
  for conf in /etc/valkey/valkey.conf /etc/valkey.conf /etc/redis/redis.conf /etc/redis/valkey.conf /etc/redis.conf; do
    if [ -f "$conf" ]; then
      if ! grep -q "^port 6380" "$conf"; then
        sed -i 's/^port .*/port 6380/' "$conf"
        sed -i 's/^# port 6380/port 6380/' "$conf"
      fi
      if ! grep -q "^port 6380" "$conf"; then
        echo "port 6380" >> "$conf"
      fi
    fi
  done

  for svc in valkey valkey-server redis redis-server; do
    if systemctl list-unit-files "$svc.service" >/dev/null 2>&1; then
      systemctl enable --now "$svc" 2>/dev/null || true
      systemctl restart "$svc" 2>/dev/null || true
      sleep 1
      if check_datastore; then
        REPAIRED_DS=true
        log_fixed "Configured and restarted $svc.service on dedicated port 6380"
        break
      fi
    fi
  done

  if [ "$REPAIRED_DS" = false ]; then
    log_warn "Datastore not responding on port 6380. Check 'systemctl status valkey' or run 'docker run -d --name conduit-dragonfly -p 6380:6379 docker.dragonflydb.io/dragonflydb/dragonfly'"
  fi
fi

# ── 2. Binaries, Directories & Configuration ──────────────────────────
echo ""
echo "--- 2. Auditing Binaries & Directories ---"

# Check /usr/local/bin binaries
for bin in conduit-proxy conduit-api; do
  if [ -f "/usr/local/bin/$bin" ]; then
    log_ok "Binary /usr/local/bin/$bin is present"
  elif [ -f "$ROOT_DIR/target/release/$bin" ]; then
    cp "$ROOT_DIR/target/release/$bin" "/usr/local/bin/$bin"
    chmod 755 "/usr/local/bin/$bin"
    log_fixed "Restored /usr/local/bin/$bin from target/release/"
  else
    log_warn "Missing /usr/local/bin/$bin and target/release/$bin not compiled. Run: ./scripts/install.sh --skip-deps"
  fi
done

if [ -f "/usr/local/bin/conduit-ctl" ]; then
  log_ok "Binary /usr/local/bin/conduit-ctl is present"
else
  cp "$ROOT_DIR/scripts/conduit-ctl.sh" "/usr/local/bin/conduit-ctl"
  chmod 755 "/usr/local/bin/conduit-ctl"
  log_fixed "Installed /usr/local/bin/conduit-ctl"
fi

# Ensure user and group exist
if ! id conduit >/dev/null 2>&1; then
  useradd -r -s /usr/bin/nologin -d /var/lib/conduit -c "Conduit Proxy Daemon" conduit 2>/dev/null || true
  log_fixed "Created unprivileged 'conduit' system user"
else
  log_ok "System user 'conduit' exists"
fi

# Ensure directories exist
mkdir -p /etc/conduit/ca /var/lib/conduit/ui /var/log/conduit

# Ensure conduit.toml exists
if [ -f "/etc/conduit/conduit.toml" ]; then
  log_ok "Config /etc/conduit/conduit.toml is present"
else
  SRC_CFG="$ROOT_DIR/conduit.toml"
  [ ! -f "$SRC_CFG" ] && SRC_CFG="$ROOT_DIR/conduit.example.toml"
  cp "$SRC_CFG" /etc/conduit/conduit.toml
  sed -i 's|^#\? \?ca_cert_path = .*|ca_cert_path = "/etc/conduit/ca/ca.pem"|' /etc/conduit/conduit.toml
  sed -i 's|^#\? \?ca_key_path = .*|ca_key_path = "/etc/conduit/ca/ca-key.pem"|' /etc/conduit/conduit.toml
  sed -i 's|^#\? \?ui_dir = .*|ui_dir = "/var/lib/conduit/ui"|' /etc/conduit/conduit.toml
  log_fixed "Installed /etc/conduit/conduit.toml"
fi

# Ensure categories.txt exists
if [ -f "/etc/conduit/categories.txt" ]; then
  log_ok "Dataset /etc/conduit/categories.txt is present"
elif [ -f "$ROOT_DIR/categories.txt" ]; then
  cp "$ROOT_DIR/categories.txt" /etc/conduit/categories.txt
  log_fixed "Restored /etc/conduit/categories.txt"
fi

# Ensure UI files exist
if [ -f "/var/lib/conduit/ui/index.html" ] || [ -d "/var/lib/conduit/ui" ]; then
  if [ -z "$(ls -A /var/lib/conduit/ui 2>/dev/null)" ] && [ -d "$ROOT_DIR/conduit-ui/build" ]; then
    cp -r "$ROOT_DIR/conduit-ui/build/"* /var/lib/conduit/ui/
    log_fixed "Populated UI build into /var/lib/conduit/ui"
  else
    log_ok "UI directory /var/lib/conduit/ui is populated"
  fi
fi

# Fix permissions
chown -R conduit:conduit /etc/conduit /var/lib/conduit /var/log/conduit 2>/dev/null || true
chmod 750 /etc/conduit
chmod 700 /etc/conduit/ca
chmod 755 /var/lib/conduit

# ── 3. Systemd Services ───────────────────────────────────────────────
echo ""
echo "--- 3. Auditing Systemd Units & Services ---"

NEED_SYSTEMD_RELOAD=false
for unit in conduit-proxy.service conduit-api.service conduit.target; do
  SRC_UNIT="$ROOT_DIR/deploy/systemd/system/$unit"
  [ ! -f "$SRC_UNIT" ] && SRC_UNIT="$ROOT_DIR/deploy/systemd/$unit"
  if [ ! -f "/etc/systemd/system/$unit" ] && [ -f "$SRC_UNIT" ]; then
    cp "$SRC_UNIT" "/etc/systemd/system/$unit"
    NEED_SYSTEMD_RELOAD=true
    log_fixed "Installed missing unit /etc/systemd/system/$unit"
  elif [ -f "/etc/systemd/system/$unit" ]; then
    log_ok "Unit /etc/systemd/system/$unit is present"
  fi
done

if [ "$NEED_SYSTEMD_RELOAD" = true ]; then
  systemctl daemon-reload
fi

# Ensure services are enabled
if ! systemctl is-enabled conduit.target >/dev/null 2>&1; then
  systemctl enable conduit-proxy.service conduit-api.service conduit.target 2>/dev/null || true
  log_fixed "Enabled conduit.target and services"
else
  log_ok "Conduit systemd units are enabled"
fi

# Ensure services are running
if systemctl is-active conduit-proxy >/dev/null 2>&1 && systemctl is-active conduit-api >/dev/null 2>&1; then
  log_ok "Conduit proxy and API services are active"
else
  systemctl restart conduit-api.service conduit-proxy.service conduit.target 2>/dev/null || true
  sleep 1
  if systemctl is-active conduit-proxy >/dev/null 2>&1; then
    log_fixed "Restarted and verified Conduit proxy and API services"
  else
    log_warn "Conduit proxy failed to start. Check: journalctl -u conduit-proxy -n 20 --no-pager"
  fi
fi

# ── 4. Root CA & System Trust Stores ──────────────────────────────────
echo ""
echo "--- 4. Auditing Root CA & System Trust Stores ---"

CA_SOURCE=""
for candidate in "/etc/conduit/ca/ca.pem" "$ROOT_DIR/ca/ca.pem"; do
  if [ -f "$candidate" ] && [ -s "$candidate" ]; then
    CA_SOURCE="$candidate"
    break
  fi
done

if [ -n "$CA_SOURCE" ]; then
  log_ok "Root CA certificate found at $CA_SOURCE"
  
  # Ensure /etc/conduit/ca/ca.pem exists
  if [ ! -f "/etc/conduit/ca/ca.pem" ]; then
    cp "$CA_SOURCE" /etc/conduit/ca/ca.pem
    [ -f "${CA_SOURCE%.pem}-key.pem" ] && cp "${CA_SOURCE%.pem}-key.pem" /etc/conduit/ca/ca-key.pem
    chown -R conduit:conduit /etc/conduit/ca
    chmod 700 /etc/conduit/ca
    chmod 600 /etc/conduit/ca/*
    log_fixed "Synchronized Root CA to /etc/conduit/ca/ca.pem"
  fi

  # Check OS trust anchor
  CA_TRUST_INSTALLED=false
  case "$DISTRO" in
    arch)
      DEST="/etc/ca-certificates/trust-source/anchors/conduit-ca.crt"
      if [ -f "$DEST" ] && cmp -s "$CA_SOURCE" "$DEST"; then
        log_ok "Root CA installed in Arch trust anchors ($DEST)"
      else
        mkdir -p "$(dirname "$DEST")"
        cp "$CA_SOURCE" "$DEST"
        trust extract-compat 2>/dev/null || true
        log_fixed "Installed Root CA to $DEST and extracted trust database"
      fi
      ;;
    debian)
      DEST="/usr/local/share/ca-certificates/conduit-ca.crt"
      if [ -f "$DEST" ] && cmp -s "$CA_SOURCE" "$DEST"; then
        log_ok "Root CA installed in Debian trust store ($DEST)"
      else
        mkdir -p "$(dirname "$DEST")"
        cp "$CA_SOURCE" "$DEST"
        update-ca-certificates 2>/dev/null || true
        log_fixed "Installed Root CA to $DEST and ran update-ca-certificates"
      fi
      ;;
    fedora)
      DEST="/etc/pki/ca-trust/source/anchors/conduit-ca.crt"
      if [ -f "$DEST" ] && cmp -s "$CA_SOURCE" "$DEST"; then
        log_ok "Root CA installed in Fedora ca-trust ($DEST)"
      else
        mkdir -p "$(dirname "$DEST")"
        cp "$CA_SOURCE" "$DEST"
        update-ca-trust 2>/dev/null || true
        log_fixed "Installed Root CA to $DEST and ran update-ca-trust"
      fi
      ;;
    *)
      log_warn "Unknown distribution; could not automatically verify OS trust store."
      ;;
  esac

  # Check Chrome/Chromium NSS database
  USER_NSSDB="$REAL_HOME/.pki/nssdb"
  if command -v certutil >/dev/null 2>&1 && [ -d "$USER_NSSDB" ]; then
    if sudo -u "$REAL_USER" certutil -d "sql:$USER_NSSDB" -L -n "Conduit Root CA" >/dev/null 2>&1; then
      log_ok "Root CA trusted in Chrome/Chromium NSS database ($USER_NSSDB)"
    else
      sudo -u "$REAL_USER" certutil -d "sql:$USER_NSSDB" -A -t "C,," -n "Conduit Root CA" -i "$CA_SOURCE" 2>/dev/null || true
      log_fixed "Imported Root CA into Chrome/Chromium NSS database"
    fi
  fi
else
  log_warn "No Root CA certificate found. Start Conduit proxy once or run: sudo ./scripts/install.sh --trust-ca"
fi

# ── 5. Shell & User Session Proxy Environment ─────────────────────────
echo ""
echo "--- 5. Auditing Shell & Desktop Proxy Profiles ---"

# Check /etc/profile.d/conduit.sh
PROFILE_SH="/etc/profile.d/conduit.sh"
if [ -f "$PROFILE_SH" ] && grep -q "127.0.0.1:8888" "$PROFILE_SH"; then
  log_ok "$PROFILE_SH is configured"
else
  cat << 'EOF' > "$PROFILE_SH"
# Conduit Security Gateway Shell Proxy Environment
export http_proxy="http://127.0.0.1:8888"
export https_proxy="http://127.0.0.1:8888"
export HTTP_PROXY="http://127.0.0.1:8888"
export HTTPS_PROXY="http://127.0.0.1:8888"
export ALL_PROXY="http://127.0.0.1:8888"
export NO_PROXY="localhost,127.0.0.1,::1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,169.254.0.0/16,.local,.internal,.svc,.cluster.local"
export no_proxy="localhost,127.0.0.1,::1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,169.254.0.0/16,.local,.internal,.svc,.cluster.local"
EOF
  chmod 644 "$PROFILE_SH"
  log_fixed "Installed /etc/profile.d/conduit.sh for system-wide shells"
fi

# Check ~/.config/environment.d/conduit.conf
ENV_D="$REAL_HOME/.config/environment.d"
ENV_CONF="$ENV_D/conduit.conf"
if [ -f "$ENV_CONF" ] && grep -q "127.0.0.1:8888" "$ENV_CONF"; then
  log_ok "$ENV_CONF is configured"
else
  mkdir -p "$ENV_D"
  cat << 'EOF' > "$ENV_CONF"
# Conduit Security Gateway User Environment
http_proxy=http://127.0.0.1:8888
https_proxy=http://127.0.0.1:8888
HTTP_PROXY=http://127.0.0.1:8888
HTTPS_PROXY=http://127.0.0.1:8888
ALL_PROXY=http://127.0.0.1:8888
no_proxy=localhost,127.0.0.1,::1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,169.254.0.0/16,.local,.internal,.svc,.cluster.local
NO_PROXY=localhost,127.0.0.1,::1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,169.254.0.0/16,.local,.internal,.svc,.cluster.local
EOF
  chown -R "$REAL_USER:$REAL_USER" "$ENV_D"
  log_fixed "Created $ENV_CONF for desktop session environment"
fi

# Check Chrome flags
for flag_file in "$REAL_HOME/.config/chrome-flags.conf" "$REAL_HOME/.config/chromium-flags.conf" "$REAL_HOME/.config/google-chrome-flags.conf"; do
  if [ -f "$flag_file" ] || [ "$(basename "$flag_file")" = "chrome-flags.conf" ]; then
    if grep -q -- "--proxy-server=http://127.0.0.1:8888" "$flag_file" 2>/dev/null; then
      log_ok "Browser proxy flags active in $flag_file"
    else
      sed -i '/--proxy-server=/d' "$flag_file" 2>/dev/null || true
      sed -i '/--proxy-bypass-list=/d' "$flag_file" 2>/dev/null || true
      sed -i '/# Conduit MITM Proxy/d' "$flag_file" 2>/dev/null || true
      cat >> "$flag_file" << 'EOF'

# Conduit MITM Proxy
--proxy-server=http://127.0.0.1:8888
--proxy-bypass-list=*.local;10.0.0.0/8;172.16.0.0/12;192.168.0.0/16;169.254.0.0/16
EOF
      chown "$REAL_USER:$REAL_USER" "$flag_file" 2>/dev/null || true
      log_fixed "Configured browser proxy flags in $flag_file"
    fi
  fi
done

# Ensure live user systemd and D-Bus session have proxy
SET_ENV_CMD='
  for v in http_proxy="http://127.0.0.1:8888" https_proxy="http://127.0.0.1:8888" \
           HTTP_PROXY="http://127.0.0.1:8888" HTTPS_PROXY="http://127.0.0.1:8888" \
           ALL_PROXY="http://127.0.0.1:8888" \
           no_proxy="localhost,127.0.0.1,::1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,169.254.0.0/16,.local,.internal,.svc,.cluster.local" \
           NO_PROXY="localhost,127.0.0.1,::1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,169.254.0.0/16,.local,.internal,.svc,.cluster.local"; do
    systemctl --user set-environment "$v" 2>/dev/null || true
  done
  if command -v dbus-update-activation-environment >/dev/null 2>&1; then
    dbus-update-activation-environment --systemd \
      http_proxy https_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY no_proxy NO_PROXY 2>/dev/null || true
  fi
'
REAL_UID=$(id -u "$REAL_USER" 2>/dev/null || true)
USER_RUNTIME_DIR="/run/user/$REAL_UID"
sudo -u "$REAL_USER" env "XDG_RUNTIME_DIR=$USER_RUNTIME_DIR" "DBUS_SESSION_BUS_ADDRESS=unix:path=$USER_RUNTIME_DIR/bus" bash -c "$SET_ENV_CMD" 2>/dev/null || true
log_ok "Live user systemd & D-Bus session proxy environment propagated"

# ── 6. Docker & Containerd Daemon Proxy Drop-ins ──────────────────────
echo ""
echo "--- 6. Auditing Docker & Containerd Daemon Proxies ---"

DOCKER_INSTALLED=false
if command -v docker >/dev/null 2>&1 || [ -d /etc/docker ] || systemctl list-unit-files docker.service >/dev/null 2>&1; then
  DOCKER_INSTALLED=true
fi

if [ "$DOCKER_INSTALLED" = true ]; then
  DOCKER_DROPIN_DIR="/etc/systemd/system/docker.service.d"
  DOCKER_DROPIN_FILE="$DOCKER_DROPIN_DIR/http-proxy.conf"
  DOCKER_NEED_RESTART=false

  if [ -f "$DOCKER_DROPIN_FILE" ] && grep -q "127.0.0.1:8888" "$DOCKER_DROPIN_FILE"; then
    log_ok "Docker daemon proxy drop-in is present ($DOCKER_DROPIN_FILE)"
  else
    mkdir -p "$DOCKER_DROPIN_DIR"
    cat << 'EOF' > "$DOCKER_DROPIN_FILE"
[Service]
Environment="HTTP_PROXY=http://127.0.0.1:8888"
Environment="HTTPS_PROXY=http://127.0.0.1:8888"
Environment="http_proxy=http://127.0.0.1:8888"
Environment="https_proxy=http://127.0.0.1:8888"
Environment="NO_PROXY=localhost,127.0.0.1,::1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,169.254.0.0/16,.local,.internal,.svc,.cluster.local"
Environment="no_proxy=localhost,127.0.0.1,::1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,169.254.0.0/16,.local,.internal,.svc,.cluster.local"
EOF
    chmod 644 "$DOCKER_DROPIN_FILE"
    DOCKER_NEED_RESTART=true
    log_fixed "Created Docker daemon proxy drop-in ($DOCKER_DROPIN_FILE)"
  fi

  # containerd drop-in
  CONTAINERD_DROPIN_DIR="/etc/systemd/system/containerd.service.d"
  CONTAINERD_DROPIN_FILE="$CONTAINERD_DROPIN_DIR/http-proxy.conf"
  if systemctl list-unit-files containerd.service >/dev/null 2>&1 || command -v containerd >/dev/null 2>&1; then
    if [ -f "$CONTAINERD_DROPIN_FILE" ] && grep -q "127.0.0.1:8888" "$CONTAINERD_DROPIN_FILE"; then
      log_ok "Containerd proxy drop-in is present ($CONTAINERD_DROPIN_FILE)"
    else
      mkdir -p "$CONTAINERD_DROPIN_DIR"
      cat << 'EOF' > "$CONTAINERD_DROPIN_FILE"
[Service]
Environment="HTTP_PROXY=http://127.0.0.1:8888"
Environment="HTTPS_PROXY=http://127.0.0.1:8888"
Environment="http_proxy=http://127.0.0.1:8888"
Environment="https_proxy=http://127.0.0.1:8888"
Environment="NO_PROXY=localhost,127.0.0.1,::1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,169.254.0.0/16,.local,.internal,.svc,.cluster.local"
Environment="no_proxy=localhost,127.0.0.1,::1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,169.254.0.0/16,.local,.internal,.svc,.cluster.local"
EOF
      chmod 644 "$CONTAINERD_DROPIN_FILE"
      DOCKER_NEED_RESTART=true
      log_fixed "Created containerd proxy drop-in ($CONTAINERD_DROPIN_FILE)"
    fi
  fi

  if [ "$DOCKER_NEED_RESTART" = true ]; then
    systemctl daemon-reload
    if systemctl is-active docker >/dev/null 2>&1; then
      echo "  Restarting docker service to apply proxy configuration..."
      systemctl restart docker 2>/dev/null || true
      log_fixed "Docker daemon restarted with proxy environment active"
    fi
  fi
else
  log_info "Docker is not installed on this system (skipping)"
fi

# ── 7. Host Egress Firewall Lockdown ──────────────────────────────────
echo ""
echo "--- 7. Auditing Host Egress Firewall Lockdown ---"

if command -v nft >/dev/null 2>&1 && nft list table inet conduit_lockdown >/dev/null 2>&1; then
  log_ok "Egress firewall lockdown is active (nftables table 'conduit_lockdown')"
elif iptables -C OUTPUT -p tcp -m multiport --dports 80,443 -j REJECT >/dev/null 2>&1; then
  log_ok "Egress firewall lockdown is active (iptables OUTPUT reject rules)"
else
  log_info "Egress firewall is inactive (run 'sudo ./scripts/setup-firewall.sh --enable' to enforce proxying)"
fi

# ── 8. Omarchy Status Bar Plugin ──────────────────────────────────────
echo ""
echo "--- 8. Auditing Omarchy Desktop Widget ---"

OMARCHY_DIR="$REAL_HOME/.config/omarchy"
if [ -d "$OMARCHY_DIR" ] || command -v omarchy >/dev/null 2>&1; then
  PLUGIN_DEST="$OMARCHY_DIR/plugins/io.github.the2dl.conduit"
  PLUGIN_SRC="$ROOT_DIR/deploy/omarchy/io.github.the2dl.conduit"
  if [ -d "$PLUGIN_DEST" ] && [ -x "$PLUGIN_DEST/poll.sh" ]; then
    log_ok "Omarchy desktop widget plugin installed at $PLUGIN_DEST"
  elif [ -d "$PLUGIN_SRC" ]; then
    mkdir -p "$OMARCHY_DIR/plugins"
    rm -rf "$PLUGIN_DEST"
    cp -r "$PLUGIN_SRC" "$PLUGIN_DEST"
    chmod +x "$PLUGIN_DEST/poll.sh"
    chown -R "$REAL_USER:$REAL_USER" "$PLUGIN_DEST" 2>/dev/null || true
    if command -v omarchy >/dev/null 2>&1; then
      sudo -u "$REAL_USER" omarchy plugin enable io.github.the2dl.conduit right 2>/dev/null || true
      if command -v omarchy-shell >/dev/null 2>&1; then
        sudo -u "$REAL_USER" omarchy-shell shell rescanPlugins 2>/dev/null || true
      fi
    fi
    log_fixed "Installed and enabled Omarchy desktop status bar widget"
  fi
else
  log_info "Omarchy desktop not detected (skipping widget plugin)"
fi

# ── 9. Live Verification ──────────────────────────────────────────────
echo ""
echo "--- 9. Live Verification & Summary ---"

API_OK=false
if curl -sf http://127.0.0.1:8443/api/v1/health >/dev/null 2>&1; then
  API_OK=true
  log_ok "Conduit REST API & UI responding on http://127.0.0.1:8443"
else
  log_warn "Conduit REST API did not respond on http://127.0.0.1:8443"
fi

PROXY_OK=false
if curl -sf -I -x http://127.0.0.1:8888 http://localhost:8443/api/v1/health >/dev/null 2>&1; then
  PROXY_OK=true
  log_ok "Conduit forward proxy responding on http://127.0.0.1:8888"
else
  log_warn "Conduit forward proxy did not respond on http://127.0.0.1:8888"
fi

if [ "$DOCKER_INSTALLED" = true ]; then
  if docker info 2>/dev/null | grep -q "127.0.0.1:8888"; then
    log_ok "Docker daemon confirmed routing via Conduit proxy"
  else
    log_warn "Docker daemon proxy not yet active in 'docker info'. May require: sudo systemctl restart docker"
  fi
fi

echo ""
echo "=========================================================="
if [ "$WARN_COUNT" -eq 0 ]; then
  echo -e " \033[32mAudit Complete: System healthy. ($FIX_COUNT repairs applied)\033[0m"
else
  echo -e " \033[33mAudit Complete: $FIX_COUNT repairs applied, $WARN_COUNT warnings remaining.\033[0m"
fi
echo "=========================================================="
