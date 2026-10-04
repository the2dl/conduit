#!/usr/bin/env bash
# uninstall.sh — Cleanly disable or uninstall Conduit Security Gateway
#
# Removes all proxy routing, tears down firewall rules, cleans systemd units,
# purges CA certificates, and strips browser proxy flags with zero ghost state.
#
# Usage:
#   sudo ./scripts/uninstall.sh [--disable | --purge]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
MODE="${1:---disable}"

REAL_USER="${SUDO_USER:-$USER}"
REAL_HOME="$(eval echo "~$REAL_USER")"

echo "========================================================"
echo " Conduit Security Gateway — Clean Teardown Utility"
echo " Target user: $REAL_USER ($REAL_HOME)"
echo " Mode:        $MODE"
echo "========================================================"
echo ""

# 1. Egress Firewall Lockdown Teardown
echo "--- 1. Disabling Egress Firewall Lockdown ---"
if [ -f "$SCRIPT_DIR/setup-firewall.sh" ]; then
  bash "$SCRIPT_DIR/setup-firewall.sh" --disable 2>/dev/null || true
fi
if command -v nft >/dev/null 2>&1; then
  nft delete table inet conduit_lockdown 2>/dev/null || true
fi

# 2. Stop and Disable Systemd Services
echo ""
echo "--- 2. Stopping & Disabling Conduit Services ---"
systemctl stop conduit.target conduit-proxy.service conduit-api.service 2>/dev/null || true
systemctl disable conduit.target conduit-proxy.service conduit-api.service 2>/dev/null || true

# User-level services if running as non-root or with sudo
if [ "$EUID" -eq 0 ] && [ -n "${SUDO_USER:-}" ]; then
  sudo -u "$REAL_USER" systemctl --user stop conduit.target conduit-proxy.service conduit-api.service 2>/dev/null || true
  sudo -u "$REAL_USER" systemctl --user disable conduit.target conduit-proxy.service conduit-api.service 2>/dev/null || true
else
  systemctl --user stop conduit.target conduit-proxy.service conduit-api.service 2>/dev/null || true
  systemctl --user disable conduit.target conduit-proxy.service conduit-api.service 2>/dev/null || true
fi

# 3. Remove System Shell Proxy Profile
echo ""
echo "--- 3. Removing Shell Proxy Profiles ---"
rm -f /etc/profile.d/conduit.sh

# 4. Remove User Environment Defaults & Chrome Flags
echo ""
echo "--- 4. Cleaning User Session & Chrome Startup Flags ---"
rm -f "$REAL_HOME/.config/environment.d/conduit.conf"

if [ -f "$REAL_HOME/.config/chrome-flags.conf" ]; then
  sed -i '/--proxy-server=/d' "$REAL_HOME/.config/chrome-flags.conf" 2>/dev/null || true
  sed -i '/--proxy-bypass-list=/d' "$REAL_HOME/.config/chrome-flags.conf" 2>/dev/null || true
  sed -i '/# Conduit MITM Proxy/d' "$REAL_HOME/.config/chrome-flags.conf" 2>/dev/null || true
  echo "  Cleaned proxy flags from $REAL_HOME/.config/chrome-flags.conf"
fi

# 5. Purge Systemd User Session & D-Bus Environment
echo ""
echo "--- 5. Purging Systemd User & D-Bus Session Environment ---"
CLEAN_ENV_CMD='
  systemctl --user daemon-reload 2>/dev/null || true
  for v in http_proxy https_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY no_proxy NO_PROXY \
           CURL_CA_BUNDLE SSL_CERT_FILE REQUESTS_CA_BUNDLE NODE_EXTRA_CA_CERTS GIT_SSL_CAINFO; do
    systemctl --user unset-environment "$v" 2>/dev/null || true
  done
  if command -v dbus-update-activation-environment >/dev/null 2>&1; then
    dbus-update-activation-environment --systemd \
      http_proxy= https_proxy= HTTP_PROXY= HTTPS_PROXY= ALL_PROXY= no_proxy= NO_PROXY= \
      CURL_CA_BUNDLE= SSL_CERT_FILE= REQUESTS_CA_BUNDLE= NODE_EXTRA_CA_CERTS= GIT_SSL_CAINFO= 2>/dev/null || true
  fi
'
if [ "$EUID" -eq 0 ] && [ -n "${SUDO_USER:-}" ]; then
  REAL_UID=$(id -u "$REAL_USER" 2>/dev/null || true)
  USER_RUNTIME_DIR="/run/user/$REAL_UID"
  sudo -u "$REAL_USER" env "XDG_RUNTIME_DIR=$USER_RUNTIME_DIR" "DBUS_SESSION_BUS_ADDRESS=unix:path=$USER_RUNTIME_DIR/bus" bash -c "$CLEAN_ENV_CMD" 2>/dev/null || true
else
  bash -c "$CLEAN_ENV_CMD" 2>/dev/null || true
fi

# 6. CA Certificate Trust Removal (if --purge or full reset)
if [ "$MODE" = "--purge" ] || [ "$MODE" = "purge" ]; then
  echo ""
  echo "--- 6. Removing Root CA from Trust Stores ---"
  rm -f /etc/ca-certificates/trust-source/anchors/conduit-ca.crt \
        /usr/local/share/ca-certificates/conduit-ca.crt \
        /etc/pki/ca-trust/source/anchors/conduit-ca.crt

  if command -v trust >/dev/null 2>&1; then
    trust extract-compat 2>/dev/null || true
  elif command -v update-ca-certificates >/dev/null 2>&1; then
    update-ca-certificates 2>/dev/null || true
  elif command -v update-ca-trust >/dev/null 2>&1; then
    update-ca-trust 2>/dev/null || true
  fi

  if command -v certutil >/dev/null 2>&1 && [ -d "$REAL_HOME/.pki/nssdb" ]; then
    if [ "$EUID" -eq 0 ] && [ -n "${SUDO_USER:-}" ]; then
      sudo -u "$REAL_USER" certutil -d "sql:$REAL_HOME/.pki/nssdb" -D -n "Conduit Root CA" 2>/dev/null || true
    else
      certutil -d "sql:$REAL_HOME/.pki/nssdb" -D -n "Conduit Root CA" 2>/dev/null || true
    fi
  fi
  echo "  Root CA removed from OS and NSS trust stores."

  echo ""
  echo "--- 7. Purging Binaries & Configurations ---"
  rm -f /usr/local/bin/conduit-proxy /usr/local/bin/conduit-api /usr/local/bin/conduit-ctl
  rm -f /etc/systemd/system/conduit*
  systemctl daemon-reload 2>/dev/null || true
  rm -rf /etc/conduit /var/lib/conduit
  rm -rf "$REAL_HOME/.config/omarchy/plugins/io.github.the2dl.conduit"
  echo "  Installed files purged."
fi

echo ""
echo "========================================================"
echo " Conduit has been cleanly disabled."
echo " Direct network access is restored."
echo " In your current shell, run: source $ROOT_DIR/scripts/unenv.sh"
echo "========================================================"
