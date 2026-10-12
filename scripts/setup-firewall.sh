#!/usr/bin/env bash
# setup-firewall.sh — Configure host egress firewall lockdown for Conduit
# Forces all outbound HTTP/HTTPS traffic through Conduit (127.0.0.1:8888)
# by blocking direct outbound ports 80/443 for non-proxy processes.
#
# Usage:
#   sudo ./scripts/setup-firewall.sh [--enable|--disable|--status|--repair-tailscale] [USER]

set -euo pipefail

ACTION="${1:---enable}"
if [ -n "${2:-}" ]; then
  PROXY_USER="$2"
elif id conduit >/dev/null 2>&1 && (systemctl is-active conduit-proxy >/dev/null 2>&1 || [ -f "/etc/systemd/system/conduit-proxy.service" ]); then
  PROXY_USER="conduit"
else
  PROXY_USER="${SUDO_USER:-$USER}"
fi

PROXY_UID=$(id -u "$PROXY_USER" 2>/dev/null || true)
if [ -z "$PROXY_UID" ]; then
  echo "Error: Unknown proxy user '$PROXY_USER'." >&2
  exit 1
fi

show_status() {
  echo "=== Conduit Egress Firewall Status ==="
  if command -v nft >/dev/null 2>&1 && nft list table inet conduit_lockdown >/dev/null 2>&1; then
    echo "Firewall: ACTIVE (nftables table 'conduit_lockdown' enabled for UID $PROXY_UID / $PROXY_USER)"
    nft list table inet conduit_lockdown
  elif iptables -C OUTPUT -m owner --uid-owner "$PROXY_UID" -p tcp -m multiport --dports 80,443 -j ACCEPT >/dev/null 2>&1; then
    echo "Firewall: ACTIVE (iptables egress lockdown enabled for UID $PROXY_UID / $PROXY_USER)"
  else
    echo "Firewall: INACTIVE (Direct outbound HTTP/HTTPS is currently unconstrained)"
  fi
}

disable_firewall() {
  echo "Disabling Conduit egress firewall rules..."
  if command -v nft >/dev/null 2>&1; then
    nft delete table inet conduit_lockdown 2>/dev/null || true
  fi

  # Remove iptables rules if present
  for family in iptables ip6tables; do
    if command -v "$family" >/dev/null 2>&1; then
      while "$family" -C OUTPUT -p tcp -m multiport --dports 80,443 -m owner --uid-owner 0 -m mark --mark 0x80000/0xff0000 -m comment --comment conduit-tailscale -j ACCEPT 2>/dev/null; do
        "$family" -D OUTPUT -p tcp -m multiport --dports 80,443 -m owner --uid-owner 0 -m mark --mark 0x80000/0xff0000 -m comment --comment conduit-tailscale -j ACCEPT
      done
    fi
  done
  iptables -D OUTPUT -m owner --uid-owner "$PROXY_UID" -p tcp -m multiport --dports 80,443 -j ACCEPT 2>/dev/null || true
  iptables -D OUTPUT -p tcp -m multiport --dports 80,443 -j REJECT --reject-with icmp-port-unreachable 2>/dev/null || true
  echo "Conduit egress firewall disabled."
}

nft_rules() {
  if [ "${1:-false}" = true ]; then
    echo "delete table inet conduit_lockdown"
  fi
  # Replace only our own table in one transaction; repeated enables must not
  # append new exceptions behind an old terminal reject rule.
  cat <<EOF
table inet conduit_lockdown {
    chain output {
        type filter hook output priority filter - 5; policy accept;

        # Allow loopback traffic
        oif "lo" accept

        # Allow established and related connections
        ct state established,related accept

        # tailscaled marks its own coordination/DERP sockets with the bypass mark.
        # Preserve unrelated mark bits and require the standard root daemon UID.
        meta skuid 0 meta mark & 0x00ff0000 == 0x00080000 tcp dport { 80, 443 } counter accept comment "conduit-tailscale"

        # Essential direct services
        udp dport { 53, 123, 41641, 51820 } accept
        tcp dport { 22, 53, 6443 } accept

        # Allow direct LAN and private RFC 1918 traffic (exempt from proxying)
        ip daddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16 } accept
        ip6 daddr { fc00::/7, fe80::/10 } accept

        # Allow Conduit proxy process (UID $PROXY_UID) direct outbound web access
        skuid $PROXY_UID tcp dport { 80, 443 } accept

        # Reject all other direct HTTP/HTTPS attempts (forces routing via 127.0.0.1:8888)
        tcp dport { 80, 443 } log prefix "[CONDUIT EGRESS BLOCKED]: " counter reject with icmpx type port-unreachable
    }
}
EOF
}

repair_tailscale() {
  if command -v nft >/dev/null 2>&1 && nft list chain inet conduit_lockdown output >/dev/null 2>&1; then
    if ! nft list chain inet conduit_lockdown output | grep -q 'comment "conduit-tailscale"'; then
      # Insert at the head of the existing chain. Do not reload or disable the
      # firewall, and leave every other table and rule untouched.
      nft insert rule inet conduit_lockdown output meta skuid 0 meta mark \& 0x00ff0000 == 0x00080000 tcp dport '{' 80, 443 '}' counter accept comment '"conduit-tailscale"'
    fi
    echo "Tailscale daemon exception present in Conduit nftables lockdown."
  elif command -v iptables >/dev/null 2>&1 && iptables -C OUTPUT -p tcp -m multiport --dports 80,443 -j REJECT --reject-with icmp-port-unreachable >/dev/null 2>&1; then
    for family in iptables ip6tables; do
      if command -v "$family" >/dev/null 2>&1 && ! "$family" -C OUTPUT -p tcp -m multiport --dports 80,443 -m owner --uid-owner 0 -m mark --mark 0x80000/0xff0000 -m comment --comment conduit-tailscale -j ACCEPT 2>/dev/null; then
        "$family" -I OUTPUT 1 -p tcp -m multiport --dports 80,443 -m owner --uid-owner 0 -m mark --mark 0x80000/0xff0000 -m comment --comment conduit-tailscale -j ACCEPT
      fi
    done
    echo "Tailscale daemon exception present in Conduit iptables lockdown."
  else
    echo "No active Conduit lockdown found; no firewall rules changed." >&2
    return 1
  fi
}

enable_firewall() {
  echo "Enabling Conduit egress lockdown for user '$PROXY_USER' (UID: $PROXY_UID)..."

  if command -v nft >/dev/null 2>&1; then
    local replace=false
    if nft list table inet conduit_lockdown >/dev/null 2>&1; then replace=true; fi
    nft_rules "$replace" | nft -f -
    echo "nftables egress lockdown applied successfully."
  elif command -v iptables >/dev/null 2>&1; then
    # iptables implementation
    disable_firewall >/dev/null 2>&1 || true

    # Insert rules at the top of OUTPUT
    iptables -I OUTPUT 1 -p tcp -m multiport --dports 80,443 -j REJECT --reject-with icmp-port-unreachable
    iptables -I OUTPUT 1 -m owner --uid-owner "$PROXY_UID" -p tcp -m multiport --dports 80,443 -j ACCEPT
    iptables -I OUTPUT 1 -d 10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,169.254.0.0/16 -j ACCEPT
    iptables -I OUTPUT 1 -p tcp -m multiport --dports 22,53,6443 -j ACCEPT
    iptables -I OUTPUT 1 -p udp -m multiport --dports 53,123,41641,51820 -j ACCEPT
    iptables -I OUTPUT 1 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables -I OUTPUT 1 -o lo -j ACCEPT
    repair_tailscale
    echo "iptables egress lockdown applied successfully."
  else
    echo "Error: Neither nftables nor iptables found." >&2
    exit 1
  fi
}

# Read-only rendering supports syntax/ordering checks without privileged changes.
if [ "$ACTION" = --print-nft ]; then nft_rules; exit 0; fi
if [ "$EUID" -ne 0 ]; then
  echo "Error: Firewall configuration requires root privileges. Please run with sudo." >&2
  exit 1
fi

case "$ACTION" in
  --repair-tailscale|repair-tailscale)
    repair_tailscale
    ;;
  --enable|enable)
    enable_firewall
    ;;
  --disable|disable)
    disable_firewall
    ;;
  --status|status)
    show_status
    ;;
  *)
    echo "Usage: sudo $0 {--enable|--disable|--status|--repair-tailscale} [USER]"
    exit 1
    ;;
esac
