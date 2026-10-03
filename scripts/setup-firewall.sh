#!/usr/bin/env bash
# setup-firewall.sh — Configure host egress firewall lockdown for Conduit
# Forces all outbound HTTP/HTTPS traffic through Conduit (127.0.0.1:8888)
# by blocking direct outbound ports 80/443 for non-proxy processes.
#
# Usage:
#   sudo ./scripts/setup-firewall.sh [--enable|--disable|--status] [USER]

set -euo pipefail

ACTION="${1:---enable}"
if [ -n "${2:-}" ]; then
  PROXY_USER="$2"
elif id conduit >/dev/null 2>&1 && (systemctl is-active conduit-proxy >/dev/null 2>&1 || [ -f "/etc/systemd/system/conduit-proxy.service" ]); then
  PROXY_USER="conduit"
else
  PROXY_USER="${SUDO_USER:-$USER}"
fi

if [ "$EUID" -ne 0 ]; then
  echo "Error: Firewall configuration requires root privileges. Please run with sudo." >&2
  exit 1
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
  iptables -D OUTPUT -m owner --uid-owner "$PROXY_UID" -p tcp -m multiport --dports 80,443 -j ACCEPT 2>/dev/null || true
  iptables -D OUTPUT -p tcp -m multiport --dports 80,443 -j REJECT --reject-with icmp-port-unreachable 2>/dev/null || true
  echo "Conduit egress firewall disabled."
}

enable_firewall() {
  echo "Enabling Conduit egress lockdown for user '$PROXY_USER' (UID: $PROXY_UID)..."

  if command -v nft >/dev/null 2>&1; then
    # nftables implementation
    nft -f - <<EOF
table inet conduit_lockdown {
    chain output {
        type filter hook output priority filter - 5; policy accept;

        # Allow loopback traffic
        oif "lo" accept

        # Allow established and related connections
        ct state established,related accept

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
    echo "iptables egress lockdown applied successfully."
  else
    echo "Error: Neither nftables nor iptables found." >&2
    exit 1
  fi
}

case "$ACTION" in
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
    echo "Usage: sudo $0 {--enable|--disable|--status} [USER]"
    exit 1
    ;;
esac
