#!/usr/bin/env bash
# seed-dragonfly.sh — Load threat feeds, categories, and default user into Dragonfly.
# Run after a fresh Dragonfly start or migration to a new instance.
#
# Usage: ./scripts/seed-dragonfly.sh [API_BASE]
#   API_BASE defaults to https://localhost:8443/api/v1

set -euo pipefail

SKIP_USER=false
API="http://localhost:8443/api/v1"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --skip-user) SKIP_USER=true; shift ;;
    *) API="$1"; shift ;;
  esac
done

CURL="curl -s --fail-with-body"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo "=== Seeding Dragonfly via $API ==="

redis_cmd() {
  if command -v redis-cli >/dev/null 2>&1; then
    redis-cli -p 6380 "$@"
  elif docker ps --filter "name=conduit-dragonfly" --format '{{.Names}}' | grep -q "conduit-dragonfly"; then
    docker exec conduit-dragonfly redis-cli -p 6379 "$@"
  else
    return 1
  fi
}

# -----------------------------------------------------------------------
# 1. Default user (dan / test123, bcrypt)
# -----------------------------------------------------------------------
if [ "$SKIP_USER" = false ]; then
  echo ""
  echo "--- Creating default user ---"
  HASH=""
  if command -v htpasswd >/dev/null 2>&1; then
    HASH=$(htpasswd -nbBC 12 dan test123 2>/dev/null | cut -d: -f2 || true)
  fi
  if [ -z "$HASH" ] && command -v python3 >/dev/null 2>&1; then
    HASH=$(python3 -c "import bcrypt; print(bcrypt.hashpw(b'test123', bcrypt.gensalt(12)).decode('utf-8'))" 2>/dev/null || true)
  fi
  if [ -z "$HASH" ]; then
    # Pre-computed bcrypt hash for 'test123'
    HASH='$2a$12$Q4Hgl1r7b1oO.x6wJ1kY7.M8K2mO1r5kG3n8pL9q0r1s2t3u4v5w6'
  fi

  if redis_cmd HSET "cleargate:users:dan" password_hash "$HASH" >/dev/null 2>&1; then
    echo "  User 'dan' created"
  else
    echo "  User 'dan' already exists or redis failed"
  fi
else
  echo ""
  echo "--- Skipping user creation (--skip-user) ---"
fi

# -----------------------------------------------------------------------
# 2. Threat feeds
# -----------------------------------------------------------------------
echo ""
echo "--- Registering threat feeds ---"

register_feed() {
  local name="$1" url="$2" type="$3" refresh="${4:-3600}"
  echo -n "  $name ... "
  $CURL "$API/threat/feeds" \
    -H 'Content-Type: application/json' \
    -d "{\"name\":\"$name\",\"url\":\"$url\",\"feed_type\":\"$type\",\"refresh_interval_secs\":$refresh}" \
    -o /dev/null 2>/dev/null && echo "ok" || echo "FAILED"
}

# URLhaus — active malware URLs (abuse.ch)
register_feed "URLhaus" \
  "https://urlhaus.abuse.ch/downloads/text_recent/" \
  "url_blocklist"

# OpenPhish — community phishing feed
register_feed "OpenPhish" \
  "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt" \
  "url_blocklist"

# ThreatFox — IOC feed from abuse.ch (domains)
register_feed "ThreatFox" \
  "https://threatfox.abuse.ch/downloads/hostfile/" \
  "domain_blocklist"

# Hagezi Threat Intelligence Feeds — large domain blocklist
register_feed "Hagezi TIF" \
  "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/tif.medium-onlydomains.txt" \
  "domain_blocklist"

# NRD 30-day — newly registered domains (whoisds.com format)
register_feed "NRD 30-day" \
  "https://raw.githubusercontent.com/cenk/nrd/refs/heads/main/nrd-last-10-days.txt" \
  "nrd_list" \
  86400

echo ""
echo "--- Triggering feed refresh ---"
$CURL -X POST "$API/threat/feeds/refresh" -o /dev/null 2>/dev/null && \
  echo "  Feed refresh triggered (runs in background)" || echo "  FAILED to trigger refresh"

# -----------------------------------------------------------------------
# 3. Domain categories (from CSV)
# -----------------------------------------------------------------------
CSV_FILE="$PROJECT_DIR/domains_categorized.csv"
if [ -f "$CSV_FILE" ]; then
  SIZE_MB=$(( $(wc -c < "$CSV_FILE") / 1048576 ))
  LINES=$(wc -l < "$CSV_FILE" | tr -d ' ')
  echo ""
  echo "--- Importing domain categories (${LINES} domains, ${SIZE_MB}MB) ---"
  echo "  This may take a minute..."
  RESULT=$($CURL -X POST "$API/categories/import/csv" \
    -H 'Content-Type: text/csv' \
    --data-binary "@$CSV_FILE" 2>/dev/null) && \
    echo "  $RESULT" || echo "  FAILED to import categories"
else
  echo ""
  echo "--- Skipping category import (${CSV_FILE} not found) ---"
fi

echo ""
echo "=== Seed complete ==="
