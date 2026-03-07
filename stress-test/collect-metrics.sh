#!/usr/bin/env bash
set -euo pipefail

# Polls Prometheus metrics endpoint and appends timestamped snapshots to a JSONL file.
# Usage: collect-metrics.sh <metrics_url> <output_file> [interval_secs]

METRICS_URL="${1:?Usage: collect-metrics.sh <metrics_url> <output_file> [interval_secs]}"
OUTPUT_FILE="${2:?Usage: collect-metrics.sh <metrics_url> <output_file> [interval_secs]}"
INTERVAL="${3:-5}"

while true; do
  TIMESTAMP=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  METRICS=$(curl -s --connect-timeout 2 "$METRICS_URL" 2>/dev/null || echo "")

  if [ -n "$METRICS" ]; then
    # Extract key metrics into a compact JSON line
    REQUESTS=$(echo "$METRICS" | grep '^conduit_requests_total' | awk '{sum+=$2} END {printf "%.0f", sum}')
    BLOCKS=$(echo "$METRICS" | grep '^conduit_blocks_total' | awk '{sum+=$2} END {printf "%.0f", sum}')
    ACTIVE=$(echo "$METRICS" | grep '^conduit_active_connections ' | awk '{print $2}')
    RATE_LIMITS=$(echo "$METRICS" | grep '^conduit_rate_limits_total ' | awk '{print $2}')
    CACHE_HITS=$(echo "$METRICS" | grep '^conduit_cache_hits_total ' | awk '{print $2}')
    CACHE_MISSES=$(echo "$METRICS" | grep '^conduit_cache_misses_total ' | awk '{print $2}')
    DNS_HITS=$(echo "$METRICS" | grep '^conduit_dns_cache_hits_total ' | awk '{print $2}')

    echo "{\"ts\":\"${TIMESTAMP}\",\"requests\":${REQUESTS:-0},\"blocks\":${BLOCKS:-0},\"active_conns\":${ACTIVE:-0},\"rate_limits\":${RATE_LIMITS:-0},\"cache_hits\":${CACHE_HITS:-0},\"cache_misses\":${CACHE_MISSES:-0},\"dns_hits\":${DNS_HITS:-0}}" >> "$OUTPUT_FILE"
  fi

  sleep "$INTERVAL"
done
