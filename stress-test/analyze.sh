#!/usr/bin/env bash
set -euo pipefail

# Conduit Proxy — Stress Test Analyzer
# Reads k6 summary.json and produces sizing recommendations.
#
# Usage: ./analyze.sh <results_dir>

RESULTS_DIR="${1:?Usage: ./analyze.sh <results_dir>}"
SUMMARY="${RESULTS_DIR}/summary.json"
REPORT="${RESULTS_DIR}/report.txt"

if [ ! -f "$SUMMARY" ]; then
  echo "Error: No summary.json found in ${RESULTS_DIR}"
  echo "Make sure the k6 test completed successfully."
  exit 1
fi

# Check for jq
if ! command -v jq &>/dev/null; then
  echo "Error: jq is required. Install with: brew install jq"
  exit 1
fi

# Load metadata
TIER="unknown"
PROXY_ADDR="unknown"
if [ -f "${RESULTS_DIR}/metadata.json" ]; then
  TIER=$(jq -r '.tier // "unknown"' "${RESULTS_DIR}/metadata.json")
  PROXY_ADDR=$(jq -r '.proxy // "unknown"' "${RESULTS_DIR}/metadata.json")
  CPU_CORES=$(jq -r '.cpu_cores // "unknown"' "${RESULTS_DIR}/metadata.json")
fi

# Extract k6 metrics
TOTAL_REQS=$(jq '.metrics.http_reqs.values.count // 0' "$SUMMARY")
RPS=$(jq '.metrics.http_reqs.values.rate // 0' "$SUMMARY")
AVG_DURATION=$(jq '.metrics.http_req_duration.values.avg // 0' "$SUMMARY")
P50_DURATION=$(jq '.metrics.http_req_duration.values.med // 0' "$SUMMARY")
P90_DURATION=$(jq '.metrics.http_req_duration.values["p(90)"] // 0' "$SUMMARY")
P95_DURATION=$(jq '.metrics.http_req_duration.values["p(95)"] // 0' "$SUMMARY")
P99_DURATION=$(jq '.metrics.http_req_duration.values["p(99)"] // 0' "$SUMMARY")
MAX_DURATION=$(jq '.metrics.http_req_duration.values.max // 0' "$SUMMARY")
FAIL_RATE=$(jq '.metrics.http_req_failed.values.rate // 0' "$SUMMARY")
MAX_VUS=$(jq '.metrics.vus_max.values.max // 0' "$SUMMARY")

# Custom metrics (may not exist)
CONNECT_TUNNELS=$(jq '.metrics.connect_tunnels.values.count // 0' "$SUMMARY" 2>/dev/null)
HTTP_PLAIN=$(jq '.metrics.http_plain_requests.values.count // 0' "$SUMMARY" 2>/dev/null)
LARGE_DL=$(jq '.metrics.large_downloads.values.count // 0' "$SUMMARY" 2>/dev/null)
BURST=$(jq '.metrics.burst_requests.values.count // 0' "$SUMMARY" 2>/dev/null)

# Data transfer
DATA_SENT=$(jq '.metrics.data_sent.values.count // 0' "$SUMMARY")
DATA_RECV=$(jq '.metrics.data_received.values.count // 0' "$SUMMARY")

# Thresholds
THRESH_FAIL=$(jq '[.metrics | to_entries[] | select(.value.thresholds != null) | .value.thresholds | to_entries[] | select(.value.ok == false)] | length' "$SUMMARY" 2>/dev/null || echo "0")

# Format bytes
format_bytes() {
  local bytes=$1
  if [ "$bytes" -ge 1073741824 ]; then
    echo "$(echo "scale=2; $bytes / 1073741824" | bc) GB"
  elif [ "$bytes" -ge 1048576 ]; then
    echo "$(echo "scale=2; $bytes / 1048576" | bc) MB"
  elif [ "$bytes" -ge 1024 ]; then
    echo "$(echo "scale=2; $bytes / 1024" | bc) KB"
  else
    echo "${bytes} B"
  fi
}

format_ms() {
  printf "%.2f ms" "$1"
}

# Generate sizing recommendations based on observed performance
sizing_recommendation() {
  local vus=$1
  local rps=$2
  local p95=$3
  local fail_rate=$4

  echo ""
  echo "DEPLOYMENT SIZING RECOMMENDATIONS"
  echo "================================="
  echo ""

  # Determine if the test was healthy
  local healthy=1
  if (( $(echo "$fail_rate > 0.05" | bc -l) )); then
    healthy=0
    echo "WARNING: High error rate ($(printf '%.1f%%' "$(echo "$fail_rate * 100" | bc -l)"))"
    echo "         The proxy was overloaded at this concurrency level."
    echo "         Scale horizontally or vertically before deploying at this tier."
    echo ""
  fi

  if (( $(echo "$p95 > 5000" | bc -l) )); then
    healthy=0
    echo "WARNING: p95 latency exceeded 5s ($(format_ms "$p95"))"
    echo "         Users will experience unacceptable delays."
    echo ""
  fi

  # Per-proxy instance sizing
  echo "--- Per Proxy Instance ---"
  echo ""

  if [ "$vus" -le 500 ]; then
    echo "  Tier: Small (up to 500 concurrent users)"
    echo "  CPU:  2 cores"
    echo "  RAM:  2 GB"
    echo "  Proxy instances: 1 (+ 1 standby for HA)"
    echo "  Dragonfly: 1 instance, 1 GB RAM"
    echo "  Est. RPS capacity: ~$(echo "$rps" | awk '{printf "%.0f", $1}') req/s per instance"
  elif [ "$vus" -le 1000 ]; then
    echo "  Tier: Medium (up to 1,000 concurrent users)"
    echo "  CPU:  4 cores"
    echo "  RAM:  4 GB"
    echo "  Proxy instances: 2 (active-active behind LB)"
    echo "  Dragonfly: 1 instance, 2 GB RAM"
    echo "  Est. RPS capacity: ~$(echo "$rps" | awk '{printf "%.0f", $1}') req/s per instance"
  elif [ "$vus" -le 10000 ]; then
    echo "  Tier: Large (up to 10,000 concurrent users)"
    echo "  CPU:  8 cores"
    echo "  RAM:  8 GB"
    echo "  Proxy instances: 4-6 (active-active behind LB)"
    echo "  Dragonfly: 2 instances (primary + replica), 4 GB RAM each"
    echo "  Est. RPS capacity: ~$(echo "$rps" | awk '{printf "%.0f", $1}') req/s total"
    echo "  Network: 1 Gbps minimum per proxy"
  else
    echo "  Tier: Enterprise (100,000+ concurrent users)"
    echo "  CPU:  16 cores per proxy"
    echo "  RAM:  16 GB per proxy"
    echo "  Proxy instances: 20-40 (active-active, multi-AZ)"
    echo "  Dragonfly: 3+ instances (clustered), 8 GB RAM each"
    echo "  Est. RPS capacity: ~$(echo "$rps" | awk '{printf "%.0f", $1}') req/s total"
    echo "  Network: 10 Gbps per proxy"
    echo "  Load Balancer: L4 (TCP) with connection-level balancing"
  fi

  echo ""
  echo "--- Dragonfly Sizing ---"
  echo ""

  # Estimate Dragonfly memory needs
  # Each logged request ~500 bytes, policy rules ~1KB each, bloom filter ~2MB
  local log_mem_mb
  log_mem_mb=$(echo "scale=0; $vus * 100 * 500 / 1048576" | bc)
  echo "  Estimated memory for log retention: ~${log_mem_mb} MB"
  echo "  Bloom filter (threat feeds): ~2-8 MB"
  echo "  Policy cache: ~1 MB"
  echo "  Connection pool: redis_pool_size = $([ "$vus" -le 1000 ] && echo '16' || echo '32-64')"
  echo ""

  echo "--- OS Tuning (Linux production) ---"
  echo ""
  echo "  # /etc/sysctl.conf"
  echo "  net.core.somaxconn = 65535"
  echo "  net.ipv4.tcp_max_syn_backlog = 65535"
  echo "  net.core.netdev_max_backlog = 65535"
  echo "  net.ipv4.ip_local_port_range = 1024 65535"
  echo "  net.ipv4.tcp_tw_reuse = 1"
  echo "  net.ipv4.tcp_fin_timeout = 15"
  echo "  fs.file-max = 1000000"
  echo ""
  echo "  # /etc/security/limits.conf"
  echo "  *  soft  nofile  1000000"
  echo "  *  hard  nofile  1000000"
  echo ""

  if [ "$vus" -ge 10000 ]; then
    echo "--- Additional Enterprise Notes ---"
    echo ""
    echo "  - Deploy proxies across multiple availability zones"
    echo "  - Use a TCP (L4) load balancer in front of proxy fleet"
    echo "  - Enable Dragonfly replication for HA"
    echo "  - Set up Prometheus + Grafana for monitoring"
    echo "  - Consider separate Dragonfly instances for logging vs policy"
    echo "  - Run soak tests (--tier soak) before production deployment"
    echo "  - Monitor: conduit_active_connections gauge for capacity planning"
    echo ""
  fi
}

# Build report
{
  echo "============================================================"
  echo "  CONDUIT PROXY STRESS TEST REPORT"
  echo "============================================================"
  echo ""
  echo "  Date:          $(date)"
  echo "  Test Tier:     ${TIER}"
  echo "  Proxy:         ${PROXY_ADDR}"
  echo "  Test Machine:  ${CPU_CORES} CPU cores"
  echo ""
  echo "============================================================"
  echo ""
  echo "LOAD SUMMARY"
  echo "============"
  echo ""
  echo "  Peak VUs:          ${MAX_VUS}"
  echo "  Total Requests:    ${TOTAL_REQS}"
  echo "  Throughput:        $(printf '%.1f' "$RPS") req/s"
  echo "  Data Sent:         $(format_bytes "$DATA_SENT")"
  echo "  Data Received:     $(format_bytes "$DATA_RECV")"
  echo ""
  echo "  Breakdown:"
  echo "    HTTPS CONNECT:   ${CONNECT_TUNNELS}"
  echo "    HTTP Plain:      ${HTTP_PLAIN}"
  echo "    Large Downloads: ${LARGE_DL}"
  echo "    Burst Requests:  ${BURST}"
  echo ""
  echo "LATENCY"
  echo "======="
  echo ""
  echo "  Average:  $(format_ms "$AVG_DURATION")"
  echo "  Median:   $(format_ms "$P50_DURATION")"
  echo "  p90:      $(format_ms "$P90_DURATION")"
  echo "  p95:      $(format_ms "$P95_DURATION")"
  echo "  p99:      $(format_ms "$P99_DURATION")"
  echo "  Max:      $(format_ms "$MAX_DURATION")"
  echo ""
  echo "RELIABILITY"
  echo "==========="
  echo ""
  echo "  Error Rate:         $(printf '%.2f%%' "$(echo "$FAIL_RATE * 100" | bc -l)")"
  echo "  Threshold Failures: ${THRESH_FAIL}"
  echo ""

  sizing_recommendation "$MAX_VUS" "$RPS" "$P95_DURATION" "$FAIL_RATE"

  echo "============================================================"
  echo "  Raw data: ${RESULTS_DIR}/summary.json"
  echo "============================================================"
} | tee "$REPORT"

echo ""
echo "Report saved to: ${REPORT}"
