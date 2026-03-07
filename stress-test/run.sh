#!/usr/bin/env bash
set -euo pipefail

# Conduit Proxy — Stress Test Runner
#
# Usage:
#   ./run.sh [OPTIONS]
#
# Options:
#   --tier TIER          Test tier: small|medium|large|enterprise|soak (default: small)
#   --vus N              Custom VU count (overrides tier)
#   --duration DUR       Custom sustain duration, e.g. "5m" (overrides tier)
#   --proxy HOST:PORT    Proxy address (default: localhost:8888)
#   --mock               Use local mock upstream (starts it automatically)
#   --collect-metrics    Scrape Prometheus metrics during the test
#   --metrics-url URL    Metrics endpoint (default: http://localhost:9091/metrics)
#   --no-report          Skip the analysis report
#   --help               Show this help

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RESULTS_BASE="${SCRIPT_DIR}/results"

# Defaults
TIER="small"
CUSTOM_VUS=""
CUSTOM_DURATION=""
PROXY_HOST="localhost"
PROXY_PORT="8888"
USE_MOCK=0
COLLECT_METRICS=0
METRICS_URL="http://localhost:9091/metrics"
SKIP_REPORT=0
MOCK_PID=""

usage() {
  head -20 "$0" | grep '^#' | sed 's/^# \?//'
  exit 0
}

cleanup() {
  if [ -n "$MOCK_PID" ]; then
    echo "Stopping mock upstream (PID $MOCK_PID)..."
    kill "$MOCK_PID" 2>/dev/null || true
    wait "$MOCK_PID" 2>/dev/null || true
  fi
  if [ -n "${METRICS_COLLECTOR_PID:-}" ]; then
    kill "$METRICS_COLLECTOR_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT

# Parse args
while [[ $# -gt 0 ]]; do
  case "$1" in
    --tier) TIER="$2"; shift 2 ;;
    --vus) CUSTOM_VUS="$2"; shift 2 ;;
    --duration) CUSTOM_DURATION="$2"; shift 2 ;;
    --proxy)
      PROXY_HOST="${2%%:*}"
      PROXY_PORT="${2##*:}"
      shift 2
      ;;
    --mock) USE_MOCK=1; shift ;;
    --collect-metrics) COLLECT_METRICS=1; shift ;;
    --metrics-url) METRICS_URL="$2"; shift 2 ;;
    --no-report) SKIP_REPORT=1; shift ;;
    --help) usage ;;
    *) echo "Unknown option: $1"; usage ;;
  esac
done

# Preflight checks
if ! command -v k6 &>/dev/null; then
  echo "Error: k6 is not installed. Install with: brew install k6"
  exit 1
fi

# Create results directory
TIMESTAMP=$(date +%Y-%m-%dT%H-%M-%S)
RESULTS_DIR="${RESULTS_BASE}/${TIMESTAMP}_${TIER}"
mkdir -p "$RESULTS_DIR"

echo "============================================"
echo "  Conduit Proxy Stress Test"
echo "============================================"
echo "  Tier:       ${TIER}"
echo "  Proxy:      ${PROXY_HOST}:${PROXY_PORT}"
echo "  Mock:       $([ $USE_MOCK -eq 1 ] && echo 'yes' || echo 'no')"
echo "  Results:    ${RESULTS_DIR}"
echo "============================================"
echo ""

# Verify proxy is reachable
if ! curl -s --connect-timeout 5 -o /dev/null "http://${PROXY_HOST}:${PROXY_PORT}/" 2>/dev/null; then
  echo "Warning: Proxy at ${PROXY_HOST}:${PROXY_PORT} may not be reachable."
  echo "         Make sure conduit-proxy is running."
  read -p "Continue anyway? [y/N] " -n 1 -r
  echo
  [[ $REPLY =~ ^[Yy]$ ]] || exit 1
fi

# Start mock upstream if requested
if [ $USE_MOCK -eq 1 ]; then
  MOCK_BIN="${SCRIPT_DIR}/../target/release/conduit-mock"
  if [ ! -f "$MOCK_BIN" ]; then
    echo "Error: conduit-mock not built. Run: cargo build --release -p conduit-mock"
    exit 1
  fi
  echo "Starting mock upstream server..."
  "$MOCK_BIN" &
  MOCK_PID=$!
  sleep 1
  if ! kill -0 "$MOCK_PID" 2>/dev/null; then
    echo "Error: Mock upstream failed to start."
    exit 1
  fi
  echo "Mock upstream running (PID $MOCK_PID)"
fi

# Collect system baseline
echo ""
echo "System baseline:"
echo "  CPU cores: $(sysctl -n hw.ncpu 2>/dev/null || nproc 2>/dev/null || echo 'unknown')"
echo "  Memory:    $(sysctl -n hw.memsize 2>/dev/null | awk '{printf "%.0f GB", $1/1024/1024/1024}' 2>/dev/null || free -h 2>/dev/null | awk '/Mem:/{print $2}' || echo 'unknown')"
echo ""

# Save test metadata
cat > "${RESULTS_DIR}/metadata.json" <<METAEOF
{
  "timestamp": "${TIMESTAMP}",
  "tier": "${TIER}",
  "proxy": "${PROXY_HOST}:${PROXY_PORT}",
  "mock": ${USE_MOCK},
  "custom_vus": "${CUSTOM_VUS}",
  "custom_duration": "${CUSTOM_DURATION}",
  "cpu_cores": "$(sysctl -n hw.ncpu 2>/dev/null || nproc 2>/dev/null || echo 'unknown')",
  "os": "$(uname -s) $(uname -r)"
}
METAEOF

# Start metrics collector in background
if [ $COLLECT_METRICS -eq 1 ]; then
  echo "Starting metrics collector (polling every 5s)..."
  "${SCRIPT_DIR}/collect-metrics.sh" "$METRICS_URL" "${RESULTS_DIR}/metrics_timeseries.jsonl" &
  METRICS_COLLECTOR_PID=$!
fi

# Capture pre-test metrics snapshot
if [ $COLLECT_METRICS -eq 1 ]; then
  curl -s "$METRICS_URL" > "${RESULTS_DIR}/metrics_before.txt" 2>/dev/null || true
fi

# Build k6 environment
K6_ENV=(
  -e "PROXY_HOST=${PROXY_HOST}"
  -e "PROXY_PORT=${PROXY_PORT}"
  -e "RESULTS_DIR=${RESULTS_DIR}"
  -e "USE_MOCK=${USE_MOCK}"
)

if [ -n "$CUSTOM_VUS" ]; then
  K6_ENV+=(-e "TARGET_TIER=custom" -e "CUSTOM_VUS=${CUSTOM_VUS}")
  [ -n "$CUSTOM_DURATION" ] && K6_ENV+=(-e "CUSTOM_DURATION=${CUSTOM_DURATION}")
else
  K6_ENV+=(-e "TARGET_TIER=${TIER}")
fi

# Run k6
echo "Starting k6 load test..."
echo ""

HTTP_PROXY="http://${PROXY_HOST}:${PROXY_PORT}" \
HTTPS_PROXY="http://${PROXY_HOST}:${PROXY_PORT}" \
NO_PROXY="" \
k6 run \
  "${K6_ENV[@]}" \
  --summary-trend-stats="avg,min,med,max,p(90),p(95),p(99)" \
  "${SCRIPT_DIR}/k6-proxy-test.js" \
  2>&1 | tee "${RESULTS_DIR}/k6_output.txt"

K6_EXIT=$?

# Capture post-test metrics snapshot
if [ $COLLECT_METRICS -eq 1 ]; then
  curl -s "$METRICS_URL" > "${RESULTS_DIR}/metrics_after.txt" 2>/dev/null || true
fi

echo ""
echo "============================================"
echo "  Test Complete (exit code: ${K6_EXIT})"
echo "  Results: ${RESULTS_DIR}"
echo "============================================"

# Generate report
if [ $SKIP_REPORT -eq 0 ] && [ -f "${RESULTS_DIR}/summary.json" ]; then
  echo ""
  echo "Generating analysis report..."
  "${SCRIPT_DIR}/analyze.sh" "${RESULTS_DIR}"
fi

exit $K6_EXIT
