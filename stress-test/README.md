# Conduit Proxy Stress Testing Suite

Load testing and capacity planning for Conduit proxy deployments.

## Prerequisites

- [k6](https://k6.io/docs/get-started/installation/) — load generator
- [jq](https://jqlang.github.io/jq/) — JSON processing
- A running Conduit proxy (default: `localhost:8888`)
- A running Dragonfly instance
- (Optional) A running metrics endpoint (default: `localhost:9091`)

### Install k6 (macOS)

```bash
brew install k6
```

## Quick Start

```bash
# Run the default profile (ramp to 500 VUs)
./run.sh

# Run a specific tier
./run.sh --tier small      # 500 concurrent clients
./run.sh --tier medium     # 1,000 concurrent clients
./run.sh --tier large      # 10,000 concurrent clients
./run.sh --tier enterprise # 100,000 concurrent clients

# Custom target
./run.sh --vus 2000 --duration 5m

# Burn test (sustained load for stability)
./run.sh --tier medium --duration 30m

# With metrics collection
./run.sh --tier large --collect-metrics
```

## Test Tiers

| Tier       | Peak VUs  | Ramp Up | Sustain | Ramp Down | Use Case                          |
|------------|-----------|---------|---------|-----------|-----------------------------------|
| small      | 500       | 1m      | 5m      | 30s       | Single-team / small office        |
| medium     | 1,000     | 2m      | 5m      | 1m        | Mid-size org                      |
| large      | 10,000    | 5m      | 10m     | 2m        | Large enterprise                  |
| enterprise | 100,000   | 10m     | 15m     | 5m        | Campus / MSP / multi-tenant       |
| soak       | 1,000     | 2m      | 60m     | 1m        | Long-running stability            |

## Test Scenarios

The k6 script runs a realistic traffic mix:

- **70%** — HTTPS CONNECT tunnels (typical browser traffic)
- **20%** — Plain HTTP GET requests
- **5%**  — Large response downloads (content inspection stress)
- **5%**  — Rapid-fire bursts (rate limiter stress)

## Output

Results are saved to `results/` with timestamps:

```
results/
  2026-03-07T14-30-00_medium/
    summary.json          # k6 JSON summary
    metrics_snapshot.json # Prometheus metrics at end of test
    report.txt            # Human-readable report with sizing recs
```

## Sizing Recommendations

After a test run, `analyze.sh` produces deployment sizing estimates:

```bash
./analyze.sh results/2026-03-07T14-30-00_medium/
```

## Architecture Notes

- k6 acts as an HTTP client using the proxy (via `HTTP_PROXY`)
- Each VU (virtual user) represents one concurrent client connection
- CONNECT tunnels test the full TLS interception path
- Tests hit real external endpoints by default; use `--mock` to target a local echo server
- The `--collect-metrics` flag polls the Prometheus endpoint during the test
