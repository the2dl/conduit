// Conduit Proxy — k6 Load Test Script
//
// k6 routes traffic through the proxy via HTTP_PROXY / HTTPS_PROXY env vars
// (set by run.sh). Auth is disabled in the stress test config for clean perf numbers.
//
// Usage:
//   HTTP_PROXY=http://localhost:8888 k6 run k6-proxy-test.js
//
// Environment variables:
//   TARGET_TIER      — test tier: smoke|small|medium|large|enterprise|soak|custom
//   CUSTOM_VUS       — VUs for custom tier
//   CUSTOM_DURATION  — duration for custom tier (e.g., "5m")
//   USE_MOCK         — if "1", use mock upstream targets
//   MOCK_HTTP_PORT   — mock HTTP server port (default: "18080")
//   MOCK_HTTPS_PORT  — mock HTTPS server port (default: "18443")
//   RESULTS_DIR      — directory to write summary.json

import http from "k6/http";
import { check, sleep, group } from "k6";
import { Counter, Rate, Trend } from "k6/metrics";

// Inline helpers to avoid remote imports (which fail through the MITM proxy)
function randomIntBetween(min, max) {
  return Math.floor(Math.random() * (max - min + 1) + min);
}

// ---------------------------------------------------------------------------
// Custom metrics
// ---------------------------------------------------------------------------
const proxyErrors = new Counter("proxy_errors");
const connectTunnels = new Counter("connect_tunnels");
const httpRequests = new Counter("http_plain_requests");
const largeDownloads = new Counter("large_downloads");
const burstRequests = new Counter("burst_requests");
const successRate = new Rate("success_rate");
const ttfb = new Trend("ttfb_ms", true);

// ---------------------------------------------------------------------------
// Config from environment
// ---------------------------------------------------------------------------
const USE_MOCK = __ENV.USE_MOCK === "1";

// ---------------------------------------------------------------------------
// Test tier configurations
// ---------------------------------------------------------------------------
const TIERS = {
  smoke: {
    stages: [
      { duration: "30s", target: 10 },
      { duration: "1m", target: 10 },
      { duration: "15s", target: 0 },
    ],
  },
  small: {
    stages: [
      { duration: "1m", target: 500 },
      { duration: "5m", target: 500 },
      { duration: "30s", target: 0 },
    ],
  },
  medium: {
    stages: [
      { duration: "2m", target: 1000 },
      { duration: "5m", target: 1000 },
      { duration: "1m", target: 0 },
    ],
  },
  large: {
    stages: [
      { duration: "30s", target: 100 },
      { duration: "5m", target: 10000 },
      { duration: "10m", target: 10000 },
      { duration: "2m", target: 0 },
    ],
  },
  enterprise: {
    stages: [
      { duration: "1m", target: 1000 },
      { duration: "10m", target: 100000 },
      { duration: "15m", target: 100000 },
      { duration: "5m", target: 0 },
    ],
  },
  soak: {
    stages: [
      { duration: "2m", target: 1000 },
      { duration: "60m", target: 1000 },
      { duration: "1m", target: 0 },
    ],
  },
};

function getCustomTier() {
  const vus = parseInt(__ENV.CUSTOM_VUS || "500");
  const dur = __ENV.CUSTOM_DURATION || "5m";
  return {
    stages: [
      { duration: "1m", target: vus },
      { duration: dur, target: vus },
      { duration: "30s", target: 0 },
    ],
  };
}

const tier = __ENV.TARGET_TIER || "small";
const tierConfig = TIERS[tier] || getCustomTier();

// ---------------------------------------------------------------------------
// k6 options
// ---------------------------------------------------------------------------
export const options = {
  stages: tierConfig.stages,
  thresholds: {
    http_req_failed: ["rate<0.05"],       // <5% errors
    http_req_duration: ["p(95)<5000"],     // p95 < 5s
    success_rate: ["rate>0.90"],           // >90% success
  },
  insecureSkipTLSVerify: true,
  noConnectionReuse: false,
  userAgent: "conduit-stress-test/1.0",
};

// ---------------------------------------------------------------------------
// Target URLs
// ---------------------------------------------------------------------------

// External targets (realistic traffic patterns)
const HTTPS_TARGETS = [
  "https://httpbin.org/get",
  "https://httpbin.org/headers",
  "https://httpbin.org/ip",
  "https://httpbin.org/user-agent",
  "https://httpbin.org/uuid",
  "https://www.example.com/",
];

const HTTP_TARGETS = [
  "http://httpbin.org/get",
  "http://httpbin.org/headers",
  "http://httpbin.org/ip",
  "http://httpbin.org/status/200",
];

const LARGE_TARGETS = [
  "https://httpbin.org/bytes/102400",  // 100KB
  "https://httpbin.org/bytes/524288",  // 512KB
  "http://httpbin.org/bytes/1048576",  // 1MB
];

// Mock targets (local echo server — much higher throughput)
// Mock targets use fake hostnames routed via load balancer in conduit-stress.toml
// to bypass the proxy's SSRF protection on loopback/private IPs.
const MOCK_HTTPS_TARGETS = [
  "https://mock-tls.stress.local/get",
  "https://mock-tls.stress.local/headers",
  "https://mock-tls.stress.local/uuid",
];

const MOCK_HTTP_TARGETS = [
  "http://mock.stress.local/get",
  "http://mock.stress.local/headers",
  "http://mock.stress.local/status/200",
];

const MOCK_LARGE_TARGETS = [
  "http://mock.stress.local/bytes/102400",
  "http://mock.stress.local/bytes/524288",
  "http://mock.stress.local/bytes/1048576",
];

function pickHttps() {
  const targets = USE_MOCK ? MOCK_HTTPS_TARGETS : HTTPS_TARGETS;
  return targets[randomIntBetween(0, targets.length - 1)];
}

function pickHttp() {
  const targets = USE_MOCK ? MOCK_HTTP_TARGETS : HTTP_TARGETS;
  return targets[randomIntBetween(0, targets.length - 1)];
}

function pickLarge() {
  const targets = USE_MOCK ? MOCK_LARGE_TARGETS : LARGE_TARGETS;
  return targets[randomIntBetween(0, targets.length - 1)];
}

// ---------------------------------------------------------------------------
// Request helpers
// ---------------------------------------------------------------------------

const proxyParams = {
  timeout: "30s",
};

function makeRequest(url) {
  const res = http.get(url, proxyParams);
  const ok = res.status >= 200 && res.status < 500;
  successRate.add(ok);
  if (res.timings && res.timings.waiting) {
    ttfb.add(res.timings.waiting);
  }
  if (!ok) {
    proxyErrors.add(1);
  }
  return res;
}

// ---------------------------------------------------------------------------
// Scenarios — weighted traffic mix
// ---------------------------------------------------------------------------

export default function () {
  const roll = Math.random();

  if (roll < 0.70) {
    // 70% — HTTPS CONNECT tunnel
    group("https_connect", function () {
      connectTunnels.add(1);
      const res = makeRequest(pickHttps());
      check(res, {
        "HTTPS status ok": (r) => r.status >= 200 && r.status < 400,
      });
    });
  } else if (roll < 0.90) {
    // 20% — Plain HTTP
    group("http_plain", function () {
      httpRequests.add(1);
      const res = makeRequest(pickHttp());
      check(res, {
        "HTTP status ok": (r) => r.status >= 200 && r.status < 400,
      });
    });
  } else if (roll < 0.95) {
    // 5% — Large download
    group("large_download", function () {
      largeDownloads.add(1);
      const res = makeRequest(pickLarge());
      check(res, {
        "Large download ok": (r) => r.status === 200,
      });
    });
  } else {
    // 5% — Burst (rapid-fire, no sleep)
    group("burst", function () {
      for (let i = 0; i < 10; i++) {
        burstRequests.add(1);
        const res = makeRequest(pickHttp());
        check(res, {
          "Burst request ok": (r) => r.status >= 200 && r.status < 500,
        });
      }
    });
  }

  // Simulate realistic think time (except burst)
  if (roll < 0.95) {
    sleep(randomIntBetween(1, 3));
  }
}

// ---------------------------------------------------------------------------
// Summary handler — write JSON summary
// ---------------------------------------------------------------------------

export function handleSummary(data) {
  const outputs = { stdout: textSummary(data, { indent: "  ", enableColors: false }) };
  const dir = __ENV.RESULTS_DIR;
  if (dir) {
    outputs[`${dir}/summary.json`] = JSON.stringify(data, null, 2);
  }
  return outputs;
}

// Minimal text summary renderer (avoids remote import of jslib.k6.io)
function textSummary(data, opts) {
  const lines = [];
  const indent = (opts && opts.indent) || "  ";

  // Checks
  if (data.root_group && data.root_group.checks) {
    for (const check of data.root_group.checks) {
      const total = check.passes + check.fails;
      const pct = total > 0 ? ((check.passes / total) * 100).toFixed(1) : "0.0";
      const icon = check.fails === 0 ? "✓" : "✗";
      lines.push(`${indent}${icon} ${check.name}: ${pct}% (${check.passes}/${total})`);
    }
    lines.push("");
  }

  // Metrics
  for (const [name, metric] of Object.entries(data.metrics)) {
    if (metric.type === "counter") {
      lines.push(`${indent}${name}: count=${metric.values.count} rate=${metric.values.rate.toFixed(2)}/s`);
    } else if (metric.type === "rate") {
      lines.push(`${indent}${name}: ${(metric.values.rate * 100).toFixed(2)}%`);
    } else if (metric.type === "trend") {
      const v = metric.values;
      const fmt = (n) => (typeof n === "number" ? n.toFixed(2) : "N/A");
      lines.push(`${indent}${name}: avg=${fmt(v.avg)}ms min=${fmt(v.min)}ms med=${fmt(v.med)}ms max=${fmt(v.max)}ms p(90)=${fmt(v["p(90)"])}ms p(95)=${fmt(v["p(95)"])}ms p(99)=${fmt(v["p(99)"])}ms`);
    } else if (metric.type === "gauge") {
      lines.push(`${indent}${name}: value=${metric.values.value} min=${metric.values.min} max=${metric.values.max}`);
    }
  }
  return lines.join("\n") + "\n";
}
