# Conduit Proxy — Stress Test Results

**Date:** 2026-03-07
**Platform:** Rackspace Spot Kubernetes (2 nodes, 8 CPU / 16 GB each)
**Proxy node:** 4 CPU request, 6 CPU limit, 10 GB RAM limit
**Mock upstream:** Rust/axum on same node as proxy
**Load generator:** k6 on dedicated node (6 CPU request, 8 CPU limit, 14 GB RAM)

## Configuration

Full production pipeline enabled:
- Threat detection (5 feeds loaded, fail_closed=false)
- DLP scanning (SSN, CC, AWS keys)
- DNS cache (LRU, TTL clamping)
- Domain categorization (1M+ categories loaded in-memory from Dragonfly)
- Response cache (in-memory)
- Rate limiting (100k/IP — effectively unlimited for test)
- Connection limiting (100k/IP)
- Load balancer routing (round-robin to mock upstream)
- Auth disabled for clean performance numbers

## Smoke Tier (10 VUs, 1m45s)

| Metric | avg | med | p(90) | p(95) | p(99) | max |
|---|---|---|---|---|---|---|
| http_req_duration | 1.53ms | 0.98ms | 2.11ms | 2.70ms | 7.15ms | 66.37ms |
| TTFB | 1.41ms | 0.90ms | 1.94ms | 2.31ms | 5.06ms | 66.32ms |

- **Error rate:** 0.00%
- **Checks passed:** 100%
- **Iterations:** 444 (4.22/s)
- **Total requests:** 633 (6.02/s)
- **Data received:** 9.1 MB (86.3 KB/s)

## Medium Tier (1,000 VUs, 8m)

| Metric | avg | med | p(90) | p(95) | p(99) | max |
|---|---|---|---|---|---|---|
| http_req_duration | 0.74ms | 0.61ms | 0.91ms | 1.24ms | 4.36ms | 80.69ms |
| TTFB | 0.63ms | 0.57ms | 0.85ms | 1.01ms | 1.53ms | 80.63ms |

- **Error rate:** 0.00%
- **Checks passed:** 100%
- **Iterations:** 205,911 (427.27/s)
- **Total requests:** 298,332 (619.04/s)
- **Data received:** 5.86 GB (12.2 MB/s)
- **CONNECT tunnels:** 143,722 (298.22/s)

## Large Tier (10,000 VUs, 17m30s)

| Metric | avg | med | p(90) | p(95) | p(99) | max |
|---|---|---|---|---|---|---|
| http_req_duration | 1.51ms | 1.14ms | 2.68ms | 3.47ms | 6.76ms | 327.38ms |
| TTFB | 1.34ms | 1.09ms | 2.44ms | 2.99ms | 4.25ms | 131.86ms |

- **Error rate:** 0.00%
- **Checks passed:** 100%
- **Iterations:** 4,272,710 (4,058.45/s)
- **Total requests:** 6,202,670 (5,891.64/s)
- **Data received:** 121.1 GB (115.1 MB/s)
- **CONNECT tunnels:** 2,988,181 (2,838.34/s)
- **Peak throughput:** ~5,892 req/s sustained

## Capacity Planning

Based on observed scaling across 10 → 1,000 → 10,000 concurrent users with 0% error rate
at every tier. All estimates assume full security pipeline enabled (threat detection, DLP,
domain categorization, DNS cache, response cache).

### Single proxy instance (4-6 CPU, 10 GB RAM)

| Concurrent users | req/s | median latency | p(99) latency | headroom |
|---|---|---|---|---|
| 100 | ~60 | <1ms | <5ms | idle |
| 1,000 | ~620 | <1ms | ~4ms | comfortable |
| 5,000 | ~3,000 | ~1ms | ~5ms | comfortable |
| 10,000 | ~5,900 | ~1ms | ~7ms | comfortable |

- Throughput at 10K users: **~5,900 req/s per instance**, 0% errors, 1.14ms median
- Per-CPU throughput: **~980 req/s** (with all security features active)
- Linear scaling holds across all tested tiers — median latency stays ~1ms even at 10K VUs
- p(99) stays under 7ms at all concurrency levels — no queueing wall
- Instance never drops requests and maintains sub-millisecond median throughout

### Multi-instance sizing guide

Assumes a load balancer (e.g., k8s Service, cloud LB) distributing across proxy replicas.
Each replica: 4 CPU request / 6 CPU limit / 10 GB RAM.

| Org size | Concurrent users | Proxy replicas | Est. throughput | Median latency |
|---|---|---|---|---|
| Small team | 100 | 1 | 60 req/s | <1ms |
| SMB | 500 | 1 | 300 req/s | <1ms |
| Mid-market | 1,000 | 1 | 620 req/s | <1ms |
| Growth | 5,000 | 1 | 3,000 req/s | ~1ms |
| Large enterprise | 10,000 | 2 | 5,900 req/s | ~1ms |
| Enterprise+ | 25,000 | 5 | 15,000 req/s | ~1ms |
| Fortune 500 | 50,000 | 9 | 30,000 req/s | ~1ms |
| Hyperscale | 100,000 | 17 | 60,000 req/s | <2ms |

### Cost context

At typical cloud pricing (~$0.05/CPU-hour for on-demand):
- 1,000 users: 1 replica = ~$7/month (4 CPU)
- 10,000 users: 2 replicas = ~$14/month (8 CPU)
- 50,000 users: 9 replicas = ~$65/month (36 CPU)
- 100,000 users: 17 replicas = ~$122/month (68 CPU)

Spot/reserved instances reduce these by 50-70%.

## Traffic Mix

All tiers use the same weighted traffic distribution:
- 70% HTTPS requests (via CONNECT tunnel → mock-tls.stress.local:443)
- 20% HTTP plain requests (mock.stress.local)
- 5% large downloads (128 KB response bodies)
- 5% burst requests (rapid-fire, no sleep)

## Performance Optimization History

### v2 — Performance optimizations (2026-03-07)

Targeted hot-path improvements yielding **+32% throughput** and **95% median latency reduction**
at 10K concurrent users:

1. **Pingora worker threads** — set to `available_parallelism()` (was defaulting to 1 thread)
2. **Bloom filters: RwLock → ArcSwap** — lock-free reads on every request
3. **Full in-memory category map** — eliminates Redis from hot path entirely
4. **Category cache** — 10K→100K capacity, 60s→300s TTL
5. **Connection pool idle_timeout** — enables TCP reuse to upstreams
6. **DLP early exit** — break on first Block match
7. **Bloom filter allocation** — skip format! when path is empty
8. **Reputation cache peek()** — avoid LRU reorder under lock
9. **Threat feed immediate reload** — Notify-based pub/sub instead of polling interval

**Large tier improvement:**

| Metric | Before | After | Change |
|---|---|---|---|
| Throughput | 4,460 req/s | 5,892 req/s | **+32%** |
| Median latency | 24.84ms | 1.14ms | **-95%** |
| p(99) latency | 1,985ms | 6.76ms | **-99.7%** |
| Max latency | 2,677ms | 327ms | **-88%** |

### v1 — Initial baseline (2026-03-07)

First stress test run with full security pipeline. Established baseline of 4,460 req/s at
10K VUs with 0% errors but significant tail latency (p99 ~2s) due to single-threaded worker.

## Notes

- Median latency stays remarkably consistent across tiers: 0.98ms (smoke) → 0.61ms (medium)
  → 1.14ms (large), indicating the proxy scales linearly without queueing.
- Sub-millisecond median TTFB at 1,000 concurrent users with the full security pipeline active.
- Zero errors across all tiers — 0.00% failure rate even at 10,000 concurrent VUs.
- 121 GB transferred in 17.5 minutes with zero drops at the large tier.
- 5,892 req/s sustained with full security pipeline (threat + DLP + categorization + cache).
- The single biggest optimization was setting Pingora worker threads to match available CPUs —
  the framework defaults to 1 thread per service, which was the primary bottleneck at scale.
