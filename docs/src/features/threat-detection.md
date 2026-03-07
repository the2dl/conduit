# Threat Detection

Conduit includes a multi-tier threat detection pipeline that analyzes requests and responses for malicious activity.

```toml
[threat]
enabled = true
```

## Detection tiers

### Tier 0: Heuristics (fast, every request)

Lightweight checks that run on every request:

- **DGA detection** — Shannon entropy analysis on domain names to detect algorithmically generated domains
- **Suspicious TLD matching** — Known-bad top-level domains
- **URL pattern analysis** — Detects phishing indicators, encoded payloads, excessive subdomains

```toml
tier0_escalation_threshold = 0.3   # Score to escalate to Tier 1
tier0_block_threshold = 0.9        # Score to block immediately
dga_entropy_threshold = 3.5        # Entropy threshold for DGA detection
```

### Tier 1: ML Model

A trained model that scores requests based on domain features. Escalates to Tier 2 if the score exceeds the threshold.

```toml
tier1_enabled = true
tier1_escalation_threshold = 0.5
```

### Tier 2: Content Inspection

Analyzes response bodies (HTML, JavaScript) for phishing indicators, credential harvesting forms, and obfuscated scripts.

```toml
tier2_enabled = true
tier2_escalation_threshold = 0.6
max_inspect_bytes = 262144          # 256KB max inspection size
tier2_block_on_inspect = true       # Block on first visit (adds latency)
max_buffer_bytes = 1048576          # 1MB max buffer for first-visit blocking
```

When `tier2_block_on_inspect = false` (default), content analysis runs asynchronously after the response is forwarded. Threats are blocked on subsequent visits via reputation.

### Tier 3: LLM Analysis (optional)

Sends suspicious content to an LLM for deeper analysis. Disabled by default due to latency and cost.

```toml
tier3_enabled = true
llm_provider = "anthropic"
llm_api_url = "https://api.anthropic.com/v1/messages"
llm_api_key = "sk-..."
tier3_behavior = "allow_and_flag"   # or "block_on_flag"
tier3_timeout_ms = 5000
```

## Domain reputation

Conduit maintains per-domain reputation scores that decay over time. Domains with consistently suspicious activity are blocked automatically.

```toml
reputation_enabled = true
reputation_decay_hours = 168        # 7 days
reputation_block_threshold = 0.55
```

## Threat feeds

Bloom filter-backed threat intelligence feeds are refreshed periodically.

```toml
bloom_capacity = 2000000
bloom_fp_rate = 0.0001
feed_refresh_interval_secs = 3600   # 1 hour
```
