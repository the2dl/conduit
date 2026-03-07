# Request Pipeline

This page details the full lifecycle of a request through Conduit.

## 1. Connection acceptance

A client connects to Conduit's listener port. `ClearGateService::process_new` handles the raw connection.

## 2. Protocol detection

- **Plain HTTP** — Request is parsed and forwarded to the proxy pipeline directly.
- **CONNECT** — Client requests a tunnel to a target host:port.

## 3. MITM handshake (CONNECT only)

If `tls_intercept = true`:

1. Conduit responds with `200 Connection Established`
2. Generates (or retrieves from cache) a TLS certificate for the target domain, signed by Conduit's CA
3. Performs a TLS handshake with the client
4. The decrypted stream enters the proxy pipeline as a regular HTTP request

If `tls_intercept = false`, bytes are proxied bidirectionally without inspection.

## 4. Request filter

The `request_filter` phase runs before upstream connection:

1. **Authentication** — Validates `Proxy-Authorization` if `auth_required = true`
2. **Connection limiting** — Checks per-IP connection count
3. **Rate limiting** — Checks per-IP/user/destination request rates
4. **Policy evaluation** — Loads rules from Dragonfly, checks domain against allow/block lists and categories
5. **Threat Tier 0** — Fast heuristics (DGA, suspicious TLD, URL patterns)
6. **Threat Tier 1** — ML model scoring (if escalated from Tier 0)

If any check results in a block, the request is rejected with an appropriate status code.

## 5. Upstream selection

`upstream_peer` determines where to send the request:

- If the domain matches a load balancing group, selects a backend via round-robin
- Otherwise, connects directly to the target host

## 6. Upstream request

The request is forwarded to the selected upstream. If HTTP caching is enabled, the cache is checked first.

## 7. Response filter

The `response_filter` phase processes the upstream response:

1. **HTTP cache storage** — Cacheable responses are stored
2. **Threat Tier 2** — Content inspection for suspicious HTML/JS (if escalated)
3. **DLP scanning** — Regex matching for sensitive data patterns
4. **Threat Tier 3** — LLM analysis (if enabled and escalated)

## 8. Logging

After the response is sent to the client:

- Request metadata is logged to Dragonfly (domain, status, user, policy action, threat verdict)
- If syslog is configured, a copy is forwarded via syslog
- Prometheus metrics are updated
