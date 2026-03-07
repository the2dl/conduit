# Multi-Node Clustering

Conduit supports multi-node deployments where multiple proxy instances share policy and state through a central Dragonfly instance.

## Node configuration

Each node needs a `[node]` section in its config:

```toml
[node]
node_id = "node-abc123"
dragonfly_url = "redis://node-abc123:password@controlplane:6379"
name = "proxy-east-1"
enrollment_token = "one-time-token"
hmac_key = "base64url-encoded-hmac-key"
```

## Enrollment flow

1. **Generate a node** via the API on the control plane:
   ```sh
   curl -X POST http://controlplane:8443/api/nodes \
     -H "Content-Type: application/json" \
     -d '{"name": "proxy-east-1"}'
   ```
   This returns a `node_id`, `enrollment_token`, and per-node Dragonfly credentials.

2. **Configure the node** with the returned values in `conduit.toml`.

3. **Start the node** — it registers with the control plane using the enrollment token. After successful enrollment, the token is consumed and the HMAC key is used for ongoing heartbeat authentication.

## Heartbeats

Nodes send periodic heartbeats (default: every 10 seconds) to report their status. Heartbeats are HMAC-signed to prevent spoofing.

```toml
heartbeat_interval_secs = 10
```

## Shared state

All nodes share:

- Policy rules
- Domain categories
- DLP rules
- Request logs
- Threat reputation data

Each node maintains its own in-memory caches (DNS, certs, HTTP responses) independently.
