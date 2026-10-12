# Assessment capture and replay

Conduit can retain request/response headers and bodies for an explicitly scoped assessment. Ordinary traffic keeps its existing metadata-only logs. Each captured request needs a registered session and both `X-Conduit-Assessment` and `X-Conduit-Capture-Token`. These control headers are consumed before forwarding.

## Enable

Set `CONDUIT_ASSESSMENT_API_KEY` in the API service environment. This protects only assessment endpoints and leaves existing dashboard authentication unchanged. A configured global `api_key` is supported as a fallback when the dedicated key is absent. Set the same `CONDUIT_ASSESSMENT_KEY` in the API and proxy service environments. Generate its base64-encoded 32-byte encryption key with `openssl rand -base64 32`. Store keys in protected service environment configuration, outside Valkey, and restart both services after configuring them. Capture is disabled without a valid encryption key; assessment endpoints always require authentication.

Session definitions, capture tokens, and flows are encrypted with AES-256-GCM before entering Valkey. Each record uses a random nonce and authenticates its datastore key. Auth cookies, bearer tokens, query strings, and body secrets remain available after decryption so authenticated replay works. Treat decrypted API responses as sensitive and use loopback or TLS for management access. Rotate the key after sessions expire; changing it makes old records unreadable.

## Start and capture

For an existing system installation on the default ports, the activation helper creates protected key files and systemd drop-ins, deploys prebuilt release binaries with the rollback watchdog, and verifies real capture/replay:

```bash
cargo build --release -p conduit-api -p conduit-proxy
sudo bash scripts/activate-assessment.sh "$USER"
```

Existing keys are reused. The API key is saved for the selected user in `~/.config/conduit/assessment-client.env` (mode 0600). The encryption key stays in `/etc/conduit/assessment-encryption.env`; the server API key stays in `/etc/conduit/assessment-api.env`, both root-owned mode 0600. Only the API service loads the API key. The helper preserves the global management authentication setting, stages binaries atomically, and rolls back binaries, keys, and drop-ins if activation fails. `conduit-ctl rollback` restores the checkpoint. The live smoke assessment is deleted after verification.

`bash scripts/activate-assessment.sh --check` validates embedded Python without requiring root or changing services. To verify new normal-log metadata before committing a deployment, add `--verify-request-metadata` after the client user. This sends an untagged local fixture request and requires its running proxy JSON log to contain the expected `referer` and `user_agent` fields before canceling the rollback watchdog.

Load client settings without displaying the key:

```bash
set -a
source "$HOME/.config/conduit/assessment-client.env"
set +a
```

The curl examples below use `$CONDUIT_ASSESSMENT_API_KEY` for assessment authentication.

```bash
curl --noproxy '*' -sS http://127.0.0.1:8443/api/v1/assessments \
  -H "Authorization: Bearer $CONDUIT_ASSESSMENT_API_KEY" \
  -H 'Content-Type: application/json' \
  -d '{"origins":["https://app.example.com"],"ttl_seconds":3600,"max_body_bytes":262144,"max_flows":500}'
```

The response contains `session.id`, `session.token`, canonical origins, limits, and the capture headers. Attach them only to assessment target requests:

```bash
curl --proxy http://127.0.0.1:8888 --noproxy '' https://app.example.com/api/me \
  -H "X-Conduit-Assessment: $RUN_ID" \
  -H "X-Conduit-Capture-Token: $CAPTURE_TOKEN" \
  -H "Authorization: Bearer $TARGET_TOKEN"
```

HTTPS payload capture requires interception and Conduit's trusted CA. Encrypted pass-through tunnels cannot expose HTTP payloads. Browser automation should add capture headers to scoped target requests, including requests from new tabs, rather than all browsing traffic.

Origins match scheme, host, and effective port exactly; wildcards are unsupported. Invalid tokens, expired sessions, and out-of-scope traffic proceed without payload capture. Tagging does not bypass proxy authentication, egress rules, DLP, threat protection, or rate limits. Captured requests bypass Conduit's cache. Captured target responses include `X-Conduit-Flow-Id` for correlation.

Defaults: one hour, 256 KiB per body, and 500 flows. Maximums: 24 hours, 1 MiB per body, 1000 flows, and 32 origins. At the flow cap, further traffic proceeds without persisted captures. Session, index, and flows share an absolute expiry. In-flight traffic cannot resurrect expired or deleted sessions. Bodies have a `truncated` flag. Streams/errors may have partial bodies; proxy-generated blocks may contain request data and status/error metadata without their generated response payload.

Headers are capped separately at 64 KiB per message. `headers_truncated` indicates incomplete or non-text headers, and those requests cannot be replayed automatically. Recent/search reads small encrypted summaries rather than decrypting full payloads. Assessment responses send `Cache-Control: no-store`.

## Inspect and replay

Paths are relative to `/api/v1` and require the management API key:

| Method | Path | Behavior |
| --- | --- | --- |
| GET | `/assessments/{run}` | Scope and limits, without capture token |
| GET | `/assessments/{run}/flows?limit=50&offset=0&search=/api` | Recent metadata; substring search on URL/method |
| GET | `/assessments/{run}/flows/{id}` | Decrypted headers and base64 request/response bodies |
| POST | `/assessments/{run}/flows/{id}/replay` | Replay with optional mutations |
| DELETE | `/assessments/{run}` | Atomically stop capture and purge session/flows |

Replay accepts `{}` or:

```json
{
  "method": "POST",
  "url": "https://app.example.com/api/example",
  "set_headers": [["Authorization", "Bearer replacement"], ["Content-Type", "application/json"]],
  "remove_headers": ["Cookie"],
  "body_base64": "e30="
}
```

Application auth and duplicate headers are preserved; replacement/removal is case-insensitive. Framing and proxy control headers are rebuilt. Truncated request bodies require complete replacements. Replay URLs must stay within session origins. Redirects are returned without following them. Replays use the configured Conduit listener and its CA with normal policy enforcement, a 30-second timeout, and a 1 MiB request-body ceiling. Results include `status`, `flow_id`, and a bounded response. Proxy blocks may have no `flow_id`.

The replay API currently does not supply separate proxy-auth credentials on installations with `auth_required`; authenticated clients can still capture and replay directly through the listener. The first implementation targets a local API/proxy pair. In multi-node installations, replay targets the API's configured listener, not an arbitrary capture node.

## Verification

```bash
cargo test -p conduit-common assessment
cargo test -p conduit-api assessment
cargo build -p conduit-api -p conduit-proxy
python3 scripts/test_assessment.py
```

The integration script starts temporary Valkey, API, proxy, and mock-origin instances on isolated ports and leaves installed services unchanged.
