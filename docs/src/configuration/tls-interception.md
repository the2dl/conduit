# TLS Interception

Conduit can operate in two modes for HTTPS traffic:

## Interception mode (default)

```toml
tls_intercept = true
```

When a client sends a `CONNECT` request, Conduit:

1. Accepts the tunnel and responds with `200 Connection Established`
2. Performs a TLS handshake with the client using a dynamically generated certificate for the target domain
3. Forwards the decrypted request to the upstream server over a new TLS connection
4. Applies policy rules, threat detection, DLP scanning, and caching to the full request/response

This gives full visibility into HTTPS traffic, including URLs, headers, and bodies.

### CA certificates

On first run, Conduit generates a CA certificate and key:

- `cleargate-ca.pem` — CA certificate (distribute to clients)
- `cleargate-ca-key.pem` — CA private key (keep secure)

Override the paths:

```toml
ca_cert_path = "/etc/conduit/ca.pem"
ca_key_path = "/etc/conduit/ca-key.pem"
```

The generated certificates are cached in memory (up to `cert_cache_size` entries) to avoid repeated generation for the same domain.

## Passthrough mode

```toml
tls_intercept = false
```

In passthrough mode, Conduit forwards encrypted bytes directly between client and server without decryption. Only the `CONNECT` target (host:port) is visible for policy enforcement — URLs, headers, and bodies are not inspected.

Use this when:

- You only need domain-level blocking
- Privacy requirements prohibit content inspection
- Upstream servers use certificate pinning
