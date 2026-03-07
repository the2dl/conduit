# Quick Start

## 1. Start Dragonfly

```sh
docker compose up -d
```

## 2. Create a config file

Copy the example configuration:

```sh
cp conduit.example.toml conduit.toml
```

The defaults work out of the box for local development. Key settings to review:

```toml
listen_addr = "0.0.0.0:8888"    # proxy listener
api_addr = "0.0.0.0:8443"       # management API
dragonfly_url = "redis://127.0.0.1:6380"
tls_intercept = true             # set false for passthrough
```

## 3. Start the proxy and API

```sh
./target/release/conduit-proxy &
./target/release/conduit-api &
```

## 4. Configure your client

Point your browser or application at the proxy:

```sh
export http_proxy=http://127.0.0.1:8888
export https_proxy=http://127.0.0.1:8888
```

For TLS interception, you need to trust Conduit's CA certificate. On first run, Conduit generates `cleargate-ca.pem` and `cleargate-ca-key.pem` in the working directory.

### Trust the CA (macOS)

```sh
sudo security add-trusted-cert -d -r trustRoot \
  -k /Library/Keychains/System.keychain cleargate-ca.pem
```

### Trust the CA (Linux, per-session)

```sh
export SSL_CERT_FILE=cleargate-ca.pem
# or for curl specifically:
curl --cacert cleargate-ca.pem https://example.com
```

## 5. Test it

```sh
curl -x http://127.0.0.1:8888 http://httpbin.org/ip
curl -x http://127.0.0.1:8888 --cacert cleargate-ca.pem https://httpbin.org/ip
```

## 6. Manage policies via API

```sh
# Create a block rule
curl -X POST http://127.0.0.1:8443/api/policies \
  -H "Content-Type: application/json" \
  -d '{"domain": "blocked.example.com", "action": "block"}'

# List rules
curl http://127.0.0.1:8443/api/policies
```
