# Docker Deployment

Conduit provides a multi-stage Dockerfile with separate targets for the proxy and API.

## Build images

```sh
docker build --target proxy -t conduit-proxy .
docker build --target api -t conduit-api .
```

## Run with Docker Compose

The included `docker-compose.yml` starts Dragonfly. You can extend it for a full stack:

```yaml
services:
  dragonfly:
    image: docker.dragonflydb.io/dragonflydb/dragonfly
    ports:
      - "6380:6379"

  proxy:
    image: conduit-proxy
    ports:
      - "8888:8888"
    volumes:
      - ./conduit.toml:/etc/conduit/conduit.toml
    environment:
      CONDUIT_CONFIG: /etc/conduit/conduit.toml
    depends_on:
      - dragonfly

  api:
    image: conduit-api
    ports:
      - "8443:8443"
    volumes:
      - ./conduit.toml:/etc/conduit/conduit.toml
    environment:
      CONDUIT_CONFIG: /etc/conduit/conduit.toml
    depends_on:
      - dragonfly
```

## Configuration

Mount your `conduit.toml` into the container and set the `CONDUIT_CONFIG` environment variable to point to it. Make sure `dragonfly_url` uses the container hostname (e.g., `redis://dragonfly:6379`).

## CA certificates

When `tls_intercept = true`, the proxy generates CA certificates on first run. To persist them across restarts, mount a volume for the certificate directory or set `ca_cert_path` and `ca_key_path` in your config.
