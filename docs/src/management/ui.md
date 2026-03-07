# Web UI

Conduit includes a SvelteKit-based management dashboard for visual policy management and log viewing.

## Building the UI

```sh
cd conduit-ui
pnpm install    # or npm install
pnpm run build  # static output in conduit-ui/build/
```

## Serving the UI

The API server can serve the built UI as static files. Set `ui_dir` in your config:

```toml
ui_dir = "./conduit-ui/build"
```

Then access the dashboard at `http://localhost:8443/`.

## Development

```sh
cd conduit-ui
pnpm run dev    # Dev server with hot reload
```

The dev server proxies API requests to the running `conduit-api` instance.

## Features

- View and manage policy rules (allow/block by domain)
- Browse request logs with filtering
- Manage DLP rules
- View proxy statistics and threat detection results
- Download the CA certificate
