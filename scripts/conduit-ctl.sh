#!/usr/bin/env bash
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
API_LOG="$DIR/logs/api.log"
PROXY_LOG="$DIR/logs/proxy.log"

status() {
    echo "=== Conduit Systemd Services ==="
    systemctl --user is-active conduit-dragonfly conduit-api conduit-proxy conduit.target 2>&1 | paste <(echo -e "Dragonfly:\nAPI:\nProxy:\nTarget:") - || true

    echo ""
    echo "=== Process & Port Details ==="
    if docker ps --filter "name=conduit-dragonfly" --format '{{.Status}}' | grep -q "Up"; then
        echo "Dragonfly: RUNNING (Docker container conduit-dragonfly on :6380)"
    else
        echo "Dragonfly: STOPPED"
    fi

    if pgrep -f "target/release/conduit-api" >/dev/null; then
        echo "Conduit API: RUNNING (PID: $(pgrep -f "target/release/conduit-api"), UI/API on http://localhost:8443)"
    else
        echo "Conduit API: STOPPED"
    fi

    if pgrep -f "target/release/conduit-proxy" >/dev/null; then
        echo "Conduit Proxy: RUNNING (PID: $(pgrep -f "target/release/conduit-proxy"), listening on :8888, metrics on :9091)"
    else
        echo "Conduit Proxy: STOPPED"
    fi

    if curl -s http://localhost:8443/api/v1/health >/dev/null 2>&1; then
        echo ""
        echo "=== Health & Statistics ==="
        echo "API Health:    $(curl -s http://localhost:8443/api/v1/health)"
        echo "Proxy Stats:   $(curl -s http://localhost:8443/api/v1/stats)"
        echo "Bloom Threats: $(curl -s http://localhost:8443/api/v1/threat/bloom/stats)"
    fi
}

start() {
    echo "Starting Conduit via systemd..."
    systemctl --user start conduit.target
    sleep 2
    status
}

stop() {
    echo "Stopping Conduit proxy and API via systemd..."
    systemctl --user stop conduit-proxy conduit-api
    echo "Done. (Dragonfly remains running. To stop Dragonfly as well: systemctl --user stop conduit-dragonfly)"
}

restart() {
    echo "Restarting Conduit..."
    systemctl --user restart conduit-api conduit-proxy
    sleep 2
    status
}

case "${1:-status}" in
    start) start ;;
    stop) stop ;;
    restart) restart ;;
    status) status ;;
    *) echo "Usage: $0 {start|stop|restart|status}" ;;
esac
