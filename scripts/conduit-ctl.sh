#!/usr/bin/env bash
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
API_LOG="$DIR/logs/api.log"
PROXY_LOG="$DIR/logs/proxy.log"

# Detect whether running in system or user systemd mode
if systemctl is-enabled conduit.target >/dev/null 2>&1 || [ -f "/etc/systemd/system/conduit.target" ]; then
    SYSTEMCTL="systemctl"
    MODE="system"
else
    SYSTEMCTL="systemctl --user"
    MODE="user"
fi

status() {
    echo "=== Conduit Systemd Services ($MODE mode) ==="
    $SYSTEMCTL is-active conduit-proxy conduit-api conduit.target 2>&1 | paste <(echo -e "Proxy:\nAPI:\nTarget:") - || true

    echo ""
    echo "=== Datastore (Valkey / Redis / Dragonfly) ==="
    DATASTORE_STATUS="STOPPED"
    DATASTORE_INFO=""

    # Check native Valkey / Redis services
    for svc in valkey valkey-server redis redis-server; do
        if systemctl is-active --quiet "$svc" 2>/dev/null; then
            DATASTORE_STATUS="RUNNING"
            DATASTORE_INFO="System service $svc.service is active"
            break
        fi
    done

    # Check configured port (default 6380)
    CFG_PORT=6380
    if [ -f "$DIR/conduit.toml" ]; then
        DETECTED_PORT=$(grep -E '^(dragonfly_url|valkey_url|redis_url)' "$DIR/conduit.toml" | head -n1 | sed -n 's/.*:\([0-9]\+\).*/\1/p' || true)
        if [ -n "$DETECTED_PORT" ]; then
            CFG_PORT="$DETECTED_PORT"
        fi
    elif [ -f "/etc/conduit/conduit.toml" ]; then
        DETECTED_PORT=$(grep -E '^(dragonfly_url|valkey_url|redis_url)' "/etc/conduit/conduit.toml" | head -n1 | sed -n 's/.*:\([0-9]\+\).*/\1/p' || true)
        if [ -n "$DETECTED_PORT" ]; then
            CFG_PORT="$DETECTED_PORT"
        fi
    fi

    if command -v valkey-cli >/dev/null 2>&1 && valkey-cli -p "$CFG_PORT" ping 2>/dev/null | grep -q PONG; then
        DATASTORE_STATUS="RUNNING"
        DATASTORE_INFO="Native Valkey responding on port $CFG_PORT"
    elif command -v redis-cli >/dev/null 2>&1 && redis-cli -p "$CFG_PORT" ping 2>/dev/null | grep -q PONG; then
        DATASTORE_STATUS="RUNNING"
        DATASTORE_INFO="Native Valkey/Redis responding on port $CFG_PORT"
    elif (echo > /dev/tcp/127.0.0.1/"$CFG_PORT") 2>/dev/null; then
        DATASTORE_STATUS="RUNNING"
        DATASTORE_INFO="Datastore responding on 127.0.0.1:$CFG_PORT"
    elif [ "$DATASTORE_STATUS" = "STOPPED" ] && docker ps --filter "name=conduit-dragonfly" --format '{{.Status}}' 2>/dev/null | grep -q "Up"; then
        DATASTORE_STATUS="RUNNING"
        DATASTORE_INFO="Dragonfly container 'conduit-dragonfly' on port 6380"
    fi

    echo "Datastore: $DATASTORE_STATUS ($DATASTORE_INFO)"

    echo ""
    echo "=== Process & Port Details ==="
    if pgrep -f "conduit-api" >/dev/null; then
        echo "Conduit API:   RUNNING (PID: $(pgrep -f "conduit-api" | head -n1), UI/API on http://localhost:8443)"
    else
        echo "Conduit API:   STOPPED"
    fi

    if pgrep -f "conduit-proxy" >/dev/null; then
        echo "Conduit Proxy: RUNNING (PID: $(pgrep -f "conduit-proxy" | head -n1), proxy on :8888, metrics on :9091)"
    else
        echo "Conduit Proxy: STOPPED"
    fi

    if curl -s http://localhost:8443/api/v1/health >/dev/null 2>&1; then
        echo ""
        echo "=== Health & Statistics ==="
        echo "API Health:    $(curl -s http://localhost:8443/api/v1/health)"
        echo "Proxy Stats:   $(curl -s http://localhost:8443/api/v1/stats 2>/dev/null || echo 'unavailable')"
        echo "Bloom Threats: $(curl -s http://localhost:8443/api/v1/threat/bloom/stats 2>/dev/null || echo 'unavailable')"
    fi
}

start() {
    echo "Starting Conduit via $SYSTEMCTL ($MODE mode)..."
    $SYSTEMCTL start conduit.target
    sleep 2
    status
}

stop() {
    echo "Stopping Conduit proxy and API via $SYSTEMCTL..."
    $SYSTEMCTL stop conduit-proxy conduit-api
    echo "Done."
}

restart() {
    echo "Restarting Conduit via $SYSTEMCTL..."
    $SYSTEMCTL restart conduit-api conduit-proxy
    sleep 2
    status
}

case "${1:-status}" in
    start) start ;;
    stop) stop ;;
    restart) restart ;;
    status) status ;;
    fix|repair)
        if [ "$EUID" -ne 0 ]; then
            exec sudo "$DIR/scripts/fix.sh" "$@"
        else
            exec "$DIR/scripts/fix.sh" "$@"
        fi
        ;;
    disable)
        exec "$DIR/scripts/uninstall.sh" --disable
        ;;
    uninstall|purge)
        exec "$DIR/scripts/uninstall.sh" --purge
        ;;
    *) echo "Usage: $0 {start|stop|restart|status|fix|disable|uninstall}" ;;
esac
