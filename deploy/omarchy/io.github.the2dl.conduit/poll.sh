#!/bin/bash
HEALTH=$(curl -s --noproxy "*" --max-time 1 http://127.0.0.1:8443/api/v1/health 2>/dev/null || echo '{"status":"down"}')
STATS=$(curl -s --noproxy "*" --max-time 1 http://127.0.0.1:8443/api/v1/stats 2>/dev/null || echo '{}')
CONFIG=$(curl -s --noproxy "*" --max-time 1 http://127.0.0.1:8443/api/v1/config 2>/dev/null || echo '{}')
METRICS=$(curl -s --noproxy "*" --max-time 1 http://127.0.0.1:9091/metrics 2>/dev/null || echo '')
BLOCKED=$(curl -s --noproxy "*" --max-time 1 "http://127.0.0.1:8443/api/v1/logs?action=block&limit=25" 2>/dev/null || echo '{"entries":[]}')
MUTES=$(curl -s --noproxy "*" --max-time 1 "http://127.0.0.1:8443/api/v1/notifications/mutes" 2>/dev/null || echo '[]')
CACHE_HITS=$(echo "$METRICS" | awk '/^conduit_cache_hits_total/ {print $2}' | head -n 1)
CACHE_MISSES=$(echo "$METRICS" | awk '/^conduit_cache_misses_total/ {print $2}' | head -n 1)
[[ -n "$CACHE_HITS" ]] || CACHE_HITS=0
[[ -n "$CACHE_MISSES" ]] || CACHE_MISSES=0

echo "{\"health\":$HEALTH,\"stats\":$STATS,\"config\":$CONFIG,\"cache\":{\"hits\":$CACHE_HITS,\"misses\":$CACHE_MISSES},\"blocked\":$BLOCKED,\"mutes\":$MUTES}"
