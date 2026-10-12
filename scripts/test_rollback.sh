#!/usr/bin/env bash
# shellcheck source-path=SCRIPTDIR
# shellcheck disable=SC2329
# No root, services, network, or installed binaries are touched by this test.
set -euo pipefail
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=rollback-deploy.sh
source "$SCRIPT_DIR/rollback-deploy.sh"
FIXTURE=$(mktemp -d /tmp/conduit-rollback-test.XXXXXXXX)
TARGET="$FIXTURE/proxy"
NEW_FILE="$FIXTURE/new-config"
STATE="$FIXTURE/checkpoint"
mkdir "$STATE"
printf 'user\n' > "$STATE/mode"
printf '%s\n' "$FIXTURE/config" > "$STATE/config"
printf 'https://example.com/\n' > "$STATE/check-url"
printf 'conduit-test-watchdog\n' > "$STATE/unit"
cp "$SCRIPT_DIR/rollback-deploy.sh" "$STATE/worker.sh"
printf 'old working binary\n' > "$TARGET"
chmod 751 "$TARGET"
snapshot_file "$STATE" "$TARGET" 1
snapshot_file "$STATE" "$NEW_FILE" 2
printf 'broken upgrade\n' > "$TARGET"
printf 'newly created config\n' > "$NEW_FILE"
systemctl() { printf '%s\n' "$*" >> "$FIXTURE/systemctl.calls"; }
systemd-run() { printf '%s\n' "$*" > "$FIXTURE/watchdog.calls"; }
healthy() { return 0; }
# Exercise the real process-stop path on an isolated fixture process tree.
bash -c 'trap "exit 143" TERM; sleep 30 & wait' &
PROBE_PID=$!
sleep 0.1
PROBE_START=$(process_identity "$PROBE_PID")
quiesce_installer "$PROBE_PID" "$PROBE_START"
if wait "$PROBE_PID" 2>/dev/null; then
  echo "ERROR: watchdog did not stop fixture installer" >&2
  exit 1
fi
quiesce_installer() { printf '%s\n' "$1" > "$FIXTURE/kill.calls"; }
arm "$STATE" "$$"
[[ -f "$STATE/armed" ]]
[[ $(< "$FIXTURE/watchdog.calls") == *"--on-active=180s"* ]]
[[ $(< "$FIXTURE/watchdog.calls") == *"$STATE/worker.sh auto-rollback $STATE"* ]]
rollback "$STATE" true
[[ $(< "$FIXTURE/kill.calls") == "$$" ]]
[[ $(< "$TARGET") == 'old working binary' ]]
[[ $(stat -c %a "$TARGET") == 751 ]]
[[ ! -e "$NEW_FILE" ]]
[[ -f "$STATE/rolled-back" ]]
[[ $(< "$FIXTURE/systemctl.calls") == *"restart conduit-api.service conduit-proxy.service"* ]]

# A late timer cannot undo a deployment once it has been committed.
SECOND="$FIXTURE/second"
mkdir "$SECOND"
cp "$STATE/mode" "$STATE/config" "$STATE/check-url" "$STATE/unit" "$SECOND/"
snapshot_file "$SECOND" "$TARGET" 1
printf 'new healthy binary\n' > "$TARGET"
touch "$SECOND/armed"
verify_commit "$SECOND"
[[ -f "$SECOND/committed" ]]
rollback "$SECOND" true
[[ $(< "$TARGET") == 'new healthy binary' ]]
[[ $(readlink "$FIXTURE/previous") == "$SECOND" ]]

# Manual rollback is still available after committing a healthy deployment.
rollback "$SECOND"
[[ $(< "$TARGET") == 'old working binary' ]]

THIRD="$FIXTURE/failed-health"
mkdir "$THIRD"
cp "$STATE/mode" "$STATE/config" "$STATE/check-url" "$STATE/unit" "$THIRD/"
snapshot_file "$THIRD" "$TARGET" 1
touch "$THIRD/armed"
printf 'unhealthy new binary\n' > "$TARGET"
healthy() { return 1; }
if verify_commit "$THIRD"; then echo "ERROR: committed an unhealthy deployment" >&2; exit 1; fi
[[ ! -f "$THIRD/committed" ]]
healthy() { return 0; }
rollback "$THIRD" true
[[ $(< "$TARGET") == 'old working binary' ]]
echo "PASS: independent watchdog command, atomic restoration, file modes, absent-file cleanup, late-timer cancellation, manual rollback"
echo "Temporary test fixtures retained at $FIXTURE"
