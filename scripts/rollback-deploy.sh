#!/usr/bin/env bash
# Persistent deployment checkpoint and independent systemd rollback watchdog.
set -euo pipefail

die() { echo "conduit rollback: $*" >&2; exit 1; }

snapshot_file() {
  local state=$1 target=$2 number=$3
  printf '%s\n' "$target" > "$state/$number.path"
  if [ -e "$target" ]; then
    [ -f "$target" ] && [ ! -L "$target" ] || die "refusing non-regular deployment file: $target"
    cp -a -- "$target" "$state/$number.saved"
  fi
}

restore_files() {
  local state=$1 entry target staged
  for entry in "$state"/*.path; do
    [ -f "$entry" ] || continue
    IFS= read -r target < "$entry"
    if [ -f "${entry%.path}.saved" ]; then
      mkdir -p -- "$(dirname "$target")"
      staged=$(mktemp "$(dirname "$target")/.conduit-restore.XXXXXX")
      cp -a -- "${entry%.path}.saved" "$staged"
      mv -fT -- "$staged" "$target"
    elif [ -f "$target" ] && [ ! -L "$target" ]; then
      # Only the exact file recorded as absent at checkpoint creation is removed.
      rm -- "$target"
    fi
  done
}

load_state() {
  STATE=$(realpath -e -- "$1")
  [ -d "$STATE" ] && [ -f "$STATE/mode" ] || die "invalid checkpoint"
  MODE=$(< "$STATE/mode")
  case "$MODE" in system) CTL=(systemctl);; user) CTL=(systemctl --user);; *) die "invalid mode";; esac
  UNIT=$(< "$STATE/unit")
  CONFIG=$(< "$STATE/config")
  CHECK_URL=$(< "$STATE/check-url")
}

healthy() {
  "${CTL[@]}" is-active --quiet conduit-api.service conduit-proxy.service || return 1
  local endpoints api proxy
  endpoints=$(python3 - "$CONFIG" <<'PY'
import ipaddress, sys, tomllib
with open(sys.argv[1], 'rb') as handle:
    config = tomllib.load(handle)
def local(value):
    host, port = value.rsplit(':', 1)
    host = host.strip('[]')
    if ipaddress.ip_address(host).is_unspecified:
        host = '::1' if ':' in host else '127.0.0.1'
    return ('[' + host + ']' if ':' in host else host) + ':' + str(int(port))
print('http://' + local(config.get('api_addr', '0.0.0.0:8443')) + '/api/v1/health')
print('http://' + local(config.get('listen_addr', '0.0.0.0:8888')))
PY
  ) || return 1
  api=${endpoints%%$'\n'*}
  proxy=${endpoints#*$'\n'}
  curl --noproxy '*' --fail --silent --show-error --max-time 4 "$api" |
    python3 -c 'import json,sys; d=json.load(sys.stdin); sys.exit(0 if d.get("status")=="healthy" and (d.get("valkey") is True or d.get("dragonfly") is True) else 1)' || return 1
  curl --proxy "$proxy" --noproxy '' --fail --silent --show-error \
    --connect-timeout 4 --max-time 8 --output /dev/null "$CHECK_URL"
}

checkpoint() {
  local mode=$1 root=$2 check_url=${3:-https://example.com/} base bins units config state n=0 file
  command -v python3 >/dev/null || die "python3 is required for deployment health checks"
  command -v flock >/dev/null || die "flock is required for deployment coordination"
  case "$mode" in
    system)
      [ "$EUID" -eq 0 ] || die "system checkpoints require root"
      base=/var/lib/conduit/deployments; bins=/usr/local/bin
      units=/etc/systemd/system; config=/etc/conduit/conduit.toml;;
    user)
      base="${XDG_STATE_HOME:-$HOME/.local/state}/conduit/deployments"
      bins="$root/target/release"; units="$HOME/.config/systemd/user"; config="$root/conduit.toml";;
    *) die "expected system or user mode";;
  esac
  if [ ! -x "$bins/conduit-api" ] || [ ! -x "$bins/conduit-proxy" ]; then
    echo "No existing installation to roll back; fresh install." >&2
    return 0
  fi
  umask 077
  mkdir -p -- "$base"
  [ ! -L "$base" ] || die "checkpoint directory must not be a symlink"
  chmod 700 "$base"
  state=$(mktemp -d "$base/checkpoint.XXXXXXXX")
  printf '%s\n' "$mode" > "$state/mode"
  printf '%s\n' "$config" > "$state/config"
  printf '%s\n' "$check_url" > "$state/check-url"
  printf 'conduit-rollback-%s\n' "${state##*.}" > "$state/unit"
  cp -- "${BASH_SOURCE[0]}" "$state/worker.sh"
  chmod 700 "$state/worker.sh"
  load_state "$state"
  healthy >&2 || die "existing proxy is not healthy; refusing upgrade (set CONDUIT_DEPLOY_CHECK_URL to a permitted working URL)"
  for file in "$bins/conduit-api" "$bins/conduit-proxy" "$config" \
    "$units/conduit-api.service" "$units/conduit-proxy.service" "$units/conduit.target"; do
    n=$((n + 1)); snapshot_file "$state" "$file" "$n"
  done
  if [ "$mode" = system ]; then
    for file in /etc/conduit/ca/ca.pem /etc/conduit/ca/ca-key.pem; do
      n=$((n + 1)); snapshot_file "$state" "$file" "$n"
    done
  fi
  echo "$state"
}

process_identity() {
  python3 - "$1" <<'PY'
import pathlib, sys
try:
    stat = pathlib.Path('/proc/' + sys.argv[1] + '/stat').read_text()
    print(stat.rsplit(')', 1)[1].split()[19])
except (OSError, IndexError):
    sys.exit(1)
PY
}

quiesce_installer() {
  python3 - "$1" "$2" <<'PY'
import os, pathlib, signal, sys, time
root, expected = int(sys.argv[1]), sys.argv[2]
def identity(pid):
    try:
        return pathlib.Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()[19]
    except (OSError, IndexError):
        return None
if identity(root) != expected:
    sys.exit(0)
stopped = []
def freeze(pid):
    start = identity(pid)
    if start is None:
        return
    try:
        os.kill(pid, signal.SIGSTOP)
        stopped.append((pid, start))
        children = pathlib.Path(f'/proc/{pid}/task/{pid}/children').read_text().split()
        for child in children:
            freeze(int(child))
    except ProcessLookupError:
        pass
def send(pid, start, sig):
    if identity(pid) == start:
        try:
            os.kill(pid, sig)
        except ProcessLookupError:
            pass
try:
    # Freeze before walking descendants so no new deployment commands can start.
    freeze(root)
    for pid, start in reversed(stopped):
        if pid != root:
            send(pid, start, signal.SIGTERM)
            send(pid, start, signal.SIGCONT)
    time.sleep(0.2)
    for pid, start in reversed(stopped):
        if pid != root:
            send(pid, start, signal.SIGKILL)
    send(root, expected, signal.SIGTERM)
finally:
    # The installer's EXIT trap can now wait for our lock and observe restoration.
    for pid, start in stopped:
        send(pid, start, signal.SIGCONT)
PY
}

arm() {
  load_state "$1"
  exec 9> "$STATE/lock"
  flock 9
  [ ! -f "$STATE/rolled-back" ] || die "checkpoint already rolled back"
  if [ -n "${2:-}" ]; then
    [[ "$2" =~ ^[0-9]+$ ]] || die "invalid installer PID"
    printf '%s\n' "$2" > "$STATE/installer-pid"
    process_identity "$2" > "$STATE/installer-start"
  fi
  local flags=()
  [ "$MODE" != user ] || flags=(--user)
  # Copy in STATE survives source edits, terminal loss, and installer failures.
  systemd-run "${flags[@]}" --quiet --unit="$UNIT" --on-active=180s \
    --timer-property=AccuracySec=1s /usr/bin/bash "$STATE/worker.sh" auto-rollback "$STATE"
  touch "$STATE/armed"
}

rollback() {
  local automatic=${2:-false}
  load_state "$1"
  exec 9> "$STATE/lock"
  flock 9
  [ ! -f "$STATE/rolled-back" ] || return 0
  if [ "$automatic" = true ] && { [ ! -f "$STATE/armed" ] || [ -f "$STATE/committed" ]; }; then return 0; fi
  if [ "$automatic" = true ] && [ -f "$STATE/installer-pid" ]; then
    local installer_pid installer_start
    installer_pid=$(< "$STATE/installer-pid")
    installer_start=$(process_identity "$installer_pid" 2>/dev/null || true)
    if [ -n "$installer_start" ] && [ "$installer_start" = "$(< "$STATE/installer-start")" ]; then
      # Do not let a slow installer keep writing after the watchdog restores files.
      quiesce_installer "$installer_pid" "$installer_start"
    fi
  fi
  echo "Restoring Conduit checkpoint: $STATE" >&2
  # Restore executable names by atomic rename; do not wait for broken services to stop.
  restore_files "$STATE"
  "${CTL[@]}" daemon-reload
  "${CTL[@]}" reset-failed conduit-api.service conduit-proxy.service || true
  "${CTL[@]}" restart conduit-api.service conduit-proxy.service
  local attempt
  for attempt in {1..30}; do
    if healthy; then
      touch "$STATE/rolled-back"
      "${CTL[@]}" stop "$UNIT.timer" || true
      echo "Conduit rollback verified." >&2
      return 0
    fi
    echo "Waiting for restored services (attempt $attempt/30)..." >&2
    sleep 1
  done
  die "old files restored but health checks failed; inspect systemd logs"
}

verify_commit() {
  load_state "$1"
  exec 9> "$STATE/lock"
  flock 9
  [ ! -f "$STATE/rolled-back" ] || die "deployment was already rolled back"
  healthy || return 1
  touch "$STATE/committed"
  "${CTL[@]}" stop "$UNIT.timer"
  ln -sfn -- "$STATE" "$(dirname "$STATE")/previous"
  echo "Deployment verified. Rollback checkpoint: $STATE" >&2
}

main() {
  case "${1:-}" in
    checkpoint) checkpoint "$2" "$3" "${4:-https://example.com/}";;
    arm) arm "$2" "${3:-}";;
    verify-commit) verify_commit "$2";;
    rollback) rollback "$2";;
    auto-rollback) rollback "$2" true;;
    *) die "usage: rollback-deploy.sh {checkpoint MODE ROOT [CHECK_URL]|arm STATE|verify-commit STATE|rollback STATE}";;
  esac
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then main "$@"; fi
