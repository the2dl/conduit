#!/usr/bin/env bash
# setup.sh — Turnkey native installer for Conduit Security Gateway
# (Delegates directly to install.sh)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec "$SCRIPT_DIR/install.sh" "$@"
