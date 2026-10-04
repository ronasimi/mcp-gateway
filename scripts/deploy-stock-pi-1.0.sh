#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PI_DOCKER_DIR="${1:-${PI_DOCKER_DIR:-$HOME/Projects/pi-docker}}"
cd "$ROOT"

[[ -d "$PI_DOCKER_DIR" ]] || { echo "Pi Docker repo not found: $PI_DOCKER_DIR" >&2; exit 1; }
[[ -x "$PI_DOCKER_DIR/scripts/upgrade-stock-pi-1.0.sh" ]] || {
  echo "Pi repo is missing scripts/upgrade-stock-pi-1.0.sh; install the stock Pi repo update first." >&2
  exit 1
}

echo '[validate] MCP tests and catalog metadata'
node --test tests/*.test.mjs
python3 tests/config-merge-test.py
node scripts/validate-catalog.mjs

echo '[deploy] update the required host reconnaissance helper'
./scripts/install-security-host-recon-helper.sh

echo '[deploy] owned MCP catalogs: system + security'
docker compose build mcp-system mcp-security
docker compose up -d --no-deps --force-recreate mcp-system mcp-security

# Google is optional. Rebuild/recreate it only when configured or already running.
google_client="$(docker compose --profile google config --format json | python3 -c 'import json,sys; print(json.load(sys.stdin).get("secrets",{}).get("google_oauth_client",{}).get("file",""))')"
if [[ -s "$google_client" ]] || docker ps --format '{{.Names}}' | grep -qx 'mcp-google'; then
  echo '[deploy] Google MCP catalog metadata'
  docker compose --profile google build mcp-google
  docker compose --profile google up -d --no-deps --force-recreate mcp-google
fi

echo '[deploy] stock Pi prompt + native MCP config'
./scripts/install-pi-stock-config.sh "$PI_DOCKER_DIR"

echo '[deploy] stock Pi 1.0 runtime; persistent bind mounts are retained'
"$PI_DOCKER_DIR/scripts/upgrade-stock-pi-1.0.sh"

echo '[verify] gateway status'
./scripts/status.sh || true

echo '[done] stock Pi 1.0 + native deferred MCP/tool_search deployment complete.'
echo 'Start a new Pi conversation, then ask for the London local daily briefing.'
