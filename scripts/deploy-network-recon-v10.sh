#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PI_DOCKER_DIR="${1:-${PI_DOCKER_DIR:-$HOME/Projects/pi-docker}}"
cd "$ROOT"

node --test tests/*.test.mjs
node scripts/validate-catalog.mjs

docker compose build mcp-security
docker compose up -d --no-deps --force-recreate mcp-security

./scripts/install-pi-bounded-config.sh "$PI_DOCKER_DIR"
"$PI_DOCKER_DIR/scripts/upgrade-upstream-runtime.sh"

echo '[deploy] v10 network recon + Pi upstream runtime deployment complete.'
