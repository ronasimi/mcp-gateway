#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PI_DOCKER_DIR="${1:-${PI_DOCKER_DIR:-$HOME/Projects/pi-docker}}"
cd "$ROOT"

node --test tests/*.test.mjs
node scripts/validate-catalog.mjs
./scripts/install-pi-bounded-config.sh "$PI_DOCKER_DIR"

cd "$PI_DOCKER_DIR"
./scripts/upgrade-upstream-runtime.sh

echo '[deploy] v12 MCP search recovery + workflow completion deployment complete.'
