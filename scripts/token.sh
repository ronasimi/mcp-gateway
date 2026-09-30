#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
if [[ ! -f .env ]]; then
  echo ".env does not exist; run ./scripts/init.sh first" >&2
  exit 1
fi
sed -n 's/^MCP_GATEWAY_AUTH_TOKEN=//p' .env
