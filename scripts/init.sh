#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

if ! command -v docker >/dev/null 2>&1; then
  echo "docker is required" >&2
  exit 1
fi

if ! docker compose version >/dev/null 2>&1; then
  echo "docker compose v2 is required" >&2
  exit 1
fi

if [[ ! -f .env ]]; then
  if command -v openssl >/dev/null 2>&1; then
    token="$(openssl rand -hex 32)"
  else
    token="$(python3 - <<'PY'
import secrets
print(secrets.token_hex(32))
PY
)"
  fi
  cp .env.example .env
  python3 - "$token" <<'PY'
from pathlib import Path
import sys
p = Path('.env')
s = p.read_text()
s = s.replace('MCP_GATEWAY_AUTH_TOKEN=replace-me', 'MCP_GATEWAY_AUTH_TOKEN=' + sys.argv[1])
p.write_text(s)
PY
  chmod 600 .env
  echo "Created .env with a random SearXNG MCP API key."
fi

if ! docker network inspect ai-local >/dev/null 2>&1; then
  docker network create ai-local >/dev/null
  echo "Created external Docker network: ai-local"
fi

echo "Building SearXNG + Playwright MCP image..."
docker compose build --pull

echo "Starting MCP container..."
docker compose up -d

echo
echo "MCP container started."
echo "Pi SearXNG MCP:     http://mcp-gateway:8888/mcp/"
echo "Pi Playwright MCP:  http://mcp-gateway:8931/mcp"
echo "Host SearXNG MCP:   http://127.0.0.1:${MCP_GATEWAY_PORT:-8811}/mcp/"
echo "Host Playwright:     http://127.0.0.1:${PLAYWRIGHT_HOST_PORT:-8931}/mcp"
echo "SearXNG local UI:    http://127.0.0.1:${MCP_GATEWAY_PORT:-8811}/"
echo "Run ./scripts/token.sh to print the SearXNG API key."
echo "Run ./scripts/status.sh to inspect both MCP endpoints."
