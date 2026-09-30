#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
set -a
source ./.env
set +a

echo "== compose =="
docker compose ps

echo
echo "== SearXNG MCP =="
if command -v curl >/dev/null 2>&1; then
  code="$(curl -sS -o /dev/null -w '%{http_code}' \
    -H "x-api-key: ${MCP_GATEWAY_AUTH_TOKEN}" \
    "http://127.0.0.1:${MCP_GATEWAY_PORT:-8888}/mcp/" || true)"
  echo "HTTP ${code:-unreachable} at http://127.0.0.1:${MCP_GATEWAY_PORT:-8888}/mcp/"
else
  echo "curl not installed; skipping HTTP probe"
fi

echo
echo "== Playwright MCP =="
if command -v curl >/dev/null 2>&1; then
  code="$(curl -sS -o /dev/null -w '%{http_code}' \
    "http://127.0.0.1:${PLAYWRIGHT_HOST_PORT:-8931}/mcp" || true)"
  echo "HTTP ${code:-unreachable} at http://127.0.0.1:${PLAYWRIGHT_HOST_PORT:-8931}/mcp"
else
  echo "curl not installed; skipping HTTP probe"
fi

echo
echo "== Memory MCP =="
if command -v curl >/dev/null 2>&1; then
  code="$(curl -sS -o /dev/null -w '%{http_code}' \
    "http://127.0.0.1:${MEMORY_HOST_PORT:-8932}/mcp" || true)"
  echo "HTTP ${code:-unreachable} at http://127.0.0.1:${MEMORY_HOST_PORT:-8932}/mcp"
else
  echo "curl not installed; skipping HTTP probe"
fi

echo
echo "== memory file =="
if [[ -f data/memory/memory.jsonl ]]; then
  printf 'Path: %s\n' "$(realpath data/memory/memory.jsonl)"
  printf 'Lines: %s\n' "$(wc -l < data/memory/memory.jsonl)"
  printf 'Size: %s bytes\n' "$(stat -c %s data/memory/memory.jsonl)"
else
  echo "No memory file yet; it will be created on first write."
fi

echo
echo "== recent logs =="
docker compose logs --tail=160 mcp-gateway
