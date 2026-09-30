#!/usr/bin/env bash
set -u
cd "$(dirname "${BASH_SOURCE[0]}")/.."

if [[ -f .env ]]; then
  set -a
  # shellcheck disable=SC1091
  source .env
  set +a
fi

echo "== MCP containers =="
docker compose ps

echo
echo "== Local endpoints =="
ui_code="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 5 "http://127.0.0.1:${MCP_GATEWAY_PORT:-8888}/" 2>/dev/null || true)"
if [[ "$ui_code" == "200" ]]; then
  echo "SearXNG UI       OK (HTTP 200) http://127.0.0.1:${MCP_GATEWAY_PORT:-8888}/"
else
  echo "SearXNG UI       ERROR (HTTP ${ui_code:-000}) http://127.0.0.1:${MCP_GATEWAY_PORT:-8888}/"
fi

for spec in \
  "SearXNG MCP|${MCP_GATEWAY_PORT:-8888}|/mcp/" \
  "Playwright MCP|${PLAYWRIGHT_HOST_PORT:-8931}|/mcp" \
  "Memory MCP|${MEMORY_HOST_PORT:-8932}|/mcp"; do
  IFS='|' read -r name port path <<<"$spec"
  code="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 3 "http://127.0.0.1:${port}${path}" 2>/dev/null || true)"
  if [[ -n "$code" && "$code" != "000" ]]; then
    printf '%-16s reachable (HTTP %s) at http://127.0.0.1:%s%s\n' "$name" "$code" "$port" "$path"
  else
    printf '%-16s NOT reachable at http://127.0.0.1:%s%s\n' "$name" "$port" "$path"
  fi
done

echo
echo "== SearXNG network =="
if docker inspect mcp-searxng --format '{{json .NetworkSettings.Networks}}' 2>/dev/null | grep -q 'mcp-backend'; then
  echo "mcp-searxng attached to egress-capable mcp-backend"
else
  echo "mcp-searxng network attachment missing"
fi

echo
echo "== Persistent data =="
printf 'Playwright: %s\n' "$(du -sh data/playwright 2>/dev/null | cut -f1 || echo 0)"
printf 'Memory:     %s\n' "$(du -sh data/memory 2>/dev/null | cut -f1 || echo 0)"

echo
echo "== Architecture =="
echo "mcp-gateway :8888 -> private egress-capable mcp-searxng:8888"
echo "mcp-gateway :8931 -> Playwright MCP"
echo "mcp-gateway :8932 -> Memory MCP"
