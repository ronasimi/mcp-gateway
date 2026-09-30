#!/usr/bin/env bash
set -u
cd "$(dirname "$0")/.."

echo "== Containers =="
docker compose ps

echo
echo "== Local endpoints =="
for spec in \
  "SearXNG MCP|${MCP_GATEWAY_PORT:-8888}|/mcp" \
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
echo "== Persistent data =="
printf 'SearXNG:    %s\n' "$(du -sh data/searxng 2>/dev/null | cut -f1 || echo 0)"
printf 'Playwright: %s\n' "$(du -sh data/playwright 2>/dev/null | cut -f1 || echo 0)"
printf 'Memory:     %s\n' "$(du -sh data/memory 2>/dev/null | cut -f1 || echo 0)"
