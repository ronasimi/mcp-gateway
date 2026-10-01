#!/usr/bin/env bash
set -u
cd "$(dirname "${BASH_SOURCE[0]}")/.."

if [[ -f .env ]]; then
  set -a
  # shellcheck disable=SC1091
  source .env
  set +a
fi

PORT="${MCP_GATEWAY_PORT:-8888}"

echo "== MCP containers =="
docker compose ps

echo
echo "== SearXNG direct endpoint =="
root_code="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 5 "http://127.0.0.1:${PORT}/" 2>/dev/null || true)"
html_code="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 15 --get --data-urlencode 'q=searxng' "http://127.0.0.1:${PORT}/search" 2>/dev/null || true)"
printf 'UI root:       HTTP %s  http://127.0.0.1:%s/\n' "${root_code:-000}" "$PORT"
printf 'HTML search:   HTTP %s  http://127.0.0.1:%s/search?q=searxng\n' "${html_code:-000}" "$PORT"

# MCP GET can legitimately return a protocol status other than 200 without an
# initialized MCP session. Any non-000 response proves the listener is present.
mcp_code="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 5 "http://127.0.0.1:${PORT}/mcp/" 2>/dev/null || true)"
printf 'SearXNG MCP:   HTTP %s  http://127.0.0.1:%s/mcp/\n' "${mcp_code:-000}" "$PORT"

if [[ "$html_code" == "403" ]]; then
  echo "ERROR: SearXNG search is forbidden. Check data/searxng/settings.yml (html/json formats, limiter=false)."
fi

echo
echo "== SearXNG effective local config =="
docker compose exec -T mcp-searxng sh -lc \
  "grep -nE '^(search:|server:|  formats:|    - (html|json)|  limiter:|  public_instance:|  method:)' /etc/searxng/settings.yml || true" 2>/dev/null || true

echo
echo "== Other MCP endpoints =="
for spec in \
  "Playwright MCP|${PLAYWRIGHT_HOST_PORT:-8931}|/mcp" \
  "Memory MCP|${MEMORY_HOST_PORT:-8932}|/mcp" \
  "System Tools MCP|${SYSTEM_TOOLS_HOST_PORT:-8933}|/mcp" \
  "Google MCP|${GOOGLE_MCP_HOST_PORT:-8934}|/mcp" \
  "Security MCP|${SECURITY_MCP_HOST_PORT:-8935}|/mcp"; do
  IFS='|' read -r name port path <<<"$spec"
  code="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 3 "http://127.0.0.1:${port}${path}" 2>/dev/null || true)"
  if [[ -n "$code" && "$code" != "000" ]]; then
    printf '%-16s reachable (HTTP %s) at http://127.0.0.1:%s%s\n' "$name" "$code" "$port" "$path"
  else
    printf '%-16s NOT reachable at http://127.0.0.1:%s%s\n' "$name" "$port" "$path"
  fi
done

echo
echo "== ai-local DNS =="
docker compose exec -T mcp-gateway getent hosts mcp-searxng 2>/dev/null || echo "mcp-searxng not resolvable from ai-local"
docker compose exec -T mcp-gateway getent hosts mcp-system 2>/dev/null || echo "mcp-system not resolvable from ai-local"
docker compose exec -T mcp-gateway getent hosts mcp-google 2>/dev/null || echo "mcp-google not running/resolvable (optional)"
docker compose exec -T mcp-gateway getent hosts mcp-security 2>/dev/null || echo "mcp-security not resolvable from ai-local"

echo
echo "== Persistent data =="
printf 'SearXNG:   %s\n' "$(du -sh data/searxng 2>/dev/null | cut -f1 || echo 0)"
printf 'Playwright:%s\n' "$(du -sh data/playwright 2>/dev/null | cut -f1 || echo 0)"
printf 'Memory:    %s\n' "$(du -sh data/memory 2>/dev/null | cut -f1 || echo 0)"
printf 'Workspace: %s\n' "$(du -sh data/workspace 2>/dev/null | cut -f1 || echo 0)"
printf 'Google:    %s\n' "$(du -sh data/google 2>/dev/null | cut -f1 || echo 0)"
printf 'Security:  %s\n' "$(du -sh data/security 2>/dev/null | cut -f1 || echo 0)"

echo
echo "== Client endpoints =="
echo "Host/local SearXNG:  http://127.0.0.1:${PORT}/mcp/"
echo "Container SearXNG:   http://mcp-searxng:8888/mcp/"
echo "Container Playwright:http://mcp-gateway:8931/mcp"
echo "Container Memory:    http://mcp-gateway:8932/mcp"
echo "Container System:    http://mcp-system:8933/mcp"
echo "Container Google:    http://mcp-google:8934/mcp (when enabled)"
echo "Container Security:  http://mcp-security:8935/mcp"
