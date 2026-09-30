#!/bin/sh
set -eu

SEARX_PID=""
SEARCH_MCP_PID=""
PLAYWRIGHT_PID=""
MEMORY_PID=""

cleanup() {
  trap - INT TERM EXIT
  for pid in "${MEMORY_PID}" "${PLAYWRIGHT_PID}" "${SEARCH_MCP_PID}" "${SEARX_PID}"; do
    [ -n "${pid}" ] && kill "${pid}" 2>/dev/null || true
  done
  wait 2>/dev/null || true
}
trap cleanup INT TERM EXIT

mkdir -p /etc/searxng /data/playwright /data/memory

# Keep config host-visible and durable. Generate only on first start.
if [ ! -s /etc/searxng/settings.yml ]; then
  SECRET="${SEARXNG_SECRET:-${MCP_GATEWAY_AUTH_TOKEN:-}}"
  if [ -z "${SECRET}" ]; then
    SECRET="$(python -c 'import secrets; print(secrets.token_hex(32))')"
  fi
  cat > /etc/searxng/settings.yml <<CFG
use_default_settings: true

general:
  debug: false
  instance_name: "Local Agent Search"

server:
  secret_key: "${SECRET}"
  limiter: false
  public_instance: false

search:
  safe_search: 0
  formats:
    - html
    - json
CFG
fi

export SEARXNG_SETTINGS_PATH=/etc/searxng/settings.yml
export SEARXNG_URL=http://127.0.0.1:8080

# SearXNG itself stays private inside this container. Only its MCP facade is
# published on :8888.
echo "Starting SearXNG on 127.0.0.1:8080" >&2
GRANIAN_INTERFACE=wsgi \
GRANIAN_HOST=127.0.0.1 \
GRANIAN_PORT=8080 \
GRANIAN_WEBSOCKETS=false \
GRANIAN_WORKERS=1 \
GRANIAN_BLOCKING_THREADS=4 \
granian searx.webapp:app &
SEARX_PID=$!

# Wait for SearXNG before bringing up the MCP facade.
i=0
until curl -fsS 'http://127.0.0.1:8080/search?q=health&format=json' >/dev/null 2>&1; do
  i=$((i + 1))
  if [ "$i" -ge 60 ]; then
    echo "SearXNG did not become ready within 60 seconds" >&2
    exit 1
  fi
  if ! kill -0 "${SEARX_PID}" 2>/dev/null; then
    wait "${SEARX_PID}" || true
    echo "SearXNG exited during startup" >&2
    exit 1
  fi
  sleep 1
done

echo "Starting SearXNG MCP on :8888" >&2
supergateway \
  --stdio "searxng-http-mcp" \
  --outputTransport streamableHttp \
  --port 8888 \
  --streamableHttpPath /mcp \
  --logLevel info < /dev/null &
SEARCH_MCP_PID=$!

CHROMIUM_BIN="${PLAYWRIGHT_MCP_EXECUTABLE_PATH:-/usr/bin/chromium}"
if [ ! -x "${CHROMIUM_BIN}" ]; then
  echo "Chromium executable not found at ${CHROMIUM_BIN}" >&2
  exit 1
fi

echo "Starting Playwright MCP on :${PLAYWRIGHT_MCP_PORT:-8931}" >&2
playwright-mcp \
  --headless \
  --host 0.0.0.0 \
  --allowed-hosts "*" \
  --no-sandbox \
  --port "${PLAYWRIGHT_MCP_PORT:-8931}" \
  --executable-path "${CHROMIUM_BIN}" \
  --user-data-dir "${PLAYWRIGHT_MCP_USER_DATA_DIR:-/data/playwright}" \
  --idle-timeout "${PLAYWRIGHT_MCP_IDLE_TIMEOUT:-300000}" \
  --codegen none &
PLAYWRIGHT_PID=$!

MEMORY_FILE_PATH="${MEMORY_FILE_PATH:-/data/memory/memory.jsonl}"
export MEMORY_FILE_PATH
mkdir -p "$(dirname "${MEMORY_FILE_PATH}")"

echo "Starting Memory MCP on :${MEMORY_MCP_PORT:-8932}; data=${MEMORY_FILE_PATH}" >&2
supergateway \
  --stdio "mcp-server-memory" \
  --outputTransport streamableHttp \
  --port "${MEMORY_MCP_PORT:-8932}" \
  --streamableHttpPath /mcp \
  --logLevel info < /dev/null &
MEMORY_PID=$!

# Keep the container alive only while all primary services are alive.
while :; do
  for pair in \
    "SearXNG:${SEARX_PID}" \
    "SearXNG MCP:${SEARCH_MCP_PID}" \
    "Playwright MCP:${PLAYWRIGHT_PID}" \
    "Memory MCP:${MEMORY_PID}"; do
    name=${pair%%:*}
    pid=${pair#*:}
    if ! kill -0 "${pid}" 2>/dev/null; then
      wait "${pid}" || true
      echo "${name} process exited" >&2
      exit 1
    fi
  done
  sleep 2
done
