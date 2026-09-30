#!/bin/sh
set -eu

PLAYWRIGHT_PID=""
MEMORY_PID=""

cleanup() {
  trap - INT TERM EXIT
  for pid in "${MEMORY_PID}" "${PLAYWRIGHT_PID}"; do
    [ -n "${pid}" ] && kill "${pid}" 2>/dev/null || true
  done
  wait 2>/dev/null || true
}
trap cleanup INT TERM EXIT

mkdir -p /data/playwright /data/memory

CHROMIUM_BIN="${PLAYWRIGHT_MCP_EXECUTABLE_PATH:-/usr/bin/chromium}"
if [ ! -x "${CHROMIUM_BIN}" ]; then
  echo "Chromium executable not found at ${CHROMIUM_BIN}" >&2
  exit 1
fi

set -- \
  --headless \
  --host 0.0.0.0 \
  --allowed-hosts '*' \
  --no-sandbox \
  --port "${PLAYWRIGHT_MCP_PORT:-8931}" \
  --executable-path "${CHROMIUM_BIN}" \
  --user-data-dir "${PLAYWRIGHT_MCP_USER_DATA_DIR:-/data/playwright}" \
  --idle-timeout "${PLAYWRIGHT_MCP_IDLE_TIMEOUT:-300000}"

if [ "${PLAYWRIGHT_MCP_SHARED_BROWSER_CONTEXT:-true}" = "true" ]; then
  set -- "$@" --shared-browser-context
fi

echo "Starting Playwright MCP on :${PLAYWRIGHT_MCP_PORT:-8931}" >&2
PLAYWRIGHT_MCP_PING_TIMEOUT_MS="${PLAYWRIGHT_MCP_PING_TIMEOUT_MS:-30000}" \
  playwright-mcp "$@" &
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

while :; do
  for pair in \
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
