#!/bin/sh
set -eu

SEARX_PID=""
PLAYWRIGHT_PID=""
MEMORY_PID=""

cleanup() {
  trap - INT TERM EXIT
  [ -n "${MEMORY_PID}" ] && kill "${MEMORY_PID}" 2>/dev/null || true
  [ -n "${PLAYWRIGHT_PID}" ] && kill "${PLAYWRIGHT_PID}" 2>/dev/null || true
  [ -n "${SEARX_PID}" ] && kill "${SEARX_PID}" 2>/dev/null || true
  wait 2>/dev/null || true
}
trap cleanup INT TERM EXIT

# Start the upstream SearXNG + HTTP MCP stack unchanged.
/usr/local/searxng/custom-entrypoint.sh &
SEARX_PID=$!

mkdir -p "${PLAYWRIGHT_MCP_USER_DATA_DIR:-/data/playwright}"

if [ -n "${PLAYWRIGHT_MCP_EXECUTABLE_PATH:-}" ]; then
  CHROMIUM_BIN="${PLAYWRIGHT_MCP_EXECUTABLE_PATH}"
elif command -v chromium-browser >/dev/null 2>&1; then
  CHROMIUM_BIN="$(command -v chromium-browser)"
elif command -v chromium >/dev/null 2>&1; then
  CHROMIUM_BIN="$(command -v chromium)"
else
  echo "Chromium executable not found" >&2
  exit 1
fi

echo "Starting Playwright MCP on :${PLAYWRIGHT_MCP_PORT:-8931} using ${CHROMIUM_BIN}" >&2

playwright-mcp   --headless   --host 0.0.0.0   --allowed-hosts "*"   --no-sandbox   --port "${PLAYWRIGHT_MCP_PORT:-8931}"   --executable-path "${CHROMIUM_BIN}"   --user-data-dir "${PLAYWRIGHT_MCP_USER_DATA_DIR:-/data/playwright}"   --idle-timeout "${PLAYWRIGHT_MCP_IDLE_TIMEOUT:-300000}"   --codegen none &
PLAYWRIGHT_PID=$!

MEMORY_FILE_PATH="${MEMORY_FILE_PATH:-/data/memory/memory.jsonl}"
export MEMORY_FILE_PATH
mkdir -p "$(dirname "${MEMORY_FILE_PATH}")"

echo "Starting Memory MCP on :${MEMORY_MCP_PORT:-8932}; data=${MEMORY_FILE_PATH}" >&2

# The official memory server is stdio-only. Supergateway keeps it in this
# container while presenting a standard Streamable HTTP MCP endpoint.
supergateway   --stdio "mcp-server-memory"   --outputTransport streamableHttp   --port "${MEMORY_MCP_PORT:-8932}"   --streamableHttpPath /mcp   --logLevel info < /dev/null &
MEMORY_PID=$!

# Exit the container if any primary service exits. Tini handles reaping.
while :; do
  if ! kill -0 "${SEARX_PID}" 2>/dev/null; then
    wait "${SEARX_PID}" || true
    echo "SearXNG MCP process exited" >&2
    exit 1
  fi
  if ! kill -0 "${PLAYWRIGHT_PID}" 2>/dev/null; then
    wait "${PLAYWRIGHT_PID}" || true
    echo "Playwright MCP process exited" >&2
    exit 1
  fi
  if ! kill -0 "${MEMORY_PID}" 2>/dev/null; then
    wait "${MEMORY_PID}" || true
    echo "Memory MCP process exited" >&2
    exit 1
  fi
  sleep 2
done
