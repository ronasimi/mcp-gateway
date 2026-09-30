#!/bin/sh
set -eu

check_http() {
  curl -sS -o /dev/null --max-time 3 "$1"
}

# Any HTTP response means the MCP listener is accepting connections; curl only
# fails here on DNS/connect/timeout errors because --fail is intentionally off.
check_http "http://127.0.0.1:${SEARXNG_PROXY_PORT:-8888}/"
check_http "http://127.0.0.1:${PLAYWRIGHT_MCP_PORT:-8931}/mcp"
check_http "http://127.0.0.1:${MEMORY_MCP_PORT:-8932}/mcp"
