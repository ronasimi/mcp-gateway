#!/bin/sh
set -eu

check_http() {
  curl -sS -o /dev/null --max-time 3 "$1"
}

check_http "http://127.0.0.1:${PLAYWRIGHT_MCP_PORT:-8931}/mcp"
check_http "http://127.0.0.1:${MEMORY_MCP_PORT:-8932}/mcp"
