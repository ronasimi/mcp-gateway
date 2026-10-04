#!/usr/bin/env bash
set -Eeuo pipefail
printf '[compat] bounded Pi gate retired; installing stock Pi native MCP/tool_search config\n' >&2
exec "$(dirname "${BASH_SOURCE[0]}")/install-pi-stock-config.sh" "$@"
