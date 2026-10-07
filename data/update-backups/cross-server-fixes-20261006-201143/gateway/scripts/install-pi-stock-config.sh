#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

PI_DOCKER_DIR="${1:-${PI_DOCKER_DIR:-$HOME/Projects/pi-docker}}"
CONFIG_DIR="$PI_DOCKER_DIR/config"
[[ -d "$CONFIG_DIR" ]] || { echo "Pi config directory not found: $CONFIG_DIR" >&2; exit 1; }

ts="$(date +%Y%m%d-%H%M%S)"
for f in "$CONFIG_DIR/APPEND_SYSTEM.md" "$CONFIG_DIR/mcp.json"; do
  [[ -e "$f" ]] && cp -a "$f" "$f.bak.$ts"
done

python3 scripts/merge-pi-native-mcp.py "$CONFIG_DIR/mcp.json" pi/mcp.json.example
install -m 0644 pi/APPEND_SYSTEM.md "$CONFIG_DIR/APPEND_SYSTEM.md"

echo "Installed stock Pi 1.0 native MCP/tool_search configuration into $CONFIG_DIR"
echo "Backups use suffix: .bak.$ts"
