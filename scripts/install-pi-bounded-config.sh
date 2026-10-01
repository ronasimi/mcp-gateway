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

install -m 0644 pi/APPEND_SYSTEM.md "$CONFIG_DIR/APPEND_SYSTEM.md"

python3 - "$CONFIG_DIR/mcp.json" pi/mcp-adapter.json.example <<'PY'
import json, pathlib, sys
out=pathlib.Path(sys.argv[1]); template=pathlib.Path(sys.argv[2])
base=json.loads(out.read_text()) if out.exists() else {}
src=json.loads(template.read_text())
base.setdefault('mcpServers', {}).update(src.get('mcpServers', {}))
base.setdefault('settings', {}).update(src.get('settings', {}))
out.write_text(json.dumps(base, indent=2)+'\n')
PY

python3 - "$PI_DOCKER_DIR" <<'PY'
from pathlib import Path
import os, sys
root=Path(sys.argv[1])
old='Discover tools for any capability absent from the four core tools. Search before claiming unavailable. Returns up to 3 complete schemas. Use server playwright for live page reading, searxng for web search, memory for durable memory. Call matches via mcp_call.'
new='Discover bounded MCP tools for capabilities beyond core file/edit/bash tools. Search before shell/network workarounds for infrastructure or external services. Servers: system=Docker/host/network/OpenWrt/image/document; google=Gmail/Calendar/Drive; playwright=live browser; searxng=web search; memory=durable memory. Returns up to 3 schemas; call exact matches via mcp_call.'
changed=[]
for dp, dns, fns in os.walk(root):
    dns[:] = [d for d in dns if d not in {'.git','node_modules','cache','logs'}]
    for fn in fns:
        if Path(fn).suffix.lower() not in {'.js','.mjs','.cjs','.ts','.json','.md'}: continue
        p=Path(dp)/fn
        try:
            if p.stat().st_size > 5_000_000: continue
            s=p.read_text(errors='ignore')
        except Exception: continue
        if old in s:
            p.write_text(s.replace(old,new)); changed.append(str(p))
if changed:
    print('Updated native mcp_search description in:')
    for p in changed: print('  '+p)
else:
    print('Native mcp_search description was not found in the host repo; it may be baked into the Pi image/installed extension.')
    print('The strengthened APPEND_SYSTEM.md still enforces system/google routing.')
PY

echo "Updated: $CONFIG_DIR/APPEND_SYSTEM.md"
echo "Updated: $CONFIG_DIR/mcp.json"
echo "Backups use suffix: .bak.$ts"
