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
servers=base.setdefault('mcpServers', {})
for name, incoming in src.get('mcpServers', {}).items():
    existing=servers.get(name, {})
    if isinstance(existing, dict) and isinstance(incoming, dict):
        # Preserve host/Pi-specific transport settings that the portable template
        # does not carry (for example requestTimeoutMs), while template-owned
        # metadata such as searchKeywords replaces stale wildcard catalogs.
        servers[name]={**existing, **incoming}
    else:
        servers[name]=incoming
base.setdefault('settings', {}).update(src.get('settings', {}))
out.write_text(json.dumps(base, indent=2)+'\n')
PY

python3 - "$PI_DOCKER_DIR" "$ts" <<'PY'
from pathlib import Path
import os, shutil, sys
root=Path(sys.argv[1]); ts=sys.argv[2]
old_descs=[
'Discover tools for any capability absent from the four core tools. Search before claiming unavailable. Returns up to 3 complete schemas. Use server playwright for live page reading, searxng for web search, memory for durable memory. Call matches via mcp_call.',
'Discover bounded MCP tools for capabilities beyond core file/edit/bash tools. Search before shell/network workarounds for infrastructure or external services. Servers: system=Docker/host/network/OpenWrt/image/document; google=Gmail/Calendar/Drive; playwright=live browser; searxng=web search; memory=durable memory. Returns up to 3 schemas; call exact matches via mcp_call.',
'Discover bounded MCP tools for capabilities beyond core file/edit/bash tools. Search before shell/network workarounds for infrastructure or external services. Servers: system=Docker/host/network/OpenWrt/image/document; security=authorized red-team/blue-team assessment and defensive analysis; google=Gmail/Calendar/Drive; playwright=live browser; searxng=web search; memory=durable memory. Returns up to 3 schemas; call exact matches via mcp_call.'
]
new_desc='Discover bounded MCP tools for capabilities not directly provided by core tools. Security work should use server=security; the gate also strongly infers security routing when that filter is omitted. Returns up to 3 complete schemas plus hasMore/nextOffset for bounded continuation. Validate schema fit before execution and use mcp_call only with an exact returned tool.'
old_preambles=[
'You are an expert coding assistant operating inside pi, a coding agent harness. You help users by reading files, executing commands, editing code, and writing new files.',
'You are an expert coding assistant operating inside Pi, a coding agent harness. You help users by reading files, executing commands, editing code, and writing new files.'
]
new_preamble='You are an expert assistant operating inside Pi, a local agent harness. You help the user reason about tasks and, when appropriate, use the available tools to inspect files, execute authorized operations, edit code, and complete work.'
changed=[]
for dp, dns, fns in os.walk(root):
    dns[:] = [d for d in dns if d not in {'.git','node_modules','cache','logs','dist','build'}]
    for fn in fns:
        if Path(fn).suffix.lower() not in {'.js','.mjs','.cjs','.ts','.tsx','.json','.md'}: continue
        p=Path(dp)/fn
        try:
            if p.stat().st_size > 5_000_000: continue
            original=p.read_text(errors='ignore')
        except Exception: continue
        updated=original
        labels=[]
        for old in old_descs:
            if old in updated:
                updated=updated.replace(old,new_desc)
                labels.append('mcp_search description')
        for old in old_preambles:
            if old in updated:
                updated=updated.replace(old,new_preamble)
                labels.append('base preamble')
        if updated != original:
            backup=p.with_name(p.name+f'.bak.{ts}')
            if not backup.exists(): shutil.copy2(p,backup)
            p.write_text(updated)
            changed.append((str(p), ', '.join(sorted(set(labels)))))
if changed:
    print('Updated Pi source prompt text:')
    for path,label in changed: print(f'  {path} ({label})')
else:
    print('Native Pi prompt strings were not found in the host repo; they may be baked into the installed image/extension.')
    print('pi/BASE_PREAMBLE.txt and pi/MCP_SEARCH_DESCRIPTION.txt contain the intended replacement text.')
PY
echo "Updated: $CONFIG_DIR/APPEND_SYSTEM.md"
echo "Updated: $CONFIG_DIR/mcp.json"
echo "Backups use suffix: .bak.$ts"
