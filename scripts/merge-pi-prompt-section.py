#!/usr/bin/env python3
"""Insert or replace the managed cross-server orchestration section in a Pi prompt."""
from pathlib import Path
import os
import re
import sys
import tempfile

BEGIN = '<!-- BEGIN MCP CROSS-SERVER ORCHESTRATION -->'
END = '<!-- END MCP CROSS-SERVER ORCHESTRATION -->'

def merge_prompt(existing: str, section: str) -> str:
    block = f"{BEGIN}\n{section.strip()}\n{END}"
    pattern = re.compile(re.escape(BEGIN) + r'.*?' + re.escape(END), re.S)
    if pattern.search(existing):
        return pattern.sub(block, existing, count=1).rstrip() + '\n'
    anchor = "Use the runtime's native tools and built-in tool discovery."
    if anchor in existing:
        return existing.replace(anchor, anchor + '\n\n' + block, 1).rstrip() + '\n'
    return (block + '\n\n' + existing.lstrip()).rstrip() + '\n'

def atomic_write(target: Path, value: str) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    mode = target.stat().st_mode & 0o777 if target.exists() else 0o600
    uid = target.stat().st_uid if target.exists() else None
    gid = target.stat().st_gid if target.exists() else None
    fd, tmp = tempfile.mkstemp(prefix=target.name + '.', dir=target.parent)
    try:
        with os.fdopen(fd, 'w') as stream:
            stream.write(value)
        os.chmod(tmp, mode)
        if uid is not None and os.geteuid() == 0:
            os.chown(tmp, uid, gid)
        os.replace(tmp, target)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)

if __name__ == '__main__':
    target, source = map(Path, sys.argv[1:])
    existing = target.read_text() if target.exists() else ''
    section = source.read_text()
    atomic_write(target, merge_prompt(existing, section))
