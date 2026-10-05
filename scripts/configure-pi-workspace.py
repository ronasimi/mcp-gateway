#!/usr/bin/env python3
"""Bind MCP tools to Pi's repository-local workspace, preserving other settings."""
from pathlib import Path
import os, re, shutil, sys, time

def configure(gateway, pi):
    gateway, pi = Path(gateway).resolve(), Path(pi).resolve()
    target = pi / 'workspace'
    if target.is_symlink():
        raise ValueError('Pi workspace must be a directory inside its repository, not a symlink')
    target.mkdir(mode=0o775, parents=True, exist_ok=True)
    if os.geteuid() == 0:
        os.chown(target, 1000, 1000)
    env = gateway / '.env'
    original = env.read_text() if env.exists() else ''
    value = "'" + str(target).replace('\\', '\\\\').replace("'", "\\'") + "'"
    line = 'MCP_WORKSPACE_PATH=' + value
    updated = re.sub(r'^(?:export\s+)?MCP_WORKSPACE_PATH=.*$', line, original, flags=re.M) if re.search(r'^(?:export\s+)?MCP_WORKSPACE_PATH=', original, re.M) else original.rstrip('\n') + '\n' + line + '\n'
    if updated != original:
        if env.exists():
            shutil.copy2(env, env.with_name('.env.workspace-backup.' + str(time.time_ns())))
        env.write_text(updated)
        env.chmod(0o600)
    return target

if __name__ == '__main__':
    print(configure(sys.argv[1], sys.argv[2]))
