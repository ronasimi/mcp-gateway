#!/usr/bin/env python3
"""Merge shipped server definitions into existing native/adapter configuration."""
import json
import os
from pathlib import Path
import sys
import tempfile

LEGACY_ROOT = {'directTools', 'scriptMode', 'disableProxyTool', 'exposeResources',
               'deferWithMissingMetadata', 'serverGroups', 'toolCache', 'lazy', 'idleTimeout', 'settings'}
LEGACY_SERVER = {'directTools', 'searchKeywords', 'exposeResources', 'deferWithMissingMetadata',
                 'toolPrefix', 'eager', 'lazy', 'idleTimeout', 'cacheTTL', 'lifecycle', 'requestTimeoutMs', 'transport'}

CURATED_HIDDEN = {
    'searxng': {'engine_info', 'autocomplete'},
    'memory': {'read_graph'},
}


CONSOLIDATED = {
    'security': {'tool_status': 'status', 'suricata_analyze_pcap': 'suricata_alerts', 'network_discover': 'perform_network_discovery', 'service_detect': 'port_scan',
                 'pcap_fields': 'pcap_analyze', 'pcap_summary': 'pcap_analyze',
                 'pcap_conversations': 'pcap_analyze', 'lldp_observe': 'protocol_observe',
                 'cdp_observe': 'protocol_observe', 'llmnr_nbns_observe': 'protocol_observe'},
    'system': {'image_thumbnail': 'image_resize'},
}


def migrate_exposure(name, overrides):
    result = {}
    for key, exposure in overrides.items():
        if name in {'security', 'google'}:
            key = key.removeprefix(name + '_')
        key = CONSOLIDATED.get(name, {}).get(key, key)
        # A consolidated capability inherits an old hidden restriction even if
        # another predecessor was visible. Exact canonical overrides remain editable.
        result[key] = 'hidden' if 'hidden' in {exposure, result.get(key)} else exposure
    return result


def merge(existing, template):
    if not isinstance(existing, dict) or not isinstance(existing.get('mcpServers', {}), dict):
        raise ValueError('mcp.json must contain an object with an mcpServers object')
    result = {k: v for k, v in existing.items() if k not in LEGACY_ROOT}
    servers = dict(existing.get('mcpServers', {}))
    for name, shipped in template['mcpServers'].items():
        current = servers.get(name, {})
        if not isinstance(current, dict):
            raise ValueError(f'mcpServers.{name} must be an object')
        entry = {**shipped, **{k: v for k, v in current.items() if k not in LEGACY_SERVER}}
        if 'timeout' not in current and 'requestTimeoutMs' in current:
            milliseconds = current['requestTimeoutMs']
            if not isinstance(milliseconds, (int, float)) or isinstance(milliseconds, bool) or milliseconds <= 0:
                raise ValueError(f'mcpServers.{name}.requestTimeoutMs must be positive')
            entry['timeout'] = milliseconds / 1000
        if 'type' not in current and current.get('transport') in {'http', 'stdio', 'streamable-http'}:
            entry['type'] = current['transport']
        entry['exposure'] = 'deferred'
        entry['description'] = shipped['description']
        if shipped.get('toolExposure') or current.get('toolExposure'):
            exposure = {**shipped.get('toolExposure', {}),
                        **migrate_exposure(name, current.get('toolExposure', {}))}
            for tool_name in CURATED_HIDDEN.get(name, set()):
                exposure[tool_name] = 'hidden'
            entry['toolExposure'] = exposure
        servers[name] = entry
    result['mcpServers'] = servers
    return result


if __name__ == '__main__':
    target, source = map(Path, sys.argv[1:])
    existing = json.loads(target.read_text()) if target.exists() else {}
    value = merge(existing, json.loads(source.read_text()))
    fd, tmp = tempfile.mkstemp(prefix=target.name + '.', dir=target.parent)
    try:
        with os.fdopen(fd, 'w') as stream:
            json.dump(value, stream, indent=2)
            stream.write('\n')
        os.chmod(tmp, target.stat().st_mode & 0o777 if target.exists() else 0o600)
        if target.exists() and os.geteuid() == 0:
            os.chown(tmp, target.stat().st_uid, target.stat().st_gid)
        os.replace(tmp, target)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)
