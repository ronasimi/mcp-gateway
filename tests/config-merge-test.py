import importlib.util
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location('merge', Path(__file__).resolve().parents[1] / 'scripts/merge-pi-native-mcp.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class MergeTest(unittest.TestCase):
    def test_renamed_exposure_rules_preserve_hidden_tools(self):
        old = {'mcpServers': {'security': {'toolExposure': {
            'security_*': 'deferred', 'security_listener_start': 'hidden',
            'security_service_detect': 'hidden', 'security_port_scan': 'direct',
            'security_tool_status': 'hidden', 'security_suricata_analyze_pcap': 'hidden'}},
            'google': {'toolExposure': {'google_auth_status': 'hidden'}}}}
        template = {'mcpServers': {n: {'description': n} for n in ['security', 'google']}}
        new = module.merge(old, template)
        self.assertEqual(new['mcpServers']['security']['toolExposure'], {
            '*': 'deferred', 'listener_start': 'hidden', 'port_scan': 'hidden',
            'status': 'hidden', 'suricata_alerts': 'hidden'})
        self.assertEqual(new['mcpServers']['google']['toolExposure'], {'auth_status': 'hidden'})
        self.assertEqual(module.merge(new, template), new)

    def test_browser_default_hides_shared_context_close_and_keeps_custom_rules(self):
        template = {'mcpServers': {'playwright': {'description': 'Playwright',
                    'toolExposure': {'browser_close': 'hidden'}}}}
        old = {'mcpServers': {'playwright': {'toolExposure': {'browser_evaluate': 'hidden'}}}}
        self.assertEqual(module.merge(old, template)['mcpServers']['playwright']['toolExposure'],
                         {'browser_close': 'hidden', 'browser_evaluate': 'hidden'})

    def test_native_merge_preserves_accounts_endpoints_and_custom_servers(self):
        old = {'directTools': False, 'autoEnableCodemode': False, 'mcpServers': {
            'system': {'url': 'http://custom:123/mcp', 'headers': {'X-Test': '${TOKEN}'}, 'timeout': 90,
                       'enabled': False, 'directTools': False},
            'custom': {'command': 'my-mcp', 'args': ['serve']}}}
        template = {'mcpServers': {
            'system': {'url': 'http://default/mcp', 'description': 'System tools', 'exposure': 'deferred'},
            'security': {'url': 'http://security/mcp', 'description': 'Security tools', 'exposure': 'deferred'}}}
        new = module.merge(old, template)
        self.assertEqual(new['mcpServers']['system']['headers'], old['mcpServers']['system']['headers'])
        self.assertEqual(new['mcpServers']['system']['url'], 'http://custom:123/mcp')
        self.assertFalse(new['mcpServers']['system']['enabled'])
        self.assertEqual(new['mcpServers']['custom'], old['mcpServers']['custom'])
        self.assertIn('security', new['mcpServers'])
        self.assertNotIn('directTools', new)
        self.assertNotIn('directTools', new['mcpServers']['system'])
        self.assertEqual(module.merge(new, template), new)


    def test_shipped_third_party_discovery_hygiene_is_merged_idempotently(self):
        import json
        template = json.loads((Path(__file__).resolve().parents[1] / 'pi' / 'mcp.json.example').read_text())
        old = {'mcpServers': {
            'searxng': {'url': 'http://custom-searx/mcp', 'toolExposure': {'engine_info': 'direct'}},
            'memory': {'url': 'http://custom-memory/mcp', 'toolExposure': {'read_graph': 'direct'}},
        }}
        new = module.merge(old, template)
        self.assertEqual(new['mcpServers']['searxng']['toolExposure'],
                         {'engine_info': 'hidden', 'autocomplete': 'hidden', 'search': 'deferred'})
        self.assertEqual(new['mcpServers']['memory']['toolExposure'],
                         {'read_graph': 'hidden', 'search_nodes': 'deferred'})
        self.assertEqual(new['mcpServers']['searxng']['url'], 'http://custom-searx/mcp')
        self.assertEqual(new['mcpServers']['memory']['url'], 'http://custom-memory/mcp')
        self.assertEqual(module.merge(new, template), new)

    def test_adapter_timeout_converts_milliseconds_to_native_seconds(self):
        old = {'settings': {'scriptMode': True}, 'mcpServers': {'security': {
            'requestTimeoutMs': 330000, 'lifecycle': 'lazy', 'transport': 'http'}}}
        template = {'mcpServers': {'security': {'url': 'http://security/mcp', 'description': 'Security', 'timeout': 60}}}
        new = module.merge(old, template)
        self.assertEqual(new['mcpServers']['security']['timeout'], 330)
        self.assertEqual(new['mcpServers']['security']['type'], 'http')
        self.assertNotIn('requestTimeoutMs', new['mcpServers']['security'])
        self.assertNotIn('settings', new)


if __name__ == '__main__':
    unittest.main()
