import importlib.util
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location('merge', Path(__file__).resolve().parents[1] / 'scripts/merge-pi-native-mcp.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class MergeTest(unittest.TestCase):
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
