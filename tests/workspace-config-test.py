import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
spec=importlib.util.spec_from_file_location('workspace_config',Path(__file__).resolve().parents[1]/'scripts/configure-pi-workspace.py')
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
class WorkspaceTests(unittest.TestCase):
 def test_preserves_settings_and_data_and_is_idempotent(self):
  with tempfile.TemporaryDirectory() as d, patch.object(module.os, 'chown'):
   root=Path(d);gw=root/'gateway';pi=root/'pi repo';gw.mkdir();pi.mkdir()
   env=gw/'.env';env.write_text('OTHER=value\nMCP_WORKSPACE_PATH=/old/projects\n')
   target=module.configure(gw,pi);(target/'keep.txt').write_text('existing')
   self.assertEqual(target,pi/'workspace');self.assertIn('OTHER=value',env.read_text());self.assertIn(str(target),env.read_text());self.assertEqual(len(list(gw.glob('.env.workspace-backup.*'))),1)
   module.configure(gw,pi);self.assertEqual(len(list(gw.glob('.env.workspace-backup.*'))),1);self.assertEqual((target/'keep.txt').read_text(),'existing')
 def test_rejects_external_workspace_symlink(self):
  with tempfile.TemporaryDirectory() as d, patch.object(module.os, 'chown'):
   root=Path(d);gw=root/'gw';pi=root/'pi';gw.mkdir();pi.mkdir();(pi/'workspace').symlink_to(gw)
   with self.assertRaises(ValueError):module.configure(gw,pi)
if __name__=='__main__':unittest.main()
