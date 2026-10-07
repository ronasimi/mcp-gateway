import importlib.util
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location('prompt_merge', Path(__file__).resolve().parents[1] / 'scripts' / 'merge-pi-prompt-section.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class PromptMergeTest(unittest.TestCase):
    def setUp(self):
        self.section = (Path(__file__).resolve().parents[1] / 'pi' / 'CROSS_SERVER_ORCHESTRATION.md').read_text()

    def test_inserts_after_runtime_anchor_and_preserves_existing_sections(self):
        base = "# Runtime behavior\n\nUse the runtime's native tools and built-in tool discovery.\n\n# Existing policy\n\nKeep me.\n"
        merged = module.merge_prompt(base, self.section)
        self.assertIn(module.BEGIN, merged)
        self.assertIn('# Cross-server orchestration', merged)
        self.assertIn('# Existing policy\n\nKeep me.', merged)
        self.assertLess(merged.index(module.BEGIN), merged.index('# Existing policy'))

    def test_merge_is_idempotent_and_replaces_managed_section_only(self):
        base = "# Runtime behavior\n\nUse the runtime's native tools and built-in tool discovery.\n\n# Tail\n\nPreserve.\n"
        once = module.merge_prompt(base, self.section)
        twice = module.merge_prompt(once, self.section)
        self.assertEqual(once, twice)
        changed = module.merge_prompt(once, self.section.replace('per-turn ledger', 'per-turn execution ledger'))
        self.assertEqual(changed.count(module.BEGIN), 1)
        self.assertIn('per-turn execution ledger', changed)
        self.assertIn('# Tail\n\nPreserve.', changed)


if __name__ == '__main__':
    unittest.main()
