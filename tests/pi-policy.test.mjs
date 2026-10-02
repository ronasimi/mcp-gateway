import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../', import.meta.url));

test('Pi bounded config enforces multi-step discovery completion and evidence grounding', async () => {
  const prompt = await fs.readFile(new URL('../pi/APPEND_SYSTEM.md', import.meta.url), 'utf8');
  const searchDescription = await fs.readFile(new URL('../pi/MCP_SEARCH_DESCRIPTION.txt', import.meta.url), 'utf8');
  const installer = await fs.readFile(new URL('../scripts/install-pi-bounded-config.sh', import.meta.url), 'utf8');
  assert.match(prompt, /## Multi-step MCP completion/);
  assert.match(prompt, /never a complete server catalog/i);
  assert.match(prompt, /Search each still-outstanding capability separately before finalizing/i);
  assert.match(prompt, /## Evidence grounding/);
  assert.match(prompt, /Unknown stays unknown/i);
  assert.match(prompt, /HE\/NSS\/GI are PHY fields/i);
  assert.match(prompt, /runtime blocks that no-progress loop/i);
  assert.match(prompt, /emit the tool call immediately/i);
  assert.match(searchDescription, /not a server catalog/i);
  assert.match(searchDescription, /different outstanding capability/i);
  assert.match(installer, /not a server catalog/i);
});
