import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';

const negative = /\b(do not|don't|never|avoid|must not|cannot|can't|without)\b/i;

test('Pi prompt is positive, compact, and keeps domain routing', async () => {
  const prompt = await fs.readFile(new URL('../pi/APPEND_SYSTEM.md', import.meta.url), 'utf8');
  assert.doesNotMatch(prompt, negative);
  assert.match(prompt, /Use the runtime's native tools and built-in tool discovery/);
  assert.match(prompt, /Use Pi's built-in `tool_search`/);
  for (const domain of ['security','system','playwright','searxng','google','memory']) {
    assert.match(prompt, new RegExp('Use `'+domain+'` MCP capabilities'));
  }
});

test('Pi MCP template uses native deferred exposure', async () => {
  const cfg = JSON.parse(await fs.readFile(new URL('../pi/mcp.json.example', import.meta.url), 'utf8'));
  assert.deepEqual(Object.keys(cfg), ['mcpServers']);
  for (const [name, server] of Object.entries(cfg.mcpServers)) {
    assert.equal(server.exposure, 'deferred', `${name} should use deferred native MCP exposure`);
    assert.equal(typeof server.url, 'string');
  }
});
