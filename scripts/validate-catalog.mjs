#!/usr/bin/env node
import fs from 'node:fs';
import { spawnSync } from 'node:child_process';

const adapter = JSON.parse(fs.readFileSync(new URL('../pi/mcp-adapter.json.example', import.meta.url), 'utf8'));
const failures = [];

function fail(msg) { failures.push(msg); }
function listTools(script) {
  const req = JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} }) + '\n';
  const p = spawnSync(process.execPath, [script], { input: req, encoding: 'utf8' });
  if (p.status !== 0) throw new Error(`${script} failed: ${p.stderr}`);
  const line = p.stdout.trim().split('\n').find(Boolean);
  return JSON.parse(line).result.tools;
}

if (adapter.settings?.directTools !== false) fail('settings.directTools must remain false for bounded discovery');

for (const [name, server] of Object.entries(adapter.mcpServers || {})) {
  if (!server.description || server.description.length < 30) fail(`${name}: missing/weak server description`);
  if (!server.searchKeywords || Object.keys(server.searchKeywords).length === 0) fail(`${name}: missing searchKeywords`);
}

for (const [serverName, script] of [['system', 'scripts/system-tools.mjs'], ['security', 'scripts/security-tools.mjs'], ['google', 'scripts/google-tools.mjs']]) {
  const tools = listTools(script);
  const keywords = adapter.mcpServers?.[serverName]?.searchKeywords || {};
  console.log(`${serverName}: ${tools.length} tools`);
  for (const tool of tools) {
    if (!tool.description || tool.description.length < 35) fail(`${serverName}.${tool.name}: weak tool description`);
    if (!tool.inputSchema?.description) fail(`${serverName}.${tool.name}: input schema missing description`);
    if (!tool.annotations) fail(`${serverName}.${tool.name}: missing MCP tool annotations`);
    if (!keywords[tool.name]) fail(`${serverName}.${tool.name}: missing per-tool discovery aliases`);
    for (const [arg, schema] of Object.entries(tool.inputSchema?.properties || {})) {
      if (!schema.description) fail(`${serverName}.${tool.name}.${arg}: argument missing description`);
      if (serverName === 'google' && /(password|secret|access.?token|refresh.?token|api.?key|credential)/i.test(arg)) {
        fail(`${serverName}.${tool.name}.${arg}: account secret must never be accepted as a model/tool argument`);
      }
    }
  }
}

if (failures.length) {
  console.error('\nCatalog validation FAILED:');
  for (const f of failures) console.error(`- ${f}`);
  process.exit(1);
}
console.log('Catalog validation passed: bounded discovery, descriptions, aliases, schemas, annotations, and Google secret isolation are intact.');
