#!/usr/bin/env node
import { spawnSync } from 'node:child_process';
import { TOOL_CATALOG } from './catalog-metadata.mjs';

const failures = [];
const catalogs = new Map();
function fail(msg) { failures.push(msg); }
function listTools(script) {
  const req = JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} }) + '\n';
  const p = spawnSync(process.execPath, [script], { input: req, encoding: 'utf8', timeout: 15000, maxBuffer: 4 * 1024 * 1024 });
  if (p.error || p.status !== 0) throw new Error(`${script} failed: ${p.error?.message || p.stderr}`);
  const line = p.stdout.trim().split('\n').find(Boolean);
  if (!line) throw new Error(`${script} returned no MCP catalog`);
  return JSON.parse(line).result.tools;
}

for (const [serverName, script] of [['system', 'scripts/system-tools.mjs'], ['security', 'scripts/security-tools.mjs'], ['google', 'scripts/google-tools.mjs']]) {
  const tools = listTools(script);
  catalogs.set(serverName, tools);
  console.log(`${serverName}: ${tools.length} tools`);
  for (const tool of tools) {
    if (!tool.description || tool.description.length < 35) fail(`${serverName}.${tool.name}: weak tool description`);
    if (!tool.inputSchema?.description) fail(`${serverName}.${tool.name}: input schema missing description`);
    if (!tool.annotations) fail(`${serverName}.${tool.name}: missing MCP tool annotations`);
    const meta = tool._meta?.['ai.catalog'];
    if (!meta || meta.domain !== serverName) fail(`${serverName}.${tool.name}: missing ai.catalog domain metadata`);
    if (!meta?.scope || !meta?.preferredFor || !Array.isArray(meta?.aliases)) fail(`${serverName}.${tool.name}: incomplete catalog metadata`);
    for (const [arg, schema] of Object.entries(tool.inputSchema?.properties || {})) {
      if (!schema.description) fail(`${serverName}.${tool.name}.${arg}: argument missing description`);
      if (serverName === 'google' && /(password|secret|access.?token|refresh.?token|api.?key|credential)/i.test(arg)) {
        fail(`${serverName}.${tool.name}.${arg}: account secret must stay server-side`);
      }
    }
  }
}

const all = new Map([...catalogs.values()].flat().map((t) => [t.name, t]));
for (const [name, expected] of Object.entries(TOOL_CATALOG)) {
  const tool = all.get(name);
  if (!tool) { fail(`catalog metadata references missing tool: ${name}`); continue; }
  const meta = tool._meta?.['ai.catalog'];
  if (expected.aliases?.length && meta?.aliases?.length !== expected.aliases.length) fail(`${name}: aliases not published`);
  if (expected.overlapGroup && meta?.overlapGroup !== expected.overlapGroup) fail(`${name}: overlapGroup mismatch`);
  if (expected.preferredFor && meta?.preferredFor !== expected.preferredFor) fail(`${name}: preferredFor mismatch`);
  if (expected.scope && !tool.description.includes('Scope:')) fail(`${name}: scope missing from searchable description`);
  if (expected.aliases?.length && !tool.description.includes('Search terms:')) fail(`${name}: aliases missing from searchable description`);
}

const requiredOverlapGroups = ['network-recon','host-enumeration','system-network','openwrt','documents','images','gmail','calendar','drive'];
for (const group of requiredOverlapGroups) {
  const members = [...all.values()].filter((t) => t._meta?.['ai.catalog']?.overlapGroup === group);
  if (members.length < 2) fail(`overlap group ${group}: expected at least two tools`);
  const aliases = new Map();
  for (const tool of members) {
    const meta = tool._meta?.['ai.catalog'] || {};
    if (!meta.scope) fail(`${tool.name}: overlap group ${group} needs an explicit scope`);
    if (!meta.preferredFor) fail(`${tool.name}: overlap group ${group} needs preferredFor guidance`);
    for (const alias of meta.aliases || []) {
      const key = String(alias).trim().toLowerCase();
      if (!key) continue;
      if (aliases.has(key)) fail(`overlap group ${group}: duplicate alias ${JSON.stringify(alias)} on ${aliases.get(key)} and ${tool.name}`);
      aliases.set(key, tool.name);
    }
  }
}

if (failures.length) {
  console.error('\nCatalog validation FAILED:');
  for (const f of failures) console.error(`- ${f}`);
  process.exit(1);
}
console.log('Catalog validation passed: schemas, annotations, searchable scope/aliases, overlap metadata, and secret isolation are intact.');
