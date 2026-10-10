import {spawn} from 'node:child_process';
import {mkdtemp, rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';

// Exercise imports and MCP dispatch without executing any security operation.
const workspace = await mkdtemp(path.join(tmpdir(), 'security-startup-'));
const child = spawn(process.execPath, [fileURLToPath(new URL('./security-tools.mjs', import.meta.url))], {
  env: {...process.env, MCP_WORKSPACE: workspace}, stdio: ['pipe', 'pipe', 'pipe'],
});
let buffer = '', errors = '';
const pending = new Map();
child.stderr.on('data', chunk => { errors = (errors + chunk).slice(-8192); });
child.stdout.on('data', chunk => {
  buffer += chunk;
  let end;
  while ((end = buffer.indexOf('\n')) !== -1) {
    const line = buffer.slice(0, end); buffer = buffer.slice(end + 1);
    try {
      const reply = JSON.parse(line), request = pending.get(reply.id);
      if (request) { pending.delete(reply.id); reply.error ? request.reject(new Error(JSON.stringify(reply.error))) : request.resolve(reply.result); }
    } catch (error) { for (const request of pending.values()) request.reject(error); pending.clear(); }
  }
});
const fail = error => { for (const request of pending.values()) request.reject(error); pending.clear(); };
child.on('error', fail);
child.on('exit', code => fail(new Error(`Security MCP exited (${code}): ${errors}`)));
child.stdin.on('error', fail);
function request(id, method, params) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => { pending.delete(id); reject(new Error(`Security MCP ${method} timed out: ${errors}`)); }, 5000);
    pending.set(id, {resolve: value => {clearTimeout(timer); resolve(value);}, reject: error => {clearTimeout(timer); reject(error);}});
    child.stdin.write(JSON.stringify({jsonrpc:'2.0', id, method, ...(params ? {params} : {})}) + '\n');
  });
}
try {
  const initialized = await request(1, 'initialize', {protocolVersion:'2025-11-25', capabilities:{}, clientInfo:{name:'security-startup-check', version:'1.0.0'}});
  if (!initialized?.serverInfo || !initialized?.capabilities?.tools) throw new Error('Invalid Security MCP initialize response');
  child.stdin.write(JSON.stringify({jsonrpc:'2.0', method:'notifications/initialized'}) + '\n');
  const catalog = await request(2, 'tools/list');
  if (!catalog?.tools?.some(tool => tool.name === 'read_security_result')) throw new Error('Security MCP catalog is missing read_security_result');
  const passive = catalog.tools.find(tool=>tool.name==='observe_broadcast_multicast');
  if (passive?.inputSchema?.['x-pi-effect'] !== 'passive_capture' || passive?.annotations?.idempotentHint !== false)
    throw new Error('Passive observation must publish passive_capture and remain fresh between executions');
  for (const name of ['probe_gateway_proxy_arp','probe_gateway_hairpin','observe_dns_cache']) {
    if (catalog.tools.find(tool=>tool.name===name)?.inputSchema?.['x-pi-effect'] !== 'active_probe')
      throw new Error(`Active operation lost its probe gate: ${name}`);
  }
  const masscan=catalog.tools.find(tool=>tool.name==='masscan_scan');
  if(masscan?.inputSchema?.['x-pi-effect']!=='active_probe' || masscan?.annotations?.idempotentHint!==false || masscan?.annotations?.readOnlyHint!==false)
    throw new Error('Masscan must remain an active, fresh, separately authorized operation');
  console.log(`Security MCP startup passed: initialize and ${catalog.tools.length} catalog tools; no operations executed.`);
} finally {
  child.kill();
  await rm(workspace, {recursive:true, force:true});
}
