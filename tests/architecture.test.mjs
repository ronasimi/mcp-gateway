import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const read=rel=>fs.readFile(path.join(root,rel),'utf8');

const requiredModules=[
  'src/core/schema.mjs',
  'src/core/mcp-stdio.mjs',
  'src/adapters/host-recon-client.mjs',
  'src/domains/network/mdns/ip.mjs',
  'src/domains/network/mdns/wire.mjs',
  'src/domains/network/mdns/collector.mjs',
  'src/domains/network/mdns/normalize.mjs',
  'src/domains/network/mdns/infer.mjs',
  'src/domains/network/mdns/report.mjs',
  'src/domains/network/recon/tools.mjs',
  'src/domains/network/recon/helpers.mjs',
  'src/domains/network/recon/artifacts.mjs',
  'src/domains/network/recon/service.mjs',
];

test('atomic network modules and compatibility entrypoints remain separated', async()=>{
  for(const rel of requiredModules) await fs.access(path.join(root,rel));
  const recon=await read('scripts/security-network-recon.mjs');
  const mdns=await read('scripts/mdns-subnets.mjs');
  assert.ok(recon.split(/\r?\n/).length<=35,'network recon compatibility entrypoint grew into an implementation');
  assert.ok(mdns.split(/\r?\n/).length<=15,'mDNS compatibility entrypoint grew into an implementation');
  assert.doesNotMatch(recon,/createSocket|nmap|Graphviz|parseNmapXml/);
  assert.doesNotMatch(mdns,/createSocket|Buffer\.alloc|candidate_networks\s*=/);
});

test('all owned MCP servers share the core stdio transport primitive', async()=>{
  const core=await read('src/core/mcp-stdio.mjs');
  assert.match(core,/export function startMcpStdioServer/);
  for(const rel of ['scripts/system-tools.mjs','scripts/security-tools.mjs','scripts/google-tools.mjs']){
    const source=await read(rel);
    assert.match(source,/startMcpStdioServer/);
    assert.doesNotMatch(source,/process\.stdin\.on\('data'/);
  }
});

test('runtime images deploy compatibility loaders and shared source modules', async()=>{
  for(const rel of ['Dockerfile.system','Dockerfile.security','Dockerfile.google']){
    const dockerfile=await read(rel);
    assert.match(dockerfile,/scripts\/module-layout\.mjs/);
    assert.match(dockerfile,/scripts\/mcp-stdio\.mjs/);
    assert.match(dockerfile,/COPY src \/opt\/mcp\/src/);
  }
  const installer=await read('scripts/install-security-host-recon-helper.sh');
  assert.match(installer,/module-layout\.mjs/);
  assert.match(installer,/\$ROOT\/src/);
});

test('domain dependency direction does not point back at server entrypoints', async()=>{
  const files=[];
  async function walk(dir){for(const entry of await fs.readdir(dir,{withFileTypes:true})){const p=path.join(dir,entry.name);if(entry.isDirectory())await walk(p);else if(entry.name.endsWith('.mjs'))files.push(p);}}
  await walk(path.join(root,'src'));
  for(const file of files){
    const source=await fs.readFile(file,'utf8');
    assert.doesNotMatch(source,/from ['"](?:\.\.\/)+scripts\//,`${path.relative(root,file)} imports scripts/`);
    assert.doesNotMatch(source,/security-tools\.mjs|system-tools\.mjs|google-tools\.mjs/,`${path.relative(root,file)} imports a top-level server`);
  }
});
