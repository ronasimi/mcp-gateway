import test from 'node:test';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {loadCatalogs,auditCatalog,rankTools} from '../scripts/audit-catalog.mjs';
const tools=loadCatalogs();
test('client description update preserves endpoints, auth and exposure and is idempotent',()=>{
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'mcp-config-'));
 try{
  const file=path.join(dir,'mcp.json'),server={url:'http://fixture/mcp',enabled:false,exposure:'deferred',headers:{Authorization:'fixture'},toolExposure:{browser_close:'hidden'},description:'Long old description'};
  fs.writeFileSync(file,JSON.stringify({autoEnableCodemode:false,mcpServers:{system:server,custom:{description:'Keep me'}}}));
  for(let i=0;i<2;i++)assert.equal(spawnSync(process.execPath,['scripts/compact-mcp-config.mjs',file]).status,0);
  const result=JSON.parse(fs.readFileSync(file));
  assert.deepEqual(result.mcpServers.system,{...server,description:'System utilities.'});
  assert.deepEqual(result.mcpServers.custom,{description:'Keep me'});
  assert.equal(fs.readdirSync(dir).filter(n=>n.includes('catalog-backup')).length,1);
 }finally{fs.rmSync(dir,{recursive:true,force:true});}
});
test('every canonical tool name and curated alias retrieves its owner in the lexical top three',()=>{
 const report=auditCatalog(tools);
 assert.deepEqual(report.failures,[]);
 assert.equal(report.top3_passed,report.queries);
});
test('task phrasing distinguishes passive/active work, host/container scope and scalar/list results',()=>{
 const cases={
  'passive network discovery':'observe_broadcast_multicast',
  'passive network reconnaissance':'observe_broadcast_multicast',
  'broadcast multicast capture':'observe_broadcast_multicast',
  'ARP mDNS LLMNR SSDP observation':'observe_broadcast_multicast',
  'what clients are connected to my router':'openwrt_clients',
  'nmap service versions':'port_scan',
  'tcpdump capture':'packet_capture',
  'host network interfaces':'get_host_interface_info',
  'container network interfaces':'network_interfaces',
  'mDNS reflector evidence':'discover_mdns_subnets',
  'how many unread emails':'gmail_get_unread_count',
  'read PDF pages':'pdf_read',
  'edit spreadsheet formulas':'office_edit',
  'calendar free busy':'calendar_freebusy',
  'installed security tools':'status',
  'stop background job':'job_stop',
 };
 for(const [query,name] of Object.entries(cases))assert.equal(rankTools(tools,query)[0]?.tool.name,name,query);
});
test('schemas remain bounded, descriptive and structurally valid at every nesting level',()=>{
 const walk=(schema,label)=>{
  assert(schema.description?.trim(),`${label}: description`);
  assert(schema.description.length<=240,`${label}: description budget`);
  if(schema.properties){
   for(const key of schema.required||[])assert(Object.hasOwn(schema.properties,key),`${label}: unknown required field ${key}`);
   for(const [key,child] of Object.entries(schema.properties))walk(child,label+'.'+key);
  }
  if(schema.items)walk(schema.items,label+'[]');
 };
 for(const tool of tools){
  assert(tool.description.length<=550,tool.name);
  assert(Buffer.byteLength(JSON.stringify(tool.inputSchema))<=4096,tool.name);
  assert.equal(tool.inputSchema.additionalProperties,false,tool.name);
  const aliases=tool._meta['ai.catalog'].aliases;
  assert(aliases.length>0&&aliases.length<=6,tool.name);
  assert.equal(new Set(aliases.map(a=>a.toLowerCase())).size,aliases.length,tool.name);
  for(const alias of aliases)assert(alias.length<=80&&!alias.includes('*'),tool.name);
  walk(tool.inputSchema,tool.name);
 }
});
test('fractional PID, result count and TCP port fail validation before backend execution',()=>{
 for(const [server,name,args] of [['system','host_process_info',{pid:1.5}],['google','gmail_search_messages',{max_results:1.5}],['security','tls_audit',{host:'127.0.0.1',port:443.5}]]){
  const p=spawnSync(process.execPath,[`scripts/${server}-tools.mjs`],{input:JSON.stringify({jsonrpc:'2.0',id:1,method:'tools/call',params:{name,arguments:args}})+'\n',encoding:'utf8',timeout:15000});
  assert.equal(p.status,0,p.stderr);
  const r=JSON.parse(p.stdout.trim().split('\n')[0]);
  assert.equal(r.result?.isError,true,server);
  assert.match(JSON.stringify(r),/out of range/,server);
 }
});
