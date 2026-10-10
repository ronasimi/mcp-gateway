import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import {spawnSync} from 'node:child_process';
import {MASSCAN_TOOL,createMasscan,masscanTarget,masscanPorts,parseMasscanList} from '../scripts/security-masscan.mjs';
import {validateArguments} from '../scripts/security-runtime.mjs';
import {decorateCatalogTools} from '../scripts/catalog-metadata.mjs';

function fixture(result={code:0,stdout:'open tcp 80 192.168.1.10 1791640000\n',stderr:''},extra={}) {
  const calls=[],targets=[];
  const api=createMasscan({validateArguments,requireActive(){},rejectAmbientConfig:async()=>{},assertAuthorizedTarget:async(target,options)=>targets.push({target,options}),runStatus:async(command,args,options)=>{calls.push({command,args,options});return result;},...extra});
  return {api,calls,targets};
}
test('Masscan catalog has explicit scope, required ports and conservative bounds',()=>{
  const tool=decorateCatalogTools([MASSCAN_TOOL],'security')[0];
  assert.deepEqual(tool.inputSchema.required,['target','ports']);assert.equal(tool.inputSchema.additionalProperties,false);
  assert(tool._meta['ai.catalog'].aliases.includes('massscan'));assert.equal(tool.annotations.readOnlyHint,false);assert.equal(tool.annotations.idempotentHint,false);
  assert.equal(tool.inputSchema.properties.rate_limit.maximum,1000);
});
test('Masscan uses canonical authorized scope, compact ports and bounded argv without a shell',async()=>{
  const f=fixture();const result=await f.api.call({target:'192.168.1.42/24',ports:'81,80,80,443',rate_limit:1000,timeout_seconds:20,interface:'eth0'});
  assert.deepEqual(f.targets,[{target:'192.168.1.0/24',options:{allowCidr:true}}]);
  assert.deepEqual(f.calls[0],{command:'masscan',args:['192.168.1.0/24','-p','80-81,443','--rate','1000','--wait','5','--retries','0','--open','-oL','-','-e','eth0'],options:{timeout:20000,maxBuffer:1024*1024}});
  assert.equal(result.planned_probe_count,768);assert.equal(result.open_port_count,1);assert.equal(result.complete,true);assert.equal(result.scope,'security-container-target-scan');
});
test('Masscan rejects unsupported targets, oversized ranges, invalid ports and unknown options before execution',async()=>{
  for(const target of ['example.org','::1','192.168.1.1,192.168.1.2','192.168.1.1;id','--rate=100000','10.0.0.0/19','10.0.0.0/0','300.1.1.1','192.168.1.0/-1'])assert.throws(()=>masscanTarget(target),target);
  for(const ports of ['','0','65536','2-1','1-1025','U:53','80;id','80 --banners','1-1024,4433'])assert.throws(()=>masscanPorts(ports),ports);
  for(const args of [{target:'192.168.1.10',ports:'80',rate_limit:1001},{target:'192.168.1.10',ports:'80',timeout_seconds:181},{target:'192.168.1.10',ports:'80',interface:'eth0;id'},{target:'192.168.1.10',ports:'80',flags:'--banners'}]){
    const f=fixture();await assert.rejects(f.api.call(args));assert.equal(f.calls.length,0);
  }
});
test('Masscan enforces total probes and feasible scope/rate/deadline combinations',async()=>{
  const f=fixture();await assert.rejects(f.api.call({target:'192.168.0.0/20',ports:'1-1024',rate_limit:1000,timeout_seconds:180}),/262144/);
  await assert.rejects(f.api.call({target:'192.168.1.0/24',ports:'1-100',rate_limit:100,timeout_seconds:60}),/narrow the scope/);assert.equal(f.calls.length,0);
});
test('Masscan active, target and ambient configuration gates fail before spawn',async()=>{
  for(const extra of [{requireActive(){throw Error('active disabled');}},{assertAuthorizedTarget:async()=>{throw Error('target denied');}},{rejectAmbientConfig:async()=>{throw Error('ambient configuration');}}]){
    const f=fixture(undefined,extra);await assert.rejects(f.api.call({target:'192.168.1.10',ports:'80'}));assert.equal(f.calls.length,0);
  }
});
test('Masscan list parser deduplicates, checks scan scope and rejects malformed/unrequested observations',()=>{
  const parsed=parseMasscanList('# masscan\nopen tcp 80 192.168.1.10 1791640000\nopen tcp 80 192.168.1.10 1791640001\nopen tcp 22 192.168.1.10 1791640000\nopen tcp 80 192.168.2.10 1791640000\nopen udp 80 192.168.1.10 1791640000\nnot a row',masscanTarget('192.168.1.0/24'),masscanPorts('80'));
  assert.equal(parsed.rows.length,1);assert.equal(parsed.duplicates,1);assert.equal(parsed.invalid,4);
});
test('Masscan reports timeout, output cap, nonzero exit and malformed results as incomplete',async()=>{
  for(const result of [{code:124,timed_out:true},{code:125,output_limited:true},{code:1},{code:0,stdout:'malformed'}]){
    const f=fixture({stdout:'',stderr:'bounded diagnostic',...result});const data=await f.api.call({target:'192.168.1.10',ports:'80'});assert.equal(data.complete,false);assert.equal(data.open_port_count,0);
  }
  const empty=await fixture({code:0,stdout:'# completed\n',stderr:''}).api.call({target:'192.168.1.10',ports:'80'});assert.equal(empty.complete,true);assert.match(empty.limitations.join(' '),/unreported ports are closed/);
});
test('Masscan image pins the binary and includes offline regression checks',async()=>{
  const image=await fs.readFile(new URL('../Dockerfile.security',import.meta.url),'utf8');assert.match(image,/ARG MASSCAN_VERSION=2:1\.3\.2\+ds1-1/);assert.match(image,/masscan=\$\{MASSCAN_VERSION\}/);assert.match(image,/masscan --regress/);assert.match(image,/masscan 192\.0\.2\.1 .*--echo > \/dev\/null/);assert.match(image,/rm -f \/etc\/masscan\/masscan\.conf/);
});

test('actual MCP dispatch denies disabled/public/invalid scans before executing a stub, and spills large evidence',async t=>{
  const temp=await fs.mkdtemp(path.join(os.tmpdir(),'masscan-mcp-'));t.after(()=>fs.rm(temp,{recursive:true,force:true}));
  const executable=path.join(temp,'masscan'),marker=path.join(temp,'argv.json'),workspace=path.join(temp,'workspace');await fs.mkdir(workspace);
  await fs.writeFile(executable,'#!/usr/bin/env node\nconst fs=require("node:fs");fs.writeFileSync(process.env.MASSCAN_TEST_MARKER,JSON.stringify(process.argv.slice(2)));for(let p=1;p<=1000;p++)console.log("open tcp "+p+" 192.168.1.10 1791640000");\n',{mode:0o755});
  const run=(args,env={})=>{
    const child=spawnSync(process.execPath,[new URL('../scripts/security-tools.mjs',import.meta.url).pathname],{env:{...process.env,PATH:temp+path.delimiter+process.env.PATH,MCP_WORKSPACE:workspace,MASSCAN_TEST_MARKER:marker,SECURITY_ALLOW_ACTIVE:'true',SECURITY_ALLOW_PUBLIC_TARGETS:'false',SECURITY_TARGET_ALLOWLIST:'192.168.1.0/24',...env},input:JSON.stringify({jsonrpc:'2.0',id:1,method:'tools/call',params:{name:'masscan_scan',arguments:args}})+'\n',encoding:'utf8',timeout:10000});
    assert.equal(child.status,0,child.stderr);return JSON.parse(child.stdout.trim()).result;
  };
  for(const [args,env] of [[{target:'192.168.1.10',ports:'80'},{SECURITY_ALLOW_ACTIVE:'false'}],[{target:'8.8.8.8',ports:'80'},{}],[{target:'192.168.1.0/23',ports:'80'},{}],[{target:'192.168.1.10',ports:'80',rate_limit:999999},{}]]){
    assert.equal(run(args,env).isError,true);await assert.rejects(fs.access(marker));
  }
  const result=run({target:'192.168.1.10',ports:'1-1000'});assert.equal(result.isError,false);
  const wrapped=JSON.parse(result.content[0].text);assert(wrapped.output_file);const stored=JSON.parse(await fs.readFile(path.join(workspace,wrapped.output_file),'utf8'));assert.equal(stored.open_port_count,1000);assert.equal(stored.open_ports.length,1000);assert.equal(stored.complete,true);
  const argv=JSON.parse(await fs.readFile(marker,'utf8'));assert.deepEqual(argv.slice(0,3),['192.168.1.10','-p','1-1000']);
});
