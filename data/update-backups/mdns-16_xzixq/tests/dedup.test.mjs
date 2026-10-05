import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {createCipheriv,randomBytes} from 'node:crypto';
import {createNetworkRecon} from '../scripts/security-network-recon.mjs';
import {createExtendedSecurity} from '../scripts/security-extended.mjs';
import {createProtocolSecurity} from '../scripts/security-protocols.mjs';
import {confinedPath} from '../scripts/security-runtime.mjs';
const root=fileURLToPath(new URL('../',import.meta.url));
const ok=stdout=>({code:0,stdout,stderr:''});
function rpc(server,requests,env={},imports=[]){
 const p=spawnSync(process.execPath,[...imports,path.join(root,'scripts',server+'-tools.mjs')],{env:{...process.env,...env},input:requests.map((params,i)=>JSON.stringify({jsonrpc:'2.0',id:i+1,...params})).join('\n')+'\n',encoding:'utf8',timeout:10000,maxBuffer:2*1024*1024});
 assert.equal(p.status,0,p.stderr||p.error?.message);return p.stdout.trim().split('\n').map(JSON.parse).sort((a,b)=>a.id-b.id);
}
const call=(name,args={})=>({method:'tools/call',params:{name,arguments:args}});

test('every owned catalog has concise unique names and retires duplicate wrappers',()=>{
 const counts={system:51,security:58,google:23};
 const retired=['host_network_info','network_scan_ports','image_thumbnail','network_discover','service_detect','dns_records','pcap_fields','pcap_summary','pcap_conversations','lldp_observe','cdp_observe','llmnr_nbns_observe'];
 for(const [server,count] of Object.entries(counts)){
  const tools=rpc(server,[{method:'tools/list'}])[0].result.tools;
  assert.equal(tools.length,count);assert.equal(new Set(tools.map(t=>t.name)).size,count);
  for(const t of tools){assert(!t.name.startsWith(server+'_'),t.name);assert(!retired.includes(t.name),t.name);assert(t.description.length<=550,t.name);assert(t._meta['ai.catalog'].aliases.length,t.name);}
  if(server==='system')assert(!tools.some(t=>t.name==='network_interfaces'));
 }
});

test('DNS consolidation preserves PTR and CAA, deduplicates requests and rejects mixed selectors',async()=>{
 const dir=await fs.mkdtemp(path.join(os.tmpdir(),'dns-dedup-'));
 try{
  await fs.writeFile(path.join(dir,'dig'),`#!${process.execPath}\nprocess.stdout.write(process.argv.at(-1));`,{mode:0o755});
  const rows=rpc('system',[call('network_dns_lookup',{name:'example.test',types:['PTR','CAA','PTR']}),call('network_dns_lookup',{name:'example.test',type:'A',types:['MX']})],{PATH:dir+':'+process.env.PATH});
  assert.deepEqual(JSON.parse(rows[0].result.content[0].text).records,{PTR:'PTR',CAA:'CAA'});assert.equal(rows[1].result.isError,true);
 }finally{await fs.rm(dir,{recursive:true,force:true});}
});

test('thumbnail mode retains thumbnail processing and no-enlargement geometry',async()=>{
 const dir=await fs.mkdtemp(path.join(os.tmpdir(),'thumbnail-dedup-'));
 try{
  await fs.writeFile(path.join(dir,'convert'),`#!${process.execPath}\nrequire('node:fs').writeFileSync(process.argv.at(-1),JSON.stringify(process.argv.slice(2)));`,{mode:0o755});
  await fs.writeFile(path.join(dir,'in.png'),'fixture');
  const r=rpc('system',[call('image_resize',{input:'in.png',output:'out.png',mode:'thumbnail',width:120,height:90})],{MCP_WORKSPACE:dir,PATH:dir+':'+process.env.PATH})[0].result;
  assert.equal(r.isError,false);const args=JSON.parse(await fs.readFile(path.join(dir,'out.png'),'utf8'));assert.equal(args[1],'-thumbnail');assert.equal(args[2],'120x90>');
 }finally{await fs.rm(dir,{recursive:true,force:true});}
});

test('OpenWrt target discovery returns configured aliases without exposing credentials',async()=>{
 const dir=await fs.mkdtemp(path.join(os.tmpdir(),'router-targets-'));
 try{
  const config=path.join(dir,'ssh-config');await fs.writeFile(config,'Host anansi arachne\n HostName 192.0.2.1\n IdentityFile /private/key\nHost *\n User root\n');
  const r=rpc('system',[call('openwrt_targets')],{OPENWRT_SSH_CONFIG:config})[0].result;
  assert.deepEqual(JSON.parse(r.content[0].text).aliases,['anansi','arachne']);assert.doesNotMatch(r.content[0].text,/private\/key|192\.0\.2\.1/);
 }finally{await fs.rm(dir,{recursive:true,force:true});}
});

test('host tools fail closed when the host helper is unavailable',async()=>{
 const api=createNetworkRecon({runStatus:async()=>{throw new Error('container command must not run');},safeWorkspace:x=>x,assertAuthorizedTarget:async x=>x,requireActive:()=>{},requireCapture:()=>{}});
 await assert.rejects(api.call('get_host_interface_info',{}),/host recon helper unavailable/);
});

function reconFixture(run){return createNetworkRecon({runStatus:run,safeWorkspace:x=>x,assertAuthorizedTarget:async x=>x,requireActive:()=>{},requireCapture:()=>{},physicalInterfaceExists:()=>true,disableHostDelegation:true});}
function hostState(cmd,args){
 if(cmd==='ip'&&args.includes('addr'))return ok('[{"ifname":"eth0","operstate":"UP","link_type":"ether","addr_info":[{"family":"inet","local":"127.0.0.1","prefixlen":24}]}]');
 if(cmd==='ip')return ok('[]');
 return ok('');
}

test('hosts-only discovery paginates and skips port, share and media probes',async()=>{
 const commands=[];
 const api=reconFixture(async(cmd,args)=>{commands.push({cmd,args});return cmd==='nmap'?ok('Host: 127.0.0.2 (a)\tStatus: Up\nHost: 127.0.0.3 (b)\tStatus: Up\n'):hostState(cmd,args);});
 const first=await api.call('perform_network_discovery',{cidrs:['127.0.0.0/24'],detail:'hosts',max_hosts:1});
 const second=await api.call('perform_network_discovery',{cidrs:['127.0.0.0/24'],detail:'hosts',max_hosts:1,host_offset:first.next_offset});
 assert.equal(first.next_offset,1);assert.equal(first.complete,false);assert.equal(first.page_complete,true);assert.equal(second.next_offset,null);assert.equal(second.hosts[0].address,'127.0.0.3');assert.equal(second.complete,true);
 assert(commands.filter(c=>c.cmd==='nmap').every(c=>c.args.includes('-sn')));
});

test('reconnaissance shares one deadline and reports incomplete phases',async t=>{
 let clock=1000; t.mock.method(Date,'now',()=>clock);const budgets=[];
 const api=reconFixture(async(cmd,args,options)=>{
  if(cmd!=='nmap')return hostState(cmd,args);
  budgets.push(options.timeout);
  if(args.includes('-sn')){clock+=21000;return ok('Host: 127.0.0.2 ()\tStatus: Up\n');}
  clock+=options.timeout;return {code:124,stdout:'',stderr:'deadline',timed_out:true};
 });
 const r=await api.call('perform_network_discovery',{cidrs:['127.0.0.0/24'],timeout_seconds:30,resolve_names:false});
 assert.deepEqual(budgets,[30000,9000]);assert.equal(r.elapsed_seconds,30);assert.equal(r.complete,false);assert(r.phases.some(p=>!p.complete));assert.equal(r.hosts[0].address,'127.0.0.2');
});

test('PCAP views retain summary and conversation statistics',async()=>{
 const dir=await fs.mkdtemp(path.join(os.tmpdir(),'pcap-dedup-'));await fs.writeFile(path.join(dir,'in.pcap'),'fixture');
 const calls=[];const api=createExtendedSecurity({safeWorkspace:(p,o)=>confinedPath(dir,p,o),runStatus:async(cmd,args)=>{calls.push(args);return ok('statistics');}});
 try{
  const summary=await api.call('pcap_analyze',{path:'in.pcap'});const conversations=await api.call('pcap_analyze',{path:'in.pcap',view:'conversations',protocol:'udp'});
  assert.equal(summary.protocol_hierarchy,'statistics');assert.equal(conversations.conversations,'statistics');assert(calls[0].includes('io,phs'));assert(calls[1].includes('conv,udp'));
 }finally{api.jobs.stopAll();await fs.rm(dir,{recursive:true,force:true});}
});

test('passive protocol selector uses only fixed LLDP/CDP/name-resolution filters',async()=>{
 const calls=[];const api=createProtocolSecurity({runStatus:async(cmd,args)=>{calls.push(args);return ok('[]');},assertAuthorizedTarget:async x=>x,requireActive:()=>{},requireCapture:()=>{}});
 for(const protocol of ['lldp','cdp','llmnr_nbns'])await api.call('protocol_observe',{protocol,interface:'eth0'});
 assert.deepEqual(calls.map(a=>a[a.indexOf('-Y')+1]),['lldp','cdp','llmnr || nbns']);await assert.rejects(api.call('protocol_observe',{protocol:'arbitrary',interface:'eth0'}),/Unsupported/);
});

test('maps require observations and keep unknown physical links visibly uncertain',async()=>{
 const dir=await fs.mkdtemp(path.join(os.tmpdir(),'map-evidence-'));
 const api=createNetworkRecon({safeWorkspace:(p,o)=>confinedPath(dir,p,o),runStatus:async(cmd,args)=>{
   assert.equal(cmd,'dot');await fs.writeFile(args[args.indexOf('-o')+1],'<svg xmlns="http://www.w3.org/2000/svg"/>');return ok('');
 },assertAuthorizedTarget:async x=>x,requireActive:()=>{},requireCapture:()=>{}});
 try{
  await assert.rejects(api.call('generate_graphical_network_map',{data:{},output_base:'empty'}),/requires collected/);
  const r=await api.call('generate_graphical_network_map',{data:{interface_info:{selected_interface:'eth0',default_routes:[{interface:'eth0',gateway:'127.0.0.1'}]},discovery:{cidrs:['127.0.0.0/24'],hosts:[{address:'127.0.0.2'}]}},output_base:'observed',format:'svg'});
  const dot=await fs.readFile(path.join(dir,r.outputs.dot),'utf8');assert.match(dot,/attachment unknown/);assert.match(dot,/style=dotted/);assert.doesNotMatch(dot,/laptop -> laptop|Solid edge = wired\/unknown/);
 }finally{await fs.rm(dir,{recursive:true,force:true});}
});

test('Drive downloads preserve binary and JSON bytes, while read_text rejects binary',async()=>{
 const dir=await fs.mkdtemp(path.join(os.tmpdir(),'drive-download-'));
 try{
  const key=randomBytes(32),iv=randomBytes(12),cipher=createCipheriv('aes-256-gcm',key,iv);
  const encrypted=Buffer.concat([cipher.update(JSON.stringify({access_token:'fixture',expiry_date:Date.now()+3600000})),cipher.final()]);
  const keyFile=path.join(dir,'key'),tokenFile=path.join(dir,'token.json');await fs.writeFile(keyFile,key.toString('hex'));
  await fs.writeFile(tokenFile,JSON.stringify({version:1,algorithm:'AES-256-GCM',iv:iv.toString('base64'),tag:cipher.getAuthTag().toString('base64'),ciphertext:encrypted.toString('base64')}));
  const mock=path.join(dir,'fetch.mjs');await fs.writeFile(mock,`globalThis.fetch=async input=>{const u=new URL(input),json=u.pathname.endsWith('/json'),mime=json?'application/json':'application/pdf';if(!u.searchParams.has('alt'))return Response.json({id:json?'json':'pdf',name:'fixture',mimeType:mime});return new Response(json?' { "key" : 1 }\\n':Buffer.from([0,255,10,13,128]),{headers:{'content-type':mime}});};`);
  const results=rpc('google',[call('drive_download_file',{file_id:'pdf',output:'out.pdf'}),call('drive_download_file',{file_id:'json',output:'out.json'}),call('drive_read_text',{file_id:'pdf'})],{MCP_WORKSPACE:dir,GOOGLE_TOKEN_FILE:tokenFile,GOOGLE_TOKEN_KEY_FILE:keyFile},['--import',mock]);
  assert.equal(results[0].result.isError,false);assert.equal(results[1].result.isError,false);assert.equal(results[2].result.isError,true);
  assert.deepEqual(await fs.readFile(path.join(dir,'out.pdf')),Buffer.from([0,255,10,13,128]));assert.equal(await fs.readFile(path.join(dir,'out.json'),'utf8'),' { "key" : 1 }\n');
 }finally{await fs.rm(dir,{recursive:true,force:true});}
});
