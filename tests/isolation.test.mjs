import test from 'node:test';
import assert from 'node:assert/strict';
import {createIsolationAssessment} from '../src/domains/network/recon/isolation.mjs';
import {createNetworkRecon,NETWORK_RECON_TOOLS,NETWORK_RECON_HOST_TOOL_NAMES,NETWORK_RECON_ACTIVE_TOOL_NAMES} from '../scripts/security-network-recon.mjs';
import {validateArguments} from '../scripts/security-runtime.mjs';
import {decorateCatalogTools} from '../scripts/catalog-metadata.mjs';
const info={selected_interface:'wlan0',interfaces:[{name:'wlan0',mac:'00:11:22:33:44:55',addresses:[{family:'inet',address:'192.168.1.20',prefixlen:24}]}],default_routes:[{interface:'wlan0',gateway:'192.168.1.1'}]};
function setup(overrides={}){
 const runs=[],authorized=[],gates=[];
 const api=createIsolationAssessment({interfaceInfo:async()=>info,validateArguments,
 runStatus:async(c,a,o)=>{runs.push({command:c,args:a,options:o});return {code:0,stdout:JSON.stringify({complete:true}),stderr:''};},
 assertAuthorizedTarget:async(t,o)=>authorized.push({t,o}),requireActive:()=>gates.push('active'),requireCapture:()=>gates.push('capture'),...overrides});
 return {api,runs,authorized,gates};
}
test('all four tools publish host scope, discovery metadata and bounded schemas',()=>{
 for(const name of ['observe_broadcast_multicast','probe_gateway_proxy_arp','probe_gateway_hairpin','observe_dns_cache']){
  assert(NETWORK_RECON_HOST_TOOL_NAMES.has(name));assert(NETWORK_RECON_ACTIVE_TOOL_NAMES.has(name));
  const tool=NETWORK_RECON_TOOLS.find(t=>t.name===name);assert(tool);
  const catalog=decorateCatalogTools([tool],'security')[0];assert(catalog._meta['ai.catalog'].aliases.length);
  assert.equal(tool.inputSchema.additionalProperties,false);
 }
});
test('passive capture uses only capture gate and selected physical interface',async()=>{
 const {api,runs,authorized,gates}=setup();const r=await api.call('observe_broadcast_multicast',{});
 assert.deepEqual(gates,['capture']);assert.deepEqual(authorized,[]);assert.equal(r.scope,'host-network');
 assert.equal(runs[0].command,'python3');assert.match(runs[0].args[0],/src\/domains\/network\/recon\/isolation-worker.py$/);
 assert.equal(JSON.parse(runs[0].args[2]).interface,'wlan0');assert.equal(runs[0].options.timeout,120000);
});
test('capture gate fails before interface lookup or worker execution',async()=>{
 const {api,runs}=setup({requireCapture:()=>{throw Error('capture disabled');},interfaceInfo:()=>{throw Error('should not run');}});
 await assert.rejects(api.call('observe_broadcast_multicast',{}),/capture disabled/);assert.equal(runs.length,0);
});
test('active gate and target policy cannot be bypassed',async()=>{
 const {api,runs}=setup({requireActive:()=>{throw Error('active disabled');}});
 await assert.rejects(api.call('observe_dns_cache',{names:['example.org']}),/active disabled/);assert.equal(runs.length,0);
 const denied=setup({assertAuthorizedTarget:()=>{throw Error('target denied');}});
 await assert.rejects(denied.api.call('probe_gateway_hairpin',{peer_targets:['192.168.1.50']}),/target denied/);assert.equal(denied.runs.length,0);
});
test('ARP sweeps use gateway/source, reject oversized/off-link/invalid CIDRs',async()=>{
 const {api,runs,authorized}=setup();await api.call('probe_gateway_proxy_arp',{});
 const a=JSON.parse(runs[0].args[2]);assert.equal(a.cidr,'192.168.1.0/24');assert.equal(a.source_address,'192.168.1.20');
 assert(authorized.some(x=>x.t===a.cidr&&x.o.allowCidr));
 for(const cidr of ['192.168.0.0/16','10.0.0.0/24','192.168.1.1/33','192.168.1.1/NaN'])await assert.rejects(api.call('probe_gateway_proxy_arp',{cidr}));
 await assert.rejects(api.call('probe_gateway_proxy_arp',{max_hosts:300}));assert.equal(runs.length,1);
});
test('hairpin requires explicit connected peers and rejects gateway/self/duplicates',async()=>{
 const {api,runs}=setup();
 for(const peers of [undefined,[],['192.168.1.1'],['192.168.1.20'],['10.0.0.2'],['192.168.1.50','192.168.1.50'],['example.org']]){
  await assert.rejects(api.call('probe_gateway_hairpin',peers?{peer_targets:peers}:{}));
 }
 assert.equal(runs.length,0);await api.call('probe_gateway_hairpin',{peer_targets:['192.168.1.50']});assert.equal(runs.length,1);
});
test('DNS uses explicit names, bounded samples and LAN server, rejects injection',async()=>{
 const {api,runs}=setup();await api.call('observe_dns_cache',{names:['printer.lan','_ipp._tcp.example.org'],baseline_ttl:300});
 const a=JSON.parse(runs[0].args[2]);assert.equal(a.server,'192.168.1.1');assert.equal(a.baseline_ttl,300);
 for(const args of [{names:['example.org'],server:'8.8.8.8'},{names:['$(id)']},{names:['a..b']},{names:['example.org'],samples:4},{names:['example.org'],recursive:true},{names:[]}])await assert.rejects(api.call('observe_dns_cache',args));
 assert.equal(runs.length,1);
});
test('worker failure is explicit, never interpreted as an empty observation',async()=>{
 const {api}=setup({runStatus:async()=>({code:1,stdout:'',stderr:'missing scapy'})});
 await assert.rejects(api.call('observe_broadcast_multicast',{}),/unavailable.*missing scapy/);
});
test('missing host helper never runs assessments in Docker namespace',async()=>{
 const saved=process.env.SECURITY_HOST_RECON_SOCKET;delete process.env.SECURITY_HOST_RECON_SOCKET;
 try{
 const api=createNetworkRecon({runStatus:()=>{throw Error('unexpected worker');},safeWorkspace:r=>'/tmp/'+r,assertAuthorizedTarget:async()=>{},requireActive:()=>{},requireCapture:()=>{},validateArguments});
 await assert.rejects(api.call('observe_broadcast_multicast',{}),/refusing to substitute/);
 }finally{if(saved===undefined)delete process.env.SECURITY_HOST_RECON_SOCKET;else process.env.SECURITY_HOST_RECON_SOCKET=saved;}
});

test('delegated assessments save full observations and preserve recovery hint in envelopes',async t=>{
 const fs=await import('node:fs/promises'),os=await import('node:os'),path=await import('node:path'),http=await import('node:http'),{EventEmitter}=await import('node:events');
 const {confinedPath}=await import('../scripts/security-runtime.mjs');const {resultEnvelope}=await import('../scripts/security-network-recon.mjs');
 const dir=await fs.mkdtemp(path.join(os.tmpdir(),'isolation-save-'));const prior=process.env.SECURITY_HOST_RECON_SOCKET;
 const socket=path.join(dir,'helper.sock');await fs.writeFile(socket,'mock transport');process.env.SECURITY_HOST_RECON_SOCKET=socket;
 const fixture={complete:true,observations:[{protocol:'arp',claimed_sender_ip:'192.168.1.50'}]};
 t.mock.method(http.default,'request',(options,receive)=>{const req=new EventEmitter();req.setTimeout=()=>{};req.end=()=>{const res=new EventEmitter();res.statusCode=200;receive(res);res.emit('data',Buffer.from(JSON.stringify({result:fixture})));res.emit('end');};return req;});
 const api=createNetworkRecon({safeWorkspace:(p,o)=>confinedPath(dir,p,o),runStatus:async()=>{throw Error('must use helper');},assertAuthorizedTarget:async()=>{},requireActive:()=>{},requireCapture:()=>{},validateArguments});
 try{
  const result=await api.call('observe_broadcast_multicast',{});assert(result.observation_path);assert.match(result.read_hint,/untrusted/);
  const artifact=JSON.parse(await fs.readFile(path.join(dir,result.observation_path),'utf8'));
  assert.deepEqual(artifact.observe_broadcast_multicast,fixture);assert.equal(result.map_hint,undefined);
  const envelope=resultEnvelope(result,'out.json',20000,'preview');assert.equal(envelope.observation_path,result.observation_path);assert.equal(envelope.read_hint,result.read_hint);
 }finally{if(prior===undefined)delete process.env.SECURITY_HOST_RECON_SOCKET;else process.env.SECURITY_HOST_RECON_SOCKET=prior;await fs.rm(dir,{recursive:true,force:true});}
});

test('gateway gate blocks delegated tools even when helper permissions would allow them',async()=>{
 const base={safeWorkspace:r=>'/tmp/'+r,runStatus:async()=>{throw Error('must not run');},assertAuthorizedTarget:async()=>{},validateArguments};
 const api=createNetworkRecon({...base,requireCapture:()=>{throw Error('gateway capture disabled');},requireActive:()=>{throw Error('gateway active disabled');}});
 await assert.rejects(api.call('observe_broadcast_multicast',{}),/gateway capture disabled/);
 await assert.rejects(api.call('observe_dns_cache',{names:['printer.lan']}),/gateway active disabled/);
});
