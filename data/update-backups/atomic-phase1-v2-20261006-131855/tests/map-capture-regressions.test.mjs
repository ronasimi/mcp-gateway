import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {createNetworkRecon,normalizeMapOutputBase} from '../scripts/security-network-recon.mjs';
import {confinedPath} from '../scripts/security-runtime.mjs';
const context={assertAuthorizedTarget:async x=>x,requireActive:()=>{},requireCapture:()=>{}};
test('map basename relocation rejects absolute paths and traversal',()=>{
 assert.equal(normalizeMapOutputBase('recon-session-1/network-map'),'.security-results/recon-session-1/network-map');
 assert.equal(normalizeMapOutputBase('.security-results/run/map'),'.security-results/run/map');
 for(const input of ['/workspace/map','../map','.security-results/../map','C:/map','a\\map','','.security-results','foo/'])assert.throws(()=>normalizeMapOutputBase(input));
});
test('map writes only within results and rejects internal symlink escapes',async()=>{
 const root=await fs.mkdtemp(path.join(os.tmpdir(),'map-confine-'));
 const api=createNetworkRecon({...context,safeWorkspace:(p,o)=>confinedPath(root,p,o),runStatus:async(cmd,args)=>{assert.equal(cmd,'dot');await fs.writeFile(args.at(-1),'<svg/>');return {code:0,stdout:'',stderr:''};}});
 const data={perform_network_discovery:{hosts:[{address:'192.168.1.1'}]}};
 try{
  await fs.mkdir(path.join(root,'.security-results'));
  const result=await api.call('generate_graphical_network_map',{data,output_base:'recon-session-1/network-map',format:'both'});
  assert.equal(result.outputs.svg,'.security-results/recon-session-1/network-map.svg');
  await assert.rejects(fs.stat(path.join(root,'recon-session-1')), {code:'ENOENT'});
  assert.equal((await fs.stat(path.join(root,result.outputs.html))).mode&0o777,0o640);
  assert.equal((await fs.stat(path.dirname(path.join(root,result.outputs.html)))).mode&0o7777,0o2750);
  await fs.mkdir(path.join(root,'elsewhere'));
  await fs.symlink(path.join(root,'elsewhere'),path.join(root,'.security-results','escape'));
  await assert.rejects(api.call('generate_graphical_network_map',{data,output_base:'.security-results/escape/map'}),/real directory/);
  await fs.writeFile(path.join(root,'victim'),'unchanged');
  await fs.symlink(path.join(root,'victim'),path.join(root,'.security-results','evil.dot'));
  await assert.rejects(api.call('generate_graphical_network_map',{data,output_base:'evil'}),/regular file/);
  assert.equal(await fs.readFile(path.join(root,'victim'),'utf8'),'unchanged');
 }finally{await fs.rm(root,{recursive:true,force:true});}
});
test('capture outcome distinguishes zero packets, observations, and failure despite diagnostics',async()=>{
 for(const [code,stdout,completed,observed,status] of [[0,'',true,false,'no_matching_packets'],[0,'1|aa:bb:cc:dd:ee:ff|switch|port',true,true,'packets_observed'],[1,'',false,false,'unavailable']]){
  const api=createNetworkRecon({...context,disableHostDelegation:true,physicalInterfaceExists:()=>true,safeWorkspace:p=>p,runStatus:async(cmd,args)=>{
   if(cmd==='tshark')return {code,stdout,stderr:'configuration warning'};
   let out='';if(cmd==='ip'&&args.includes('addr'))out='[{"ifname":"eth0","addr_info":[{"family":"inet","local":"192.168.1.10","prefixlen":24}]}]';else if(cmd==='ip')out='[]';
   return {code:0,stdout:out,stderr:''};
  }});
  const r=await api.call('analyze_network_topology',{observe_l2:true,observe_mdns:false});
  assert.equal(r.l2_discovery.capture_completed,completed);assert.equal(r.l2_discovery.observed,observed);assert.equal(r.l2_discovery.observation_status,status);assert.equal(r.complete,completed);assert.equal(r.l2_discovery.exit_code,code);
 }
});
