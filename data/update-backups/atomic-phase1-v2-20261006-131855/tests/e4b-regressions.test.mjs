import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {createNetworkRecon,normalizeReconInput,resultEnvelope} from '../scripts/security-network-recon.mjs';
import {confinedPath} from '../scripts/security-runtime.mjs';
test('active wireless rescan rejected before commands or delegation',async()=>{
 const api=createNetworkRecon({assertAuthorizedTarget:async x=>x,requireActive:()=>{},requireCapture:()=>{},safeWorkspace:p=>{if(p==='.')return '/tmp';throw Error('unexpected storage');},runStatus:()=>{throw Error('unexpected command');}});
 await assert.rejects(api.call('analyze_wireless_environment',{rescan:true}),/Passive-only/);
});
test('truncation preserves observation paths and incomplete pagination',()=>{
 const r=resultEnvelope({observation_path:'wifi.json',report_path:'wifi-report.json',read_hint:'read report_path',status:'observed',coverage:'partial',complete:false,next_offset:64,observation_mode:'passive-cached'},'raw.json',20000,'preview');
 assert.equal(r.observation_path,'wifi.json');assert.equal(r.report_path,'wifi-report.json');assert.equal(r.read_hint,'read report_path');assert.equal(r.status,'observed');assert.equal(r.coverage,'partial');assert.equal(r.complete,false);assert.equal(r.next_offset,64);assert.equal(r.observation_mode,'passive-cached');
});
test('raw wireless accepted; empty, arbitrary and preview JSON rejected',()=>{
 assert(normalizeReconInput({current_connection:{connected:true},nearby_access_points:[]}).analyze_wireless_environment);
 for(const v of [{},{foo:'bar'},{truncated:true,preview:'{}'},{wireless:{}}])assert.throws(()=>normalizeReconInput(v));
});
test('raw wireless appears on map with missing topology warning and zoom controls',async()=>{
 const dir=await fs.mkdtemp(path.join(os.tmpdir(),'e4b-map-'));
 const api=createNetworkRecon({assertAuthorizedTarget:async x=>x,requireActive:()=>{},requireCapture:()=>{},safeWorkspace:(p,o)=>confinedPath(dir,p,o),runStatus:async(cmd,args)=>{assert.equal(cmd,'dot');await fs.writeFile(args.at(-1),'<svg/>');return {code:0,stdout:'',stderr:''};}});
 try{
  await fs.writeFile(path.join(dir,'wifi.json'),JSON.stringify({current_connection:{connected:true,ssid:'Evidence AP'},nearby_access_points:[]}));
  await fs.writeFile(path.join(dir,'host.json'),JSON.stringify({get_host_interface_info:{selected_interface:'wlan0',connection_type:'wifi',interfaces:[{name:'wlan0'}]}}));
  const r=await api.call('generate_graphical_network_map',{input_paths:['wifi.json','host.json'],format:'both'});
  assert(r.included_observations.includes('analyze_wireless_environment'));assert(r.missing_observations.includes('analyze_network_topology'));
  assert.match(await fs.readFile(path.join(dir,r.outputs.dot),'utf8'),/Evidence AP/);
  assert.match(await fs.readFile(path.join(dir,r.outputs.html),'utf8'),/zoom-in.*onclick/s);
  await assert.rejects(api.call('generate_graphical_network_map',{input_paths:[]}),/requires collected/);
 }finally{await fs.rm(dir,{recursive:true,force:true});}
});
test('cached wireless ignores duration and unavailable mDNS stays unknown',async()=>{
 const calls=[];
 const api=createNetworkRecon({disableHostDelegation:true,physicalInterfaceExists:()=>true,safeWorkspace:p=>p,assertAuthorizedTarget:async x=>x,requireActive:()=>{},requireCapture:()=>{},runStatus:async(cmd,args)=>{
  calls.push([cmd,args]);let stdout='';let code=0;
  if(cmd==='ip'&&args.includes('addr'))stdout='[{"ifname":"wlan0","addr_info":[{"family":"inet","local":"192.168.1.10","prefixlen":24}]}]';
  else if(cmd==='ip'&&args.includes('route'))stdout='[{"dst":"default","dev":"wlan0","gateway":"192.168.1.1"}]';
  else if(cmd==='ip')stdout='[]';
  else if(cmd==='iw'&&args.length===1)stdout='phy#0\n Interface wlan0\n  type managed\n';
  else if(cmd==='timeout')code=127;
  return {code,stdout,stderr:code?'unavailable':''};
 }});
 const wifi=await api.call('analyze_wireless_environment',{duration_seconds:15});
 assert.equal(wifi.observation_mode,'passive-cached');assert.equal(wifi.observation_duration_seconds,null);
 assert(calls.some(([cmd,args])=>cmd==='nmcli'&&args.at(-1)==='no'));
 assert(calls.some(([cmd,args])=>cmd==='iw'&&args.includes('scan')&&args.includes('dump')));
 const top=await api.call('analyze_network_topology',{});
 assert.equal(top.mdns_reflector_assessment.possible_reflector,null);assert.equal(top.mdns_reflector_assessment.status,'unavailable');assert.equal(top.segmentation_assessment.status,'not_tested');
});
