import test, {mock} from 'node:test';
import {EventEmitter} from 'node:events';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import http from 'node:http';
import {createNetworkRecon} from '../scripts/security-network-recon.mjs';
import {confinedPath} from '../scripts/security-runtime.mjs';
const ok=stdout=>({code:0,stdout,stderr:''});
test('denied optional capture retains base topology and never runs tshark',async()=>{
 const calls=[];
 const api=createNetworkRecon({disableHostDelegation:true,safeWorkspace:x=>x,physicalInterfaceExists:()=>true,assertAuthorizedTarget:async x=>x,requireActive:()=>{},requireCapture:()=>{throw Error('packet capture disabled');},runStatus:async(cmd,args)=>{calls.push(cmd);if(cmd==='ip'&&args.includes('addr'))return ok('[{"ifname":"eth0","addr_info":[{"family":"inet","local":"192.168.1.10","prefixlen":24}]}]');if(cmd==='ip'&&args.includes('route'))return ok('[{"dst":"default","dev":"eth0","gateway":"192.168.1.1"}]');if(cmd==='ip')return ok('[]');return ok('');}});
 const r=await api.call('analyze_network_topology',{observe_l2:true,observe_mdns:false});
 assert.equal(r.default_routes[0].gateway,'192.168.1.1');assert.equal(r.l2_discovery.status,'unavailable');assert.equal(r.complete,false);assert(!calls.includes('tshark'));
});
test('delegated observations persist as distinct artifacts and map without JSON reconstruction',async()=>{
 const dir=await fs.mkdtemp(path.join(os.tmpdir(),'recon-artifacts-')),socket=path.join(dir,'helper.sock'),prior=process.env.SECURITY_HOST_RECON_SOCKET;
 let page=0;
 await fs.writeFile(socket,'fixture');process.env.SECURITY_HOST_RECON_SOCKET=socket;
 const transport=mock.method(http,'request',(options,receive)=>{const req=new EventEmitter();req.setTimeout=()=>{};req.end=()=>{const res=new EventEmitter();res.statusCode=200;receive(res);res.emit('data',Buffer.from(JSON.stringify({result:{hosts:[{address:'192.168.1.'+(++page)}],cidrs:['192.168.1.0/24'],complete:true}})));res.emit('end');};return req;});
 const api=createNetworkRecon({safeWorkspace:(p,o)=>confinedPath(dir,p,o),assertAuthorizedTarget:async x=>x,requireActive:()=>{},requireCapture:()=>{},runStatus:async(cmd,args)=>{assert.equal(cmd,'dot');await fs.writeFile(args[args.indexOf('-o')+1],'<svg/>');return ok('');}});
 try{
  const a=await api.call('perform_network_discovery'),b=await api.call('perform_network_discovery');assert.notEqual(a.observation_path,b.observation_path);
  const saved=JSON.parse(await fs.readFile(path.join(dir,a.observation_path),'utf8'));assert.equal(saved.perform_network_discovery.hosts[0].address,'192.168.1.1');
  const r=await api.call('generate_graphical_network_map',{input_paths:[a.observation_path,b.observation_path],format:'both'});assert.equal(r.host_count,2);assert(r.outputs.svg&&r.outputs.html);
  await assert.rejects(api.call('generate_graphical_network_map',{input_paths:['../escape.json']}),/outside|escape|workspace/i);
 }finally{if(prior===undefined)delete process.env.SECURITY_HOST_RECON_SOCKET;else process.env.SECURITY_HOST_RECON_SOCKET=prior;transport.mock.restore();await fs.rm(dir,{recursive:true,force:true});}
});
