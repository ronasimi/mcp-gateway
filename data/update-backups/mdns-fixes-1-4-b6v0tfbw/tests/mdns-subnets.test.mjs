import test from 'node:test';
import assert from 'node:assert/strict';
import {EventEmitter} from 'node:events';
import {addressRange,inferMdnsSubnets,parseMdnsPacket,collectMdns} from '../scripts/mdns-subnets.mjs';
import {createNetworkRecon,NETWORK_RECON_HOST_TOOL_NAMES} from '../scripts/security-network-recon.mjs';
const interfaces=[{ifname:'wlan0',addr_info:[{family:'inet',local:'192.168.1.20',prefixlen:24},{family:'inet6',local:'fd00:1::20',prefixlen:64}]}];
const a=(address,name='host.local')=>({name,type:address.includes(':')?'AAAA':'A',address,ttl:120});
test('advertised IPv4 /24 is a hypothesis with exact range; known route is not remote subnet proof',()=>{
 const r=inferMdnsSubnets([a('192.168.20.45'),a('192.168.20.46'),a('10.2.3.4')],{interface:'wlan0',interfaces,routes:[{dst:'10.2.0.0/16'}]});
 assert.equal(r.candidate_networks.length,2);const guess=r.candidate_networks[0];assert.equal(guess.cidr,'192.168.20.0/24');assert.equal(guess.range_end,'192.168.20.255');assert.equal(guess.address_count,'256');assert.equal(guess.basis,'heuristic');assert.equal(guess.actual_subnet_mask_known,false);assert.equal(guess.scan_automatically,false);assert.equal(guess.observed_addresses.length,2);
 assert.equal(r.candidate_networks[1].basis,'known_route');assert.equal(r.candidate_networks[1].actual_subnet_mask_known,false);assert.equal(r.possible_reflection,true);assert.equal(r.reflector_confirmed,false);
});
test('confirmed local prefixes, longest matching route and link-local exclusion',()=>{
 const r=inferMdnsSubnets([a('192.168.1.45'),a('10.2.3.4'),a('169.254.1.4'),a('fe80::5'),a('8.8.8.8')],{interface:'wlan0',interfaces,routes:[{dst:'10.0.0.0/8'},{dst:'10.2.3.4/32'}]});
 assert.equal(r.candidate_networks[0].actual_subnet_mask_known,true);assert.equal(r.candidate_networks[1].cidr,'10.2.3.4/32');assert.equal(r.candidate_networks.length,2);assert.equal(r.addresses[2].outside_selected_subnets,false);assert.equal(r.addresses[3].range_status,'link_local_or_loopback');assert.equal(r.addresses[4].range_status,'unknown');
});
test('IPv6 candidate boundaries and real /23 range math',()=>{
 const r=inferMdnsSubnets([a('fd00:2::9'),a('fd00:1::5')],{interface:'wlan0',interfaces});
 assert.equal(r.candidate_networks[0].basis,'heuristic');assert.equal(r.candidate_networks[0].address_count,'18446744073709551616');assert.equal(r.candidate_networks[1].actual_subnet_mask_known,true);
 assert.deepEqual(addressRange('192.168.21.45',23),{cidr:'192.168.20.0/23',family:4,prefix_length:23,range_start:'192.168.20.0',range_end:'192.168.21.255',address_count:'512'});
 assert.throws(()=>addressRange('192.168.1.1',33));
});
const name=s=>Buffer.concat([...s.split('.').map(x=>Buffer.concat([Buffer.from([x.length]),Buffer.from(x)])),Buffer.from([0])]);
function packet(type,data,ttl=120){const h=Buffer.alloc(12);h.writeUInt16BE(0x8400,2);h.writeUInt16BE(1,6);const r=Buffer.alloc(10);r.writeUInt16BE(type,0);r.writeUInt16BE(0x8001,2);r.writeUInt32BE(ttl,4);r.writeUInt16BE(data.length,8);return Buffer.concat([h,name('host.local'),r,data]);}
test('DNS parser retains A/AAAA/PTR/SRV and rejects malformed/compression loops',()=>{
 assert.equal(parseMdnsPacket(packet(1,Buffer.from([192,168,20,45])))[0].address,'192.168.20.45');
 const v6=Buffer.alloc(16);v6.writeUInt16BE(0xfd00);v6.writeUInt16BE(9,14);assert.equal(parseMdnsPacket(packet(28,v6))[0].address,'fd00:0:0:0:0:0:0:9');
 assert.equal(parseMdnsPacket(packet(12,name('_http._tcp.local')))[0].target,'_http._tcp.local');
 const srv=Buffer.alloc(6);srv.writeUInt16BE(8080,4);assert.equal(parseMdnsPacket(packet(33,Buffer.concat([srv,name('web.local')])))[0].port,8080);
 assert.throws(()=>parseMdnsPacket(packet(1,Buffer.from([1,2,3,4])).subarray(0,24)));
 const cycle=Buffer.alloc(24);cycle.writeUInt16BE(0x8400,2);cycle.writeUInt16BE(1,6);cycle[12]=0xc0;cycle[13]=12;assert.throws(()=>parseMdnsPacket(cycle),/invalid DNS name/);
 assert.deepEqual(parseMdnsPacket(Buffer.alloc(12)),[]);
});
test('collector reports socket failure and closes transport',async()=>{
 const socket=new EventEmitter();let closed=false;socket.bind=()=>queueMicrotask(()=>socket.emit('error',Error('port unavailable')));socket.close=()=>{closed=true;};
 const r=await collectMdns({address:'192.168.1.20',socketFactory:()=>socket});assert.equal(r.available,false);assert.equal(r.complete,false);assert.match(r.diagnostics,/port unavailable/);assert(closed);
});
test('collector follows PTR/SRV, records A and honors goodbye TTL without real network traffic',async()=>{
 const socket=new EventEmitter();let queries=0;socket.close=()=>{};socket.addMembership=()=>{};socket.setMulticastInterface=()=>{};socket.setMulticastTTL=()=>{};socket.bind=(p,h,cb)=>cb();
 socket.send=(q,p,h,cb)=>{queries++;cb();if(queries===1)queueMicrotask(()=>{
  const peer={port:5353,address:'192.168.1.1'};socket.emit('message',packet(12,name('_http._tcp.local')),peer);
  const srv=Buffer.alloc(6);srv.writeUInt16BE(80,4);socket.emit('message',packet(33,Buffer.concat([srv,name('host.local')])),peer);
  socket.emit('message',packet(1,Buffer.from([192,168,20,45])),peer);
  socket.emit('message',packet(1,Buffer.from([192,168,20,45]),0),peer);
  socket.emit('error',Error('fixture ended'));
 });};
 const r=await collectMdns({address:'192.168.1.20',socketFactory:()=>socket});assert(queries>=4);assert(!r.records.some(r=>r.type==='A'));assert(r.records.some(r=>r.type==='SRV'));
});
test('MCP host integration exposes evidence without scanning advertised targets',async()=>{
 let scanned=false;const api=createNetworkRecon({disableHostDelegation:true,physicalInterfaceExists:()=>true,safeWorkspace:x=>x,requireActive:()=>{},requireCapture:()=>{},assertAuthorizedTarget:()=>{scanned=true;},collectMdns:async()=>({records:[a('192.168.20.45')],available:true,complete:true,status:'observed'}),runStatus:async(cmd,args)=>({code:0,stdout:cmd==='ip'&&args.includes('addr')?JSON.stringify(interfaces):cmd==='ip'&&args.includes('route')?'[{"dst":"default","dev":"wlan0"}]':'[]',stderr:''})});
 const r=await api.call('discover_mdns_subnets',{interface:'wlan0'});assert.equal(r.scope,process.env.SECURITY_NETWORK_SCOPE||'security-container-network');assert.equal(r.candidate_networks[0].cidr,'192.168.20.0/24');assert.equal(r.scan_performed,false);assert.equal(scanned,false);assert(NETWORK_RECON_HOST_TOOL_NAMES.has('discover_mdns_subnets'));
});
