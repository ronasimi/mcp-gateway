import test from 'node:test';
import assert from 'node:assert/strict';
import {EventEmitter} from 'node:events';
import http from 'node:http';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {addressRange,inferMdnsSubnets,parseMdnsPacket,collectMdns,normalizeMdnsRecords} from '../scripts/mdns-subnets.mjs';
import {createNetworkRecon,mdnsReportView,NETWORK_RECON_HOST_TOOL_NAMES} from '../scripts/security-network-recon.mjs';
const interfaces=[{ifname:'wlan0',addr_info:[{family:'inet',local:'192.168.1.20',prefixlen:24},{family:'inet6',local:'fd00:1::20',prefixlen:64}]}];
const a=(address,name='host.local')=>({name,type:address.includes(':')?'AAAA':'A',address,ttl:120});
test('advertised IPv4 /24 is a hypothesis with exact range; known route is not remote subnet proof',()=>{
 const r=inferMdnsSubnets([a('192.168.20.45'),a('192.168.20.46'),a('10.2.3.4')],{interface:'wlan0',interfaces,routes:[{dst:'10.2.0.0/16'}]});
 assert.equal(r.candidate_networks.length,2);const guess=r.candidate_networks[0];assert.equal(guess.cidr,'192.168.20.0/24');assert.equal(guess.range_end,'192.168.20.255');assert.equal(guess.address_count,'256');assert.equal(guess.basis,'heuristic');assert.equal(guess.address_scope,'private');assert.equal(guess.actual_subnet_mask_known,false);assert.equal(guess.scan_automatically,false);assert.equal(guess.observed_addresses.length,2);
 assert.equal(r.candidate_networks[1].basis,'known_route');assert.equal(r.candidate_networks[1].actual_subnet_mask_known,false);assert.equal(r.possible_reflection,true);assert.equal(r.reflector_confirmed,false);
});
test('confirmed local prefixes, longest matching route and link-local exclusion',()=>{
 const r=inferMdnsSubnets([a('192.168.1.45'),a('10.2.3.4'),a('169.254.1.4'),a('fe80::5'),a('8.8.8.8')],{interface:'wlan0',interfaces,routes:[{dst:'10.0.0.0/8'},{dst:'10.2.3.4/32'}]});
 assert.equal(r.candidate_networks[0].actual_subnet_mask_known,true);assert.equal(r.candidate_networks[1].cidr,'10.2.3.4/32');assert.equal(r.candidate_networks.length,2);assert.equal(r.addresses[2].outside_selected_subnets,false);assert.equal(r.addresses[3].range_status,'link_local_or_loopback');assert.equal(r.addresses[4].range_status,'unknown');
});
test('IPv6 candidate boundaries and real /23 range math',()=>{
 const r=inferMdnsSubnets([a('fd00:2::9'),a('fd00:1::5')],{interface:'wlan0',interfaces});
 assert.equal(r.candidate_networks[0].basis,'heuristic');assert.equal(r.candidate_networks[0].address_scope,'unique_local');assert.equal(r.candidate_networks[0].address_count,'18446744073709551616');assert.equal(r.candidate_networks[1].actual_subnet_mask_known,true);
 assert.deepEqual(addressRange('192.168.21.45',23),{cidr:'192.168.20.0/23',family:4,prefix_length:23,range_start:'192.168.20.0',range_end:'192.168.21.255',address_count:'512'});
 assert.throws(()=>addressRange('192.168.1.1',33));
});
const name=s=>Buffer.concat([...s.split('.').map(x=>Buffer.concat([Buffer.from([x.length]),Buffer.from(x)])),Buffer.from([0])]);
function packet(type,data,ttl=120,owner='host.local'){const h=Buffer.alloc(12);h.writeUInt16BE(0x8400,2);h.writeUInt16BE(1,6);const r=Buffer.alloc(10);r.writeUInt16BE(type,0);r.writeUInt16BE(0x8001,2);r.writeUInt32BE(ttl,4);r.writeUInt16BE(data.length,8);return Buffer.concat([h,name(owner),r,data]);}
test('DNS parser retains A/AAAA/PTR/SRV and rejects malformed/compression loops',()=>{
 assert.equal(parseMdnsPacket(packet(1,Buffer.from([192,168,20,45])))[0].address,'192.168.20.45');
 const v6=Buffer.alloc(16);v6.writeUInt16BE(0xfd00);v6.writeUInt16BE(9,14);assert.equal(parseMdnsPacket(packet(28,v6))[0].address,'fd00:0:0:0:0:0:0:9');
 assert.equal(parseMdnsPacket(packet(12,name('_http._tcp.local')))[0].target,'_http._tcp.local');
 const srv=Buffer.alloc(6);srv.writeUInt16BE(8080,4);assert.equal(parseMdnsPacket(packet(33,Buffer.concat([srv,name('web.local')])))[0].port,8080);
 assert.throws(()=>parseMdnsPacket(packet(1,Buffer.from([1,2,3,4])).subarray(0,24)));
 const cycle=Buffer.alloc(24);cycle.writeUInt16BE(0x8400,2);cycle.writeUInt16BE(1,6);cycle[12]=0xc0;cycle[13]=12;assert.throws(()=>parseMdnsPacket(cycle),/invalid DNS name/);
 assert.deepEqual(parseMdnsPacket(Buffer.alloc(12)),[]);
});
test('normalized DNS-SD evidence separates advertised addresses from packet sources and joins SRV targets',()=>{
 const records=[
  {name:'_googlecast._tcp.local',type:'PTR',target:'Living Room._googlecast._tcp.local',ttl:120,source_address:'192.168.1.1'},
  {name:'Living Room._googlecast._tcp.local',type:'SRV',target:'speaker.local',port:8009,ttl:120,source_address:'192.168.1.1'},
  {name:'Living Room._googlecast._tcp.local',type:'TXT',txt:['fn=Living Room','md=Google Nest Mini'],ttl:120,source_address:'192.168.1.1'},
  {name:'speaker.local',type:'A',address:'192.168.20.45',ttl:120,source_address:'192.168.1.1'},
  {name:'speaker.local',type:'AAAA',address:'fd00:2::45',ttl:120,source_address:'192.168.1.1'},
 ];
 const r=normalizeMdnsRecords(records);assert.equal(r.services.length,1);assert.equal(r.services[0].target_hostname,'speaker.local');assert.equal(r.services[0].port,8009);assert.deepEqual(r.services[0].service_types,['_googlecast._tcp.local']);assert.deepEqual(r.services[0].advertised_addresses.map(x=>x.address),['192.168.20.45','fd00:2::45']);assert.deepEqual(r.services[0].packet_source_addresses,['192.168.1.1']);
 assert.equal(r.advertised_hosts[0].hostname,'speaker.local');assert.deepEqual(r.advertised_hosts[0].advertised_addresses.map(x=>x.address),['192.168.20.45','fd00:2::45']);assert.deepEqual(r.advertised_hosts[0].packet_source_addresses,['192.168.1.1']);assert.notEqual(r.advertised_hosts[0].advertised_addresses[0].address,r.advertised_hosts[0].packet_source_addresses[0]);
 assert.equal(r.report_hosts.length,1);assert.equal(r.report_hosts[0].hostname,'speaker.local');assert.deepEqual(r.report_hosts[0].ipv4_addresses,['192.168.20.45']);assert.deepEqual(r.report_hosts[0].ipv6_addresses,['fd00:2::45']);assert.deepEqual(r.report_hosts[0].advertised_addresses.map(x=>x.scope),['private','unique_local']);assert.equal(r.report_hosts[0].services[0].port,8009);assert.equal(r.report_hosts[0].services[0].friendly_name,'Living Room');assert.equal(r.report_hosts[0].services[0].model,'Google Nest Mini');
});

test('compact mDNS report excludes raw audit records and stays below the MCP response budget for a service-rich LAN',()=>{
 const host=(i)=>({hostname:`host-${i}.local`,ipv4_addresses:[`192.168.20.${100+i}`],ipv6_addresses:i%2?[`fd00:20::${i}`]:[],advertised_addresses:[{address:`192.168.20.${100+i}`,family:4,type:'A',ttl:120,scope:'private'}],packet_source_addresses:['192.168.1.1'],services:[{instance:`Device ${i}._googlecast._tcp.local`,service_types:['_googlecast._tcp.local'],port:8009,model:'Google Nest Mini',friendly_name:`Room ${i}`},{instance:`Device ${i}._googlezone._tcp.local`,service_types:['_googlezone._tcp.local'],port:10001,model:null,friendly_name:null}]});
 const raw=Array.from({length:200},(_,i)=>({name:`raw-${i}.local`,type:'TXT',txt:['x='.padEnd(100,'x')],source_address:'192.168.1.1'}));
 const evidence=Array.from({length:5},(_,i)=>({address:`192.168.20.${100+i}`,hostname:`host-${i}.local`,reason:'Advertised address is outside known selected-interface subnets; multihoming or stale advertisements are alternative explanations.'}));
 const view=mdnsReportView({scope:'host-network',selected_interface:'wlan0',status:'observed',available:true,complete:true,coverage:'complete',coverage_limitations:[],evidence_available:true,report_host_count:8,report_hosts:Array.from({length:8},(_,i)=>host(i)),report_candidate_networks:[{cidr:'192.168.20.0/24',family:4,prefix_length:24,range_start:'192.168.20.0',range_end:'192.168.20.255',address_count:'256',basis:'heuristic',address_scope:'private',actual_subnet_mask_known:false,scan_automatically:false,observed_addresses:evidence.map(x=>x.address),hostnames:evidence.map(x=>x.hostname),note:'Grouping hypothesis only. mDNS does not advertise a subnet mask.'}],evidence,possible_reflection:true,reflector_confirmed:false,reflection_status:'possible',subnet_masks_advertised:false,scan_performed:false,queries_sent:65,query_limit:96,query_limit_reached:false,queries_suppressed_by_limit:0,raw_records:raw,records:raw,raw_audit_evidence_saved:true});
 assert.equal(view.raw_records_returned,false);assert.equal(view.raw_audit_evidence_saved,true);assert.equal('raw_records' in view,false);assert.equal('records' in view,false);assert.equal(view.report_hosts.length,8);assert.deepEqual(Object.keys(view.report_hosts[0]).sort(),['hostname','ipv4_addresses','ipv6_addresses']);assert.equal(view.report_candidate_networks[0].observed_host_count,5);assert.equal(view.report_candidate_networks[0].observed_address_count,5);assert.equal(view.outside_subnet_advertisements.length,5);assert.deepEqual(Object.keys(view.outside_subnet_advertisements[0]).sort(),['address','hostname']);assert.match(view.outside_subnet_reason,/outside selected-interface subnets/i);assert.equal(view.reporting_contract.expected_host_rows,8);assert.equal(view.reporting_contract.copy_host_table_markdown_verbatim,true);assert.equal(view.reporting_contract.copy_candidate_table_markdown_verbatim,true);assert.match(view.host_table_markdown,/host-7\.local/);assert.match(view.candidate_table_markdown,/192\.168\.20\.0\/24/);assert.equal(view.reporting_contract.do_not_abbreviate_ipv6,true);assert.equal(view.reporting_contract.preserve_address_count_strings,true);assert(Buffer.byteLength(JSON.stringify(view))<8000);
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
 const r=await collectMdns({address:'192.168.1.20',socketFactory:()=>socket});assert(queries>=4);assert(!r.records.some(r=>r.type==='A'));assert(r.records.some(r=>r.type==='SRV'));assert.deepEqual(r.raw_records,r.records);
});
test('collector exposes query suppression and marks coverage partial when follow-up cap is reached',async()=>{
 const socket=new EventEmitter();let sends=0;socket.close=()=>{};socket.addMembership=()=>{};socket.setMulticastInterface=()=>{};socket.setMulticastTTL=()=>{};socket.bind=(p,h,cb)=>cb();
 socket.send=(q,p,h,cb)=>{sends++;cb();if(sends===1)queueMicrotask(()=>{const peer={port:5353,address:'192.168.1.1'};for(let i=0;i<40;i++)socket.emit('message',packet(12,name(`svc${i}._http._tcp.local`),120,'_http._tcp.local'),peer);});};
 const r=await collectMdns({address:'192.168.1.20',durationSeconds:.02,maxQueries:64,socketFactory:()=>socket});assert.equal(r.query_limit,64);assert.equal(r.query_limit_reached,true);assert(r.queries_suppressed_by_limit>0);assert.equal(r.queries_sent,64);assert.equal(r.coverage,'partial');assert(r.coverage_limitations.includes('query_limit_reached'));assert.equal(r.limited,true);assert.equal(r.complete,false);assert.deepEqual(r.raw_records,r.records);
});
test('MCP host integration exposes evidence without scanning advertised targets',async()=>{
 let scanned=false,collectOptions=null;const api=createNetworkRecon({disableHostDelegation:true,physicalInterfaceExists:()=>true,safeWorkspace:x=>x,requireActive:()=>{},requireCapture:()=>{},assertAuthorizedTarget:()=>{scanned=true;},collectMdns:async(options)=>{collectOptions=options;return{records:[a('192.168.20.45')],available:true,complete:true,status:'observed'};},runStatus:async(cmd,args)=>({code:0,stdout:cmd==='ip'&&args.includes('addr')?JSON.stringify(interfaces):cmd==='ip'&&args.includes('route')?'[{"dst":"default","dev":"wlan0"}]':'[]',stderr:''})});
 const r=await api.call('discover_mdns_subnets',{interface:'wlan0'});assert.equal(r.scope,process.env.SECURITY_NETWORK_SCOPE||'security-container-network');assert.equal(r.candidate_networks[0].cidr,'192.168.20.0/24');assert.deepEqual(r.raw_records,r.records);assert.equal(r.advertised_hosts[0].advertised_addresses[0].address,'192.168.20.45');assert.equal(r.report_hosts[0].hostname,'host.local');assert.equal(r.report_candidate_networks[0].address_scope,'private');assert.equal(r.reporting_contract.never_move_addresses_between_hosts,true);assert(JSON.stringify(r).indexOf('\"report_hosts\"')<JSON.stringify(r).indexOf('\"records\"'));assert.equal(r.scan_performed,false);assert.equal(collectOptions.maxQueries,96);assert.equal(scanned,false);assert(NETWORK_RECON_HOST_TOOL_NAMES.has('discover_mdns_subnets'));
});
test('delegated mDNS call returns compact report while saving full raw observation and compact report artifact',async()=>{
 const tmp=await fs.mkdtemp(path.join(os.tmpdir(),'mdns-report-'));const socket=path.join(tmp,'helper.sock');
 const raw=Array.from({length:120},(_,i)=>({name:`raw-${i}.local`,type:'TXT',txt:['x='.padEnd(120,'x')],ttl:120,source_address:'192.168.1.1'}));
 const delegated={scope:'host-network',selected_interface:'wlan0',status:'observed',available:true,complete:true,coverage:'complete',coverage_limitations:[],evidence_available:true,report_host_count:1,report_hosts:[{hostname:'host.local',ipv4_addresses:['192.168.20.45'],ipv6_addresses:[],advertised_addresses:[{address:'192.168.20.45',family:4,type:'A',ttl:120,scope:'private'}],packet_source_addresses:['192.168.1.1'],services:[]}],report_candidate_networks:[{cidr:'192.168.20.0/24',family:4,prefix_length:24,range_start:'192.168.20.0',range_end:'192.168.20.255',address_count:'256',basis:'heuristic',address_scope:'private'}],advertised_hosts:[],services:[],addresses:[],candidate_networks:[],possible_reflection:true,reflector_confirmed:false,evidence:[{address:'192.168.20.45',hostname:'host.local',reason:'outside selected subnet'}],reflection_status:'possible',subnet_masks_advertised:false,scan_performed:false,reporting_contract:{host_rows_source:'report_hosts'},authorization_note:'authorized',evidence_note:'evidence',reporting_note:'report',queries_sent:20,query_limit:96,query_limit_reached:false,queries_suppressed_by_limit:0,records:raw,raw_records:raw};
 const server=http.createServer((req,res)=>{let body='';req.setEncoding('utf8');req.on('data',c=>body+=c);req.on('end',()=>{res.setHeader('content-type','application/json');res.end(JSON.stringify({result:delegated}));});});
 const old=process.env.SECURITY_HOST_RECON_SOCKET;process.env.SECURITY_HOST_RECON_SOCKET=socket;
 await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(socket,resolve);});
 try{
  const api=createNetworkRecon({safeWorkspace:(rel='.')=>path.resolve(tmp,rel),assertAuthorizedTarget:async x=>x,requireActive:()=>{},requireCapture:()=>{},runStatus:async()=>({code:0,stdout:'',stderr:''})});
  const r=await api.call('discover_mdns_subnets',{interface:'wlan0'});
  assert.equal(r.report_hosts[0].hostname,'host.local');assert.equal(r.raw_records_returned,false);assert.equal(r.raw_audit_evidence_saved,true);assert.equal('raw_records' in r,false);assert.equal('records' in r,false);assert.match(r.report_path,/discover_mdns_subnets-report\.json$/);assert.match(r.read_hint,/read report_path/i);assert(Buffer.byteLength(JSON.stringify(r))<10000);
  const full=JSON.parse(await fs.readFile(path.join(tmp,r.observation_path),'utf8'));assert.equal(full.discover_mdns_subnets.raw_records.length,120);
  const report=JSON.parse(await fs.readFile(path.join(tmp,r.report_path),'utf8'));assert.equal(report.discover_mdns_subnets_report.report_hosts[0].hostname,'host.local');assert.equal('raw_records' in report.discover_mdns_subnets_report,false);
 }finally{await new Promise(resolve=>server.close(resolve));if(old===undefined)delete process.env.SECURITY_HOST_RECON_SOCKET;else process.env.SECURITY_HOST_RECON_SOCKET=old;await fs.rm(tmp,{recursive:true,force:true});}
});

test('unavailable collection marks empty evidence as unavailable rather than absent',async()=>{
 const api=createNetworkRecon({disableHostDelegation:true,physicalInterfaceExists:()=>true,safeWorkspace:x=>x,assertAuthorizedTarget:()=>{},requireActive:()=>{},requireCapture:()=>{},collectMdns:async()=>({records:[],raw_records:[],available:false,complete:false,status:'unavailable',diagnostics:'Selected physical interface requires an IPv4 address for this mDNS transport.'}),runStatus:async(cmd,args)=>({code:0,stdout:cmd==='ip'&&args.includes('addr')?JSON.stringify(interfaces):cmd==='ip'&&args.includes('route')?'[{"dst":"default","dev":"wlan0"}]':'[]',stderr:''})});
 const r=await api.call('discover_mdns_subnets',{interface:'wlan0'});
 assert.equal(r.status,'unavailable');assert.equal(r.coverage,'unavailable');assert.equal(r.evidence_available,false);assert.equal(r.advertised_hosts_status,'unavailable');assert.equal(r.services_status,'unavailable');assert.equal(r.candidate_networks_status,'unavailable');assert.equal(r.reflection_status,'unavailable');assert.equal(r.possible_reflection,null);assert.match(r.reporting_note,/do not convert empty arrays/i);assert(r.coverage_limitations.some(x=>/requires an IPv4 address/.test(x)));assert.deepEqual(r.advertised_hosts,[]);assert.deepEqual(r.candidate_networks,[]);
});
