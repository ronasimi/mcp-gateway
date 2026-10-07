import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';
import { fileURLToPath } from 'node:url';
import { runStatus, confinedPath, validateArguments, JobManager } from '../scripts/security-runtime.mjs';
import { createExtendedSecurity, EXTENDED_TOOLS } from '../scripts/security-extended.mjs';
import { createProtocolSecurity, PROTOCOL_TOOLS } from '../scripts/security-protocols.mjs';
import { createNetworkRecon, NETWORK_RECON_TOOLS, NETWORK_RECON_HOST_TOOL_NAMES } from '../scripts/security-network-recon.mjs';

const root = fileURLToPath(new URL('../', import.meta.url));
const wait = ms => new Promise(resolve => setTimeout(resolve, ms));
const ok = stdout => ({ code: 0, stdout, stderr: '' });

function protocolFixture(run, { capture=true }={}) {
  const calls=[];
  const api=createProtocolSecurity({
    runStatus: async (command,args,options) => { calls.push({command,args,options}); return run(command,args,options); },
    assertAuthorizedTarget: async (target,options={}) => {
      if (target === '127.0.0.1' || (options.allowCidr && target === '127.0.0.0/8')) return target;
      throw new Error('unauthorized target');
    },
    requireActive: () => {},
    requireCapture: () => { if(!capture) throw new Error('packet capture disabled'); },
  });
  return {...api,calls};
}

function networkReconFixture(run, { capture=true, physicalInterfaceExists=()=>true, collectMdns=async()=>({records:[],available:false,complete:false,status:"unavailable"}) }={}) {
  const calls=[];
  return fs.mkdtemp(path.join(os.tmpdir(),'network-recon-')).then(workspace=>{
    const api=createNetworkRecon({collectMdns,
      runStatus: async (command,args,options) => { calls.push({command,args,options}); return run(command,args,options,workspace); },
      safeWorkspace: (p,options) => confinedPath(workspace,p,options),
      assertAuthorizedTarget: async (target,options={}) => {
        if (target === '127.0.0.1' || target === '127.0.0.2' || (options.allowCidr && ['127.0.0.0/24','127.0.0.0/8'].includes(target))) return target;
        throw new Error('unauthorized target');
      },
      requireActive: () => {},
      requireCapture: () => { if(!capture) throw new Error('packet capture disabled'); },
      hostRoot: path.join(workspace,'host'),
      physicalInterfaceExists, disableHostDelegation:true,
    });
    return {...api,calls,workspace,cleanup:()=>fs.rm(workspace,{recursive:true,force:true})};
  });
}

async function fixture(fn, run = runStatus) {
  const workspace = await fs.mkdtemp(path.join(os.tmpdir(), 'security-test-'));
  const calls = [];
  const ctx = {
    safeWorkspace: (p, options) => confinedPath(workspace, p, options),
    assertAuthorizedTarget: async target => { if (!['127.0.0.1','::1'].includes(target)) throw new Error('unauthorized target'); return target; },
    assertAuthorizedUrl: async url => { if (new URL(url).hostname !== '127.0.0.1') throw new Error('unauthorized URL'); return url; },
    runStatus: async (command, args, options) => { calls.push({ command, args, options }); return run(command,args,options); },
  };
  const ext = createExtendedSecurity(ctx);
  try { await fn({ ...ext, workspace, calls }); }
  finally { ext.jobs.stopAll(); await fs.rm(workspace, { recursive: true, force: true }); }
}

test('real jq streams JSONL, filters matching records and signals a row limit', async () => {
  await fixture(async ({ call, workspace }) => {
    await fs.writeFile(path.join(workspace,'events.jsonl'), '{"status":200,"url":"a"}\n{"status":403,"url":"b"}\n{"status":200,"url":"c"}\n');
    const r = await call('jq', { path:'events.jsonl', filter:'select(.status == 200) | {url}', limit:1 });
    assert.deepEqual(r.records,[{url:'a'}]); assert.equal(r.truncated,true);
    await assert.rejects(call('jq',{ path:'events.jsonl', filter:'bad syntax !' }), /jq failed/);
  });
});
test('workspace symlinks cannot escape for reads or new outputs', async () => {
  await fixture(async ({ workspace }) => {
    await fs.symlink('/etc',path.join(workspace,'escape'));
    assert.throws(() => confinedPath(workspace,'escape/passwd',{mustExist:true}),/symlink/);
    assert.throws(() => confinedPath(workspace,'escape/new-file'),/symlink/);
    assert.throws(() => confinedPath(workspace,'../outside'),/escapes/);
  });
});
test('strict schemas reject unknown arguments, invalid enums, fractional ports and missing inputs', () => {
  const schema = EXTENDED_TOOLS.find(t => t.name === 'listener_start').inputSchema;
  for (const args of [{}, {port:4444,engine:'bash'}, {port:4444.5}, {port:22}, {port:4444,command:'x'}]) assert.throws(() => validateArguments(schema,args));
  validateArguments(schema,{port:4444,engine:'socat'});
});
test('deadlines and output limits return partial status and terminate commands', async () => {
  const timed = await runStatus(process.execPath,['-e', 'process.stdout.write("started");setInterval(()=>{},1000)'],{timeout:150});
  assert.equal(timed.code,124); assert.equal(timed.timed_out,true); assert.equal(timed.stdout,'started');
  const limited = await runStatus(process.execPath,['-e','process.stdout.write("x".repeat(100000));setInterval(()=>{},1000)'],{timeout:2000,maxBuffer:1024});
  assert.equal(limited.code,125); assert.ok(Buffer.byteLength(limited.stdout)<=1024);
});
test('background jobs allow input, bounded paginated output, cancellation and capacity enforcement', async () => {
  const jobs = new JobManager({maxJobs:1,maxBytes:2048});
  try {
    const job = await jobs.start(process.execPath,['-e','process.stdin.on("data",b=>process.stdout.write(b));setInterval(()=>{},1000)'],{interactive:true,timeout:2000});
    await assert.rejects(jobs.start(process.execPath,['-e','0']),/limit/);
    jobs.send(job.job_id,'hello\n');
    for(let i=0;i<30&&!jobs.status(job.job_id).output;i++) await wait(20);
    const status=jobs.status(job.job_id,0,3); assert.equal(status.output,'hel'); assert.equal(status.next_offset,3); assert.equal(status.has_more,true);
    assert.equal(jobs.status(job.job_id,3).output,'lo\n');
    assert.equal(jobs.stop(job.job_id).status,'stopped');
    assert.throws(()=>jobs.send(job.job_id,'x'),/writable/);
  } finally { jobs.stopAll(); }
});
test('sqlmap uses batch mode, target policy, timeout, and separate argv values', async () => {
  await fixture(async ({call,calls}) => {
    const result=await call('sqlmap',{url:'http://127.0.0.1/?id=1',data:'x=$(not-a-shell)',action:'enumerate_databases'});
    assert.equal(result.complete,true);
    assert.ok(calls[0].args.includes('--batch')); assert.ok(calls[0].args.includes('--ignore-redirects')); assert.ok(calls[0].args.includes('--dbs'));
    assert.ok(calls[0].args.includes('--data=x=$(not-a-shell)'));
    await assert.rejects(call('sqlmap',{url:'https://example.com/?id=1'}),/unauthorized/);
  },async()=>ok('assessment completed'));
});
test('Metasploit module info uses a generated resource file; rejects console injection and target overrides', async () => {
  let resource='';
  await fixture(async ({call}) => {
    await call('metasploit_info',{module:'auxiliary/scanner/http/http_version'});
    assert.match(resource,/use auxiliary\/scanner\/http\/http_version\ninfo\nshow options\nexit -y/);
    await assert.rejects(call('metasploit_info',{module:'exploit/x; shell evil'}),/invalid/);
    await assert.rejects(call('metasploit_run',{module:'exploit/test',target:'127.0.0.1',options:{RHOSTS:'elsewhere'}}),/reserved/);
    await assert.rejects(call('metasploit_run',{module:'exploit/test',target:'127.0.0.1',options:{TARGETURI:'/; shell evil'}}),/unsupported/);
  },async(cmd,args)=>{resource=await fs.readFile(args[2],'utf8');return ok('module info');});
});
test('osquery constrains a read-only query and reports its actual namespace', async () => {
  await fixture(async({call,calls})=>{
    const r=await call('osquery',{query:'SELECT * FROM listening_ports;',limit:1});
    assert.equal(r.truncated,true); assert.match(r.visibility,/container/);
    assert.ok(calls[0].args.includes('--disable_extensions')); assert.match(calls[0].args.at(-1),/LIMIT 2/);
    await assert.rejects(call('osquery',{query:'SELECT 1; DELETE FROM x;'}),/read-only/);
  },async()=>ok('[{"port":"22"},{"port":"80"}]'));
});
test('Radare2 operations cannot inject arbitrary commands', async () => {
  await fixture(async({call,workspace,calls})=>{
    await fs.writeFile(path.join(workspace,'sample.bin'),'sample');
    const r=await call('binary_analyze',{path:'sample.bin',operation:'disassemble',address:'0x1000',count:8});
    assert.deepEqual(r.result,[]); assert.ok(calls[0].args.includes('e cfg.sandbox=true;pdj 8 @ 0x1000')); assert.ok(!calls[0].args.includes('-w'));
    await assert.rejects(call('binary_analyze',{path:'sample.bin',address:'0;!sh'}),/address/);
  },async()=>ok('[]'));
});
test('Tshark extracts selected fields and marks the packet examination limit', async () => {
  await fixture(async({call,workspace,calls})=>{
    await fs.writeFile(path.join(workspace,'sample.pcap'),'fixture');
    const r=await call('pcap_analyze',{view:'fields',path:'sample.pcap',fields:['ip.src','ip.dst'],display_filter:'tcp',packet_limit:10});
    assert.deepEqual(r.rows,[{'ip.src':'127.0.0.1','ip.dst':'127.0.0.2'}]); assert.equal(r.exhaustive,false);
    assert.ok(calls[0].args.includes('-T')); assert.ok(calls[0].args.includes('-Y'));
  },async()=>ok('127.0.0.1\t127.0.0.2\n'));
});
test('Suricata custom-rule validation and PCAP hit rate use the supplied rules', async () => {
  await fixture(async({call,workspace})=>{
    await fs.writeFile(path.join(workspace,'custom.rules'),'alert ip any any -> any any (sid:1;)');
    await fs.writeFile(path.join(workspace,'sample.pcap'),'fixture');
    const r=await call('suricata_test_rules',{rules:'custom.rules',pcap:'sample.pcap'});
    assert.equal(r.valid,true); assert.equal(r.alert_count,2); assert.equal(r.matched_packets,1); assert.equal(r.packet_hit_rate,0.5);
  },async(cmd,args)=>{
    assert.ok(args.includes('-S'));
    if(args.includes('-r')) await fs.writeFile(path.join(args[args.indexOf('-l')+1],'eve.json'),[
      {event_type:'alert',pcap_cnt:1,alert:{signature_id:1,signature:'one'}},
      {event_type:'alert',pcap_cnt:1,alert:{signature_id:2,signature:'two'}},
      {event_type:'stats',stats:{decoder:{pkts:2}}},
    ].map(JSON.stringify).join('\n'));
    return ok('');
  });
});
test('Subfinder filters out-of-domain records; invalid JSON never becomes a clean empty result', async () => {
  await fixture(async({call,calls})=>{
    const r=await call('subdomain_enum',{domain:'example.com'});
    assert.deepEqual(r.subdomains,['a.example.com']); assert.equal(r.complete,false); assert.ok(calls[0].args.includes('-json'));
    assert.ok(!calls[0].args.includes('-active'));
  },async()=>ok('{"host":"a.example.com"}\n{"host":"badexample.com"}\ninvalid\n'));
});
test('Firecrawl uses Markdown/JSON modes; credentials are never tool arguments', async () => {
  const old=process.env.FIRECRAWL_API_URL; process.env.FIRECRAWL_API_URL='http://127.0.0.1:3002';
  try {
    await fixture(async({call,calls})=>{
      const scrape=await call('firecrawl_scrape',{url:'https://example.com'}); assert.equal(scrape.markdown,'# Page');
      const map=await call('firecrawl_map',{url:'https://example.com',limit:2}); assert.equal(map.links.length,1);
      assert.ok(calls[0].args.includes('markdown')); assert.ok(calls[1].args.includes('--json'));
      assert.ok(calls.every(c=>!c.args.includes('--api-key')));
    },async(cmd,args)=>ok(args[0]==='scrape'?'# Page':'{"links":["https://example.com/a"]}'));
  } finally { if(old===undefined) delete process.env.FIRECRAWL_API_URL; else process.env.FIRECRAWL_API_URL=old; }
});


test('protocol schemas are strict and keep dangerous behavior out of the model-facing API', () => {
  const dns = PROTOCOL_TOOLS.find(t=>t.name==='dns_audit').inputSchema;
  const lldp = PROTOCOL_TOOLS.find(t=>t.name==='protocol_observe').inputSchema;
  assert.throws(()=>validateArguments(dns,{server:'127.0.0.1',domain:'example.com',command:'dig any'}));
  assert.throws(()=>validateArguments(lldp,{protocol:'lldp',interface:'eth0',duration_seconds:31}));
  validateArguments(dns,{server:'127.0.0.1',domain:'example.com',check_axfr:false});
});

test('protocol discovery uses bounded targeted NSE scripts and parses script output', async () => {
  const xml='<?xml version="1.0"?><nmaprun><host><ports><port><script id="dns-service-discovery" output="80/tcp http&#xa;Address: 127.0.0.1&#xa;Machine Name: fixture"/></port></ports></host></nmaprun>';
  const api=protocolFixture(async()=>ok(xml));
  const r=await api.call('mdns_discover',{target:'127.0.0.1',timeout_seconds:7});
  assert.equal(r.scope,'target-scan'); assert.equal(r.mode,'target');
  assert.equal(r.scripts[0].id,'dns-service-discovery'); assert.equal(r.scripts[0].fields.address,'127.0.0.1');
  assert.ok(api.calls[0].args.includes('-sU')); assert.ok(api.calls[0].args.includes('5353')); assert.ok(api.calls[0].args.includes('dns-service-discovery'));
  assert.ok(!api.calls[0].args.some(x=>/[;&|`$<>]/.test(x)));
});

test('broadcast protocol discovery is explicitly container scoped', async () => {
  const xml='<?xml version="1.0"?><nmaprun><prescript><script id="broadcast-dhcp-discover" output="Server Identifier: 172.20.0.1"/></prescript></nmaprun>';
  const api=protocolFixture(async()=>ok(xml));
  const r=await api.call('dhcp_discover',{interface:'eth0'});
  assert.equal(r.scope,'security-container-network'); assert.match(r.warning,/Docker bridge/i);
  assert.equal(r.scripts[0].fields.server_identifier,'172.20.0.1');
  assert.ok(api.calls[0].args.includes('broadcast-dhcp-discover')); assert.ok(api.calls[0].args.includes('-e')); assert.ok(api.calls[0].args.includes('eth0'));
});

test('DNS audit keeps target authorization, makes AXFR explicit, and reports recursion/DNSSEC evidence', async () => {
  const api=protocolFixture(async(cmd,args)=>{
    assert.equal(cmd,'dig'); assert.ok(args[0].startsWith('@127.0.0.1'));
    if(args.includes('AXFR')) return ok('example.com. 3600 IN SOA ns.example.com. hostmaster.example.com. 1 1 1 1 1\nexample.com. 3600 IN SOA ns.example.com. hostmaster.example.com. 1 1 1 1 1\n');
    if(args.includes('version.bind')) return ok('"BIND 9"\n');
    if(args.includes('id.server')) return ok(';; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1\n;; flags: qr ra; QUERY: 1, ANSWER: 0\n');
    if(args.includes('+dnssec')) return ok(';; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1\n;; flags: qr rd ra ad; QUERY: 1, ANSWER: 1\nexample.com. 300 IN RRSIG A 13 2 300 0 0 0 example.com. sig\n');
    return ok(';; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1\n;; flags: qr rd ra; QUERY: 1, ANSWER: 1\nexample.com. 300 IN A 127.0.0.1\n');
  });
  const r=await api.call('dns_audit',{server:'127.0.0.1',domain:'example.com',check_axfr:true});
  assert.equal(r.response.recursion_available,true); assert.equal(r.dnssec.authenticated_data,true); assert.equal(r.dnssec.rrsig_present,true); assert.equal(r.axfr.succeeded,true);
  assert.equal(api.calls.length,5);
});

test('passive L2/name-resolution observation respects the packet-capture gate and never starts a responder', async () => {
  const blocked=protocolFixture(async()=>ok('[]'),{capture:false});
  await assert.rejects(blocked.call('protocol_observe',{protocol:'llmnr_nbns',interface:'eth0'}),/packet capture disabled/);
  const packet=[{_source:{layers:{frame:{'frame.time_epoch':'1.0'},eth:{'eth.src':'00:11:22:33:44:55'},ip:{'ip.src':'127.0.0.1'},llmnr:{'llmnr.id':'1'}}}}];
  const api=protocolFixture(async()=>ok(JSON.stringify(packet)));
  const r=await api.call('protocol_observe',{protocol:'llmnr_nbns',interface:'eth0',duration_seconds:1,max_packets:2});
  assert.equal(r.mode,'passive-only'); assert.equal(r.packet_count,1); assert.equal(r.packets[0].source_mac,'00:11:22:33:44:55');
  assert.equal(api.calls[0].command,'tshark'); assert.ok(api.calls[0].args.includes('llmnr || nbns')); assert.ok(!api.calls[0].args.some(x=>/responder/i.test(x)));
});

test('ARP and NDP tools preserve network-namespace scope and parse compact neighbor results', async () => {
  const api=protocolFixture(async(cmd,args)=>{
    if(cmd==='nmap') return ok('Host: 127.0.0.1 ()\tStatus: Up\tMAC: 00:11:22:33:44:55 (Fixture)\n');
    if(cmd==='ip') return ok('fe80::1 dev eth0 lladdr 00:11:22:33:44:55 REACHABLE\n');
    throw new Error('unexpected command');
  });
  const arp=await api.call('arp_discover',{target:'127.0.0.0/8'}); assert.equal(arp.count,1); assert.equal(arp.hosts[0].mac,'00:11:22:33:44:55');
  const ndp=await api.call('ndp_discover',{interface:'eth0'}); assert.equal(ndp.count,1); assert.equal(ndp.neighbors[0].address,'fe80::1'); assert.equal(ndp.scope,'security-container-network');
});

test('high-level network recon schemas are strict and bounded', () => {
  const discover=NETWORK_RECON_TOOLS.find(t=>t.name==='perform_network_discovery').inputSchema;
  const wireless=NETWORK_RECON_TOOLS.find(t=>t.name==='analyze_wireless_environment').inputSchema;
  validateArguments(discover,{cidrs:['127.0.0.0/24'],max_hosts:16,port_profile:'standard'});
  assert.throws(()=>validateArguments(discover,{cidrs:['a','b','c','d','e']}));
  assert.throws(()=>validateArguments(discover,{port_profile:'unbounded'}));
  assert.throws(()=>validateArguments(wireless,{duration_seconds:31}));
  assert.throws(()=>validateArguments(wireless,{interface:'wlan0',command:'airmon-ng start wlan0'}));
});

test('host interface inventory identifies Wi-Fi/default gateway without shell execution', async () => {
  const api=await networkReconFixture(async(cmd,args)=>{
    if(cmd==='ip'&&args[0]==='-j'&&args[1]==='addr') return ok(JSON.stringify([{ifname:'wlan0',operstate:'UP',link_type:'ether',address:'00:11:22:33:44:55',mtu:1500,addr_info:[{family:'inet',local:'127.0.0.2',prefixlen:24,scope:'global'},{family:'inet6',local:'fe80::1',prefixlen:64,scope:'link'}]}]));
    if(cmd==='ip'&&args[0]==='-j'&&args[1]==='route') return ok(JSON.stringify([{dst:'default',gateway:'127.0.0.1',dev:'wlan0',metric:600},{dst:'127.0.0.0/24',dev:'wlan0',scope:'link',protocol:'kernel'}]));
    if(cmd==='ip'&&args[0]==='-d') return ok('[]');
    if(cmd==='iw'&&args.length===1) return ok('phy#0\n\tInterface wlan0\n\t\ttype managed\n');
    if(cmd==='iw'&&args.includes('link')) return ok('Connected to aa:bb:cc:dd:ee:ff (on wlan0)\n\tSSID: FixtureWiFi\n\tfreq: 5180\n\tsignal: -45 dBm\n\ttx bitrate: 866.7 MBit/s VHT-MCS 9\n');
    if(cmd==='ping') return ok('1 packets transmitted, 1 received');
    if(cmd==='getent') return ok('93.184.216.34 STREAM example.com\n');
    return {code:1,stdout:'',stderr:'fixture unavailable'};
  });
  try {
    const r=await api.call('get_host_interface_info',{});
    assert.equal(r.selected_interface,'wlan0'); assert.equal(r.connection_type,'wifi'); assert.equal(r.default_routes[0].gateway,'127.0.0.1'); assert.equal(r.internet.status,'online'); assert.equal(r.interfaces[0].link.phy,'802.11ac');
    assert.ok(api.calls.every(c=>!['sh','bash'].includes(c.command)));
  } finally { await api.cleanup(); }
});

test('high-level recon filters virtual interfaces and routes from physical-network selection', async () => {
  const api=await networkReconFixture(async(cmd,args)=>{
    if(cmd==='ip'&&args[0]==='-j'&&args[1]==='addr') return ok(JSON.stringify([
      {ifname:'wlan0',operstate:'UP',link_type:'ether',address:'00:11:22:33:44:55',mtu:1500,addr_info:[{family:'inet',local:'192.168.1.10',prefixlen:24,scope:'global'}]},
      {ifname:'docker0',operstate:'UP',link_type:'ether',address:'02:42:aa:bb:cc:dd',mtu:1500,addr_info:[{family:'inet',local:'172.17.0.1',prefixlen:16,scope:'global'}]},
      {ifname:'br-deadbeef',operstate:'UP',link_type:'ether',address:'02:42:11:22:33:44',mtu:1500,addr_info:[{family:'inet',local:'172.19.0.1',prefixlen:16,scope:'global'}]},
      {ifname:'veth1234',operstate:'UP',link_type:'ether',address:'02:42:55:66:77:88',mtu:1500,addr_info:[]}
    ]));
    if(cmd==='ip'&&args[0]==='-j'&&args[1]==='route') return ok(JSON.stringify([
      {dst:'default',gateway:'192.168.1.1',dev:'wlan0',metric:600},
      {dst:'192.168.1.0/24',dev:'wlan0',scope:'link',protocol:'kernel'},
      {dst:'172.17.0.0/16',dev:'docker0',scope:'link',protocol:'kernel'},
      {dst:'172.19.0.0/16',dev:'br-deadbeef',scope:'link',protocol:'kernel'}
    ]));
    if(cmd==='ip'&&args[0]==='-d') return ok(JSON.stringify([
      {ifname:'wlan0',operstate:'UP',link_type:'ether'},
      {ifname:'docker0',operstate:'UP',link_type:'ether',linkinfo:{info_kind:'bridge'}},
      {ifname:'br-deadbeef',operstate:'UP',link_type:'ether',linkinfo:{info_kind:'bridge'}},
      {ifname:'veth1234',operstate:'UP',link_type:'ether',linkinfo:{info_kind:'veth'}}
    ]));
    if(cmd==='iw'&&args.length===1) return ok('phy#0\n\tInterface wlan0\n\t\ttype managed\n');
    if(cmd==='iw'&&args.includes('link')) return ok('Connected to aa:bb:cc:dd:ee:ff (on wlan0)\n\tSSID: FixtureWiFi\n\tfreq: 5180\n\tsignal: -45 dBm\n');
    return {code:1,stdout:'',stderr:'fixture unavailable'};
  });
  try {
    const r=await api.call('get_host_interface_info',{internet_check:false});
    assert.equal(r.physical_interfaces_only,true);
    assert.deepEqual(r.interfaces.map(x=>x.name),['wlan0']);
    assert.deepEqual(r.default_routes.map(x=>x.interface),['wlan0']);
    assert.deepEqual(r.ignored_virtual_interfaces.map(x=>x.name).sort(),['br-deadbeef','docker0','veth1234']);
    assert.ok(api.calls.every(c=>!(c.command==='ethtool'&&['docker0','br-deadbeef','veth1234'].includes(c.args[0]))));
    await assert.rejects(api.call('get_host_interface_info',{interface:'docker0',internet_check:false}),/Available physical interfaces: wlan0.*Retry get_host_interface_info/);
  } finally { await api.cleanup(); }
});



test('physical interface selection requires sysfs device backing for non-Wi-Fi links', async () => {
  const api=await networkReconFixture(async(cmd,args)=>{
    if(cmd==='ip'&&args[0]==='-j'&&args[1]==='addr') return ok(JSON.stringify([
      {ifname:'eth0',operstate:'UP',link_type:'ether',address:'00:aa:bb:cc:dd:ee',addr_info:[{family:'inet',local:'192.168.1.10',prefixlen:24}]},
      {ifname:'mystery0',operstate:'UP',link_type:'ether',address:'02:11:22:33:44:55',addr_info:[{family:'inet',local:'172.31.9.1',prefixlen:24}]}
    ]));
    if(cmd==='ip'&&args[0]==='-j'&&args[1]==='route') return ok(JSON.stringify([
      {dst:'default',gateway:'192.168.1.1',dev:'eth0'},
      {dst:'192.168.1.0/24',dev:'eth0',scope:'link'},
      {dst:'172.31.9.0/24',dev:'mystery0',scope:'link'}
    ]));
    if(cmd==='ip'&&args[0]==='-d') return ok(JSON.stringify([
      {ifname:'eth0',link_type:'ether'},
      {ifname:'mystery0',link_type:'ether'}
    ]));
    if(cmd==='iw') return ok('');
    if(cmd==='ethtool') return ok('Speed: 1000Mb/s\nDuplex: Full\nLink detected: yes\n');
    return {code:1,stdout:'',stderr:'fixture unavailable'};
  }, { physicalInterfaceExists:name=>name==='eth0' });
  try {
    const r=await api.call('get_host_interface_info',{internet_check:false});
    assert.deepEqual(r.interfaces.map(x=>x.name),['eth0']);
    assert.equal(r.selected_interface,'eth0');
    assert.equal(r.physical_detection,'iw-or-sysfs-device-backed');
    assert.ok(r.ignored_virtual_interfaces.some(x=>x.name==='mystery0'&&/sysfs device backing/.test(x.reason)));
    assert.ok(!api.calls.some(c=>c.command==='ethtool'&&c.args[0]==='mystery0'));
  } finally { await api.cleanup(); }
});

test('comprehensive discovery parses OS/services while preserving bounded argv', async () => {
  const xml='<?xml version="1.0"?><nmaprun><host><status state="up"/><address addr="127.0.0.2" addrtype="ipv4"/><address addr="00:11:22:33:44:55" addrtype="mac" vendor="Fixture"/><hostnames><hostname name="fixture.local"/></hostnames><ports><port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="9.9"/></port><port protocol="tcp" portid="32400"><state state="open"/><service name="http" product="Plex Media Server"/></port></ports><os><osmatch name="Linux 6.x" accuracy="96"/></os></host></nmaprun>';
  const api=await networkReconFixture(async(cmd,args)=>{
    if(cmd==='ip'&&args[0]==='-j'&&args[1]==='addr') return ok(JSON.stringify([{ifname:'eth0',operstate:'UP',link_type:'ether',address:'00:aa:bb:cc:dd:ee',addr_info:[{family:'inet',local:'127.0.0.1',prefixlen:24}]}]));
    if(cmd==='ip'&&args[0]==='-j'&&args[1]==='route') return ok(JSON.stringify([{dst:'127.0.0.0/24',dev:'eth0',scope:'link'}]));
    if(cmd==='ip'&&args[0]==='-d') return ok('[]');
    if(cmd==='iw') return ok('');
    if(cmd==='ethtool') return ok('Speed: 1000Mb/s\nDuplex: Full\nLink detected: yes\n');
    if(cmd==='nmap'&&args.includes('-oG')) return ok('Host: 127.0.0.2 (fixture.local)\tStatus: Up\tMAC: 00:11:22:33:44:55 (Fixture)\n');
    if(cmd==='nmap'&&args.includes('-oX')) return ok(xml);
    return {code:1,stdout:'',stderr:'unexpected'};
  });
  try {
    const r=await api.call('perform_network_discovery',{cidrs:['127.0.0.0/24'],max_hosts:4,port_profile:'quick',resolve_names:false,include_shares:false,include_media:false});
    assert.equal(r.processed_count,1); assert.equal(r.hosts[0].os.name,'Linux 6.x'); assert.equal(r.hosts[0].open_ports[0].port,22); assert.equal(r.hosts[0].media_services[0].port,32400);
    const nmapCalls=api.calls.filter(c=>c.command==='nmap'); assert.ok(nmapCalls.length>=2); assert.ok(nmapCalls.every(c=>c.args.every(x=>!/[;&|`$<>]/.test(String(x)))));
  } finally { await api.cleanup(); }
});

test('wireless analysis is passive and never enables monitor mode or deauthenticates', async () => {
  const api=await networkReconFixture(async(cmd,args)=>{
    if(cmd==='ip'&&args[0]==='-j'&&args[1]==='addr') return ok('[]');
    if(cmd==='ip'&&args[0]==='-j'&&args[1]==='route') return ok('[]');
    if(cmd==='ip'&&args[0]==='-d') return ok('[]');
    if(cmd==='iw'&&args.length===1) return ok('phy#0\n\tInterface wlan0\n\t\ttype managed\n');
    if(cmd==='iw'&&args.includes('link')) return ok('Connected to aa:bb:cc:dd:ee:ff (on wlan0)\n\tSSID: Fixture\n\tfreq: 2412\n\tsignal: -43 dBm\n\ttx bitrate: 144.4 MBit/s HE-MCS 7\n');
    if(cmd==='iw'&&args.includes('info')) return ok('Interface wlan0\n\ttype managed\n\tchannel 1 (2412 MHz), width: 20 MHz\n');
    if(cmd==='iw'&&args.includes('station')) return ok('Station aa:bb:cc:dd:ee:ff (on wlan0)\n\tsignal: -43 dBm\n\ttx bitrate: 144.4 MBit/s HE-MCS 7\n');
    if(cmd==='nmcli') return ok('*:AA\\:BB\\:CC\\:DD\\:EE\\:FF:Fixture:1:2412 MHz:144 Mbit/s:80:WPA2\n:11\\:22\\:33\\:44\\:55\\:66:Neighbor:6:2437:72 Mbit/s:55:WPA2\n');
    return {code:1,stdout:'',stderr:'fixture unavailable'};
  });
  try {
    const r=await api.call('analyze_wireless_environment',{interface:'wlan0'});
    assert.equal(r.nearby_access_points[0].frequency_mhz,2412); assert.equal(r.nearby_access_points[0].signal_percent,80); assert.equal(r.nearby_access_points[0].signal_dbm,null); assert.equal(r.channel_analysis[0].strongest_signal_percent,80); assert.equal(r.channel_analysis[0].strongest_signal_dbm,null); assert.equal(r.current_connection.phy,'802.11ax'); assert.equal(r.nearby_access_points.length,2); assert.equal(r.observation_mode,'passive-cached'); assert.equal(r.current_connection.channel_width_mhz,20); assert.ok(api.calls.some(c=>c.command==='nmcli'&&c.args.at(-1)==='no')); assert.ok(r.channel_analysis.length>=1);
    assert.ok(api.calls.every(c=>c.command!=='airmon-ng')); assert.ok(api.calls.every(c=>!c.args.some(x=>/deauth|monitor|set\s+type/i.test(String(x)))));
  } finally { await api.cleanup(); }
});

test('topology analysis marks client isolation as possible only with control evidence', async () => {
  const api=await networkReconFixture(async(cmd,args)=>{
    if(cmd==='ip'&&args[0]==='-j'&&args[1]==='addr') return ok(JSON.stringify([{ifname:'wlan0',operstate:'UP',addr_info:[{family:'inet',local:'127.0.0.2',prefixlen:24}]}]));
    if(cmd==='ip'&&args[0]==='-j'&&args[1]==='route') return ok(JSON.stringify([{dst:'default',gateway:'127.0.0.1',dev:'wlan0'},{dst:'127.0.0.0/24',dev:'wlan0',scope:'link'}]));
    if(cmd==='ip'&&args[0]==='-d') return ok(JSON.stringify([{ifname:'wlan0',operstate:'UP'}]));
    if(cmd==='iw'&&args.length===1) return ok('phy#0\n\tInterface wlan0\n\t\ttype managed\n');
    if(cmd==='timeout'&&args.includes('avahi-browse')) return ok('=;wlan0;IPv4;Remote Service;_http._tcp;local;remote.local;192.168.50.5;80;\n');
    if(cmd==='ping'&&args.at(-1)==='127.0.0.1') return ok('reachable');
    if(cmd==='ping') return {code:1,stdout:'',stderr:''};
    if(cmd==='nmap') return ok('Host: 127.0.0.2 ()\tStatus: Down\n');
    return {code:1,stdout:'',stderr:'fixture unavailable'};
  }, {collectMdns:async()=>({available:true,complete:true,status:'observed',records:[{name:'remote.local',type:'A',address:'192.168.50.5',ttl:120},{name:'Remote Service._http._tcp.local',type:'SRV',target:'remote.local',port:80,ttl:120}]})});
  try {
    const r=await api.call('analyze_network_topology',{interface:'wlan0',peer_targets:['127.0.0.2'],observe_mdns:true});
    assert.equal(r.client_isolation_assessment.status,'possible_client_isolation_or_peer_filtering'); assert.equal(r.mdns_reflector_assessment.possible_reflector,true);
  } finally { await api.cleanup(); }
});

test('host recon helper delegation excludes graphical map generation', async () => {
  assert.deepEqual([...NETWORK_RECON_HOST_TOOL_NAMES].sort(), [
    'analyze_network_topology',
    'analyze_wireless_environment',
    'discover_mdns_subnets',
    'get_host_interface_info',
    'observe_broadcast_multicast',
    'observe_dns_cache',
    'perform_network_discovery',
    'probe_gateway_hairpin',
    'probe_gateway_proxy_arp'
  ]);
  assert.equal(NETWORK_RECON_HOST_TOOL_NAMES.has('generate_graphical_network_map'), false);
  const installer=await fs.readFile(path.join(root,'scripts/install-security-host-recon-helper.sh'),'utf8');
  assert.match(installer,/SECURITY_HOST_RECON_STATE_DIR:-\/var\/lib\/mcp-security-host/);
  assert.match(installer,/ProtectHome=true/);
  assert.match(installer,/RuntimeDirectoryPreserve=restart/);
  assert.doesNotMatch(installer,/MCP_WORKSPACE_PATH:-\$ROOT\/data\/workspace/);
});

test('network map writes DOT/SVG/HTML in the confined workspace', async () => {
  const api=await networkReconFixture(async(cmd,args)=>{
    if(cmd==='dot'){const out=args[args.indexOf('-o')+1];await fs.writeFile(out,'<svg xmlns="http://www.w3.org/2000/svg"></svg>');return ok('');}
    return {code:1,stdout:'',stderr:'fixture unavailable'};
  });
  try {
    const r=await api.call('generate_graphical_network_map',{data:{interface_info:{selected_interface:'eth0',connection_type:'ethernet',default_routes:[{interface:'eth0',gateway:'127.0.0.1'}]},discovery:{cidrs:['127.0.0.0/24'],hosts:[{address:'127.0.0.2',hostname:'fixture',os:{name:'Linux'},open_ports:[{port:22,protocol:'tcp',service:'ssh'}],shares:[{type:'smb',name:'public'}]}]}},output_base:'maps/client-network',format:'both'});
    assert.equal(r.host_count,1); assert.equal(r.outputs.svg,'.security-results/maps/client-network.svg'); assert.equal(r.outputs.html,'.security-results/maps/client-network.html');
    const dot=await fs.readFile(path.join(api.workspace,'.security-results/maps/client-network.dot'),'utf8'); assert.match(dot,/fixture/); assert.match(dot,/Ports: 22\/tcp ssh/); assert.match(dot,/Subnet 127\.0\.0\.0\/24/); assert.match(dot,/Recon Laptop/);
  } finally { await api.cleanup(); }
});


test('host helper disables recursive delegation to its own Unix socket', async () => {
  const helper=await fs.readFile(path.join(root,'scripts/security-host-recon-helper.mjs'),'utf8');
  const recon=await fs.readFile(path.join(root,'scripts/security-network-recon.mjs'),'utf8');
  assert.match(helper,/disableHostDelegation:true/);
  assert.match(recon,/ctx\.disableHostDelegation===true/);

  const oldSocket=process.env.SECURITY_HOST_RECON_SOCKET;
  process.env.SECURITY_HOST_RECON_SOCKET='/tmp/should-not-be-used.sock';
  const workspace=await fs.mkdtemp(path.join(os.tmpdir(),'host-helper-direct-'));
  const calls=[];
  const fakeRun=async(command,args,options)=>{
    calls.push({command,args,options});
    if(command==='ip'&&args[0]==='-j'&&args[1]==='addr') return ok(JSON.stringify([{ifname:'eth0',operstate:'UP',link_type:'ether',address:'00:aa:bb:cc:dd:ee',addr_info:[{family:'inet',local:'192.168.1.10',prefixlen:24}]}]));
    if(command==='ip'&&args[0]==='-j'&&args[1]==='route') return ok(JSON.stringify([{dst:'default',gateway:'192.168.1.1',dev:'eth0'}]));
    if(command==='ip'&&args[0]==='-d') return ok(JSON.stringify([{ifname:'eth0',link_type:'ether'}]));
    if(command==='iw') return ok('');
    if(command==='ethtool') return ok('Speed: 1000Mb/s\nDuplex: Full\nLink detected: yes\n');
    return {code:1,stdout:'',stderr:'fixture unavailable'};
  };
  const api=createNetworkRecon({
    runStatus:fakeRun,
    safeWorkspace:(rel,options)=>confinedPath(workspace,rel,options),
    assertAuthorizedTarget:async t=>t,
    requireActive:()=>{},
    requireCapture:()=>{},
    hostRoot:path.join(workspace,'host'),
    physicalInterfaceExists:name=>name==='eth0',
    disableHostDelegation:true,
  });
  try {
    const oldScope=process.env.SECURITY_NETWORK_SCOPE;
    process.env.SECURITY_NETWORK_SCOPE='host-network';
    const r=await api.call('get_host_interface_info',{internet_check:false});
    if(oldScope===undefined) delete process.env.SECURITY_NETWORK_SCOPE; else process.env.SECURITY_NETWORK_SCOPE=oldScope;
    assert.equal(r.selected_interface,'eth0');
    assert.equal(r.warning,null);
    assert.ok(calls.some(c=>c.command==='ip'));
  } finally {
    if(oldSocket===undefined) delete process.env.SECURITY_HOST_RECON_SOCKET; else process.env.SECURITY_HOST_RECON_SOCKET=oldSocket;
    await fs.rm(workspace,{recursive:true,force:true});
  }
});

test('host helper installer restarts updated code instead of only enabling an existing service', async () => {
  const installer=await fs.readFile(path.join(root,'scripts/install-security-host-recon-helper.sh'),'utf8');
  assert.match(installer,/systemctl restart mcp-security-host-recon\.service/);
  assert.doesNotMatch(installer,/enable --now mcp-security-host-recon\.service/);
});

test('host recon helper queues concurrent requests instead of rejecting them as busy', async () => {
  const helper=await fs.readFile(path.join(root,'scripts/security-host-recon-helper.mjs'),'utf8');
  assert.match(helper,/SECURITY_HOST_RECON_MAX_QUEUE/);
  assert.match(helper,/async function schedule\(name,args\)/);
  assert.match(helper,/queued>=MAX_QUEUE/);
  assert.match(helper,/req\.url==='\/status'/);
  assert.doesNotMatch(helper,/host recon helper is busy/);
  assert.doesNotMatch(helper,/if\(busy\)/);
  const recon=await fs.readFile(path.join(root,'scripts/security-network-recon.mjs'),'utf8');
  assert.match(recon,/ctx\.disableHostDelegation!==true/);
  assert.match(recon,/refusing to substitute the mcp-security container namespace/);
});

test('MCP protocol validates calls, parses Nmap/ffuf, preserves large JSON and rejects target bypasses', async () => {
  const dir=await fs.mkdtemp(path.join(os.tmpdir(),'security-protocol-'));
  await fs.mkdir(path.join(dir,'bin')); await fs.mkdir(path.join(dir,'workspace'));
  for(const [binary,output] of Object.entries({nmap:'Host: 127.0.0.1 ()\tPorts: 80/open/tcp//http//fixture/\n',ffuf:'{"url":"http://127.0.0.1/a","status":200}\n{"url":"http://127.0.0.1/b","status":403}\n'})) {
    await fs.writeFile(path.join(dir,'bin',binary),`#!${process.execPath}\nprocess.stdout.write(${JSON.stringify(output)});`,{mode:0o755});
  }
  const child=spawn(process.execPath,[path.join(root,'scripts/security-tools.mjs')],{env:{...process.env,PATH:path.join(dir,'bin')+':'+process.env.PATH,MCP_WORKSPACE:path.join(dir,'workspace'),SECURITY_TARGET_ALLOWLIST:'127.0.0.0/8,::1/128',SECURITY_ALLOW_PUBLIC_TARGETS:'false',SECURITY_MAX_OUTPUT:'1024'},stdio:['pipe','pipe','pipe']});
  const pending=new Map(); let seq=0;
  const lines=createInterface({input:child.stdout}); lines.on('line',line=>{const m=JSON.parse(line);pending.get(m.id)?.(m.result);pending.delete(m.id);});
  const rpc=(method,params)=>new Promise(resolve=>{const id=++seq;pending.set(id,resolve);child.stdin.write(JSON.stringify({jsonrpc:'2.0',id,method,params})+'\n');});
  const call=(name,args)=>rpc('tools/call',{name,arguments:args});
  try {
    const catalog=await rpc('tools/list',{}); assert.equal(catalog.tools.length,63);
    const interfaceTool=catalog.tools.find(t=>t.name==='network_interfaces');
    assert.match(interfaceTool.description,/container.*interfaces/i); assert.doesNotMatch(interfaceTool.description,/LAN|laptop|reconnaissance/i);
    const bad=await call('sqlmap',{}); assert.equal(bad.isError,true);
    for(const target of ['8.8.8.8','127.0.0.1/99','fd00::1','--script=default']) {
      const r=await call('port_scan',{target}); assert.equal(r.isError,true,target);
    }
    const ports=JSON.parse((await call('port_scan',{target:'127.0.0.1'})).content[0].text);assert.equal(ports.open_ports[0].port,80);
    const fuzz=JSON.parse((await call('web_content_discover',{url:'http://127.0.0.1/'})).content[0].text);assert.equal(fuzz.count,1);assert.equal(fuzz.results[0].status,200);
    await fs.writeFile(path.join(dir,'workspace','big.json'),JSON.stringify({value:'x'.repeat(4000)}));
    const large=JSON.parse((await call('jq',{path:'big.json'})).content[0].text);assert.equal(large.truncated,true);
    const full=JSON.parse(await fs.readFile(path.join(dir,'workspace',large.output_file),'utf8'));assert.equal(full.records[0].value.length,4000);
  } finally { child.kill(); lines.close(); await fs.rm(dir,{recursive:true,force:true}); }
});
