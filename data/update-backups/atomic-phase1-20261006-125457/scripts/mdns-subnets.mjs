import dgram from 'node:dgram';
import {isIP} from 'node:net';

function ipNumber(ip) {
  if (isIP(ip) === 4) return ip.split('.').reduce((n,x)=>(n<<8n)|BigInt(x),0n);
  if (isIP(ip) !== 6) throw new Error('invalid IP address');
  let text=ip.split('%')[0];
  if(text.includes('.')) text=text.replace(/(?:\d+\.){3}\d+$/,v=>{const n=ipNumber(v);return `${(n>>16n).toString(16)}:${(n&65535n).toString(16)}`;});
  const parts=text.split('::'),left=parts[0]?parts[0].split(':'):[],right=parts[1]?parts[1].split(':'):[];
  const words=parts.length===2?[...left,...Array(8-left.length-right.length).fill('0'),...right]:left;
  return words.reduce((n,x)=>(n<<16n)|BigInt('0x'+x),0n);
}
function ipText(n,family) {
  if(family===4)return [24n,16n,8n,0n].map(b=>String((n>>b)&255n)).join('.');
  return Array.from({length:8},(_,i)=>((n>>BigInt((7-i)*16))&65535n).toString(16)).join(':');
}
export function addressRange(address,prefix) {
  const family=isIP(address),bits=family===4?32:128;
  if(!family||!Number.isInteger(prefix)||prefix<0||prefix>bits)throw new Error('invalid IP prefix');
  const size=1n<<BigInt(bits-prefix),start=(ipNumber(address)/size)*size,end=start+size-1n;
  return {cidr:`${ipText(start,family)}/${prefix}`,family,prefix_length:prefix,range_start:ipText(start,family),range_end:ipText(end,family),address_count:String(size)};
}
function contains(address,cidr) {
  try {const [ip,p]=cidr.split('/');if(isIP(ip)!==isIP(address))return false;const r=addressRange(ip,Number(p));const n=ipNumber(address);return n>=ipNumber(r.range_start)&&n<=ipNumber(r.range_end);}catch{return false;}
}
function localAddress(ip) {
  return isIP(ip)===4?contains(ip,'169.254.0.0/16')||contains(ip,'127.0.0.0/8')||contains(ip,'224.0.0.0/4')||ip==='0.0.0.0':contains(ip,'fe80::/10')||contains(ip,'ff00::/8')||contains(ip,'::1/128')||contains(ip,'::/128');
}
function privateAddress(ip) {
  return isIP(ip)===4?['10.0.0.0/8','172.16.0.0/12','192.168.0.0/16'].some(c=>contains(ip,c)):contains(ip,'fc00::/7');
}
function add(map,key,value) {
  if(!key||value===undefined||value===null)return;
  const k=String(key).toLowerCase(),values=map.get(k)||[];
  if(!values.some(v=>JSON.stringify(v)===JSON.stringify(value)))values.push(value);
  map.set(k,values);
}
function serviceTypeFromInstance(instance) {
  const m=String(instance||'').match(/(_[^.]+\._(?:tcp|udp)\.local)$/i);return m?.[1]||null;
}

// Build model-friendly DNS-SD views without losing transport provenance.
// `advertised_addresses` are DNS A/AAAA RDATA. `packet_source_addresses` are
// UDP peer addresses that sent records and must never be presented as the
// advertised host address unless a DNS record independently says so.
function txtFields(txt=[]) {
  const out={};
  for(const item of txt||[]){
    const m=String(item).match(/^([^=]{1,64})=(.*)$/);
    if(m&&!Object.hasOwn(out,m[1]))out[m[1]]=m[2];
  }
  return out;
}
function addressScope(address) {
  if(isIP(address)===4){
    if(contains(address,'169.254.0.0/16'))return 'link_local';
    if(privateAddress(address))return 'private';
    return 'global_or_special';
  }
  if(isIP(address)===6){
    if(contains(address,'fe80::/10'))return 'link_local';
    if(contains(address,'fc00::/7'))return 'unique_local';
    return 'global_or_special';
  }
  return 'unknown';
}

export function normalizeMdnsRecords(records=[]) {
  const addresses=new Map(),sources=new Map(),ptrTypes=new Map(),srvs=new Map(),txts=new Map(),serviceNames=new Set();
  for(const r of records){
    const name=String(r.name||'').toLowerCase();
    if(r.source_address)add(sources,name,r.source_address);
    if(['A','AAAA'].includes(r.type)&&isIP(r.address))add(addresses,name,{address:r.address,family:isIP(r.address),type:r.type,ttl:r.ttl});
    if(r.type==='PTR'&&r.target){
      const owner=String(r.name||'').toLowerCase(),target=String(r.target).toLowerCase();
      // DNS-SD enumeration PTRs advertise service *types*, not instances.
      if(owner==='_services._dns-sd._udp.local')continue;
      if(/\._(?:tcp|udp)\.local$/i.test(owner)){add(ptrTypes,target,r.name);serviceNames.add(target);if(r.source_address)add(sources,target,r.source_address);}
    }
    if(r.type==='SRV'&&r.target){srvs.set(name,{target_hostname:r.target,port:r.port,ttl:r.ttl});serviceNames.add(name);}
    if(r.type==='TXT'){txts.set(name,{txt:[...(r.txt||[])],ttl:r.ttl});serviceNames.add(name);}
  }
  const serviceInstances=[...serviceNames].sort().map(key=>{
    const srv=srvs.get(key),targetKey=String(srv?.target_hostname||'').toLowerCase();
    const advertised=(addresses.get(targetKey)||[]).map(x=>({...x}));
    const packetSources=[...new Set([...(sources.get(key)||[]),...(targetKey?sources.get(targetKey)||[]:[])])];
    const types=(ptrTypes.get(key)||[]).map(String);
    const instance=records.find(r=>String(r.name||'').toLowerCase()===key&&['SRV','TXT'].includes(r.type))?.name
      || records.find(r=>r.type==='PTR'&&String(r.target||'').toLowerCase()===key)?.target || key;
    return {instance,service_types:types.length?types:[serviceTypeFromInstance(instance)].filter(Boolean),target_hostname:srv?.target_hostname||null,port:srv?.port??null,txt:txts.get(key)?.txt||[],advertised_addresses:advertised,packet_source_addresses:packetSources};
  });
  const serviceByHost=new Map();
  for(const svc of serviceInstances)if(svc.target_hostname)add(serviceByHost,svc.target_hostname,svc.instance);
  const advertisedHosts=[...addresses.entries()].sort(([a],[b])=>a.localeCompare(b)).map(([key,advertised])=>({
    hostname:records.find(r=>['A','AAAA'].includes(r.type)&&String(r.name||'').toLowerCase()===key)?.name||key,
    advertised_addresses:advertised.map(x=>({...x})),
    packet_source_addresses:[...(sources.get(key)||[])],
    service_instances:[...(serviceByHost.get(key)||[])],
  }));
  const servicesByTarget=new Map();
  for(const svc of serviceInstances){
    if(!svc.target_hostname)continue;
    const key=String(svc.target_hostname).toLowerCase(),fields=txtFields(svc.txt),list=servicesByTarget.get(key)||[];
    list.push({instance:svc.instance,service_types:[...svc.service_types],port:svc.port,model:fields.md||null,friendly_name:fields.fn||null});
    servicesByTarget.set(key,list);
  }
  const reportHosts=advertisedHosts.map(host=>{
    const addresses=host.advertised_addresses.map(a=>({...a,scope:addressScope(a.address)}));
    return {
      hostname:host.hostname,
      ipv4_addresses:addresses.filter(a=>a.family===4).map(a=>a.address),
      ipv6_addresses:addresses.filter(a=>a.family===6).map(a=>a.address),
      advertised_addresses:addresses,
      packet_source_addresses:[...host.packet_source_addresses],
      services:[...(servicesByTarget.get(String(host.hostname).toLowerCase())||[])],
    };
  });
  return {advertised_hosts:advertisedHosts,services:serviceInstances,report_hosts:reportHosts};
}

export function inferMdnsSubnets(records,{interfaces=[],routes=[],interface:iface,ipv4Prefix=24,ipv6Prefix=64}={}) {
  const local=interfaces.flatMap(i=>(i.addr_info||[]).filter(a=>['inet','inet6'].includes(a.family)&&isIP(a.local)).map(a=>({...addressRange(a.local,a.prefixlen),interface:i.ifname})));
  const candidates=new Map(),addresses=[];
  for(const record of records.filter(r=>['A','AAAA'].includes(r.type)&&isIP(r.address))) {
    const address=record.address,family=isIP(address),same=local.filter(c=>c.interface===iface&&contains(address,c.cidr));
    const observed={...record,family,outside_selected_subnets:!localAddress(address)&&same.length===0};
    if(localAddress(address)){addresses.push({...observed,range_status:'link_local_or_loopback',note:'Not evidence of a remote subnet.'});continue;}
    const direct=local.filter(c=>contains(address,c.cidr)).sort((a,b)=>b.prefix_length-a.prefix_length)[0];
    const route=routes.filter(r=>r.dst&&r.dst!=='default'&&contains(address,r.dst)).sort((a,b)=>Number(b.dst.split('/')[1])-Number(a.dst.split('/')[1]))[0];
    let range,basis,maskKnown=false;
    if(direct){range=addressRange(address,direct.prefix_length);basis='local_interface';maskKnown=true;}
    else if(route){range=addressRange(address,Number(route.dst.split('/')[1]));basis='known_route';}
    else if(privateAddress(address)){range=addressRange(address,family===4?ipv4Prefix:ipv6Prefix);basis='heuristic';}
    else {addresses.push({...observed,range_status:'unknown',note:'Public address retained as evidence; no scan range inferred.'});continue;}
    addresses.push({...observed,candidate_cidr:range.cidr,range_status:basis});
    const group=candidates.get(range.cidr)||{...range,basis,address_scope:addressScope(address),actual_subnet_mask_known:maskKnown,scan_automatically:false,observed_addresses:[],hostnames:[],note:basis==='heuristic'?'Grouping hypothesis only. mDNS does not advertise a subnet mask.':basis==='known_route'?'Routing coverage is known; this does not establish the remote subnet mask.':'Prefix confirmed by a local interface address.'};
    group.observed_addresses=[...new Set([...group.observed_addresses,address])];group.hostnames=[...new Set([...group.hostnames,record.name])];candidates.set(range.cidr,group);
  }
  const outside=addresses.filter(a=>a.outside_selected_subnets);
  return {addresses,candidate_networks:[...candidates.values()],possible_reflection:outside.length>0,evidence:outside.map(a=>({address:a.address,hostname:a.name,reason:'Advertised address is outside known selected-interface subnets; multihoming or stale advertisements are alternative explanations.'})),reflector_confirmed:false};
}

function readName(buf,start) {
  let offset=start,next=null,labels=[],visited=new Set();
  for(let steps=0;steps<128;steps++){
    if(offset>=buf.length||visited.has(offset))throw new Error('invalid DNS name');visited.add(offset);
    const len=buf[offset++];if(len===0)return {name:labels.join('.'),next:next??offset};
    if((len&192)===192){if(offset>=buf.length)throw new Error('short DNS pointer');const target=((len&63)<<8)|buf[offset++];next??=offset;offset=target;continue;}
    if(len>63||offset+len>buf.length)throw new Error('invalid DNS label');labels.push(buf.subarray(offset,offset+len).toString('utf8'));offset+=len;
  }
  throw new Error('DNS name too deep');
}
export function parseMdnsPacket(buf) {
  if(buf.length<12||!(buf.readUInt16BE(2)&0x8000))return [];
  let offset=12;const questions=buf.readUInt16BE(4),count=buf.readUInt16BE(6)+buf.readUInt16BE(8)+buf.readUInt16BE(10),records=[];
  if(questions>128||count>512)throw new Error('DNS record limit');
  for(let i=0;i<questions;i++){offset=readName(buf,offset).next+4;if(offset>buf.length)throw new Error('short question');}
  for(let i=0;i<count;i++){
    const n=readName(buf,offset);offset=n.next;if(offset+10>buf.length)throw new Error('short record');
    const type=buf.readUInt16BE(offset),cls=buf.readUInt16BE(offset+2)&0x7fff,ttl=buf.readUInt32BE(offset+4),len=buf.readUInt16BE(offset+8);offset+=10;
    const end=offset+len;if(end>buf.length)throw new Error('short record data');
    const base={name:n.name,ttl};let r;
    if(cls===1&&type===1&&len===4)r={...base,type:'A',address:[...buf.subarray(offset,end)].join('.')};
    else if(cls===1&&type===28&&len===16)r={...base,type:'AAAA',address:Array.from({length:8},(_,j)=>buf.readUInt16BE(offset+j*2).toString(16)).join(':')};
    else if(cls===1&&type===12){const v=readName(buf,offset);if(v.next>end)throw new Error('invalid PTR data');r={...base,type:'PTR',target:v.name};}
    else if(cls===1&&type===33&&len>=7){const v=readName(buf,offset+6);if(v.next>end)throw new Error('invalid SRV data');r={...base,type:'SRV',port:buf.readUInt16BE(offset+4),target:v.name};}
    else if(cls===1&&type===16){let cursor=offset,txt=[];while(cursor<end){const size=buf[cursor++];if(cursor+size>end)throw new Error('invalid TXT data');txt.push(buf.subarray(cursor,cursor+size).toString('utf8'));cursor+=size;}r={...base,type:'TXT',txt};}
    if(r)records.push(r);offset=end;
  }
  return records;
}
function query(name,type) {
  const labels=name.split('.');if(labels.some(l=>!l||Buffer.byteLength(l)>63))throw new Error('invalid query name');
  const head=Buffer.alloc(12);head.writeUInt16BE(1,4);const tail=Buffer.alloc(4);tail.writeUInt16BE(type,0);tail.writeUInt16BE(1,2);
  return Buffer.concat([head,...labels.map(l=>Buffer.concat([Buffer.from([Buffer.byteLength(l)]),Buffer.from(l)])),Buffer.from([0]),tail]);
}

// Direct UDP browsing avoids the avahi-browse -> D-Bus -> daemon dependency.
// Query DNS-SD enumeration, follow returned service PTR/SRV targets, and retain
// advertised A/AAAA records. Never probe hosts or infer scan authorization here.
export async function collectMdns({address,durationSeconds=8,maxRecords=256,maxQueries=64,socketFactory=dgram.createSocket}={}) {
  if(isIP(address)!==4)throw new Error('Selected physical interface requires an IPv4 address for this mDNS transport.');
  if(!Number.isInteger(maxQueries)||maxQueries<8||maxQueries>512)throw new Error('maxQueries must be an integer from 8 to 512');
  return new Promise(resolve=>{
    const socket=socketFactory({type:'udp4',reuseAddr:true}),records=new Map(),sent=new Set(),suppressed=new Set();let timer,finished=false,packets=0,malformed=0,queries=0,recordLimited=false,packetLimited=false;
    const finish=error=>{if(finished)return;finished=true;clearTimeout(timer);try{socket.close();}catch{}const queryLimited=suppressed.size>0,limited=recordLimited||packetLimited||queryLimited,raw=[...records.values()];resolve({records:raw,raw_records:raw,transport:'direct-udp4',available:!error,complete:!error&&!limited,coverage:error?'unavailable':limited?'partial':'complete',coverage_limitations:[...(recordLimited?['record_limit_reached']:[]),...(packetLimited?['packet_limit_reached']:[]),...(queryLimited?['query_limit_reached']:[])],status:error?'unavailable':records.size?'observed':'no_records_observed',diagnostics:error?.message||null,packets_received:packets,packet_limit:2048,malformed_packets:malformed,queries_sent:queries,query_limit:maxQueries,query_limit_reached:queryLimited,queries_suppressed_by_limit:suppressed.size,record_limit:maxRecords,record_limit_reached:recordLimited,limited,ipv6_transport:false,note:'AAAA records may arrive over IPv4 mDNS. IPv6-only multicast and non-advertising devices are not covered.'});};
    const send=(name,type)=>{const lower=String(name||'').toLowerCase(),key=lower+':'+type;if(finished||sent.has(key)||!lower.endsWith('.local'))return;if(queries>=maxQueries){suppressed.add(key);return;}sent.add(key);queries++;try{socket.send(query(name,type),5353,'224.0.0.251',error=>{if(error)finish(error);});}catch(error){finish(error);}};
    socket.on('error',finish);
    socket.on('message',(buf,peer)=>{
      if(finished||peer.port!==5353)return;if(++packets>2048){packetLimited=true;finish();return;}
      let parsed;try{parsed=parseMdnsPacket(buf);}catch{malformed++;return;}
      for(const r of parsed){
        const key=[r.name.toLowerCase(),r.type,r.address||r.target||JSON.stringify(r.txt)].join('|');
        if(r.ttl===0){records.delete(key);continue;}if(!records.has(key)&&records.size>=maxRecords){recordLimited=true;continue;}
        records.set(key,{...r,source_address:peer.address});
        if(r.type==='PTR'){send(r.target,r.name.toLowerCase()==='_services._dns-sd._udp.local'?12:33);if(r.name.toLowerCase()!=='_services._dns-sd._udp.local')send(r.target,16);}
        if(r.type==='SRV'){send(r.target,1);send(r.target,28);}
      }
    });
    timer=setTimeout(()=>finish(),durationSeconds*1000);
    try{socket.bind(5353,'0.0.0.0',()=>{if(finished)return;try{socket.addMembership('224.0.0.251',address);socket.setMulticastInterface(address);socket.setMulticastTTL(255);for(const type of ['_services._dns-sd._udp','_http._tcp','_ssh._tcp','_smb._tcp','_ipp._tcp','_airplay._tcp','_googlecast._tcp','_workstation._tcp'])send(type+'.local',12);}catch(error){finish(error);}});}catch(error){finish(error);}
  });
}
