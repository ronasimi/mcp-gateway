import {fileURLToPath} from 'node:url';
import {isIP} from 'node:net';
import {ipv4InCidr,networkCidr} from './helpers.mjs';
import {ISOLATION_TOOLS} from './isolation-tools.mjs';
const worker=fileURLToPath(new URL('./isolation-worker.py',import.meta.url));
export function createIsolationAssessment(ctx){
 const {interfaceInfo,runStatus,assertAuthorizedTarget,requireActive,requireCapture,validateArguments}=ctx;
 return {async call(name,a={}){
  const definition=ISOLATION_TOOLS.find(t=>t.name===name);
  if(!definition)throw new Error('unknown isolation assessment');
  if(typeof validateArguments!=='function')throw new Error('Isolation assessment requires schema validation');
  validateArguments(definition.inputSchema,a);
  for(const key of ['peer_targets','protocols','names'])if(a[key]&&new Set(a[key]).size!==a[key].length)throw new Error(`Duplicate ${key} are not allowed`);
  if(name==='observe_broadcast_multicast')requireCapture();else requireActive();
  const info=await interfaceInfo({interface:a.interface,internet_check:false});
  const iface=info.interfaces.find(x=>x.name===info.selected_interface);
  if(!iface)throw new Error('No physical host interface is available');
  const addrs=iface.addresses.filter(x=>x.family==='inet');
  const networks=addrs.map(x=>networkCidr(x.address,x.prefixlen));
  const gateway=a.gateway||info.default_routes.find(x=>x.interface===iface.name)?.gateway;
  const connected=ip=>isIP(ip)===4&&networks.some(c=>ipv4InCidr(ip,c));
  async function target(ip){if(!connected(ip)||addrs.some(x=>x.address===ip))throw new Error(`Target must be a peer on selected physical interface subnet: ${ip}`);await assertAuthorizedTarget(ip);}
  const request={...a,interface:iface.name,local_addresses:iface.addresses,local_mac:iface.mac};
  if(name!=='observe_broadcast_multicast'){
   const first=addrs[0];if(!first)throw new Error('Selected interface needs an IPv4 address');
   if(name==='observe_dns_cache'){
    request.server=a.server||gateway;if(!request.server)throw new Error('Provide a LAN DNS server; no IPv4 default gateway found');
    await target(request.server);
    for(const n of a.names)if(!/^(?=.{1,253}\.?$)(?:[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?\.)*[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?\.?$/.test(n))throw new Error('Invalid DNS name');
    request.source_address=addrs.find(x=>ipv4InCidr(request.server,networkCidr(x.address,x.prefixlen))).address;
   }else{
    if(!/^[0-9a-f]{2}(?::[0-9a-f]{2}){5}$/i.test(iface.mac||''))throw new Error('Selected interface needs an Ethernet MAC address');
    if(!gateway)throw new Error('Provide a gateway; no IPv4 default gateway found');await target(gateway);request.gateway=gateway;
    const local=addrs.find(x=>ipv4InCidr(gateway,networkCidr(x.address,x.prefixlen)));request.source_address=local.address;
    if(name==='probe_gateway_proxy_arp'){
     const c=a.cidr||networkCidr(local.address,local.prefixlen),parts=c.split('/'),bits=Number(parts[1]);
     if(parts.length!==2||isIP(parts[0])!==4||!Number.isInteger(bits)||bits<0||bits>32)throw new Error('Invalid IPv4 CIDR');
     const canonical=networkCidr(parts[0],bits),count=2**(32-bits);
     if(count>(a.max_hosts??256))throw new Error('ARP range exceeds max_hosts; provide a narrower CIDR');
     if(!(bits>=local.prefixlen&&ipv4InCidr(parts[0],networkCidr(local.address,local.prefixlen))))throw new Error('ARP CIDR must lie within a selected-interface connected prefix');
     await assertAuthorizedTarget(canonical,{allowCidr:true});request.cidr=canonical;
    }else for(const peer of a.peer_targets){await target(peer);if(peer===gateway||!ipv4InCidr(peer,networkCidr(local.address,local.prefixlen)))throw new Error('Hairpin peers must share the gateway subnet and differ from the gateway');}
   }
  }
  const r=await runStatus('python3',[worker,name,JSON.stringify(request)],{timeout:120000,maxBuffer:2*1024*1024});
  if(r.code!==0||r.timed_out)throw new Error(`Host assessment unavailable: ${(r.stderr||r.stdout||'worker timeout').slice(0,1000)}`);
  let result;try{result=JSON.parse(r.stdout);}catch{throw new Error('Invalid isolation worker response');}
  return {...result,scope:'host-network',selected_interface:iface.name,untrusted_network_data:true};
 }};
}
