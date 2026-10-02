#!/usr/bin/env node
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { isIP } from 'node:net';
import http from 'node:http';

const obj = (description, properties = {}, required = []) => ({ type:'object', description, properties, required, additionalProperties:false });
const str = (description, extra={}) => ({ type:'string', description, ...extra });
const integer = (description, minimum, maximum, extra={}) => ({ type:'integer', description, minimum, maximum, ...extra });
const bool = description => ({ type:'boolean', description });
const arr = (description, items, extra={}) => ({ type:'array', description, items, ...extra });
const anyObject = description => ({ type:'object', description, additionalProperties:true });
const tool = (name, description, properties={}, required=[]) => ({ name, description, inputSchema:obj(description, properties, required) });

const iface = str('Host network interface name such as eth0, enp1s0, wlan0, or wlp2s0.', { maxLength:64 });
const cidr = str('Authorized private/allowlisted IPv4 CIDR such as 192.168.1.0/24.', { maxLength:64 });

export const NETWORK_RECON_TOOLS = [
  tool('get_host_interface_info',
    'Host network-state inventory for a laptop connected to a new Ethernet or Wi-Fi network. Reports active/default interfaces, wired vs wireless type, IPv4/IPv6 addresses, routes/default gateway, link speed, Wi-Fi association metadata when available, and a bounded external-connectivity check. Full host visibility is provided by the optional security host-recon helper; otherwise visibility is limited to the mcp-security container namespace.',
    { interface:iface, internet_check:bool('Check default-route, DNS-resolution, and one ICMP reachability probe to a fixed public resolver; default true.') }),
  tool('perform_network_discovery',
    'Comprehensive authorized local-network discovery. Discovers live hosts, resolves names from Nmap/reverse DNS/mDNS/locally visible DHCP leases, fingerprints operating systems, scans ports/services, and identifies SMB/NFS shares and common DLNA/Plex/Jellyfin/Emby media services. CIDRs may be supplied or inferred from the selected host interface. Large inferred networks are clamped to the local /24 unless explicitly supplied.',
    {
      cidrs:arr('One to four authorized IPv4 CIDRs. Omit to infer directly connected networks from the active interface.',cidr,{maxItems:4}),
      interface:iface,
      max_hosts:integer('Maximum live hosts to enrich; default 64, maximum 128.',1,128),
      port_profile:str('Port coverage: quick=top 100, standard=top 1000 plus common share/media ports, full=all TCP ports. Full is limited to at most 16 hosts.',{enum:['quick','standard','full']}),
      os_detection:bool('Attempt Nmap OS fingerprinting; default true. Requires raw-packet privileges.'),
      resolve_names:bool('Resolve names using DHCP lease files, reverse DNS, and mDNS where available; default true.'),
      include_shares:bool('Enumerate SMB/NFS shares read-only when their services are detected; default true.'),
      include_media:bool('Probe common UPnP/DLNA/Plex/Jellyfin/Emby ports and metadata; default true.'),
      timeout_seconds:integer('Overall per-phase scan budget; default 180, maximum 600.',30,600)
    }),
  tool('analyze_network_topology',
    'Analyze local network structure and behavior. Reports connected subnets, routes, VLAN interfaces/IDs, gateways, mDNS service visibility and possible reflection across subnets. Optionally tests specified same-subnet peers for possible Wi-Fi client isolation using bounded ICMP/ARP discovery; it does not spoof or poison traffic.',
    {
      interface:iface,
      peer_targets:arr('Known authorized peer IPs expected to be on the same local network. Supplying peers enables the client-isolation test.',str('Authorized peer IPv4 address.'),{maxItems:16}),
      observe_mdns:bool('Browse mDNS/DNS-SD services for topology hints; default true.'),
      observe_l2:bool('Passively observe LLDP/CDP for topology hints; default false and requires SECURITY_ALLOW_PACKET_CAPTURE=true.'),
      timeout_seconds:integer('Observation/probe duration per bounded operation; default 8, maximum 30.',3,30)
    }),
  tool('analyze_wireless_environment',
    'Passive Wi-Fi health/security/congestion analysis using iw and nmcli, with optional airodump-ng collection from an already-existing monitor-mode interface. Reports current association, signal, bitrate/PHY hints, nearby BSSIDs/channels/security, channel congestion/overlap, and visible station data where the driver/interface mode exposes it. Never enables monitor mode, deauthenticates clients, captures credentials, or injects frames.',
    {
      interface:iface,
      rescan:bool('Request a fresh nmcli/iw Wi-Fi scan; default true.'),
      use_airodump:bool('Also collect passive airodump-ng observations; default false. Requires monitor_interface and SECURITY_ALLOW_PACKET_CAPTURE=true.'),
      monitor_interface:iface,
      duration_seconds:integer('airodump passive observation duration; default 10, maximum 30.',3,30)
    }),
  tool('generate_graphical_network_map',
    'Generate Graphviz DOT/SVG and optional self-contained HTML from aggregated network-recon JSON. The map distinguishes known wired/wireless links, shows gateway/Internet relationships, link speed when known, and annotates hosts with hostname, OS, open ports, shares, and media services. Provide either data directly or a workspace JSON input_path.',
    {
      data:anyObject('Aggregated object containing outputs from get_host_interface_info, perform_network_discovery, analyze_network_topology and/or analyze_wireless_environment.'),
      input_path:str('Workspace-relative JSON file containing aggregated network data.'),
      output_base:str('Workspace-relative output basename without extension; default .security-results/network-map.',{maxLength:240}),
      format:str('Map output format.',{enum:['svg','html','both']}),
      title:str('Optional map title; maximum 120 characters.',{maxLength:120})
    })
];

export const NETWORK_RECON_TOOL_NAMES = new Set(NETWORK_RECON_TOOLS.map(t => t.name));
// Only host-observation tools need the laptop's real network namespace. Map rendering
// intentionally stays inside mcp-security so outputs land in the normal shared workspace.
export const NETWORK_RECON_HOST_TOOL_NAMES = new Set([
  'get_host_interface_info',
  'perform_network_discovery',
  'analyze_network_topology',
  'analyze_wireless_environment'
]);
export const NETWORK_RECON_ACTIVE_TOOL_NAMES = new Set(['perform_network_discovery','analyze_network_topology','analyze_wireless_environment']);
export const NETWORK_RECON_WORKSPACE_WRITES = new Set(['generate_graphical_network_map']);

const HOST_SCOPE_WARNING = 'Full laptop/LAN visibility requires mcp-security to run with the host network namespace. Under ordinary Docker bridge networking, interfaces, routes, multicast/broadcast discovery, ARP/NDP, iw/nmcli and packet observations describe only what that namespace can see.';
const MEDIA_PORTS = [1900,32400,32410,32412,32413,32414,8008,8009,8096,8200,8443,8920];
const SHARE_PORTS = [111,139,445,548,873,2049];

function clip(value,max=12000){const text=String(value??'');return Buffer.byteLength(text)<=max?text:text.slice(0,max)+`\n...[truncated at ${max} bytes]`;}
function validInterface(value){if(value==null||value==='')return null;const v=String(value);if(!/^[A-Za-z0-9_.:@-]{1,64}$/.test(v))throw new Error('invalid interface');return v;}
function xmlDecode(value=''){return value.replace(/&#x([0-9a-fA-F]+);/g,(_,x)=>String.fromCodePoint(parseInt(x,16))).replace(/&#([0-9]+);/g,(_,x)=>String.fromCodePoint(parseInt(x,10))).replace(/&quot;/g,'"').replace(/&apos;/g,"'").replace(/&lt;/g,'<').replace(/&gt;/g,'>').replace(/&amp;/g,'&');}
function attr(text,name){const m=new RegExp(`\\b${name}="([^"]*)"`).exec(text);return m?xmlDecode(m[1]):null;}
function toJson(text,fallback=[]){try{return JSON.parse(text||'');}catch{return fallback;}}
function ipv4Int(ip){const p=String(ip).split('.').map(Number);if(p.length!==4||p.some(n=>!Number.isInteger(n)||n<0||n>255))return null;return (((p[0]<<24)>>>0)+(p[1]<<16)+(p[2]<<8)+p[3])>>>0;}
function intIpv4(n){return [24,16,8,0].map(s=>(n>>>s)&255).join('.');}
function networkCidr(ip,prefix){const a=ipv4Int(ip),bits=Number(prefix);if(a==null||!Number.isInteger(bits)||bits<0||bits>32)return null;const mask=bits===0?0:(0xffffffff<<(32-bits))>>>0;return `${intIpv4(a&mask)}/${bits}`;}
function ipv4InCidr(ip,cidr){const [net,bitsRaw]=String(cidr).split('/'),a=ipv4Int(ip),n=ipv4Int(net),bits=Number(bitsRaw);if(a==null||n==null||!Number.isInteger(bits)||bits<0||bits>32)return false;const mask=bits===0?0:(0xffffffff<<(32-bits))>>>0;return (a&mask)===(n&mask);}
function privateIpv4(ip){const n=ipv4Int(ip);if(n==null)return false;return ipv4InCidr(ip,'10.0.0.0/8')||ipv4InCidr(ip,'172.16.0.0/12')||ipv4InCidr(ip,'192.168.0.0/16')||ipv4InCidr(ip,'169.254.0.0/16');}
function uniq(xs){return [...new Set(xs.filter(Boolean))];}
function safeLabel(v){return String(v??'').replace(/[\\{}|<>"\n\r]/g,' ').replace(/\s+/g,' ').trim();}
function dotEscape(v){return String(v??'').replace(/\\/g,'\\\\').replace(/"/g,'\\"').replace(/\r?\n/g,'\\n');}
function parseGrepHosts(text=''){
  const hosts=[];
  for(const line of String(text).split(/\r?\n/)){
    if(!line.startsWith('Host: '))continue;
    const m=/^Host:\s+(\S+)\s+\(([^)]*)\)\s+(.*)$/.exec(line);if(!m)continue;
    const status=/Status:\s+(\w+)/.exec(m[3])?.[1]||null, mac=/MAC:\s+([0-9A-Fa-f:]{17})(?:\s+\(([^)]*)\))?/.exec(m[3]);
    hosts.push({address:m[1],hostname:m[2]||null,status,mac:mac?.[1]?.toUpperCase()||null,vendor:mac?.[2]||null});
  }
  return hosts;
}
function parseScripts(block=''){
  const scripts=[];
  for(const m of String(block).matchAll(/<script\b([^>]*?)(?:\/>|>([\s\S]*?)<\/script>)/g)){
    const id=attr(m[1],'id'),output=attr(m[1],'output');if(id)scripts.push({id,output:clip(output||'',8000)});
  }
  return scripts;
}
function parseNmapXml(xml=''){
  const hosts=[];
  for(const hm of String(xml).matchAll(/<host\b[^>]*>([\s\S]*?)<\/host>/g)){
    const block=hm[1],status=attr(/<status\b([^>]*)\/>/.exec(block)?.[1]||'','state');
    const addresses=[...block.matchAll(/<address\b([^>]*)\/>/g)].map(m=>({address:attr(m[1],'addr'),type:attr(m[1],'addrtype'),vendor:attr(m[1],'vendor')}));
    const ipv4=addresses.find(x=>x.type==='ipv4')?.address||null, ipv6=addresses.find(x=>x.type==='ipv6')?.address||null, mac=addresses.find(x=>x.type==='mac');
    const hostname=attr(/<hostname\b([^>]*)\/>/.exec(block)?.[1]||'','name');
    const osMatch=/<osmatch\b([^>]*)>/.exec(block)||/<osmatch\b([^>]*)\/>/.exec(block), os=osMatch?{name:attr(osMatch[1],'name'),accuracy:Number(attr(osMatch[1],'accuracy')||0)||null}:null;
    const ports=[];
    for(const pm of block.matchAll(/<port\b([^>]*)>([\s\S]*?)<\/port>/g)){
      const pb=pm[2],stateAttrs=/<state\b([^>]*)\/>/.exec(pb)?.[1]||'',svcAttrs=/<service\b([^>]*?)(?:\/>|>)/.exec(pb)?.[1]||'';
      const state=attr(stateAttrs,'state');if(state!=='open')continue;
      const service=[attr(svcAttrs,'product'),attr(svcAttrs,'version'),attr(svcAttrs,'extrainfo')].filter(Boolean).join(' ');
      ports.push({port:Number(attr(pm[1],'portid')),protocol:attr(pm[1],'protocol'),state,service:attr(svcAttrs,'name'),product:service||null,scripts:parseScripts(pb)});
    }
    hosts.push({address:ipv4||ipv6,ipv4,ipv6,hostname,status,mac:mac?.address?.toUpperCase()||null,vendor:mac?.vendor||null,os,ports,scripts:parseScripts(block)});
  }
  return hosts.filter(h=>h.address);
}
function mergeHost(base,extra){
  const out={...base,...Object.fromEntries(Object.entries(extra).filter(([,v])=>v!=null))};
  const byPort=new Map();
  for(const p of [...(base.ports||[]),...(extra.ports||[])])byPort.set(`${p.protocol||'tcp'}:${p.port}`,{...byPort.get(`${p.protocol||'tcp'}:${p.port}`),...p});
  out.ports=[...byPort.values()].sort((a,b)=>a.port-b.port);
  out.scripts=[...(base.scripts||[]),...(extra.scripts||[])];
  return out;
}
function parseNmcliLine(line){
  const fields=[];let cur='',esc=false;
  for(const ch of line){if(esc){cur+=ch;esc=false;}else if(ch==='\\')esc=true;else if(ch===':'){fields.push(cur);cur='';}else cur+=ch;}fields.push(cur);return fields;
}
function freqBand(freq){const f=Number(freq);if(!f)return null;if(f<2500)return '2.4 GHz';if(f<5925)return '5 GHz';return '6 GHz';}
function phyFromText(text=''){if(/EHT[- ]MCS|802\.11be/i.test(text))return'802.11be';if(/HE[- ]MCS|802\.11ax/i.test(text))return'802.11ax';if(/VHT[- ]MCS|802\.11ac/i.test(text))return'802.11ac';if(/\bMCS\b|802\.11n/i.test(text))return'802.11n';if(/802\.11a/i.test(text))return'802.11a';if(/802\.11g/i.test(text))return'802.11g';return null;}
function parseIwDev(text=''){
  const out=[];let phy=null,current=null;
  for(const raw of String(text).split(/\r?\n/)){const line=raw.trim();if(line.startsWith('phy#'))phy=line;else if(line.startsWith('Interface ')){current={interface:line.slice(10).trim(),phy,type:null};out.push(current);}else if(current&&line.startsWith('type '))current.type=line.slice(5).trim();}
  return out;
}
function parseIwLink(text=''){
  if(/Not connected/i.test(text))return{connected:false};
  const connected=/Connected to\s+([0-9a-f:]{17})/i.exec(text)?.[1]?.toUpperCase()||null;
  const field=name=>new RegExp(`^\\s*${name}:\\s*(.+)$`,'mi').exec(text)?.[1]?.trim()||null;
  const tx=field('tx bitrate'),rx=field('rx bitrate');
  return{connected:Boolean(connected),bssid:connected,ssid:field('SSID'),frequency_mhz:Number(field('freq'))||null,signal_dbm:Number((field('signal')||'').match(/-?\d+(?:\.\d+)?/)?.[0])||null,tx_bitrate:tx,rx_bitrate:rx,phy:phyFromText(`${text} ${tx||''} ${rx||''}`)};
}
function parseIwStations(text=''){
  const blocks=String(text).split(/(?=^Station\s+[0-9a-f:]{17})/gmi).filter(x=>/^Station\s+/i.test(x.trim()));
  return blocks.map(block=>{const mac=/^Station\s+([0-9a-f:]{17})/mi.exec(block)?.[1]?.toUpperCase()||null;const val=n=>new RegExp(`^\\s*${n}:\\s*(.+)$`,'mi').exec(block)?.[1]?.trim()||null;const tx=val('tx bitrate'),rx=val('rx bitrate');return{mac,signal_dbm:Number((val('signal')||'').match(/-?\d+/)?.[0])||null,tx_bitrate:tx,rx_bitrate:rx,phy:phyFromText(`${block} ${tx||''} ${rx||''}`)};});
}
function parseAirodumpCsv(text=''){
  const lines=String(text).split(/\r?\n/),aps=[],stations=[];let section='ap',headers=[];
  const csv=line=>{const out=[];let cur='',q=false;for(let i=0;i<line.length;i++){const c=line[i];if(c==='"'){if(q&&line[i+1]==='"'){cur+='"';i++;}else q=!q;}else if(c===','&&!q){out.push(cur.trim());cur='';}else cur+=c;}out.push(cur.trim());return out;};
  for(const line of lines){if(!line.trim()){headers=[];continue;}const f=csv(line);if(/^BSSID$/i.test(f[0])){section='ap';headers=f;continue;}if(/^Station MAC$/i.test(f[0])){section='station';headers=f;continue;}if(!headers.length)continue;const row=Object.fromEntries(headers.map((h,i)=>[h,f[i]??'']));if(section==='ap'&&/^[0-9A-F:]{17}$/i.test(row.BSSID||''))aps.push({bssid:row.BSSID.toUpperCase(),channel:Number(row.channel)||null,privacy:row.Privacy||null,cipher:row.Cipher||null,authentication:row.Authentication||null,power:Number(row.Power)||null,beacons:Number(row['# beacons'])||0,ssid:row.ESSID||null});else if(section==='station'&&/^[0-9A-F:]{17}$/i.test(row['Station MAC']||''))stations.push({mac:row['Station MAC'].toUpperCase(),bssid:/^[0-9A-F:]{17}$/i.test(row.BSSID||'')?row.BSSID.toUpperCase():null,power:Number(row.Power)||null,probed_essids:row['Probed ESSIDs']||null});}
  return{access_points:aps,stations};
}
function analyzeChannels(aps=[]){
  const per={};for(const ap of aps){const ch=Number(ap.channel);if(!ch)continue;const key=String(ch);per[key]??={channel:ch,band:freqBand(ap.frequency_mhz),access_points:0,strongest_signal:null,overlap_score:0};per[key].access_points++;if(Number.isFinite(Number(ap.signal)))per[key].strongest_signal=Math.max(per[key].strongest_signal??-999,Number(ap.signal));}
  const rows=Object.values(per).sort((a,b)=>a.channel-b.channel);for(const row of rows){row.overlap_score=aps.filter(ap=>{const ch=Number(ap.channel);if(!ch)return false;if(row.channel<=14&&ch<=14)return Math.abs(ch-row.channel)<=4;return ch===row.channel;}).length;}
  return rows;
}
function extractShareMedia(host){
  const scripts=[...(host.scripts||[]),...(host.ports||[]).flatMap(p=>p.scripts||[])];
  const shares=[];for(const s of scripts){if(s.id==='smb-enum-shares'){for(const m of s.output.matchAll(/(?:^|\n)\s*([^\n:]{1,120}):\s*$/g))shares.push({type:'smb',name:m[1].trim()});}if(/nfs-showmount|rpcinfo/.test(s.id)){for(const line of s.output.split(/\r?\n/).map(x=>x.trim()).filter(Boolean)){if(line.startsWith('/'))shares.push({type:'nfs',name:line.split(/\s+/)[0]});}}}
  const media=[];for(const p of host.ports||[]){const text=`${p.service||''} ${p.product||''}`;if(MEDIA_PORTS.includes(p.port)||/plex|minidlna|dlna|upnp|jellyfin|emby/i.test(text))media.push({port:p.port,protocol:p.protocol,service:p.service,product:p.product});}
  return{shares:[...new Map(shares.map(x=>[`${x.type}:${x.name}`,x])).values()],media_services:media};
}

export function createNetworkRecon(ctx){
  const { runStatus, safeWorkspace, assertAuthorizedTarget, requireActive, requireCapture, hostRoot='/host' }=ctx;
  if(typeof runStatus!=='function'||typeof safeWorkspace!=='function'||typeof assertAuthorizedTarget!=='function'||typeof requireActive!=='function'||typeof requireCapture!=='function')throw new Error('invalid network recon context');
  const workspaceRoot=safeWorkspace('.');
  const delegateSocket=String(process.env.SECURITY_HOST_RECON_SOCKET||'').trim();
  const requireHostHelper=/^(1|true|yes)$/i.test(String(process.env.SECURITY_HOST_RECON_REQUIRED||'false'));

  async function delegateToHost(name,args){
    if(!delegateSocket) return null;
    const body=JSON.stringify({tool:name,args});
    if(Buffer.byteLength(body)>4*1024*1024) throw new Error('host recon request exceeds 4 MiB');
    return await new Promise((resolve,reject)=>{
      const req=http.request({socketPath:delegateSocket,path:'/call',method:'POST',headers:{'content-type':'application/json','content-length':Buffer.byteLength(body)}},res=>{
        let raw='';let bytes=0;
        res.on('data',chunk=>{bytes+=chunk.length;if(bytes<=8*1024*1024)raw+=chunk.toString('utf8');});
        res.on('end',()=>{try{const parsed=JSON.parse(raw||'{}');if(res.statusCode!==200||parsed.error)reject(new Error(parsed.error||`host recon helper HTTP ${res.statusCode}`));else resolve(parsed.result);}catch(e){reject(new Error(`invalid host recon helper response: ${e.message}`));}});
      });
      req.setTimeout(650000,()=>req.destroy(new Error('host recon helper timeout')));
      req.on('error',reject);req.end(body);
    });
  }

  async function optional(command,args=[],opts={}){try{return await runStatus(command,args,opts);}catch(error){return{code:127,stdout:'',stderr:error.message,timed_out:false,missing:true};}}
  async function must(command,args=[],opts={}){const r=await runStatus(command,args,opts);if(r.code!==0)throw new Error(`${command} exited ${r.code}: ${clip(r.stderr||r.stdout,3000)}`);return r;}
  async function nmapXml(args,timeout=120000){const r=await runStatus('nmap',[...args,'-oX','-'],{timeout,maxBuffer:32*1024*1024});if(r.code!==0&&!r.stdout.includes('<nmaprun'))throw new Error(`nmap exited ${r.code}: ${clip(r.stderr||r.stdout,3000)}`);return{hosts:parseNmapXml(r.stdout),complete:r.code===0&&!r.timed_out,diagnostics:clip(r.stderr,2000)};}
  async function networkState(){
    const [addrR,routeR,linkR,iwR]=await Promise.all([
      optional('ip',['-j','addr','show'],{timeout:10000,maxBuffer:2*1024*1024}),
      optional('ip',['-j','route','show'],{timeout:10000,maxBuffer:2*1024*1024}),
      optional('ip',['-d','-j','link','show'],{timeout:10000,maxBuffer:2*1024*1024}),
      optional('iw',['dev'],{timeout:10000,maxBuffer:1024*1024})
    ]);
    return{addresses:toJson(addrR.stdout,[]),routes:toJson(routeR.stdout,[]),links:toJson(linkR.stdout,[]),wireless:parseIwDev(iwR.stdout),diagnostics:{ip_addr:clip(addrR.stderr,500),ip_route:clip(routeR.stderr,500),iw:clip(iwR.stderr,500)}};
  }
  function chooseInterface(state,requested){
    const req=validInterface(requested);if(req)return req;
    const d=state.routes.find(r=>r.dst==='default'&&r.dev)?.dev;if(d)return d;
    return state.addresses.find(x=>x.ifname!=='lo'&&x.operstate==='UP')?.ifname||state.addresses.find(x=>x.ifname!=='lo')?.ifname||null;
  }
  async function interfaceInfo(a={}){
    const state=await networkState(),selected=chooseInterface(state,a.interface),wifiSet=new Set(state.wireless.map(x=>x.interface));
    const defaults=state.routes.filter(r=>r.dst==='default').map(r=>({interface:r.dev||null,gateway:r.gateway||null,metric:r.metric??null,protocol:r.protocol||null}));
    const interfaces=[];
    for(const x of state.addresses){if(x.ifname==='lo')continue;const addrs=(x.addr_info||[]).map(v=>({family:v.family,address:v.local,prefixlen:v.prefixlen,scope:v.scope}));const type=wifiSet.has(x.ifname)?'wifi':(x.link_type==='ether'?'ethernet':x.link_type||'other');let link={};
      if(type==='wifi'){const r=await optional('iw',['dev',x.ifname,'link'],{timeout:5000,maxBuffer:256*1024});link=parseIwLink(r.stdout);}else{const r=await optional('ethtool',[x.ifname],{timeout:5000,maxBuffer:256*1024});const speed=/Speed:\s*([^\n]+)/i.exec(r.stdout)?.[1]?.trim()||null,duplex=/Duplex:\s*([^\n]+)/i.exec(r.stdout)?.[1]?.trim()||null;link={speed,duplex,link_detected:/Link detected:\s*yes/i.test(r.stdout)};}
      interfaces.push({name:x.ifname,type,state:x.operstate||null,mac:x.address||null,mtu:x.mtu||null,addresses:addrs,link});
    }
    let internet={checked:false,status:'not_checked'};
    if(a.internet_check!==false){const [ping,dns]=await Promise.all([optional('ping',['-n','-c','1','-W','2','1.1.1.1'],{timeout:4000,maxBuffer:128*1024}),optional('getent',['ahosts','example.com'],{timeout:4000,maxBuffer:128*1024})]);const hasDefault=defaults.length>0,icmp=ping.code===0,dnsOk=dns.code===0&&Boolean(dns.stdout.trim());internet={checked:true,default_route:hasDefault,icmp_reachable:icmp,dns_resolution:dnsOk,status:(hasDefault&&(icmp||dnsOk))?'online':hasDefault?'limited':'offline'};}
    return{scope:process.env.SECURITY_NETWORK_SCOPE||'security-container-network',warning:HOST_SCOPE_WARNING,selected_interface:selected,connection_type:interfaces.find(x=>x.name===selected)?.type||null,interfaces,default_routes:defaults,internet,complete:true};
  }
  function inferredCidrs(info){
    const ifaceName=info.selected_interface,record=info.interfaces.find(x=>x.name===ifaceName),notes=[],out=[];
    for(const a of record?.addresses||[]){if(a.family!=='inet'&&!/^\d+\.\d+\.\d+\.\d+$/.test(a.address))continue;let prefix=Number(a.prefixlen);if(prefix<20){notes.push(`connected network ${networkCidr(a.address,prefix)} is larger than /20; discovery inference was clamped to ${networkCidr(a.address,24)}`);prefix=24;}const c=networkCidr(a.address,prefix);if(c)out.push(c);}
    return{cidrs:uniq(out),notes};
  }
  async function loadDhcpLeases(){
    const map=new Map(),candidates=[path.join(hostRoot,'var/lib/misc/dnsmasq.leases'),path.join(hostRoot,'var/lib/NetworkManager/dnsmasq.leases'),path.join(hostRoot,'var/lib/NetworkManager/dnsmasq-shared.leases')];
    try{const d=path.join(hostRoot,'var/lib/libvirt/dnsmasq');for(const n of await fsp.readdir(d))if(n.endsWith('.leases'))candidates.push(path.join(d,n));}catch{}
    for(const file of uniq(candidates)){let text='';try{text=await fsp.readFile(file,'utf8');}catch{continue;}for(const line of text.split(/\r?\n/)){const f=line.trim().split(/\s+/);if(f.length>=4&&isIP(f[2])===4){map.set(f[2],{hostname:f[3]&&f[3]!=='*'?f[3]:null,mac:/^[0-9a-f:]{17}$/i.test(f[1])?f[1].toUpperCase():null,source:path.relative(hostRoot,file)});}}}
    return map;
  }
  async function resolveHostName(ip,gateway,leases){
    const lease=leases.get(ip);if(lease?.hostname)return{name:lease.hostname,source:'dhcp-lease',lease};
    const av=await optional('timeout',['2s','avahi-resolve-address','-4',ip],{timeout:3000,maxBuffer:128*1024});if(av.code===0&&av.stdout.trim()){const f=av.stdout.trim().split(/\s+/);if(f[1])return{name:f[1].replace(/\.$/,''),source:'mdns'};}
    if(gateway&&isIP(gateway)){const d=await optional('dig',[`@${gateway}`,'-x',ip,'+short','+time=1','+tries=1'],{timeout:2500,maxBuffer:128*1024});const n=d.stdout.trim().split(/\r?\n/)[0]?.replace(/\.$/,'');if(n)return{name:n,source:'local-dns'};}
    const ge=await optional('timeout',['2s','getent','hosts',ip],{timeout:3000,maxBuffer:128*1024});const g=ge.stdout.trim().split(/\s+/)[1];return g?{name:g.replace(/\.$/,''),source:'resolver'}:{name:null,source:null};
  }
  async function discover(a={}){
    requireActive();const info=await interfaceInfo({interface:a.interface,internet_check:false}),inferred=inferredCidrs(info),requested=a.cidrs?.length?a.cidrs:inferred.cidrs;if(!requested.length)throw new Error('no IPv4 network could be inferred; provide cidrs explicitly');
    const cidrs=[];for(const c of requested){const parts=String(c).split('/'),prefix=Number(parts[1]);if(parts.length!==2||isIP(parts[0])!==4||!Number.isInteger(prefix)||prefix<20||prefix>32)throw new Error(`CIDR must be IPv4 /20 or smaller network range (/20..../32): ${c}`);cidrs.push(await assertAuthorizedTarget(c,{allowCidr:true}));}
    const maxHosts=Math.max(1,Math.min(128,Number(a.max_hosts||64))),profile=a.port_profile||'standard',sec=Math.max(30,Math.min(600,Number(a.timeout_seconds||180)));if(profile==='full'&&maxHosts>16)throw new Error('full port profile is limited to max_hosts <= 16');
    const discovered=[];for(const c of cidrs){const r=await runStatus('nmap',['-sn','-n','-PR','-PE','-PS22,80,443','-PA80,443','--host-timeout','10s','-oG','-',c],{timeout:Math.min(sec*1000,180000),maxBuffer:8*1024*1024});if(r.code!==0)throw new Error(`nmap discovery failed for ${c}: ${clip(r.stderr||r.stdout,3000)}`);discovered.push(...parseGrepHosts(r.stdout).filter(h=>h.status==='Up'));}
    const dedup=[...new Map(discovered.map(h=>[h.address,h])).values()],limited=dedup.slice(0,maxHosts),targets=limited.map(h=>h.address);if(!targets.length)return{scope:'target-scan',warning:HOST_SCOPE_WARNING,cidrs,selected_interface:info.selected_interface,discovered_count:0,hosts:[],complete:true,inference_notes:a.cidrs?.length?[]:inferred.notes};
    const scanArgs=[profile==='full'?'-sS':'-sS','-sV','--version-light','-Pn','-n','--open','-T4','--max-retries','1','--host-timeout',`${Math.min(sec,180)}s`];if(profile==='quick')scanArgs.push('--top-ports','100');else if(profile==='standard')scanArgs.push('--top-ports','1000');else scanArgs.push('-p-');if(a.os_detection!==false)scanArgs.push('-O','--osscan-limit','--max-os-tries','1');scanArgs.push(...targets);
    let scan=await nmapXml(scanArgs,Math.min(sec*1000+30000,650000));
    // Some environments allow connect scans but not raw SYN/OS probes. Preserve useful results with a bounded fallback.
    if(!scan.hosts.length&&scan.diagnostics&&/permission|privilege|raw socket/i.test(scan.diagnostics)){const fallback=['-sT','-sV','--version-light','-Pn','-n','--open','-T4','--max-retries','1'];if(profile==='quick')fallback.push('--top-ports','100');else if(profile==='standard')fallback.push('--top-ports','1000');else fallback.push('-p-');fallback.push(...targets);scan=await nmapXml(fallback,Math.min(sec*1000+30000,650000));}
    let hosts=new Map(limited.map(h=>[h.address,{...h,ports:[],scripts:[],os:null}]));for(const h of scan.hosts)hosts.set(h.address,mergeHost(hosts.get(h.address)||{},h));
    const extras=uniq([...(a.include_shares===false?[]:SHARE_PORTS),...(a.include_media===false?[]:MEDIA_PORTS)]);if(extras.length){const ex=await nmapXml(['-sT','-sV','--version-light','-Pn','-n','--open','-T4','--max-retries','1','-p',extras.join(','),...targets],Math.min(sec*1000,300000));for(const h of ex.hosts)hosts.set(h.address,mergeHost(hosts.get(h.address)||{},h));}
    if(a.include_shares!==false){const smb=await nmapXml(['-sT','-Pn','-n','-p','139,445','--script','smb-os-discovery,smb-enum-shares','--script-timeout','20s',...targets],Math.min(sec*1000,300000));for(const h of smb.hosts)hosts.set(h.address,mergeHost(hosts.get(h.address)||{},h));const nfs=await nmapXml(['-sT','-Pn','-n','-p','111,2049','--script','rpcinfo,nfs-showmount','--script-timeout','20s',...targets],Math.min(sec*1000,300000));for(const h of nfs.hosts)hosts.set(h.address,mergeHost(hosts.get(h.address)||{},h));}
    if(a.include_media!==false){const upnp=await nmapXml(['-sU','-Pn','-n','-p','1900','--script','upnp-info','--script-timeout','12s',...targets],Math.min(sec*1000,240000));for(const h of upnp.hosts)hosts.set(h.address,mergeHost(hosts.get(h.address)||{},h));}
    const leases=a.resolve_names===false?new Map():await loadDhcpLeases(),gateway=info.default_routes.find(x=>x.interface===info.selected_interface)?.gateway||info.default_routes[0]?.gateway||null;
    const values=[...hosts.values()];
    if(a.resolve_names!==false){let index=0;const workers=Array.from({length:Math.min(8,values.length)},async()=>{while(index<values.length){const i=index++,h=values[i];const r=await resolveHostName(h.address,gateway,leases);if(r.name){h.hostname=r.name;h.hostname_source=r.source;}const lease=leases.get(h.address);if(!h.mac&&lease?.mac)h.mac=lease.mac;}});await Promise.all(workers);}
    const enriched=values.map(h=>{const sm=extractShareMedia(h);return{...h,...sm,open_ports:(h.ports||[]).map(p=>({port:p.port,protocol:p.protocol,service:p.service,product:p.product})),ports:undefined,scripts:undefined};});
    return{scope:'target-scan',warning:HOST_SCOPE_WARNING,selected_interface:info.selected_interface,cidrs,inference_notes:a.cidrs?.length?[]:inferred.notes,discovered_count:dedup.length,processed_count:enriched.length,truncated_hosts:dedup.length>maxHosts,port_profile:profile,hosts:enriched,complete:scan.complete};
  }
  async function browseMdns(dev,seconds){
    const args=['-artp'];if(dev)args.push('-i',dev);const r=await optional('timeout',[`${seconds}s`,'avahi-browse',...args],{timeout:(seconds+2)*1000,maxBuffer:4*1024*1024}),services=[];
    for(const line of r.stdout.split(/\r?\n/)){if(!line.startsWith('='))continue;const f=line.split(';');if(f.length>=9)services.push({interface:f[1],protocol:f[2],name:f[3],type:f[4],domain:f[5],hostname:f[6],address:f[7],port:Number(f[8])||null,txt:f.slice(9).join(';')||null});}
    return{services,available:r.code===0||services.length>0,diagnostics:r.code===127?clip(r.stderr,500):null};
  }
  async function topology(a={}){
    requireActive();const sec=Math.max(3,Math.min(30,Number(a.timeout_seconds||8))),state=await networkState(),dev=chooseInterface(state,a.interface),addr=state.addresses.find(x=>x.ifname===dev),localCidrs=(addr?.addr_info||[]).filter(x=>x.family==='inet').map(x=>networkCidr(x.local,x.prefixlen)).filter(Boolean),subnets=state.routes.filter(r=>r.dst&&r.dst!=='default'&&r.dev).map(r=>({subnet:r.dst,interface:r.dev,gateway:r.gateway||null,protocol:r.protocol||null,scope:r.scope||null}));
    const vlans=[];for(const l of state.links){const info=l.linkinfo||{};if(info.info_kind==='vlan'||l.link_type==='vlan')vlans.push({interface:l.ifname,parent:l.link||null,vlan_id:info.info_data?.id??null,state:l.operstate||null});}
    let mdns={services:[],possible_reflector:false,evidence:[],available:false};if(a.observe_mdns!==false){const b=await browseMdns(dev,sec),outside=b.services.filter(s=>isIP(s.address)===4&&!localCidrs.some(c=>ipv4InCidr(s.address,c)));mdns={...b,possible_reflector:outside.length>0,evidence:outside.slice(0,30).map(s=>({address:s.address,hostname:s.hostname,type:s.type,reason:'mDNS-resolved address is outside the selected interface IPv4 subnet'}))};}
    const gateway=state.routes.find(r=>r.dst==='default'&&(!dev||r.dev===dev))?.gateway||state.routes.find(r=>r.dst==='default')?.gateway||null;let gatewayReachable=null;if(gateway&&isIP(gateway)){const g=await optional('ping',['-n','-c','1','-W','2',gateway],{timeout:4000,maxBuffer:128*1024});gatewayReachable=g.code===0;}
    const peerResults=[];for(const raw of a.peer_targets||[]){const target=await assertAuthorizedTarget(raw),same=localCidrs.some(c=>ipv4InCidr(target,c));if(!same){peerResults.push({target,same_subnet:false,classification:'not_tested',reason:'target is not in a selected-interface IPv4 subnet'});continue;}const p=await optional('ping',['-n','-c','1','-W','2',target],{timeout:4000,maxBuffer:128*1024}),arp=await optional('nmap',['-sn','-PR','-PE','-n','-e',dev,'-oG','-',target],{timeout:10000,maxBuffer:512*1024}),arpUp=parseGrepHosts(arp.stdout).some(h=>h.status==='Up');peerResults.push({target,same_subnet:true,icmp_reachable:p.code===0,arp_or_host_discovery_reachable:arpUp,reachable:p.code===0||arpUp});}
    let isolation={status:'not_tested',gateway_reachable:gatewayReachable,peers:peerResults,note:'A single station cannot prove AP/client isolation unless known-live same-subnet peer targets are supplied.'};if(peerResults.some(x=>x.same_subnet)){if(peerResults.some(x=>x.reachable))isolation.status='not_detected_for_tested_peers';else if(gatewayReachable===true)isolation.status='possible_client_isolation_or_peer_filtering';else isolation.status='inconclusive';}
    let l2={observed:false};if(a.observe_l2===true){requireCapture();if(!dev)throw new Error('interface is required for L2 observation');const r=await optional('tshark',['-n','-p','-i',dev,'-a',`duration:${sec}`,'-c','100','-Y','lldp || cdp','-T','fields','-E','separator=|','-e','frame.time_epoch','-e','eth.src','-e','lldp.chassis.id','-e','lldp.port.id','-e','cdp.deviceid','-e','cdp.portid'],{timeout:(sec+5)*1000,maxBuffer:2*1024*1024});const packets=r.stdout.split(/\r?\n/).filter(Boolean).slice(0,100).map(line=>{const f=line.split('|');return{timestamp:f[0]||null,source_mac:f[1]||null,lldp_chassis:f[2]||null,lldp_port:f[3]||null,cdp_device:f[4]||null,cdp_port:f[5]||null};});l2={observed:true,packet_count:packets.length,packets,diagnostics:clip(r.stderr,1000)};}
    return{scope:process.env.SECURITY_NETWORK_SCOPE||'security-container-network',warning:HOST_SCOPE_WARNING,selected_interface:dev,local_subnets:localCidrs,connected_subnets:subnets,default_routes:state.routes.filter(r=>r.dst==='default'),vlans,multiple_subnets:uniq(subnets.map(x=>x.subnet)).length>1,mdns_reflector_assessment:mdns,client_isolation_assessment:isolation,l2_discovery:l2,complete:true};
  }
  async function wireless(a={}){
    const state=await networkState(),wirelessIfs=state.wireless,dev=validInterface(a.interface)||wirelessIfs.find(x=>x.type==='managed')?.interface||wirelessIfs[0]?.interface;if(!dev)throw new Error('no Wi-Fi interface is visible; host-network mode is required for laptop wireless analysis');if(!wirelessIfs.some(x=>x.interface===dev))throw new Error(`interface is not reported by iw as Wi-Fi: ${dev}`);
    const [linkR,infoR,stationR]=await Promise.all([optional('iw',['dev',dev,'link'],{timeout:7000,maxBuffer:512*1024}),optional('iw',['dev',dev,'info'],{timeout:7000,maxBuffer:512*1024}),optional('iw',['dev',dev,'station','dump'],{timeout:7000,maxBuffer:2*1024*1024})]),current=parseIwLink(linkR.stdout),stations=parseIwStations(stationR.stdout),mode=/\btype\s+(\S+)/.exec(infoR.stdout)?.[1]||wirelessIfs.find(x=>x.interface===dev)?.type||null;
    let aps=[];const nm=await optional('nmcli',['-t','--escape','yes','-f','IN-USE,BSSID,SSID,CHAN,FREQ,RATE,SIGNAL,SECURITY','device','wifi','list','ifname',dev,'--rescan',a.rescan===false?'no':'yes'],{timeout:20000,maxBuffer:4*1024*1024});if(nm.code===0){for(const line of nm.stdout.split(/\r?\n/).filter(Boolean)){const f=parseNmcliLine(line);if(f.length<8)continue;aps.push({in_use:f[0]==='*',bssid:f[1]?.toUpperCase()||null,ssid:f[2]||null,channel:Number(f[3])||null,frequency_mhz:Number(f[4])||null,band:freqBand(f[4]),rate:f[5]||null,signal:Number(f[6])||null,security:f[7]||null});}}
    if(!aps.length&&a.rescan!==false){const iwscan=await optional('iw',['dev',dev,'scan'],{timeout:25000,maxBuffer:8*1024*1024});let cur=null;for(const raw of iwscan.stdout.split(/\r?\n/)){const line=raw.trim();const b=/^BSS\s+([0-9a-f:]{17})/i.exec(line);if(b){cur={bssid:b[1].toUpperCase(),ssid:null,frequency_mhz:null,channel:null,signal:null,security:null};aps.push(cur);continue;}if(!cur)continue;if(line.startsWith('SSID:'))cur.ssid=line.slice(5).trim();else if(/^freq:/.test(line)){cur.frequency_mhz=Number(line.split(':')[1].trim())||null;cur.band=freqBand(cur.frequency_mhz);}else if(/^signal:/.test(line))cur.signal=Number(line.split(':')[1].trim().split(/\s+/)[0])||null;else if(/DS Parameter set: channel/.test(line))cur.channel=Number(line.match(/channel\s+(\d+)/)?.[1])||null;else if(/^RSN:|^WPA:/.test(line))cur.security=uniq([cur.security,line.replace(':','')]).filter(Boolean).join('+');}}
    let airodump=null;if(a.use_airodump===true){requireCapture();const mon=validInterface(a.monitor_interface);if(!mon)throw new Error('monitor_interface is required when use_airodump=true; the tool will not create or alter monitor mode');const sec=Math.max(3,Math.min(30,Number(a.duration_seconds||10))),dir=await fsp.mkdtemp(path.join(os.tmpdir(),'airodump-')),prefix=path.join(dir,'capture');try{const r=await optional('timeout',['--signal=INT',`${sec}s`,'airodump-ng','--write',prefix,'--output-format','csv','--write-interval','1',mon],{timeout:(sec+5)*1000,maxBuffer:2*1024*1024});let csv='';try{csv=await fsp.readFile(prefix+'-01.csv','utf8');}catch{}airodump={interface:mon,...parseAirodumpCsv(csv),complete:[0,124,130].includes(r.code),diagnostics:clip(r.stderr,1000)};}finally{await fsp.rm(dir,{recursive:true,force:true});}}
    const phy=phyFromText(`${linkR.stdout}\n${stationR.stdout}`)||current.phy||null,channel=/channel\s+(\d+)\s+\((\d+)\s+MHz\)/i.exec(infoR.stdout),channelAnalysis=analyzeChannels(aps);
    return{scope:process.env.SECURITY_NETWORK_SCOPE||'security-container-network',warning:HOST_SCOPE_WARNING,interface:dev,mode,current_connection:{...current,phy,channel:channel?Number(channel[1]):null,frequency_mhz:channel?Number(channel[2]):current.frequency_mhz},nearby_access_points:aps,channel_analysis:channelAnalysis,visible_stations:stations,station_visibility_note:mode==='AP'?'AP mode can expose associated client stations supported by the driver.':'Managed/client mode normally exposes only the connected AP/peer, not every Wi-Fi client on the LAN.',airodump,complete:true};
  }
  function normalizeMapData(data){
    const discovery=data.perform_network_discovery||data.discovery||data.network_discovery||data,interfaceInfo=data.get_host_interface_info||data.interface_info||data.host_interface||{},topology=data.analyze_network_topology||data.topology||{},wirelessData=data.analyze_wireless_environment||data.wireless||{};return{discovery,interfaceInfo,topology,wireless:wirelessData};
  }
  function buildDot(input,title){
    const {discovery,interfaceInfo,topology,wireless}=normalizeMapData(input);
    const hosts=Array.isArray(discovery.hosts)?discovery.hosts:[];
    const sel=interfaceInfo.selected_interface||discovery.selected_interface||topology.selected_interface||wireless.interface||null;
    const ifaceInfo=(interfaceInfo.interfaces||[]).find(x=>x.name===sel)||{};
    const gateway=interfaceInfo.default_routes?.find(x=>!sel||x.interface===sel)?.gateway||topology.default_routes?.find(x=>!sel||x.dev===sel)?.gateway||null;
    const connection=interfaceInfo.connection_type||ifaceInfo.type||(wireless.current_connection?.connected?'wifi':null);
    const internet=interfaceInfo.internet?.status==='online';
    const currentWifi=wireless.current_connection||{};
    const stationMacs=new Map((wireless.visible_stations||[]).filter(x=>x.mac).map(x=>[String(x.mac).toUpperCase(),x]));
    const cidrCandidates=uniq([
      ...(Array.isArray(discovery.cidrs)?discovery.cidrs:[]),
      ...(Array.isArray(topology.local_subnets)?topology.local_subnets:[]),
      ...(Array.isArray(topology.connected_subnets)?topology.connected_subnets.map(x=>x.subnet):[])
    ]).filter(c=>/^\d+\.\d+\.\d+\.\d+\/\d+$/.test(String(c)));
    const vlanBySubnet=new Map();
    for(const row of topology.connected_subnets||[]){
      const vlan=(topology.vlans||[]).find(v=>v.interface===row.interface);
      if(row.subnet&&vlan?.vlan_id!=null)vlanBySubnet.set(row.subnet,vlan.vlan_id);
    }
    function hostSubnet(address){return cidrCandidates.find(c=>isIP(address)===4&&ipv4InCidr(address,c))||'Other / unclassified';}
    const groups=new Map();
    for(const h of hosts){const k=hostSubnet(h.address);if(!groups.has(k))groups.set(k,[]);groups.get(k).push(h);}

    const lines=[
      'digraph network {',
      '  graph [rankdir=TB, bgcolor="#f8fafc", fontname="Inter", label="'+dotEscape(title)+'", labelloc=t, fontcolor="#0f172a", fontsize=22, pad=0.35, nodesep=0.45, ranksep=0.75, compound=true, splines=polyline];',
      '  node [shape=box, style="rounded,filled", fontname="Inter", color="#94a3b8", fontcolor="#0f172a", fillcolor="#ffffff", margin="0.16,0.11"];',
      '  edge [fontname="Inter", color="#64748b", fontcolor="#475569", arrowsize=0.7];'
    ];
    if(internet) lines.push('  internet [shape=oval, fillcolor="#dbeafe", color="#3b82f6", label="Internet"];');
    if(gateway) lines.push(`  gateway [shape=hexagon, fillcolor="#ede9fe", color="#7c3aed", label="Gateway / Router\n${dotEscape(gateway)}"];`);
    if(internet&&gateway) lines.push('  internet -> gateway [dir=both, arrowhead=normal, arrowtail=normal, label="WAN"];');

    let clientParent=gateway?'gateway':(internet?'internet':'laptop');
    if(connection==='wifi'&&(currentWifi.connected||currentWifi.ssid||currentWifi.bssid)){
      const apLabel=['Wi-Fi AP / Router',currentWifi.ssid?`SSID: ${currentWifi.ssid}`:null,currentWifi.bssid?`BSSID: ${currentWifi.bssid}`:null,currentWifi.channel?`Channel ${currentWifi.channel}`:null,currentWifi.phy||null].filter(Boolean).map(safeLabel).join('\n');
      lines.push(`  accesspoint [shape=diamond, fillcolor="#fef3c7", color="#d97706", label="${dotEscape(apLabel)}"];`);
      if(gateway) lines.push('  gateway -> accesspoint [dir=none, label="LAN / WLAN"];');
      clientParent='accesspoint';
    }
    const laptopLabel=['Recon Laptop',sel||null,connection||null,ifaceInfo.link?.speed||currentWifi.tx_bitrate||null].filter(Boolean).map(safeLabel).join('\n');
    lines.push(`  laptop [shape=box3d, fillcolor="#ccfbf1", color="#0f766e", label="${dotEscape(laptopLabel)}"];`);
    const laptopParent=connection==='wifi'&&clientParent==='accesspoint'?'accesspoint':(gateway?'gateway':clientParent);
    const laptopStyle=connection==='wifi'?'dashed':'solid';
    const laptopSpeed=ifaceInfo.link?.speed||currentWifi.tx_bitrate||'';
    lines.push(`  ${laptopParent} -> laptop [dir=none, style=${laptopStyle}, label="${connection==='wifi'?'Wi-Fi':'wired'}${laptopSpeed?` · ${dotEscape(laptopSpeed)}`:''}"];`);

    let idx=0,cluster=0;
    const hostEdges=[];
    for(const [subnet,groupHosts] of groups){
      const clusterId=`cluster_net_${cluster++}`,vlan=vlanBySubnet.get(subnet),clusterLabel=subnet==='Other / unclassified'?subnet:`Subnet ${subnet}${vlan!=null?` · VLAN ${vlan}`:''}`;
      lines.push(`  subgraph ${clusterId} {`);
      lines.push(`    label="${dotEscape(clusterLabel)}"; style="rounded,dashed"; color="#94a3b8"; fontname="Inter"; fontcolor="#334155"; bgcolor="#ffffff";`);
      for(const h of groupHosts){
        const id=`host${idx++}`,osName=h.os?.name||h.os||'OS unknown';
        const ports=(h.open_ports||h.ports||[]).slice(0,12).map(p=>`${p.port}/${p.protocol||'tcp'}${p.service?` ${p.service}`:''}`).join(', ');
        const shares=(h.shares||[]).slice(0,6).map(x=>x.name||x).join(', ');
        const media=(h.media_services||[]).slice(0,4).map(x=>x.product||x.service||x.port).join(', ');
        const station=h.mac&&stationMacs.get(String(h.mac).toUpperCase());
        const kind=station?'wifi':(h.connection_type||'unknown');
        const fill=kind==='wifi'?'#fff7ed':kind==='wired'?'#f0fdf4':'#f8fafc',color=kind==='wifi'?'#ea580c':kind==='wired'?'#16a34a':'#64748b';
        const labelParts=[h.hostname||h.address,h.hostname?h.address:null,h.mac?`MAC: ${h.mac}`:null,osName,ports?`Ports: ${ports}`:null,shares?`Shares: ${shares}`:null,media?`Media: ${media}`:null];
        lines.push(`    ${id} [fillcolor="${fill}", color="${color}", label="${dotEscape(labelParts.filter(Boolean).map(safeLabel).join('\n'))}"];`);
        const parent=station&&clientParent==='accesspoint'?'accesspoint':(gateway?'gateway':clientParent),style=kind==='wifi'?'dashed':'solid',edgeLabel=station?.tx_bitrate||h.link_speed||'';
        hostEdges.push(`  ${parent} -> ${id} [dir=none, style=${style}${edgeLabel?`, label="${dotEscape(edgeLabel)}"`:''}];`);
      }
      lines.push('  }');
    }
    lines.push(...hostEdges);
    for(const vlan of topology.vlans||[]){
      if(vlan.vlan_id==null)continue;
      const vlanId=Number(vlan.vlan_id);
      if(!Number.isInteger(vlanId))continue;
      lines.push(`  vlan_${vlanId} [shape=tab, fillcolor="#e0f2fe", color="#0284c7", label="VLAN ${vlanId}\n${dotEscape(vlan.interface||'')}"];`);
      if(gateway)lines.push(`  gateway -> vlan_${vlanId} [dir=none, style=dotted];`);
    }
    lines.push('  legend [shape=note, fillcolor="#f1f5f9", color="#94a3b8", label="Solid edge = wired/unknown\nDashed edge = observed Wi-Fi\nGreen node = known wired host\nOrange node = observed Wi-Fi station\nDashed boxes = subnet/VLAN groups"];');
    lines.push('}');
    return lines.join('\n');
  }
  async function graph(a={}){
    let data=a.data;if(a.input_path){const p=safeWorkspace(a.input_path,{mustExist:true});data=JSON.parse(await fsp.readFile(p,'utf8'));}if(!data||typeof data!=='object'||Array.isArray(data))throw new Error('provide data or input_path containing a JSON object');const baseRel=a.output_base||'.security-results/network-map';if(/\.(svg|html|dot|json)$/i.test(baseRel))throw new Error('output_base must not include an extension');const base=safeWorkspace(baseRel),title=String(a.title||'Network Map').slice(0,120),format=a.format||'both';await fsp.mkdir(path.dirname(base),{recursive:true});const dot=buildDot(data,title),dotPath=base+'.dot',svgPath=base+'.svg',htmlPath=base+'.html';await fsp.writeFile(dotPath,dot+'\n',{mode:0o600});const r=await runStatus('dot',['-Tsvg',dotPath,'-o',svgPath],{timeout:20000,maxBuffer:1024*1024});if(r.code!==0)throw new Error(`graphviz dot failed: ${clip(r.stderr||r.stdout,3000)}`);const outputs={dot:path.relative(workspaceRoot,dotPath),svg:null,html:null};if(format==='svg'||format==='both')outputs.svg=path.relative(workspaceRoot,svgPath);if(format==='html'||format==='both'){const svg=await fsp.readFile(svgPath,'utf8'),html=`<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${safeLabel(title)}</title><style>html,body{margin:0;background:#111827;color:#f9fafb;font-family:system-ui,sans-serif}main{padding:20px;overflow:auto}svg{max-width:100%;height:auto}h1{font-size:1.25rem}</style></head><body><main><h1>${safeLabel(title)}</h1>${svg}</main></body></html>`;await fsp.writeFile(htmlPath,html,{mode:0o600});outputs.html=path.relative(workspaceRoot,htmlPath);}if(format==='html'){await fsp.rm(svgPath,{force:true});}return{title,format,outputs,host_count:(normalizeMapData(data).discovery.hosts||[]).length,complete:true};
  }

  async function call(name,a={}){
    if(NETWORK_RECON_HOST_TOOL_NAMES.has(name)){
      if(delegateSocket&&fs.existsSync(delegateSocket)){
        try{return await delegateToHost(name,a);}
        catch(error){throw new Error(`host recon helper failed: ${error.message}`);}
      }
      if(requireHostHelper)throw new Error('host recon helper unavailable; refusing to substitute the mcp-security container namespace for the laptop/client LAN');
    }
    switch(name){
      case 'get_host_interface_info': return interfaceInfo(a);
      case 'perform_network_discovery': return discover(a);
      case 'analyze_network_topology': return topology(a);
      case 'analyze_wireless_environment': return wireless(a);
      case 'generate_graphical_network_map': return graph(a);
      default: throw new Error(`unknown network recon tool: ${name}`);
    }
  }
  return{call};
}
