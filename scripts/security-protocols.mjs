#!/usr/bin/env node
import { isIP } from 'node:net';

const obj = (description, properties = {}, required = []) => ({ type:'object', description, properties, required, additionalProperties:false });
const str = (description, extra={}) => ({ type:'string', description, ...extra });
const integer = (description, minimum, maximum, extra={}) => ({ type:'integer', description, minimum, maximum, ...extra });
const bool = description => ({ type:'boolean', description });
const tool = (name, description, properties={}, required=[]) => ({ name, description, inputSchema:obj(description, properties, required) });

const target = str('Authorized private/allowlisted hostname or IP address.');
const iface = str('Optional interface visible inside the mcp-security container, such as eth0.', { maxLength:64 });
const shortTimeout = integer('Maximum protocol probe duration in seconds; default 15, maximum 60.', 3, 60);

export const PROTOCOL_TOOLS = [
  tool('mdns_discover', 'mDNS/DNS-SD discovery: enumerate Zeroconf services and TXT metadata. Supply target for unicast UDP/5353 probing; omit target for multicast discovery limited to the security-container network namespace.', { target, interface:iface, timeout_seconds:shortTimeout }),
  tool('upnp_discover', 'UPnP/SSDP discovery: identify UPnP devices, description URLs, product/model metadata, and advertised services. Supply target for unicast UDP/1900 probing; omit target for multicast discovery limited to the security-container network namespace.', { target, interface:iface, timeout_seconds:shortTimeout }),
  tool('dhcp_discover', 'DHCP discovery: retrieve DHCP server/network options without lease-starvation behavior. Supply a DHCP server target for bounded DHCPINFORM probing; omit target for broadcast discovery limited to the security-container network namespace.', { target, interface:iface, timeout_seconds:shortTimeout }),
  tool('dhcp6_discover', 'DHCPv6 multicast discovery: enumerate DHCPv6 advertisements and returned options from interfaces visible inside the security-container network namespace.', { interface:iface, timeout_seconds:shortTimeout }),
  tool('dns_audit', 'DNS server audit: inspect response flags, recursion availability, DNSSEC response evidence, NSID/version disclosure, and optionally attempt one explicit AXFR zone-transfer check against an authorized DNS server.', { server:target, domain:str('Domain to query and, if requested, use for the AXFR check.'), check_axfr:bool('Attempt one AXFR request; default false.'), timeout_seconds:shortTimeout }, ['server','domain']),
  tool('snmp_discover', 'SNMP discovery: perform bounded read-only SNMP service/system identification against UDP/161. No brute force and no SNMP SET operations are exposed.', { target, port:integer('SNMP UDP port; default 161.',1,65535), timeout_seconds:shortTimeout }, ['target']),
  tool('snmp_interfaces', 'SNMP interface discovery: enumerate interface/address/link metadata exposed by an authorized SNMP service. Read-only; no SNMP SET operations or credential guessing.', { target, port:integer('SNMP UDP port; default 161.',1,65535), timeout_seconds:shortTimeout }, ['target']),
  tool('smb_audit', 'SMB protocol audit: inspect supported SMB dialects, message-signing posture, and anonymous OS/server metadata using safe Nmap SMB discovery scripts.', { target, port:integer('SMB TCP port; default 445.',1,65535), timeout_seconds:shortTimeout }, ['target']),
  tool('smb_shares', 'SMB share enumeration: perform bounded read-only share discovery and report anonymous/restricted access metadata. This uses Nmap smb-enum-shares and never writes to a share.', { target, port:integer('SMB TCP port; default 445.',1,65535), timeout_seconds:shortTimeout }, ['target']),
  tool('ntp_discover', 'NTP discovery: retrieve time, stratum, reference ID, implementation/version, and other read-only NTP metadata from an authorized UDP/123 service.', { target, port:integer('NTP UDP port; default 123.',1,65535), timeout_seconds:shortTimeout }, ['target']),
  tool('ldap_discover', 'LDAP RootDSE discovery: retrieve unauthenticated naming contexts, supported LDAP versions, controls, SASL mechanisms, capabilities, and server metadata from an authorized LDAP service.', { target, port:integer('LDAP TCP port; default 389. Common values are 389 and 636.',1,65535), timeout_seconds:shortTimeout }, ['target']),
  tool('protocol_observe', 'Passively observe LLDP, CDP, or LLMNR/NetBIOS advertisements on a Security-container interface. Returns bounded packet metadata; requires SECURITY_ALLOW_PACKET_CAPTURE=true.', { protocol:str('Protocol to observe.',{enum:['lldp','cdp','llmnr_nbns']}), interface:str('Interface visible inside mcp-security.'), duration_seconds:integer('Observation duration; default 8, maximum 30 seconds.',1,30), max_packets:integer('Packet limit; default 50, or 100 for LLMNR/NBNS; maximum 300.',1,300) }, ['protocol','interface']),
  tool('wsd_discover', 'WS-Discovery discovery: identify Windows, printer, IoT, and WCF endpoints using UDP/3702. Supply target for unicast probing; omit target for multicast discovery limited to the security-container network namespace.', { target, interface:iface, timeout_seconds:shortTimeout }),
  tool('arp_discover', 'ARP-based IPv4 discovery: perform bounded Nmap ARP host discovery against an authorized private/allowlisted target or CIDR. ARP is effective only when the target is directly connected to the security-container network namespace.', { target:str('Authorized private/allowlisted IPv4 address or CIDR.'), timeout_seconds:shortTimeout }, ['target']),
  tool('ndp_discover', 'IPv6 NDP neighbor inspection: return the IPv6 neighbor cache visible inside the security-container network namespace, optionally restricted to one interface.', { interface:iface }),
];

export const PROTOCOL_TOOL_NAMES = new Set(PROTOCOL_TOOLS.map(t => t.name));

const CONTAINER_NETWORK_WARNING = 'Broadcast, multicast, ARP, NDP, LLDP, CDP and passive local-name-resolution visibility is limited to the mcp-security container network namespace. Docker bridge networking may not expose the physical LAN; prefer a target-specific probe when supported.';

function clip(value, max=12000) {
  const text = String(value ?? '');
  return Buffer.byteLength(text) <= max ? text : text.slice(0,max) + `\n...[truncated at ${max} bytes]`;
}
function validInterface(value) {
  if (value == null || value === '') return null;
  const v=String(value);
  if (!/^[A-Za-z0-9_.:@-]{1,64}$/.test(v)) throw new Error('invalid interface');
  return v;
}
function xmlDecode(value='') {
  return value
    .replace(/&#x([0-9a-fA-F]+);/g,(_,x)=>String.fromCodePoint(parseInt(x,16)))
    .replace(/&#([0-9]+);/g,(_,x)=>String.fromCodePoint(parseInt(x,10)))
    .replace(/&quot;/g,'"').replace(/&apos;/g,"'").replace(/&lt;/g,'<').replace(/&gt;/g,'>').replace(/&amp;/g,'&');
}
function attr(text,name) {
  const m=new RegExp(`\\b${name}="([^"]*)"`).exec(text);
  return m ? xmlDecode(m[1]) : null;
}
function flattenFields(output='') {
  const out={};
  for (let line of String(output).split(/\r?\n/)) {
    line=line.trim().replace(/^\|[_ ]?/,'').trim();
    if(!line) continue;
    const m=/^([^:]{1,80}):\s*(.*)$/.exec(line);
    if(!m) continue;
    const key=m[1].toLowerCase().replace(/[^a-z0-9]+/g,'_').replace(/^_|_$/g,'');
    if(!key) continue;
    const value=m[2].trim();
    if(out[key]===undefined) out[key]=value;
    else if(Array.isArray(out[key])) out[key].push(value);
    else out[key]=[out[key],value];
  }
  return out;
}
function parseNmapScripts(xml='') {
  const scripts=[];
  for (const m of String(xml).matchAll(/<script\b([^>]*)>/g)) {
    const id=attr(m[1],'id'), output=attr(m[1],'output');
    if(!id) continue;
    scripts.push({ id, fields:flattenFields(output||''), output:clip(output||'',8000) });
  }
  return scripts;
}
function parseGrepHosts(text='') {
  const hosts=[];
  for(const line of String(text).split(/\r?\n/)) {
    if(!line.startsWith('Host: ')) continue;
    const m=/^Host:\s+(\S+)\s+\(([^)]*)\)\s+(.*)$/.exec(line); if(!m) continue;
    const rest=m[3], status=/Status:\s+(\w+)/.exec(rest)?.[1]||null;
    const mac=/MAC:\s+([0-9A-Fa-f:]{17})(?:\s+\(([^)]*)\))?/.exec(rest);
    hosts.push({address:m[1],hostname:m[2]||null,status,mac:mac?.[1]?.toUpperCase()||null,vendor:mac?.[2]||null});
  }
  return hosts;
}
function parseDigHeader(text='') {
  const header=/;; ->>HEADER<<- opcode:\s*(\S+), status:\s*(\S+), id:/i.exec(text);
  const flags=/;; flags:\s*([^;]+);/i.exec(text)?.[1]?.trim().split(/\s+/).filter(Boolean)||[];
  return { status:header?.[2]||null, flags, recursion_available:flags.includes('ra'), authoritative_answer:flags.includes('aa'), authenticated_data:flags.includes('ad') };
}
function dataLines(text='') { return String(text).split(/\r?\n/).map(x=>x.trim()).filter(x=>x&&!x.startsWith(';')); }
function compactPacket(item, protocolKeys=[]) {
  const layers=item?._source?.layers||{};
  const packet={
    time:layers.frame?.['frame.time_epoch'] ?? null,
    source_mac:layers.eth?.['eth.src'] ?? null,
    source_ipv4:layers.ip?.['ip.src'] ?? null,
    source_ipv6:layers.ipv6?.['ipv6.src'] ?? null,
  };
  for(const key of protocolKeys) if(layers[key]!=null) packet[key]=layers[key];
  return packet;
}

export function createProtocolSecurity(ctx) {
  const { runStatus, assertAuthorizedTarget, requireActive, requireCapture } = ctx;
  if(typeof runStatus!=='function'||typeof assertAuthorizedTarget!=='function'||typeof requireActive!=='function'||typeof requireCapture!=='function') throw new Error('invalid protocol security context');

  async function nmap(args, timeoutMs=40000) {
    const r=await runStatus('nmap',[...args,'-oX','-'],{timeout:timeoutMs,maxBuffer:8*1024*1024});
    const scripts=parseNmapScripts(r.stdout);
    if(r.code!==0 && !r.stdout.includes('<nmaprun')) throw new Error(`nmap exited ${r.code}: ${clip(r.stderr||r.stdout,3000)}`);
    return { exit_code:r.code, complete:r.code===0&&!r.timed_out, scripts, diagnostics:clip(r.stderr,2000) };
  }
  async function targetScript({target:rawTarget, port, udp=false, scripts, timeoutSeconds=15, version=false}) {
    const target=await assertAuthorizedTarget(rawTarget);
    const sec=Math.max(3,Math.min(60,Number(timeoutSeconds||15)));
    const args=[udp?'-sU':'-sT','-Pn','-n'];
    if(version) args.push('-sV','--version-light');
    args.push('-p',String(port),'--script',scripts.join(','),'--script-timeout',`${sec}s`,'--host-timeout',`${sec}s`,target);
    return { scope:'target-scan', target, ...(await nmap(args,(sec+10)*1000)) };
  }
  async function broadcastScript(script,{ipv6=false,interface:interfaceName=null,timeoutSeconds=15}={}) {
    requireActive();
    const sec=Math.max(3,Math.min(60,Number(timeoutSeconds||15))), dev=validInterface(interfaceName);
    const args=['-n']; if(ipv6) args.push('-6'); if(dev) args.push('-e',dev);
    args.push('--script',script,'--script-timeout',`${sec}s`);
    return { scope:'security-container-network', interface:dev, warning:CONTAINER_NETWORK_WARNING, ...(await nmap(args,(sec+10)*1000)) };
  }
  async function tsharkObserve(interfaceName,{durationSeconds=8,maxPackets=50,filter,captureFilter,protocolKeys}) {
    requireCapture();
    const dev=validInterface(interfaceName); if(!dev) throw new Error('interface is required');
    const sec=Math.max(1,Math.min(30,Number(durationSeconds||8))), cap=Math.max(1,Math.min(300,Number(maxPackets||50)));
    const args=['-n','-p','-i',dev,'-a',`duration:${sec}`,'-c',String(cap),'-f',captureFilter,'-Y',filter,'-T','json'];
    const r=await runStatus('tshark',args,{timeout:(sec+10)*1000,maxBuffer:16*1024*1024});
    let json=[]; try{json=JSON.parse(r.stdout||'[]');}catch{if(r.code===0) throw new Error('tshark returned invalid JSON');}
    if(r.code!==0 && !json.length) throw new Error(`tshark exited ${r.code}: ${clip(r.stderr||r.stdout,3000)}`);
    const packets=(Array.isArray(json)?json:[]).slice(0,cap).map(x=>compactPacket(x,protocolKeys));
    return { scope:'security-container-network', interface:dev, warning:CONTAINER_NETWORK_WARNING, packet_count:packets.length, packets, complete:r.code===0&&!r.timed_out, diagnostics:clip(r.stderr,2000) };
  }

  async function call(name,a={}) {
    switch(name) {
      case 'mdns_discover': {
        requireActive();
        if(a.target) return { protocol:'mdns/dns-sd', mode:'target', ...(await targetScript({target:a.target,port:5353,udp:true,scripts:['dns-service-discovery'],timeoutSeconds:a.timeout_seconds})) };
        return { protocol:'mdns/dns-sd', mode:'multicast', ...(await broadcastScript('broadcast-dns-service-discovery',{interface:a.interface,timeoutSeconds:a.timeout_seconds})) };
      }
      case 'upnp_discover': {
        requireActive();
        if(a.target) return { protocol:'upnp/ssdp', mode:'target', ...(await targetScript({target:a.target,port:1900,udp:true,scripts:['upnp-info'],timeoutSeconds:a.timeout_seconds})) };
        return { protocol:'upnp/ssdp', mode:'multicast', ...(await broadcastScript('broadcast-upnp-info',{interface:a.interface,timeoutSeconds:a.timeout_seconds})) };
      }
      case 'dhcp_discover': {
        requireActive();
        if(a.target) return { protocol:'dhcp', mode:'target-dhcpinform', ...(await targetScript({target:a.target,port:67,udp:true,scripts:['dhcp-discover'],timeoutSeconds:a.timeout_seconds})) };
        return { protocol:'dhcp', mode:'broadcast', ...(await broadcastScript('broadcast-dhcp-discover',{interface:a.interface,timeoutSeconds:a.timeout_seconds})) };
      }
      case 'dhcp6_discover': {
        requireActive();
        return { protocol:'dhcpv6', mode:'multicast', ...(await broadcastScript('broadcast-dhcp6-discover',{ipv6:true,interface:a.interface,timeoutSeconds:a.timeout_seconds})) };
      }
      case 'dns_audit': {
        requireActive();
        const server=await assertAuthorizedTarget(a.server), domain=String(a.domain||'').trim();
        if(!/^[A-Za-z0-9._-]{1,253}\.?$/.test(domain)||domain.startsWith('-')) throw new Error('invalid domain');
        const sec=Math.max(3,Math.min(60,Number(a.timeout_seconds||15))), timeout=Math.min(5,Math.max(1,Math.floor(sec/3)));
        const base=await runStatus('dig',[`@${server}`,domain,'A',`+time=${timeout}`,'+tries=1','+comments','+answer','+authority','+additional'],{timeout:sec*1000,maxBuffer:1024*1024});
        const dnssec=await runStatus('dig',[`@${server}`,domain,'A','+dnssec',`+time=${timeout}`,'+tries=1','+comments','+answer'],{timeout:sec*1000,maxBuffer:1024*1024});
        const version=await runStatus('dig',[`@${server}`,'version.bind','TXT','CH','+short',`+time=${timeout}`,'+tries=1'],{timeout:sec*1000,maxBuffer:1024*1024});
        const nsid=await runStatus('dig',[`@${server}`,'id.server','TXT','CH','+nsid',`+time=${timeout}`,'+tries=1','+comments','+answer'],{timeout:sec*1000,maxBuffer:1024*1024});
        let axfr={attempted:false};
        if(a.check_axfr===true) {
          const r=await runStatus('dig',[`@${server}`,domain,'AXFR',`+time=${timeout}`,'+tries=1'],{timeout:sec*1000,maxBuffer:4*1024*1024});
          const records=dataLines(r.stdout), failed=/transfer failed|status:\s*(?:REFUSED|SERVFAIL|NOTAUTH)|connection timed out/i.test(r.stdout+r.stderr);
          axfr={attempted:true,succeeded:r.code===0&&!failed&&records.some(x=>/\sSOA\s/i.test(x)),record_count:records.length,records:records.slice(0,100),truncated:records.length>100,diagnostics:clip(r.stderr,1000)};
        }
        const header=parseDigHeader(base.stdout), dnssecHeader=parseDigHeader(dnssec.stdout);
        return { scope:'target-scan', server, domain, response:header, dnssec:{authenticated_data:dnssecHeader.authenticated_data,rrsig_present:/\sRRSIG\s/i.test(dnssec.stdout),status:dnssecHeader.status}, version_bind:dataLines(version.stdout).slice(0,10), nsid:clip(nsid.stdout,3000), axfr, complete:base.code===0 };
      }
      case 'snmp_discover': {
        requireActive();
        return { protocol:'snmp', ...(await targetScript({target:a.target,port:a.port||161,udp:true,version:true,scripts:['snmp-info','snmp-sysdescr'],timeoutSeconds:a.timeout_seconds})) };
      }
      case 'snmp_interfaces': {
        requireActive();
        return { protocol:'snmp', ...(await targetScript({target:a.target,port:a.port||161,udp:true,scripts:['snmp-interfaces'],timeoutSeconds:a.timeout_seconds})) };
      }
      case 'smb_audit': {
        requireActive();
        return { protocol:'smb', ...(await targetScript({target:a.target,port:a.port||445,scripts:['smb-protocols','smb2-security-mode','smb-os-discovery'],timeoutSeconds:a.timeout_seconds})) };
      }
      case 'smb_shares': {
        requireActive();
        return { protocol:'smb', assessment:'read-only share enumeration; Nmap categorizes smb-enum-shares as intrusive', ...(await targetScript({target:a.target,port:a.port||445,scripts:['smb-enum-shares'],timeoutSeconds:a.timeout_seconds})) };
      }
      case 'ntp_discover': {
        requireActive();
        return { protocol:'ntp', ...(await targetScript({target:a.target,port:a.port||123,udp:true,scripts:['ntp-info'],timeoutSeconds:a.timeout_seconds})) };
      }
      case 'ldap_discover': {
        requireActive();
        return { protocol:'ldap', ...(await targetScript({target:a.target,port:a.port||389,scripts:['ldap-rootdse'],timeoutSeconds:a.timeout_seconds})) };
      }
      case 'protocol_observe': {
        const presets={
          lldp:{filter:'lldp',captureFilter:'ether proto 0x88cc',protocolKeys:['lldp']},
          cdp:{filter:'cdp',captureFilter:'ether dst 01:00:0c:cc:cc:cc',protocolKeys:['cdp']},
          llmnr_nbns:{filter:'llmnr || nbns',captureFilter:'udp port 5355 or udp port 137',protocolKeys:['llmnr','nbns']}
        };
        if(!Object.hasOwn(presets,a.protocol)) throw new Error('Unsupported observation protocol');
        return {protocol:a.protocol,mode:'passive-only',...(await tsharkObserve(a.interface,{durationSeconds:a.duration_seconds,maxPackets:a.max_packets||(a.protocol==='llmnr_nbns'?100:50),...presets[a.protocol]}))};
      }
      case 'wsd_discover': {
        requireActive();
        if(a.target) return { protocol:'ws-discovery', mode:'target', ...(await targetScript({target:a.target,port:3702,udp:true,scripts:['wsdd-discover'],timeoutSeconds:a.timeout_seconds})) };
        return { protocol:'ws-discovery', mode:'multicast', ...(await broadcastScript('broadcast-wsdd-discover',{interface:a.interface,timeoutSeconds:a.timeout_seconds})) };
      }
      case 'arp_discover': {
        requireActive();
        const target=await assertAuthorizedTarget(a.target,{allowCidr:true});
        if(target.includes(':')) throw new Error('ARP discovery requires IPv4');
        const sec=Math.max(3,Math.min(60,Number(a.timeout_seconds||15)));
        const r=await runStatus('nmap',['-sn','-PR','-n','--host-timeout',`${sec}s`,'-oG','-',target],{timeout:(sec+15)*1000,maxBuffer:4*1024*1024});
        if(r.code!==0) throw new Error(`nmap exited ${r.code}: ${clip(r.stderr||r.stdout,3000)}`);
        const hosts=parseGrepHosts(r.stdout).filter(x=>x.status==='Up');
        return { protocol:'arp', scope:'security-container-network', warning:CONTAINER_NETWORK_WARNING, target, count:hosts.length, hosts, complete:true };
      }
      case 'ndp_discover': {
        const dev=validInterface(a.interface), args=['-6','neigh','show']; if(dev) args.push('dev',dev);
        const r=await runStatus('ip',args,{timeout:10000,maxBuffer:1024*1024});
        if(r.code!==0) throw new Error(`ip exited ${r.code}: ${clip(r.stderr||r.stdout,3000)}`);
        const neighbors=[];
        for(const line of r.stdout.split(/\r?\n/).filter(Boolean)) {
          const p=line.trim().split(/\s+/), address=p[0], di=p.indexOf('dev'), li=p.indexOf('lladdr');
          neighbors.push({address:isIP(address)===6?address:null,interface:di>=0?p[di+1]:null,mac:li>=0?p[li+1]:null,state:p.at(-1)||null,raw:line.trim()});
        }
        return { protocol:'ndp', scope:'security-container-network', warning:CONTAINER_NETWORK_WARNING, interface:dev, count:neighbors.length, neighbors, complete:true };
      }
      default: throw new Error(`unknown protocol tool: ${name}`);
    }
  }
  return { call };
}
