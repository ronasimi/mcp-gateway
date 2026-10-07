export const HOST_SCOPE_WARNING = 'Full laptop/LAN visibility requires mcp-security to run with the host network namespace. Under ordinary Docker bridge networking, interfaces, routes, multicast/broadcast discovery, ARP/NDP, iw/nmcli and packet observations describe only what that namespace can see.';
export const scopeWarning = () => process.env.SECURITY_NETWORK_SCOPE === 'host-network' ? null : HOST_SCOPE_WARNING;
export const MEDIA_PORTS = [1900,32400,32410,32412,32413,32414,8008,8009,8096,8200,8443,8920];
export const SHARE_PORTS = [111,139,445,548,873,2049];

// High-level laptop reconnaissance intentionally ignores virtual/logical interfaces for now.
// This prevents Docker/Podman bridges, veth pairs, VPN/tunnel devices, VLANs and similar
// software interfaces from becoming automatic scan targets. Explicit CIDRs remain subject to
// the normal private/allowlist policy.
export const VIRTUAL_LINK_KINDS = new Set([
  'bridge','veth','vlan','bond','team','tun','tap','tuntap','wireguard','vxlan','geneve',
  'gre','gretap','ip6gre','ip6gretap','sit','ipip','dummy','ifb','macvlan','macvtap',
  'ipvlan','vrf','vti','vti6','xfrm','netdevsim','nlmon','batadv','openvswitch'
]);
export const VIRTUAL_IFACE_NAME = /^(?:lo|docker\d*|br-|virbr|veth|cni|flannel|cali|kube|podman|tailscale|wg\d*|zt|tun\d*|tap\d*|vmnet|vboxnet|dummy|ifb|vxlan|geneve|gre|gretap|sit|ipip|bond\d*|team\d*)/i;

export function clip(value,max=12000){const text=String(value??'');return Buffer.byteLength(text)<=max?text:text.slice(0,max)+`\n...[truncated at ${max} bytes]`;}
export function validInterface(value){if(value==null||value==='')return null;const v=String(value);if(!/^[A-Za-z0-9_.:@-]{1,64}$/.test(v))throw new Error('invalid interface');return v;}
function xmlDecode(value=''){return value.replace(/&#x([0-9a-fA-F]+);/g,(_,x)=>String.fromCodePoint(parseInt(x,16))).replace(/&#([0-9]+);/g,(_,x)=>String.fromCodePoint(parseInt(x,10))).replace(/&quot;/g,'"').replace(/&apos;/g,"'").replace(/&lt;/g,'<').replace(/&gt;/g,'>').replace(/&amp;/g,'&');}
function attr(text,name){const m=new RegExp(`\\b${name}="([^"]*)"`).exec(text);return m?xmlDecode(m[1]):null;}
export function toJson(text,fallback=[]){try{return JSON.parse(text||'');}catch{return fallback;}}
function ipv4Int(ip){const p=String(ip).split('.').map(Number);if(p.length!==4||p.some(n=>!Number.isInteger(n)||n<0||n>255))return null;return (((p[0]<<24)>>>0)+(p[1]<<16)+(p[2]<<8)+p[3])>>>0;}
function intIpv4(n){return [24,16,8,0].map(s=>(n>>>s)&255).join('.');}
export function networkCidr(ip,prefix){const a=ipv4Int(ip),bits=Number(prefix);if(a==null||!Number.isInteger(bits)||bits<0||bits>32)return null;const mask=bits===0?0:(0xffffffff<<(32-bits))>>>0;return `${intIpv4(a&mask)}/${bits}`;}
export function ipv4InCidr(ip,cidr){const [net,bitsRaw]=String(cidr).split('/'),a=ipv4Int(ip),n=ipv4Int(net),bits=Number(bitsRaw);if(a==null||n==null||!Number.isInteger(bits)||bits<0||bits>32)return false;const mask=bits===0?0:(0xffffffff<<(32-bits))>>>0;return (a&mask)===(n&mask);}
export function privateIpv4(ip){const n=ipv4Int(ip);if(n==null)return false;return ipv4InCidr(ip,'10.0.0.0/8')||ipv4InCidr(ip,'172.16.0.0/12')||ipv4InCidr(ip,'192.168.0.0/16')||ipv4InCidr(ip,'169.254.0.0/16');}
export function uniq(xs){return [...new Set(xs.filter(Boolean))];}
export function safeLabel(v){return String(v??'').replace(/[\\{}|<>"\n\r]/g,' ').replace(/\s+/g,' ').trim();}
export function dotEscape(v){return String(v??'').replace(/\\/g,'\\\\').replace(/"/g,'\\"').replace(/\r?\n/g,'\\n');}
export function parseGrepHosts(text=''){
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
export function parseNmapXml(xml=''){
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
export function mergeHost(base,extra){
  const out={...base,...Object.fromEntries(Object.entries(extra).filter(([,v])=>v!=null))};
  const byPort=new Map();
  for(const p of [...(base.ports||[]),...(extra.ports||[])])byPort.set(`${p.protocol||'tcp'}:${p.port}`,{...byPort.get(`${p.protocol||'tcp'}:${p.port}`),...p});
  out.ports=[...byPort.values()].sort((a,b)=>a.port-b.port);
  out.scripts=[...(base.scripts||[]),...(extra.scripts||[])];
  return out;
}
export function parseNmcliLine(line){
  const fields=[];let cur='',esc=false;
  for(const ch of line){if(esc){cur+=ch;esc=false;}else if(ch==='\\')esc=true;else if(ch===':'){fields.push(cur);cur='';}else cur+=ch;}fields.push(cur);return fields;
}
export function freqBand(freq){const f=Number(freq);if(!f)return null;if(f<2500)return '2.4 GHz';if(f<5925)return '5 GHz';return '6 GHz';}
export function phyFromText(text=''){if(/EHT[- ]MCS|802\.11be/i.test(text))return'802.11be';if(/HE[- ]MCS|802\.11ax/i.test(text))return'802.11ax';if(/VHT[- ]MCS|802\.11ac/i.test(text))return'802.11ac';if(/\bMCS\b|802\.11n/i.test(text))return'802.11n';if(/802\.11a/i.test(text))return'802.11a';if(/802\.11g/i.test(text))return'802.11g';return null;}
export function parseIwDev(text=''){
  const out=[];let phy=null,current=null;
  for(const raw of String(text).split(/\r?\n/)){const line=raw.trim();if(line.startsWith('phy#'))phy=line;else if(line.startsWith('Interface ')){current={interface:line.slice(10).trim(),phy,type:null};out.push(current);}else if(current&&line.startsWith('type '))current.type=line.slice(5).trim();}
  return out;
}
export function parseIwLink(text=''){
  if(/Not connected/i.test(text))return{connected:false};
  const connected=/Connected to\s+([0-9a-f:]{17})/i.exec(text)?.[1]?.toUpperCase()||null;
  const field=name=>new RegExp(`^\\s*${name}:\\s*(.+)$`,'mi').exec(text)?.[1]?.trim()||null;
  const tx=field('tx bitrate'),rx=field('rx bitrate');
  return{connected:Boolean(connected),bssid:connected,ssid:field('SSID'),frequency_mhz:Number(field('freq'))||null,signal_dbm:Number((field('signal')||'').match(/-?\d+(?:\.\d+)?/)?.[0])||null,tx_bitrate:tx,rx_bitrate:rx,phy:phyFromText(`${text} ${tx||''} ${rx||''}`)};
}
export function parseIwStations(text=''){
  const blocks=String(text).split(/(?=^Station\s+[0-9a-f:]{17})/gmi).filter(x=>/^Station\s+/i.test(x.trim()));
  return blocks.map(block=>{const mac=/^Station\s+([0-9a-f:]{17})/mi.exec(block)?.[1]?.toUpperCase()||null;const val=n=>new RegExp(`^\\s*${n}:\\s*(.+)$`,'mi').exec(block)?.[1]?.trim()||null;const tx=val('tx bitrate'),rx=val('rx bitrate');return{mac,signal_dbm:Number((val('signal')||'').match(/-?\d+/)?.[0])||null,tx_bitrate:tx,rx_bitrate:rx,phy:phyFromText(`${block} ${tx||''} ${rx||''}`)};});
}
export function parseAirodumpCsv(text=''){
  const lines=String(text).split(/\r?\n/),aps=[],stations=[];let section='ap',headers=[];
  const csv=line=>{const out=[];let cur='',q=false;for(let i=0;i<line.length;i++){const c=line[i];if(c==='"'){if(q&&line[i+1]==='"'){cur+='"';i++;}else q=!q;}else if(c===','&&!q){out.push(cur.trim());cur='';}else cur+=c;}out.push(cur.trim());return out;};
  for(const line of lines){if(!line.trim()){headers=[];continue;}const f=csv(line);if(/^BSSID$/i.test(f[0])){section='ap';headers=f;continue;}if(/^Station MAC$/i.test(f[0])){section='station';headers=f;continue;}if(!headers.length)continue;const row=Object.fromEntries(headers.map((h,i)=>[h,f[i]??'']));if(section==='ap'&&/^[0-9A-F:]{17}$/i.test(row.BSSID||''))aps.push({bssid:row.BSSID.toUpperCase(),channel:Number(row.channel)||null,privacy:row.Privacy||null,cipher:row.Cipher||null,authentication:row.Authentication||null,power:Number(row.Power)||null,beacons:Number(row['# beacons'])||0,ssid:row.ESSID||null});else if(section==='station'&&/^[0-9A-F:]{17}$/i.test(row['Station MAC']||''))stations.push({mac:row['Station MAC'].toUpperCase(),bssid:/^[0-9A-F:]{17}$/i.test(row.BSSID||'')?row.BSSID.toUpperCase():null,power:Number(row.Power)||null,probed_essids:row['Probed ESSIDs']||null});}
  return{access_points:aps,stations};
}
export function analyzeChannels(aps=[]){
  const per={};for(const ap of aps){const ch=Number(ap.channel);if(!ch)continue;const key=String(ch);per[key]??={channel:ch,band:freqBand(ap.frequency_mhz),access_points:0,strongest_signal_percent:null,strongest_signal_dbm:null,overlap_score:0};per[key].access_points++;for(const unit of ['percent','dbm']){const value=ap['signal_'+unit];if(typeof value==='number'&&Number.isFinite(value))per[key]['strongest_signal_'+unit]=Math.max(per[key]['strongest_signal_'+unit]??-Infinity,value);}}
  const rows=Object.values(per).sort((a,b)=>a.channel-b.channel);for(const row of rows){row.overlap_score=aps.filter(ap=>{const ch=Number(ap.channel);if(!ch)return false;if(row.channel<=14&&ch<=14)return Math.abs(ch-row.channel)<=4;return ch===row.channel;}).length;}
  return rows;
}
export function extractShareMedia(host){
  const scripts=[...(host.scripts||[]),...(host.ports||[]).flatMap(p=>p.scripts||[])];
  const shares=[];for(const s of scripts){if(s.id==='smb-enum-shares'){for(const m of s.output.matchAll(/(?:^|\n)\s*([^\n:]{1,120}):\s*$/g))shares.push({type:'smb',name:m[1].trim()});}if(/nfs-showmount|rpcinfo/.test(s.id)){for(const line of s.output.split(/\r?\n/).map(x=>x.trim()).filter(Boolean)){if(line.startsWith('/'))shares.push({type:'nfs',name:line.split(/\s+/)[0]});}}}
  const media=[];for(const p of host.ports||[]){const text=`${p.service||''} ${p.product||''}`;if(MEDIA_PORTS.includes(p.port)||/plex|minidlna|dlna|upnp|jellyfin|emby/i.test(text))media.push({port:p.port,protocol:p.protocol,service:p.service,product:p.product});}
  return{shares:[...new Map(shares.map(x=>[`${x.type}:${x.name}`,x])).values()],media_services:media};
}

