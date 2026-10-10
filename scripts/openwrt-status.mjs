// Read-only commands; structured status avoids routing inventory through old logs.
export const OPENWRT_STATUS_COMMAND = "echo '--- release ---'; cat /etc/openwrt_release 2>/dev/null || cat /etc/os-release; echo '--- uptime/load ---'; uptime; echo '--- memory ---'; free 2>/dev/null || cat /proc/meminfo; echo '--- board ---'; ubus call system board 2>/dev/null; echo '--- interfaces ---'; ubus call network.interface dump 2>/dev/null; echo '--- routes ---'; ip route 2>/dev/null || route -n";
export function parseOpenWrtStatus(text,target){
  const sections={};let key=null;
  for(const line of String(text).split('\n')){const marker=line.match(/^--- (release|uptime\/load|memory|board|interfaces|routes) ---$/);if(marker){key=marker[1];sections[key]='';}else if(key)sections[key]+=line+'\n';}
  const parse=key=>{try{return JSON.parse(sections[key]??'')}catch{return null}};
  const board=parse('board'),dump=parse('interfaces');
  const interfaces=Array.isArray(dump?.interface)?dump.interface.map(row=>Object.fromEntries(['interface','proto','up','pending','available','device','l3_device','ipv4-address','ipv6-address','route','dns-server'].filter(k=>Object.hasOwn(row,k)).map(k=>[k,row[k]]))):null;
  const available=board!==null&&interfaces!==null;
  return {status:available?'observed':'partial',target,scope:'remote_openwrt_router',evidence_available:available,complete:available,board,interfaces,release_text:(sections.release??'').trim().slice(0,2048),uptime_text:(sections['uptime/load']??'').trim().slice(0,512),memory_text:(sections.memory??'').trim().slice(0,2048),routes_text:(sections.routes??'').trim().slice(0,4096),routes_truncated:(sections.routes??'').length>4096,limitations:available?[]:['Structured board or interface status was unavailable; logs/aliases cannot replace it.']};
}
