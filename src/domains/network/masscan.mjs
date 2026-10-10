import {isIP} from 'node:net';
import fs from 'node:fs/promises';
import {toolSchema, stringSchema, integerSchema} from '../../core/schema.mjs';

export const MASSCAN_TOOL = toolSchema('masscan_scan',
  'Bounded Masscan TCP SYN scan of an authorized IPv4 address or CIDR from the Security container. Explicit ports, packet-rate and deadline bounds; no banners, DNS, spoofing or arbitrary CLI flags.', {
    target:stringSchema('One authorized IPv4 address or CIDR; maximum 4096 addresses (/20). No hostnames, lists or IPv6.',{maxLength:32}),
    ports:stringSchema('Required TCP ports or ranges, e.g. 22,80,443 or 1-1024. Maximum 1024 distinct ports.',{maxLength:128}),
    rate_limit:integerSchema('Packets per second; default 100, maximum 1000.',1,1000),
    timeout_seconds:integerSchema('Total process deadline, including a five-second receive wait; default 60, maximum 180. Must accommodate the requested probe count/rate.',10,180),
    interface:stringSchema('Optional Security-container interface (not a physical host interface); otherwise Masscan selects its route.',{maxLength:15}),
  },['target','ports']);
MASSCAN_TOOL.annotations={readOnlyHint:false,idempotentHint:false,destructiveHint:false,openWorldHint:true};

const ipv4Int = ip => ip.split('.').reduce((value,octet)=>value*256+Number(octet),0);
const ipv4Text = value => [24,16,8,0].map(shift=>(value>>>shift)&255).join('.');
export function masscanTarget(target) {
  if (typeof target!=='string' || !/^\d+\.\d+\.\d+\.\d+(?:\/\d{1,2})?$/.test(target)) throw new Error('Masscan requires one literal IPv4 address or CIDR');
  const [ip,rawBits]=target.split('/');
  if (isIP(ip)!==4) throw new Error('Invalid Masscan IPv4 address');
  const bits=rawBits===undefined?32:Number(rawBits);
  if (bits<20 || bits>32) throw new Error('Masscan target exceeds 4096 addresses; use /20 or narrower');
  const hostCount=2**(32-bits), first=Math.floor(ipv4Int(ip)/hostCount)*hostCount;
  return {target:rawBits===undefined?ip:ipv4Text(first)+'/'+bits,hostCount,first,last:first+hostCount-1};
}
export function masscanPorts(value) {
  if (typeof value!=='string' || value.length>128 || !/^\d+(?:-\d+)?(?:,\d+(?:-\d+)?)*$/.test(value)) throw new Error('Masscan ports must be explicit TCP numbers/ranges');
  const ports=new Set();
  for (const part of value.split(',')) {
    const [low,high=low]=part.split('-').map(Number);
    if (low<1 || high>65535 || high<low || high-low+1>1024) throw new Error('Invalid Masscan port range or more than 1024 ports');
    for(let port=low;port<=high;port++)ports.add(port);
    if(ports.size>1024)throw new Error('Masscan permits at most 1024 distinct ports');
  }
  return ports;
}
function portExpression(ports) {
  const sorted=[...ports].sort((a,b)=>a-b),parts=[];
  for(let i=0;i<sorted.length;i++){
    const first=sorted[i];while(i+1<sorted.length&&sorted[i+1]===sorted[i]+1)i++;
    parts.push(first===sorted[i]?String(first):first+'-'+sorted[i]);
  }
  return parts.join(',');
}
export function parseMasscanList(text,range,ports) {
  const rows=[],seen=new Set();let invalid=0,duplicates=0;
  for (const raw of String(text??'').split(/\r?\n/)) {
    const line=raw.trim();if(!line || line.startsWith('#'))continue;
    const match=line.match(/^open\s+tcp\s+(\d+)\s+(\S+)\s+(\d+)$/);
    if(!match || isIP(match[2])!==4 || !ports.has(Number(match[1])) || ipv4Int(match[2])<range.first || ipv4Int(match[2])>range.last || !Number.isSafeInteger(Number(match[3]))) {invalid++;continue;}
    const key=match[2]+':'+Number(match[1]);if(seen.has(key)){duplicates++;continue;}seen.add(key);
    rows.push({address:match[2],port:Number(match[1]),protocol:'tcp',state:'open',observed_at_epoch:Number(match[3])});
  }
  return {rows,invalid,duplicates};
}
async function rejectAmbientConfig() {
  // Masscan reads this path implicitly. Do not let ambient settings broaden
  // an otherwise validated target or port expression.
  try {
    const data=await fs.readFile('/etc/masscan/masscan.conf','utf8');
    if(data.split(/\r?\n/).some(line=>line.trim()&&!line.trim().startsWith('#')))throw new Error('Ambient Masscan configuration is unsupported; rebuild the clean Security image');
  } catch(error) {if(error.code!=='ENOENT')throw error;}
}
export function createMasscan(ctx) {
  return {async call(args={}) {
    ctx.requireActive();ctx.validateArguments(MASSCAN_TOOL.inputSchema,args);
    const range=masscanTarget(args.target),ports=masscanPorts(args.ports);
    const rate=args.rate_limit??100,seconds=args.timeout_seconds??60,probes=range.hostCount*ports.size;
    if(probes>262144)throw new Error('Masscan permits at most 262144 host/port probes per call');
    const expectedSeconds=Math.ceil(probes/rate)+10;
    if(expectedSeconds>seconds)throw new Error(`Masscan scope/rate needs at least ${expectedSeconds}s; narrow the scope or adjust rate/deadline within bounds`);
    if(args.interface && !/^[A-Za-z0-9][A-Za-z0-9_.:-]{0,14}$/.test(args.interface))throw new Error('Invalid Security-container interface');
    await ctx.assertAuthorizedTarget(range.target,{allowCidr:true});
    await (ctx.rejectAmbientConfig??rejectAmbientConfig)();
    const expression=portExpression(ports);
    const argv=[range.target,'-p',expression,'--rate',String(rate),'--wait','5','--retries','0','--open','-oL','-'];
    if(args.interface)argv.push('-e',args.interface);
    const result=await ctx.runStatus('masscan',argv,{timeout:seconds*1000,maxBuffer:1024*1024});
    const parsed=parseMasscanList(result.stdout,range,ports);
    const complete=result.code===0&&!result.timed_out&&!result.output_limited&&parsed.invalid===0;
    return {scope:'security-container-target-scan',scanner:'masscan',target:range.target,target_address_count:range.hostCount,ports:expression,requested_port_count:ports.size,planned_probe_count:probes,rate_limit:rate,timeout_seconds:seconds,interface:args.interface??null,
      open_port_count:parsed.rows.length,open_ports:parsed.rows,duplicate_rows:parsed.duplicates,invalid_rows:parsed.invalid,complete,exit_code:result.code,timed_out:!!result.timed_out,output_limited:!!result.output_limited,diagnostics:String(result.stderr??'').slice(0,2000),
      limitations:['TCP SYN observations only; no service detection.','A completed process does not prove every target replied or that unreported ports are closed.','Uses the Security-container namespace; does not establish physical LAN interfaces, topology or isolation.']};
  }};
}
