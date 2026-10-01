#!/usr/bin/env node
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import dns from 'node:dns/promises';
import crypto from 'node:crypto';
import { isIP, BlockList } from 'node:net';
import { runStatus as execute, confinedPath, validateArguments } from './security-runtime.mjs';
import { EXTENDED_TOOLS, createExtendedSecurity } from './security-extended.mjs';

const WORKSPACE = path.resolve(process.env.MCP_WORKSPACE || '/workspace');
const HOST_ROOT = path.resolve(process.env.MCP_HOST_ROOT || '/host');
const MAX_OUTPUT = Math.max(1024, Math.min(10000, Number(process.env.SECURITY_MAX_OUTPUT) || 10000));
const DEFAULT_TIMEOUT = Number(process.env.SECURITY_TIMEOUT_MS || 60000);
const ALLOW_ACTIVE = /^(1|true|yes)$/i.test(process.env.SECURITY_ALLOW_ACTIVE || 'true');
const ALLOW_CAPTURE = /^(1|true|yes)$/i.test(process.env.SECURITY_ALLOW_PACKET_CAPTURE || 'false');
const ALLOW_PUBLIC = /^(1|true|yes)$/i.test(process.env.SECURITY_ALLOW_PUBLIC_TARGETS || 'false');
const TARGET_ALLOWLIST = String(process.env.SECURITY_TARGET_ALLOWLIST || '127.0.0.0/8,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,169.254.0.0/16,::1/128,fc00::/7,fe80::/10')
  .split(',').map(x=>x.trim()).filter(Boolean);
const DEFAULT_FFUF_WORDLIST = process.env.SECURITY_FFUF_WORDLIST || '/usr/share/dirb/wordlists/common.txt';

const s = (description, properties = {}, required = []) => ({ type:'object', description, properties, required, additionalProperties:false });
const str = (description, extra={}) => ({ type:'string', description, ...extra });
const num = (description, extra={}) => ({ type:'number', description, ...extra });
const bool = (description) => ({ type:'boolean', description });
const arr = (description, items, extra={}) => ({ type:'array', description, items, ...extra });

const TOOLS = [
  ...EXTENDED_TOOLS,
  // Active / red-team assessment
  { name:'security_network_discover', description:'Authorized network discovery: find live hosts on a private or explicitly allowlisted IP/CIDR using Nmap host discovery. Use for LAN asset discovery, subnet inventory, host discovery, or identifying reachable hosts before deeper assessment. This scans the supplied target; do not substitute security_network_interfaces, which only describes the container namespace.', inputSchema:s('Discover live hosts on an authorized network target.', {target:str('Hostname, IP address, or CIDR such as 192.168.1.0/24.')}, ['target']) },
  { name:'security_port_scan', description:'Authorized TCP port scan: identify open ports on a private or explicitly allowlisted host using bounded Nmap connect scanning. Use for open ports, exposed services, attack-surface inventory, or red-team reconnaissance.', inputSchema:s('Scan TCP ports on an authorized target.', {target:str('Hostname or IP address.'), ports:str('Nmap port expression such as 22,80,443 or 1-1024; default top 1000 ports.'), timeout_seconds:num('Maximum scan duration; default 60, maximum 180.',{minimum:5,maximum:180})}, ['target']) },
  { name:'security_service_detect', description:'Authorized service/version detection: identify products and versions listening on selected TCP ports with Nmap version-light probes. Use after port discovery to fingerprint SSH, HTTP, databases, and other exposed services.', inputSchema:s('Detect services on an authorized target.', {target:str('Hostname or IP address.'), ports:str('Nmap port expression such as 22,80,443; omit for Nmap defaults.'), timeout_seconds:num('Maximum scan duration; default 90, maximum 240.',{minimum:10,maximum:240})}, ['target']) },
  { name:'security_tls_audit', description:'TLS/SSL audit: inspect protocol support, certificate metadata, and accepted cipher suites for an authorized TLS service using sslscan. Use for weak TLS versions, cipher exposure, certificate inspection, or HTTPS hardening checks.', inputSchema:s('Audit TLS configuration on an authorized host.', {host:str('Hostname or IP address.'), port:num('TLS port; default 443.',{minimum:1,maximum:65535})}, ['host']) },
  { name:'security_http_headers_audit', description:'HTTP security-header audit: fetch response headers from an authorized HTTP/HTTPS URL and summarize common browser-security headers, redirect target, status, and server disclosure. Use for CSP, HSTS, X-Frame-Options, cookie/header posture, or basic web hardening.', inputSchema:s('Inspect security-relevant HTTP response headers.', {url:str('Authorized http:// or https:// URL.')}, ['url']) },
  { name:'security_web_server_audit', description:'Authorized Nikto web-server audit: perform a bounded active check for common server misconfiguration, exposed files, risky defaults, and known web-server issues. Use for web security assessment; not for exploitation.', inputSchema:s('Run a bounded Nikto audit against an authorized web target.', {url:str('Authorized http:// or https:// URL.'), timeout_seconds:num('Maximum runtime; default 90, maximum 180.',{minimum:15,maximum:180})}, ['url']) },
  { name:'security_vulnerability_scan', description:'Authorized Nuclei vulnerability scan: run curated detection templates against one authorized HTTP/HTTPS URL and return compact findings by severity. Use for known-CVE/misconfiguration detection. Does not expose arbitrary templates or payload execution.', inputSchema:s('Run bounded vulnerability detection against an authorized URL.', {url:str('Authorized http:// or https:// URL.'), severities:arr('Severities to include; default low,medium,high,critical.', str('One severity.',{enum:['info','low','medium','high','critical']}),{maxItems:5}), rate_limit:num('Maximum requests per second; default 20, maximum 50.',{minimum:1,maximum:50}), timeout_seconds:num('Maximum total runtime; default 120, maximum 300.',{minimum:15,maximum:300})}, ['url']) },
  { name:'security_web_content_discover', description:'Authorized web content discovery: fuzz URL paths with ffuf using a bounded wordlist, request rate, concurrency, and runtime. Use for hidden paths, administrative endpoints, backup files, and content inventory on systems you are authorized to assess.', inputSchema:s('Discover web paths on an authorized URL.', {url:str('Base authorized http:// or https:// URL. FUZZ is appended when absent.'), wordlist:str('Optional workspace-relative wordlist; omit for the built-in common path list.'), status_codes:arr('HTTP status codes to return; default only 200.', {type:'integer',description:'HTTP status code.',minimum:100,maximum:599},{minItems:1,maxItems:10}), rate_limit:num('Requests per second; default 20, maximum 50.',{minimum:1,maximum:50}), concurrency:num('Concurrent workers; default 10, maximum 30.',{minimum:1,maximum:30}), timeout_seconds:num('Maximum runtime; default 60, maximum 180.',{minimum:10,maximum:180})}, ['url']) },
  { name:'security_dns_records', description:'DNS security/reconnaissance lookup: retrieve common A, AAAA, CNAME, MX, NS, TXT, SOA, and CAA records for a domain. Use for DNS inventory, mail/security policy review, or domain reconnaissance.', inputSchema:s('Retrieve common DNS records for a domain.', {domain:str('DNS domain name.')}, ['domain']) },

  // Blue-team / defensive analysis
  { name:'security_workspace_vuln_scan', description:'Defensive workspace vulnerability scan: use Trivy to inspect a workspace directory for dependency vulnerabilities, IaC/configuration issues, and exposed secrets, returning compact severity counts and top findings.', inputSchema:s('Scan workspace files for vulnerabilities, misconfiguration, and secrets.', {path:str('Workspace-relative file or directory; default current workspace.'), scanners:arr('Trivy scanners; default vuln,misconfig,secret.',str('Scanner.',{enum:['vuln','misconfig','secret']}),{maxItems:3})}) },
  { name:'security_secret_scan', description:'Defensive secret scan: use Gitleaks to identify likely credentials, tokens, private keys, and other committed secrets in a workspace directory without returning the secret values themselves.', inputSchema:s('Scan workspace files for exposed secrets.', {path:str('Workspace-relative directory; default current workspace.')}) },
  { name:'security_code_scan', description:'Defensive static code analysis: run Semgrep auto rules on a workspace source tree and return compact findings with rule IDs, severity, file, line, and message. Use for insecure coding patterns and application-security review.', inputSchema:s('Run static analysis on workspace source code.', {path:str('Workspace-relative file or directory; default current workspace.'), max_findings:num('Maximum findings returned; default 100, maximum 300.',{minimum:1,maximum:300})}) },
  { name:'security_generate_sbom', description:'Software bill of materials: use Syft to inventory packages and dependencies in a workspace path, returning package counts/types and optionally saving a CycloneDX JSON SBOM inside the workspace.', inputSchema:s('Generate an SBOM for workspace content.', {path:str('Workspace-relative file or directory; default current workspace.'), output:str('Optional workspace-relative .json path for a CycloneDX SBOM artifact.')}) },
  { name:'security_yara_scan', description:'Defensive YARA scan: scan a workspace file or directory for suspicious/malicious patterns using bundled baseline rules or a workspace-provided YARA rule file. Use for IOC/malware triage and artifact inspection.', inputSchema:s('Scan workspace content with YARA.', {path:str('Workspace-relative file or directory.'), rules:str('Optional workspace-relative .yar/.yara rule file; omit for bundled baseline rules.')}, ['path']) },
  { name:'security_malware_scan', description:'Defensive malware scan: recursively scan a workspace file or directory with ClamAV and return only detected file paths/signature names plus summary counts.', inputSchema:s('Scan workspace content with ClamAV.', {path:str('Workspace-relative file or directory.')}, ['path']) },
  { name:'security_file_hash', description:'File integrity/hash tool: compute SHA-256, SHA-512, or MD5 for a workspace file. Use for IOC comparison, integrity verification, duplicate identification, or forensic evidence.', inputSchema:s('Hash one workspace file.', {path:str('Workspace-relative file path.'), algorithm:str('Hash algorithm; default sha256.',{enum:['sha256','sha512','md5']})}, ['path']) },
  { name:'security_file_strings', description:'Artifact strings extraction: extract printable strings from a workspace binary or suspicious file for defensive triage. Use to inspect embedded domains, paths, commands, error text, or other indicators without executing the file.', inputSchema:s('Extract printable strings from a workspace file.', {path:str('Workspace-relative file path.'), min_length:num('Minimum string length; default 6, range 4-32.',{minimum:4,maximum:32}), max_lines:num('Maximum strings returned; default 300, maximum 1000.',{minimum:1,maximum:1000})}, ['path']) },
  { name:'security_pcap_summary', description:'PCAP protocol summary: analyze a workspace packet capture with tshark and return protocol hierarchy and basic packet/file statistics. Use for traffic triage before deeper conversation or IDS analysis.', inputSchema:s('Summarize a workspace PCAP/PCAPNG file.', {path:str('Workspace-relative .pcap or .pcapng file.')}, ['path']) },
  { name:'security_pcap_conversations', description:'PCAP conversation analysis: summarize IP, TCP, or UDP conversations from a workspace capture with tshark. Use for top talkers, unusual peers, ports, byte counts, and connection patterns.', inputSchema:s('Analyze conversations in a PCAP.', {path:str('Workspace-relative .pcap or .pcapng file.'), protocol:str('Conversation type.',{enum:['ip','ipv6','tcp','udp']})}, ['path']) },
  { name:'security_packet_capture', description:'Defensive packet capture: capture a bounded number of packets for a bounded duration from an interface visible inside mcp-security and save the PCAP inside the workspace. Disabled unless SECURITY_ALLOW_PACKET_CAPTURE=true.', inputSchema:s('Capture network packets into the workspace.', {interface:str('Network interface name such as eth0.'), output:str('Workspace-relative output .pcap path.'), duration_seconds:num('Capture duration; default 30, maximum 120.',{minimum:1,maximum:120}), packet_count:num('Maximum packets; default 2000, maximum 10000.',{minimum:1,maximum:10000}), filter:str('Optional tcpdump BPF capture filter such as tcp port 443.')}, ['interface','output']) },
  { name:'security_network_interfaces', description:'Security-container network namespace only: list interfaces, addresses, routes, and link state visible inside mcp-security. Use before packet capture or to diagnose the container network view. Never use this as LAN-host enumeration or as the host physical-interface inventory.', inputSchema:s('List interfaces visible to the security MCP container.', {}) },
  { name:'security_suricata_analyze_pcap', description:'Offline IDS analysis: run Suricata against a workspace PCAP and return compact alert/event counts plus top alerts. Use for blue-team detection, IOC triage, and network incident analysis.', inputSchema:s('Analyze a workspace capture with Suricata.', {path:str('Workspace-relative .pcap or .pcapng file.'), max_alerts:num('Maximum alerts returned; default 100, maximum 300.',{minimum:1,maximum:300})}, ['path']) },
  { name:'security_host_log_search', description:'Read-only host security-log search: search an allowlisted text log under host /var/log for a literal or regex pattern. Use for authentication failures, service errors, suspicious IPs, indicators, or incident-response evidence.', inputSchema:s('Search one host /var/log text file.', {path:str('Absolute host log path under /var/log, e.g. /var/log/auth.log.'), query:str('Literal text or extended regular expression.'), regex:bool('Treat query as an extended regular expression.'), max_matches:num('Maximum matching lines; default 100, maximum 500.',{minimum:1,maximum:500})}, ['path','query']) },
  { name:'security_workspace_ioc_search', description:'IOC search: recursively search workspace text files for a domain, IP, hash, filename, or other indicator without executing content. Use for incident-response scoping across logs, exports, configs, and source trees.', inputSchema:s('Search workspace files for an indicator.', {path:str('Workspace-relative directory; default current workspace.'), indicator:str('Literal indicator to locate.'), max_matches:num('Maximum matching lines; default 100, maximum 500.',{minimum:1,maximum:500})}, ['indicator']) },
  { name:'security_host_audit', description:'Read-only host hardening audit: run Lynis against the mounted host root and return warnings, suggestions, and a compact audit summary. Use for blue-team configuration/hardening review; host filesystem is mounted read-only.', inputSchema:s('Run a bounded Lynis host hardening audit.', {timeout_seconds:num('Maximum runtime; default 180, maximum 300.',{minimum:30,maximum:300})}) },
];

const ACTIVE = new Set(['security_network_discover','security_port_scan','security_service_detect','security_tls_audit','security_http_headers_audit','security_web_server_audit','security_vulnerability_scan','security_web_content_discover']);
const WRITES_WORKSPACE = new Set(['security_generate_sbom','security_packet_capture','security_suricata_analyze_pcap']);
const OPEN_WORLD = new Set([...ACTIVE,'security_dns_records']);
for (const tool of TOOLS) {
  if (tool.annotations) continue;
  tool.annotations={
    readOnlyHint: !WRITES_WORKSPACE.has(tool.name),
    destructiveHint:false,
    idempotentHint: !['security_packet_capture'].includes(tool.name),
    openWorldHint:OPEN_WORLD.has(tool.name),
  };
}
const toolMap=new Map(TOOLS.map(t=>[t.name,t]));
const extended = createExtendedSecurity({ runStatus, safeWorkspace, assertAuthorizedTarget, assertAuthorizedUrl });
const extendedNames = new Set(EXTENDED_TOOLS.map(t => t.name));
process.on('exit', () => extended.jobs.stopAll());
for (const signal of ['SIGTERM', 'SIGINT']) process.on(signal, () => { extended.jobs.stopAll(); process.exit(0); });

function clip(value,max=MAX_OUTPUT){
  const text=typeof value==='string'?value:JSON.stringify(value,null,2);
  if(Buffer.byteLength(text)<=max) return text;
  return text.slice(0,max)+`\n...[truncated at ${max} bytes]`;
}
async function runStatus(cmd,args=[],opts={}){
  return execute(cmd,args,{timeout:DEFAULT_TIMEOUT,...opts});
}
async function run(cmd,args=[],opts={}){
  const r=await runStatus(cmd,args,opts);
  if(r.code!==0) throw new Error(`${cmd} exited ${r.code}: ${clip((r.stderr||r.stdout).trim(),4000)}`);
  return r.stdout.trim();
}
function safeWorkspace(rel='.',{mustExist=false}={}){
  return confinedPath(WORKSPACE,rel,{mustExist});
}
function safeHostLog(p){
  if(typeof p!=='string'||!p.startsWith('/var/log/')||p.includes('\0')||p.includes('..')) throw new Error('host log path must be under /var/log');
  const resolved=confinedPath(path.join(HOST_ROOT,'var/log'),p.slice('/var/log/'.length),{mustExist:true});
  if(!fs.existsSync(resolved)) throw new Error(`host log not found: ${p}`);
  return resolved;
}
function validatePortExpr(v){
  if(v==null||v==='') return null;
  const x=String(v);
  if(!/^[0-9,\-]+$/.test(x)||x.length>128) throw new Error('ports must contain only numbers, commas, and hyphens');
  return x;
}
function ipv4Int(ip){
  const p=ip.split('.').map(Number); if(p.length!==4||p.some(n=>!Number.isInteger(n)||n<0||n>255)) return null;
  return (((p[0]<<24)>>>0)+(p[1]<<16)+(p[2]<<8)+p[3])>>>0;
}
function ipv4InCidr(ip,cidr){
  const [net,bitsS]=cidr.split('/'); const bits=bitsS==null?32:Number(bitsS); const a=ipv4Int(ip),n=ipv4Int(net);
  if(a==null||n==null||bits<0||bits>32) return false;
  const mask=bits===0?0:(0xffffffff<<(32-bits))>>>0; return (a&mask)===(n&mask);
}
function ipAllowed(ip){
  if (!isIP(ip)) return false;
  if(ALLOW_PUBLIC) return true;
  const rules = new BlockList();
  for (const entry of TARGET_ALLOWLIST) {
    const [address,bits] = entry.split('/'), family = isIP(address);
    if (!family) continue;
    if (bits == null) rules.addAddress(address, family === 6 ? 'ipv6' : 'ipv4');
    else rules.addSubnet(address, Number(bits), family === 6 ? 'ipv6' : 'ipv4');
  }
  return rules.check(ip, isIP(ip) === 6 ? 'ipv6' : 'ipv4');
}
function cidrAllowed(target){
  if(!target.includes('/')) return false;
  const [ip,bits]=target.split('/');
  if (!/^\d+$/.test(bits || '') || Number(bits) < 0 || Number(bits) > 32 || target.split('/').length !== 2) return false;
  if(ipv4Int(ip)!=null){
    if(ALLOW_PUBLIC) return true;
    return TARGET_ALLOWLIST.some(c=>!c.includes(':')&&ipv4InCidr(ip,c)&&Number(bits)>=Number(c.split('/')[1]??32));
  }
  return false;
}
async function assertAuthorizedTarget(target,{allowCidr=false}={}){
  if(!ALLOW_ACTIVE) throw new Error('active security tools are disabled; set SECURITY_ALLOW_ACTIVE=true');
  const t=String(target||'').trim();
  if(!t||t.startsWith('-')||t.length>253) throw new Error('invalid target');
  if(t.includes('/')&&allowCidr){ if(!cidrAllowed(t)) throw new Error(`target CIDR is not private/allowlisted: ${t}`); return t; }
  if(t.includes('/')) throw new Error('CIDR is not accepted by this tool');
  let ips=[];
  if(isIP(t)) ips=[t];
  else {
    if(!/^[A-Za-z0-9._-]+$/.test(t)) throw new Error('invalid hostname');
    try{ ips=(await dns.lookup(t,{all:true,verbatim:true})).map(x=>x.address); }catch(e){ throw new Error(`target DNS resolution failed: ${e.message}`); }
  }
  if(!ips.length||ips.some(ip=>!ipAllowed(ip))) throw new Error(`target resolves outside private/allowlisted ranges: ${t} -> ${ips.join(', ')}`);
  return t;
}
async function assertAuthorizedUrl(value){
  if(!ALLOW_ACTIVE) throw new Error('active security tools are disabled; set SECURITY_ALLOW_ACTIVE=true');
  const u=new URL(String(value));
  if(!['http:','https:'].includes(u.protocol)) throw new Error('only http/https URLs are allowed');
  if(u.username || u.password) throw new Error('embedded URL credentials are not allowed');
  await assertAuthorizedTarget(u.hostname.replace(/^\[|\]$/g,''));
  return u.toString();
}
function parseNmapGrep(text){
  const hosts=[];
  for(const line of String(text).split(/\r?\n/)){
    if(!line.startsWith('Host: ')) continue;
    const hm=/^Host:\s+(\S+)\s+\(([^)]*)\)\s+(.*)$/.exec(line); if(!hm) continue;
    const rest=hm[3]; const status=/Status:\s+(\w+)/.exec(rest)?.[1]||null;
    const ports=[]; const pm=/Ports:\s+(.+?)(?:\s+Ignored State:|\s+Seq Index:|$)/.exec(rest);
    if(pm) for(const raw of pm[1].split(', ')){
      const f=raw.split('/'); if(f.length>=5) ports.push({port:Number(f[0]),state:f[1],protocol:f[2],service:f[4]||null,version:f[6]||null});
    }
    hosts.push({address:hm[1],hostname:hm[2]||null,status,ports});
  }
  return hosts;
}
function summarizeHeaders(raw,url){
  const blocks=String(raw).split(/\r?\n\r?\n/).filter(Boolean); const block=blocks.at(-1)||''; const lines=block.split(/\r?\n/);
  const status=lines.shift()||''; const headers={};
  for(const l of lines){const i=l.indexOf(':'); if(i>0) headers[l.slice(0,i).trim().toLowerCase()]=l.slice(i+1).trim();}
  const wanted=['server','location','strict-transport-security','content-security-policy','x-frame-options','x-content-type-options','referrer-policy','permissions-policy','cross-origin-opener-policy','cross-origin-resource-policy','set-cookie'];
  const selected={}; for(const k of wanted) if(headers[k]!=null) selected[k]=headers[k];
  const expected=['strict-transport-security','content-security-policy','x-frame-options','x-content-type-options','referrer-policy'];
  return {url,status,headers:selected,missing_security_headers:expected.filter(k=>headers[k]==null)};
}
function redactSecretFinding(x){
  return {rule_id:x.RuleID||x.RuleId||null,description:x.Description||null,file:x.File||null,start_line:x.StartLine||null,end_line:x.EndLine||null,fingerprint:x.Fingerprint||null};
}
function countBy(items,keyFn){const out={}; for(const x of items){const k=keyFn(x)||'UNKNOWN'; out[k]=(out[k]||0)+1;} return out;}

async function callTool(name,a={}){
  if (extendedNames.has(name)) return extended.call(name,a);
  switch(name){
    case 'security_network_discover': {
      const target=await assertAuthorizedTarget(a.target,{allowCidr:true});
      const r=await run('nmap',['-sn','-n','--host-timeout','10s','-oG','-',target],{timeout:90000});
      const hosts=parseNmapGrep(r).filter(h=>h.status==='Up'); return {scope:'target-scan',target,count:hosts.length,hosts:hosts.map(h=>({address:h.address,hostname:h.hostname})),complete:true};
    }
    case 'security_port_scan': {
      const target=await assertAuthorizedTarget(a.target); const ports=validatePortExpr(a.ports); const sec=Math.max(5,Math.min(180,Number(a.timeout_seconds||60)));
      const args=['-sT','-Pn','-n','--open','-T4','--max-retries','1','--host-timeout',`${sec}s`,'-oG','-']; if(ports) args.push('-p',ports); args.push(target);
      const hosts=parseNmapGrep(await run('nmap',args,{timeout:(sec+15)*1000})); const open=hosts.flatMap(h=>h.ports.filter(p=>p.state==='open').map(p=>({...p,address:h.address})));
      return {target,open_port_count:open.length,open_ports:open,complete:true};
    }
    case 'security_service_detect': {
      const target=await assertAuthorizedTarget(a.target); const ports=validatePortExpr(a.ports); const sec=Math.max(10,Math.min(240,Number(a.timeout_seconds||90)));
      const args=['-sT','-sV','--version-light','-Pn','-n','--open','-T4','--max-retries','1','--host-timeout',`${sec}s`,'-oG','-']; if(ports) args.push('-p',ports); args.push(target);
      const hosts=parseNmapGrep(await run('nmap',args,{timeout:(sec+20)*1000})); return {target,hosts,complete:true};
    }
    case 'security_tls_audit': {
      const host=await assertAuthorizedTarget(a.host); const port=Math.max(1,Math.min(65535,Number(a.port||443)));
      const out=await run('sslscan',['--no-colour','--show-certificate',`${host}:${port}`],{timeout:90000,maxBuffer:4*1024*1024}); return {target:`${host}:${port}`,report:clip(out,16000)};
    }
    case 'security_http_headers_audit': {
      const url=await assertAuthorizedUrl(a.url); const raw=await run('curl',['-sS','-I','-L','--max-redirs','5','--connect-timeout','5','--max-time','20',url],{timeout:25000}); return summarizeHeaders(raw,url);
    }
    case 'security_web_server_audit': {
      const url=await assertAuthorizedUrl(a.url); const sec=Math.max(15,Math.min(180,Number(a.timeout_seconds||90)));
      const r=await runStatus('nikto',['-h',url,'-nointeractive','-maxtime',`${sec}s`],{timeout:(sec+20)*1000,maxBuffer:8*1024*1024});
      const lines=(r.stdout+'\n'+r.stderr).split(/\r?\n/).filter(x=>/^\+/.test(x)&&!/Target IP|Target Hostname|Start Time|End Time/.test(x)).slice(0,200);
      return {url,exit_code:r.code,finding_count:lines.length,findings:lines,complete:r.code===0||r.code===1};
    }
    case 'security_vulnerability_scan': {
      const url=await assertAuthorizedUrl(a.url); const sev=(a.severities?.length?a.severities:['low','medium','high','critical']).join(','); const rate=Math.max(1,Math.min(50,Number(a.rate_limit||20))); const sec=Math.max(15,Math.min(300,Number(a.timeout_seconds||120)));
      const r=await runStatus('nuclei',['-u',url,'-silent','-jsonl','-no-interactsh','-disable-update-check','-t','/opt/security/nuclei-templates','-severity',sev,'-rl',String(rate),'-timeout','8','-retries','1'],{timeout:sec*1000,maxBuffer:16*1024*1024});
      const findings=[]; for(const l of r.stdout.split(/\r?\n/)){if(!l.trim())continue; try{const x=JSON.parse(l); findings.push({template_id:x['template-id']||x.templateID||null,name:x.info?.name||null,severity:x.info?.severity||null,host:x.host||null,matched_at:x['matched-at']||null,type:x.type||null,matcher_name:x['matcher-name']||null});}catch{}}
      return {url,exit_code:r.code,count:findings.length,by_severity:countBy(findings,x=>x.severity),findings:findings.slice(0,200),complete:r.code===0};
    }
    case 'security_web_content_discover': {
      let url=await assertAuthorizedUrl(a.url); if(!url.includes('FUZZ')) url=url.replace(/\/$/,'')+'/FUZZ';
      const wl=a.wordlist?safeWorkspace(a.wordlist,{mustExist:true}):DEFAULT_FFUF_WORDLIST; const rate=Math.max(1,Math.min(50,Number(a.rate_limit||20))); const threads=Math.max(1,Math.min(30,Number(a.concurrency||10))); const sec=Math.max(10,Math.min(180,Number(a.timeout_seconds||60)));
      const statuses = a.status_codes ?? [200];
      const r = await runStatus('ffuf',['-u',url,'-w',wl,'-json','-mc',statuses.join(','),'-noninteractive','-t',String(threads),'-rate',String(rate),'-maxtime',String(sec)],{timeout:(sec+10)*1000,maxBuffer:8*1024*1024});
      const results=[]; let invalid=0;
      for(const line of r.stdout.split(/\r?\n/).filter(Boolean)) {
        try { const x=JSON.parse(line); if(statuses.includes(x.status)) results.push({url:x.url,status:x.status,length:x.length,words:x.words,lines:x.lines}); } catch { invalid++; }
      }
      return {url,exit_code:r.code,count:results.length,results:results.slice(0,200),truncated:results.length>200,complete:r.code===0&&!invalid,exhaustive:false,time_limit_seconds:sec,diagnostics:r.stderr.slice(0,2000)};
    }
    case 'security_dns_records': {
      const domain=String(a.domain||'').trim(); if(!/^[A-Za-z0-9._-]+$/.test(domain)) throw new Error('invalid domain'); const records={};
      for(const type of ['A','AAAA','CNAME','MX','NS','TXT','SOA','CAA']){const r=await runStatus('dig',['+short',domain,type],{timeout:10000}); records[type]=r.stdout.split(/\r?\n/).filter(Boolean).slice(0,50);} return {domain,records};
    }
    case 'security_workspace_vuln_scan': {
      const p=safeWorkspace(a.path||'.',{mustExist:true}); const scanners=(a.scanners?.length?a.scanners:['vuln','misconfig','secret']).join(',');
      const r=await runStatus('trivy',['fs','--quiet','--format','json','--scanners',scanners,'--timeout','2m',p],{timeout:150000,maxBuffer:32*1024*1024}); let j={}; try{j=JSON.parse(r.stdout||'{}');}catch{}
      const findings=[]; for(const res of j.Results||[]){for(const v of res.Vulnerabilities||[]) findings.push({kind:'vulnerability',target:res.Target,id:v.VulnerabilityID,severity:v.Severity,package:v.PkgName,installed:v.InstalledVersion,fixed:v.FixedVersion||null,title:v.Title||null}); for(const m of res.Misconfigurations||[]) findings.push({kind:'misconfiguration',target:res.Target,id:m.ID,severity:m.Severity,title:m.Title,message:m.Message||null}); for(const x of res.Secrets||[]) findings.push({kind:'secret',target:res.Target,rule_id:x.RuleID,severity:x.Severity,title:x.Title||null,start_line:x.StartLine||null});}
      return {path:a.path||'.',exit_code:r.code,count:findings.length,by_severity:countBy(findings,x=>x.severity),by_kind:countBy(findings,x=>x.kind),findings:findings.slice(0,200),complete:r.code===0};
    }
    case 'security_secret_scan': {
      const p=safeWorkspace(a.path||'.',{mustExist:true}); const tmp=path.join(os.tmpdir(),`gitleaks-${crypto.randomUUID()}.json`); try{const r=await runStatus('gitleaks',['dir',p,'--report-format','json','--report-path',tmp,'--redact'],{timeout:120000,maxBuffer:4*1024*1024}); let j=[]; try{j=JSON.parse(await fsp.readFile(tmp,'utf8'));}catch{} return {path:a.path||'.',exit_code:r.code,count:j.length,findings:j.slice(0,200).map(redactSecretFinding),complete:[0,1].includes(r.code)};} finally{await fsp.rm(tmp,{force:true});}
    }
    case 'security_code_scan': {
      const p=safeWorkspace(a.path||'.',{mustExist:true}); const max=Math.max(1,Math.min(300,Number(a.max_findings||100))); const r=await runStatus('semgrep',['scan','--config','auto','--json','--quiet','--metrics','off',p],{timeout:180000,maxBuffer:32*1024*1024}); let j={}; try{j=JSON.parse(r.stdout||'{}');}catch{} const results=(j.results||[]).map(x=>({rule_id:x.check_id||null,severity:x.extra?.severity||null,path:path.relative(WORKSPACE,x.path||''),line:x.start?.line||null,message:x.extra?.message||null})); return {path:a.path||'.',exit_code:r.code,count:results.length,findings:results.slice(0,max),complete:[0,1].includes(r.code)};
    }
    case 'security_generate_sbom': {
      const p=safeWorkspace(a.path||'.',{mustExist:true}); const r=await runStatus('syft',[p,'-o','json'],{timeout:180000,maxBuffer:64*1024*1024}); if(r.code!==0) throw new Error(`syft exited ${r.code}: ${clip(r.stderr,3000)}`); const j=JSON.parse(r.stdout); const pkgs=(j.artifacts||[]).map(x=>({name:x.name,version:x.version,type:x.type,purl:x.purl||null})); let output=null; if(a.output){const o=safeWorkspace(a.output); await fsp.mkdir(path.dirname(o),{recursive:true}); const rr=await runStatus('syft',[p,'-o','cyclonedx-json'],{timeout:180000,maxBuffer:64*1024*1024}); if(rr.code!==0) throw new Error(`syft exited ${rr.code}: ${clip(rr.stderr,3000)}`); await fsp.writeFile(o,rr.stdout); output=path.relative(WORKSPACE,o);} return {path:a.path||'.',package_count:pkgs.length,by_type:countBy(pkgs,x=>x.type),packages:pkgs.slice(0,200),output};
    }
    case 'security_yara_scan': {
      const p=safeWorkspace(a.path,{mustExist:true}); const rules=a.rules?safeWorkspace(a.rules,{mustExist:true}):'/opt/security/rules/default.yar'; const st=await fsp.stat(p); const args=[]; if(st.isDirectory()) args.push('-r'); args.push(rules,p); const r=await runStatus('yara',args,{timeout:120000,maxBuffer:8*1024*1024}); const hits=r.stdout.split(/\r?\n/).filter(Boolean); return {path:a.path,rules:a.rules||'bundled-default',count:hits.length,matches:hits.slice(0,500),truncated:hits.length>500,exit_code:r.code,complete:r.code===0,diagnostics:r.stderr.slice(0,2000)};
    }
    case 'security_malware_scan': {
      const p=safeWorkspace(a.path,{mustExist:true}); const st=await fsp.stat(p); const args=['--infected','--no-summary']; if(st.isDirectory()) args.push('-r'); args.push(p); const r=await runStatus('clamscan',args,{timeout:180000,maxBuffer:16*1024*1024}); const hits=r.stdout.split(/\r?\n/).filter(l=>/FOUND$/.test(l)).slice(0,500); return {path:a.path,infected_count:hits.length,detections:hits,complete:[0,1].includes(r.code),engine_error:r.code>1?clip(r.stderr||r.stdout,3000):null};
    }
    case 'security_file_hash': {
      const p=safeWorkspace(a.path,{mustExist:true}); const st=await fsp.stat(p); if(!st.isFile()) throw new Error('path must be a file'); const alg=a.algorithm||'sha256'; const h=crypto.createHash(alg); await new Promise((resolve,reject)=>{const rs=fs.createReadStream(p); rs.on('data',d=>h.update(d)); rs.on('end',resolve); rs.on('error',reject);}); return {path:a.path,algorithm:alg,hash:h.digest('hex'),size:st.size};
    }
    case 'security_file_strings': {
      const p=safeWorkspace(a.path,{mustExist:true}); const min=Math.max(4,Math.min(32,Number(a.min_length||6))); const max=Math.max(1,Math.min(1000,Number(a.max_lines||300))); const r=await runStatus('strings',['-a','-n',String(min),p],{timeout:30000,maxBuffer:16*1024*1024}); const lines=r.stdout.split(/\r?\n/).filter(Boolean); return {path:a.path,total_visible:Math.min(lines.length,max),truncated:lines.length>max,strings:lines.slice(0,max)};
    }
    case 'security_pcap_summary': {
      const p=safeWorkspace(a.path,{mustExist:true}); const out=await run('tshark',['-r',p,'-q','-z','io,phs'],{timeout:120000,maxBuffer:8*1024*1024}); return {path:a.path,protocol_hierarchy:clip(out,20000)};
    }
    case 'security_pcap_conversations': {
      const p=safeWorkspace(a.path,{mustExist:true}); const proto=a.protocol||'ip'; const out=await run('tshark',['-r',p,'-q','-z',`conv,${proto}`],{timeout:120000,maxBuffer:8*1024*1024}); return {path:a.path,protocol:proto,conversations:clip(out,20000)};
    }
    case 'security_packet_capture': {
      if(!ALLOW_CAPTURE) throw new Error('packet capture disabled; set SECURITY_ALLOW_PACKET_CAPTURE=true'); const iface=String(a.interface||''); if(!/^[A-Za-z0-9_.:@-]+$/.test(iface)) throw new Error('invalid interface'); const o=safeWorkspace(a.output); await fsp.mkdir(path.dirname(o),{recursive:true}); const dur=Math.max(1,Math.min(120,Number(a.duration_seconds||30))); const cnt=Math.max(1,Math.min(10000,Number(a.packet_count||2000))); const args=['--signal=INT',`${dur}s`,'tcpdump','-p','-i',iface,'-nn','-s','0','-c',String(cnt),'-w',o]; if(a.filter){if(String(a.filter).length>256||/[;&|`$<>]/.test(String(a.filter))) throw new Error('unsupported capture-filter characters'); args.push(String(a.filter));} const r=await runStatus('timeout',args,{timeout:(dur+10)*1000,maxBuffer:4*1024*1024}); const st=fs.existsSync(o)?await fsp.stat(o):null; return {output:path.relative(WORKSPACE,o),bytes:st?.size||0,exit_code:r.code,complete:[0,124].includes(r.code)};
    }
    case 'security_network_interfaces': return {scope:'security-container',warning:'These interfaces/routes belong to the mcp-security container namespace. They are not LAN host enumeration and are not the host physical-interface inventory.',interfaces:os.networkInterfaces(),routes:await run('ip',['route'])};
    case 'security_suricata_analyze_pcap': {
      const p=safeWorkspace(a.path,{mustExist:true}); const max=Math.max(1,Math.min(300,Number(a.max_alerts||100))); const dir=await fsp.mkdtemp(path.join(os.tmpdir(),'suricata-')); try{const r=await runStatus('suricata',['-r',p,'-l',dir,'-k','none'],{timeout:180000,maxBuffer:8*1024*1024}); const eve=path.join(dir,'eve.json'); const alerts=[]; const eventCounts={}; if(fs.existsSync(eve)){for(const l of (await fsp.readFile(eve,'utf8')).split(/\r?\n/)){if(!l)continue; try{const x=JSON.parse(l); eventCounts[x.event_type]=(eventCounts[x.event_type]||0)+1; if(x.event_type==='alert'&&alerts.length<max) alerts.push({timestamp:x.timestamp,src_ip:x.src_ip,src_port:x.src_port,dest_ip:x.dest_ip,dest_port:x.dest_port,proto:x.proto,signature:x.alert?.signature,category:x.alert?.category,severity:x.alert?.severity,signature_id:x.alert?.signature_id});}catch{}}} return {path:a.path,exit_code:r.code,event_counts:eventCounts,alert_count:eventCounts.alert||0,alerts,complete:r.code===0};} finally{await fsp.rm(dir,{recursive:true,force:true});}
    }
    case 'security_host_log_search': {
      const p=safeHostLog(a.path); const max=Math.max(1,Math.min(500,Number(a.max_matches||100))); const args=['-i','-n','-m',String(max)]; if(a.regex) args.push('-E',String(a.query)); else args.push('-F',String(a.query)); args.push(p); const r=await runStatus('grep',args,{timeout:30000,maxBuffer:8*1024*1024}); const lines=r.stdout.split(/\r?\n/).filter(Boolean); return {path:a.path,count:lines.length,matches:lines,complete:r.code===0||r.code===1};
    }
    case 'security_workspace_ioc_search': {
      const p=safeWorkspace(a.path||'.',{mustExist:true}); const max=Math.max(1,Math.min(500,Number(a.max_matches||100))); const r=await runStatus('grep',['-R','-I','-n','-F','-m',String(max),'--',String(a.indicator),p],{timeout:60000,maxBuffer:8*1024*1024}); const lines=r.stdout.split(/\r?\n/).filter(Boolean).slice(0,max).map(x=>x.replaceAll(WORKSPACE+'/','')); return {path:a.path||'.',indicator:a.indicator,count:lines.length,matches:lines,complete:r.code===0||r.code===1};
    }
    case 'security_host_audit': {
      const sec=Math.max(30,Math.min(300,Number(a.timeout_seconds||180))); const r=await runStatus('lynis',['audit','system','--rootdir',HOST_ROOT,'--quick','--no-colors','--no-log'],{timeout:sec*1000,maxBuffer:16*1024*1024}); const lines=(r.stdout+'\n'+r.stderr).split(/\r?\n/); const findings=lines.filter(l=>/Warning|Suggestion|Hardening index|Tests performed/i.test(l)).map(l=>l.trim()).filter(Boolean).slice(0,300); return {exit_code:r.code,findings,complete:r.code===0};
    }
  }
  throw new Error(`unknown tool: ${name}`);
}

// Keep large reports recoverable without putting them all in the model context.
async function encodeResult(value) {
  const encoded=JSON.stringify(value);
  if(Buffer.byteLength(encoded)<=MAX_OUTPUT) return encoded;
  const rel=`.security-results/${crypto.randomUUID()}.json`;
  const file=safeWorkspace(rel);
  await fsp.mkdir(path.dirname(file),{recursive:true});
  await fsp.writeFile(file,encoded+'\n',{mode:0o600});
  return JSON.stringify({truncated:true,output_file:rel,total_bytes:Buffer.byteLength(encoded),preview:encoded.slice(0,Math.max(128,Math.floor(MAX_OUTPUT/8)))});
}

function response(id,result){process.stdout.write(JSON.stringify({jsonrpc:'2.0',id,result})+'\n');}
function errorResponse(id,code,message,data){process.stdout.write(JSON.stringify({jsonrpc:'2.0',id,error:{code,message,...(data?{data}:{})}})+'\n');}
let input=''; process.stdin.setEncoding('utf8'); process.stdin.on('data',chunk=>{input+=chunk; let idx; while((idx=input.indexOf('\n'))>=0){const line=input.slice(0,idx).trim(); input=input.slice(idx+1); if(line) handle(line);}});
async function handle(line){let msg; try{msg=JSON.parse(line);}catch{return;} if(msg.method==='notifications/initialized'||msg.method==='notifications/cancelled')return; if(msg.id==null)return; try{if(msg.method==='initialize')return response(msg.id,{protocolVersion:msg.params?.protocolVersion||'2025-06-18',capabilities:{tools:{listChanged:false}},serverInfo:{name:'local-security-tools',version:'1.1.0'}}); if(msg.method==='ping')return response(msg.id,{}); if(msg.method==='tools/list')return response(msg.id,{tools:TOOLS}); if(msg.method==='tools/call'){const name=msg.params?.name,args=msg.params?.arguments||{}; if(!toolMap.has(name))throw new Error(`unknown tool: ${name}`); try{validateArguments(toolMap.get(name).inputSchema,args); const out=await callTool(name,args); return response(msg.id,{content:[{type:'text',text:await encodeResult(out)}],isError:false});}catch(e){return response(msg.id,{content:[{type:'text',text:clip(e?.message||String(e))}],isError:true});}} return errorResponse(msg.id,-32601,`Method not found: ${msg.method}`);}catch(e){return errorResponse(msg.id,-32603,e?.message||String(e));}}
