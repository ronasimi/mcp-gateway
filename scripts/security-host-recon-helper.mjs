#!/usr/bin/env node
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import http from 'node:http';
import path from 'node:path';
import dns from 'node:dns/promises';
import { isIP, BlockList } from 'node:net';
import { createNetworkRecon, NETWORK_RECON_TOOLS, NETWORK_RECON_HOST_TOOL_NAMES } from './security-network-recon.mjs';
import { runStatus, confinedPath, validateArguments } from './security-runtime.mjs';

const SOCKET=path.resolve(process.env.SECURITY_HOST_RECON_SOCKET||'/run/mcp-security-host/recon.sock');
const WORKSPACE=path.resolve(process.env.MCP_WORKSPACE||'/var/lib/mcp-security/workspace');
const ALLOW_ACTIVE=/^(1|true|yes)$/i.test(process.env.SECURITY_ALLOW_ACTIVE||'true');
const ALLOW_CAPTURE=/^(1|true|yes)$/i.test(process.env.SECURITY_ALLOW_PACKET_CAPTURE||'false');
const ALLOW_PUBLIC=/^(1|true|yes)$/i.test(process.env.SECURITY_ALLOW_PUBLIC_TARGETS||'false');
const TARGET_ALLOWLIST=String(process.env.SECURITY_TARGET_ALLOWLIST||'127.0.0.0/8,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,169.254.0.0/16,::1/128,fc00::/7,fe80::/10').split(',').map(x=>x.trim()).filter(Boolean);
const toolMap=new Map(NETWORK_RECON_TOOLS.filter(t=>NETWORK_RECON_HOST_TOOL_NAMES.has(t.name)).map(t=>[t.name,t]));
process.env.SECURITY_NETWORK_SCOPE='host-network';

function ipv4Int(ip){const p=ip.split('.').map(Number);if(p.length!==4||p.some(n=>!Number.isInteger(n)||n<0||n>255))return null;return (((p[0]<<24)>>>0)+(p[1]<<16)+(p[2]<<8)+p[3])>>>0;}
function ipv4InCidr(ip,cidr){const [net,bitsRaw]=cidr.split('/'),bits=bitsRaw==null?32:Number(bitsRaw),a=ipv4Int(ip),n=ipv4Int(net);if(a==null||n==null||bits<0||bits>32)return false;const mask=bits===0?0:(0xffffffff<<(32-bits))>>>0;return(a&mask)===(n&mask);}
function ipAllowed(ip){if(!isIP(ip))return false;if(ALLOW_PUBLIC)return true;const rules=new BlockList();for(const entry of TARGET_ALLOWLIST){const [address,bits]=entry.split('/'),family=isIP(address);if(!family)continue;if(bits==null)rules.addAddress(address,family===6?'ipv6':'ipv4');else rules.addSubnet(address,Number(bits),family===6?'ipv6':'ipv4');}return rules.check(ip,isIP(ip)===6?'ipv6':'ipv4');}
function cidrAllowed(target){if(!target.includes('/'))return false;const [ip,bitsRaw]=target.split('/'),bits=Number(bitsRaw);if(target.split('/').length!==2||isIP(ip)!==4||!Number.isInteger(bits)||bits<0||bits>32)return false;if(ALLOW_PUBLIC)return true;return TARGET_ALLOWLIST.some(rule=>!rule.includes(':')&&ipv4InCidr(ip,rule)&&bits>=Number(rule.split('/')[1]??32));}
async function assertAuthorizedTarget(target,{allowCidr=false}={}){if(!ALLOW_ACTIVE)throw new Error('active security tools are disabled');const t=String(target||'').trim();if(!t||t.startsWith('-')||t.length>253)throw new Error('invalid target');if(t.includes('/')){if(!allowCidr||!cidrAllowed(t))throw new Error(`target CIDR is not private/allowlisted: ${t}`);return t;}let ips=[];if(isIP(t))ips=[t];else{if(!/^[A-Za-z0-9._-]+$/.test(t))throw new Error('invalid hostname');try{ips=(await dns.lookup(t,{all:true,verbatim:true})).map(x=>x.address);}catch(e){throw new Error(`target DNS resolution failed: ${e.message}`);}}if(!ips.length||ips.some(ip=>!ipAllowed(ip)))throw new Error(`target resolves outside private/allowlisted ranges: ${t} -> ${ips.join(', ')}`);return t;}
function safeWorkspace(rel='.',options={}){return confinedPath(WORKSPACE,rel,options);}
function requireActive(){if(!ALLOW_ACTIVE)throw new Error('active security tools are disabled');}
function requireCapture(){if(!ALLOW_CAPTURE)throw new Error('packet capture disabled; set SECURITY_ALLOW_PACKET_CAPTURE=true');}

await fsp.mkdir(WORKSPACE,{recursive:true,mode:0o700});
const api=createNetworkRecon({
  runStatus, safeWorkspace, assertAuthorizedTarget, requireActive, requireCapture,
  hostRoot:'/', disableHostDelegation:true,
});
const MAX_QUEUE=Math.max(1,Math.min(16,Number(process.env.SECURITY_HOST_RECON_MAX_QUEUE||8)));
let active=null;
let queued=0;
let tail=Promise.resolve();

async function schedule(name,args){
  if(queued>=MAX_QUEUE)throw new Error(`host recon helper queue is full (${MAX_QUEUE})`);
  queued++;
  const previous=tail;
  let release;
  tail=new Promise(resolve=>{release=resolve;});
  await previous;
  active={tool:name,started_at:new Date().toISOString()};
  try{return await api.call(name,args);}
  finally{active=null;queued--;release();}
}

function send(res,status,value){const body=JSON.stringify(value);res.writeHead(status,{'content-type':'application/json','content-length':Buffer.byteLength(body),'cache-control':'no-store'});res.end(body);}
const server=http.createServer((req,res)=>{
  if(req.method==='GET'&&(req.url==='/health'||req.url==='/status'))return send(res,200,{ok:true,scope:'host-network',tools:NETWORK_RECON_HOST_TOOL_NAMES.size,busy:Boolean(active),active,queued,max_queue:MAX_QUEUE});
  if(req.method!=='POST'||req.url!=='/call')return send(res,404,{error:'not found'});
  let raw='',bytes=0,tooLarge=false;
  req.on('data',chunk=>{bytes+=chunk.length;if(bytes>4*1024*1024){tooLarge=true;req.destroy();return;}raw+=chunk.toString('utf8');});
  req.on('end',async()=>{if(tooLarge)return;let body;try{body=JSON.parse(raw||'{}');}catch{return send(res,400,{error:'invalid JSON'});}const name=body.tool,args=body.args??{};if(!NETWORK_RECON_HOST_TOOL_NAMES.has(name))return send(res,400,{error:'unsupported host-recon tool'});try{validateArguments(toolMap.get(name).inputSchema,args);}catch(e){return send(res,400,{error:e.message});}try{const result=await schedule(name,args);return send(res,200,{result});}catch(e){const full=/queue is full/.test(e?.message||'');return send(res,full?503:500,{error:e?.message||String(e)});}});
});
server.on('clientError',(_,socket)=>socket.destroy());
try{await fsp.unlink(SOCKET);}catch{}
await fsp.mkdir(path.dirname(SOCKET),{recursive:true,mode:0o755});
server.listen(SOCKET,async()=>{await fsp.chmod(SOCKET,0o600);process.stderr.write(`security host recon helper listening on ${SOCKET}\n`);});
for(const signal of ['SIGTERM','SIGINT'])process.on(signal,()=>server.close(()=>process.exit(0)));
