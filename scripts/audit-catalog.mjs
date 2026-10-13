#!/usr/bin/env node
// Offline lexical regression proxy, not Pi's native search implementation.
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import path from 'node:path';
import fs from 'node:fs';
const root=fileURLToPath(new URL('../',import.meta.url));
export function loadCatalogs() {
  return ['system','security','google'].flatMap(server=>{
    const p=spawnSync(process.execPath,[path.join(root,'scripts',server+'-tools.mjs')],{input:JSON.stringify({jsonrpc:'2.0',id:1,method:'tools/list',params:{}})+'\n',encoding:'utf8',timeout:15000,maxBuffer:4*1024*1024});
    if(p.error||p.status!==0)throw new Error(`${server}: ${p.error?.message||p.stderr}`);
    const r=JSON.parse(p.stdout.trim().split('\n')[0]);
    if(!r.result?.tools)throw new Error(`${server}: no catalog`);
    return r.result.tools.map(tool=>({...tool,server}));
  });
}
const stop=new Set('a an and are as at be by for from how in is it of on one or the to using with'.split(' '));
export const tokens=text=>String(text).toLowerCase().match(/[a-z0-9]+/g)?.filter(t=>!stop.has(t)).map(t=>t.length>4&&t.endsWith('s')?t.slice(0,-1):t)||[];
function schemaText(schema){
  return [schema.description||'',...Object.entries(schema.properties||{}).flatMap(([name,s])=>[name,schemaText(s)]),...(schema.items?[schemaText(schema.items)]:[]),...(schema.enum||[])].join(' ');
}
export function rankTools(tools,query){
  const docs=tools.map(t=>tokens(t.name+' '+t.description+' '+schemaText(t.inputSchema)));
  const avg=docs.reduce((s,d)=>s+d.length,0)/docs.length;
  const terms=[...new Set(tokens(query))];
  return tools.map((tool,i)=>({tool,score:terms.reduce((sum,term)=>{
    const tf=docs[i].filter(t=>t===term).length;
    const df=docs.filter(d=>d.includes(term)).length;
    const idf=Math.log(1+(docs.length-df+0.5)/(df+0.5));
    return sum+(tf?idf*tf*2.2/(tf+1.2*(0.25+0.75*docs[i].length/avg)):0);
  },0)})).filter(r=>r.score>0).sort((a,b)=>b.score-a.score||a.tool.name.localeCompare(b.tool.name));
}
export function auditCatalog(tools){
  const queries=tools.flatMap(t=>[t.name.replaceAll('_',' '),...t._meta['ai.catalog'].aliases].map(query=>{
    const ranked=rankTools(tools,query),rank=ranked.findIndex(r=>r.tool.name===t.name&&r.tool.server===t.server)+1;
    return {server:t.server,tool:t.name,query,rank,top3:ranked.slice(0,3).map(r=>r.tool.server+'.'+r.tool.name)};
  }));
  return {method:'Offline BM25 lexical proxy over published names, descriptions and schema text. Does not certify Pi native ranking or live availability.',
    counts:Object.fromEntries(['system','security','google'].map(s=>[s,tools.filter(t=>t.server===s).length])),
    description_bytes:tools.reduce((s,t)=>s+Buffer.byteLength(t.description),0),
    schema_bytes:tools.reduce((s,t)=>s+Buffer.byteLength(JSON.stringify(t.inputSchema)),0),
    queries:queries.length,top3_passed:queries.filter(r=>r.rank>0&&r.rank<=3).length,
    failures:queries.filter(r=>r.rank===0||r.rank>3),results:queries};
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
  const report=auditCatalog(loadCatalogs());
  if(process.argv[2])fs.writeFileSync(process.argv[2],JSON.stringify(report,null,2)+'\n');
  console.log(JSON.stringify({...report,results:undefined},null,2));
  if(report.failures.length)process.exitCode=1;
}
