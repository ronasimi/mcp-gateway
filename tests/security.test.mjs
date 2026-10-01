import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';
import { fileURLToPath } from 'node:url';
import { runStatus, confinedPath, validateArguments, JobManager } from '../scripts/security-runtime.mjs';
import { createExtendedSecurity, EXTENDED_TOOLS } from '../scripts/security-extended.mjs';

const root = fileURLToPath(new URL('../', import.meta.url));
const wait = ms => new Promise(resolve => setTimeout(resolve, ms));
const ok = stdout => ({ code: 0, stdout, stderr: '' });

async function fixture(fn, run = runStatus) {
  const workspace = await fs.mkdtemp(path.join(os.tmpdir(), 'security-test-'));
  const calls = [];
  const ctx = {
    safeWorkspace: (p, options) => confinedPath(workspace, p, options),
    assertAuthorizedTarget: async target => { if (!['127.0.0.1','::1'].includes(target)) throw new Error('unauthorized target'); return target; },
    assertAuthorizedUrl: async url => { if (new URL(url).hostname !== '127.0.0.1') throw new Error('unauthorized URL'); return url; },
    runStatus: async (command, args, options) => { calls.push({ command, args, options }); return run(command,args,options); },
  };
  const ext = createExtendedSecurity(ctx);
  try { await fn({ ...ext, workspace, calls }); }
  finally { ext.jobs.stopAll(); await fs.rm(workspace, { recursive: true, force: true }); }
}

test('real jq streams JSONL, filters matching records and signals a row limit', async () => {
  await fixture(async ({ call, workspace }) => {
    await fs.writeFile(path.join(workspace,'events.jsonl'), '{"status":200,"url":"a"}\n{"status":403,"url":"b"}\n{"status":200,"url":"c"}\n');
    const r = await call('security_jq', { path:'events.jsonl', filter:'select(.status == 200) | {url}', limit:1 });
    assert.deepEqual(r.records,[{url:'a'}]); assert.equal(r.truncated,true);
    await assert.rejects(call('security_jq',{ path:'events.jsonl', filter:'bad syntax !' }), /jq failed/);
  });
});
test('workspace symlinks cannot escape for reads or new outputs', async () => {
  await fixture(async ({ workspace }) => {
    await fs.symlink('/etc',path.join(workspace,'escape'));
    assert.throws(() => confinedPath(workspace,'escape/passwd',{mustExist:true}),/symlink/);
    assert.throws(() => confinedPath(workspace,'escape/new-file'),/symlink/);
    assert.throws(() => confinedPath(workspace,'../outside'),/escapes/);
  });
});
test('strict schemas reject unknown arguments, invalid enums, fractional ports and missing inputs', () => {
  const schema = EXTENDED_TOOLS.find(t => t.name === 'security_listener_start').inputSchema;
  for (const args of [{}, {port:4444,engine:'bash'}, {port:4444.5}, {port:22}, {port:4444,command:'x'}]) assert.throws(() => validateArguments(schema,args));
  validateArguments(schema,{port:4444,engine:'socat'});
});
test('deadlines and output limits return partial status and terminate commands', async () => {
  const timed = await runStatus(process.execPath,['-e', 'process.stdout.write("started");setInterval(()=>{},1000)'],{timeout:150});
  assert.equal(timed.code,124); assert.equal(timed.timed_out,true); assert.equal(timed.stdout,'started');
  const limited = await runStatus(process.execPath,['-e','process.stdout.write("x".repeat(100000));setInterval(()=>{},1000)'],{timeout:2000,maxBuffer:1024});
  assert.equal(limited.code,125); assert.ok(Buffer.byteLength(limited.stdout)<=1024);
});
test('background jobs allow input, bounded paginated output, cancellation and capacity enforcement', async () => {
  const jobs = new JobManager({maxJobs:1,maxBytes:2048});
  try {
    const job = await jobs.start(process.execPath,['-e','process.stdin.on("data",b=>process.stdout.write(b));setInterval(()=>{},1000)'],{interactive:true,timeout:2000});
    await assert.rejects(jobs.start(process.execPath,['-e','0']),/limit/);
    jobs.send(job.job_id,'hello\n');
    for(let i=0;i<30&&!jobs.status(job.job_id).output;i++) await wait(20);
    const status=jobs.status(job.job_id,0,3); assert.equal(status.output,'hel'); assert.equal(status.next_offset,3); assert.equal(status.has_more,true);
    assert.equal(jobs.status(job.job_id,3).output,'lo\n');
    assert.equal(jobs.stop(job.job_id).status,'stopped');
    assert.throws(()=>jobs.send(job.job_id,'x'),/writable/);
  } finally { jobs.stopAll(); }
});
test('sqlmap uses batch mode, target policy, timeout, and separate argv values', async () => {
  await fixture(async ({call,calls}) => {
    const result=await call('security_sqlmap',{url:'http://127.0.0.1/?id=1',data:'x=$(not-a-shell)',action:'enumerate_databases'});
    assert.equal(result.complete,true);
    assert.ok(calls[0].args.includes('--batch')); assert.ok(calls[0].args.includes('--ignore-redirects')); assert.ok(calls[0].args.includes('--dbs'));
    assert.ok(calls[0].args.includes('--data=x=$(not-a-shell)'));
    await assert.rejects(call('security_sqlmap',{url:'https://example.com/?id=1'}),/unauthorized/);
  },async()=>ok('assessment completed'));
});
test('Metasploit module info uses a generated resource file; rejects console injection and target overrides', async () => {
  let resource='';
  await fixture(async ({call}) => {
    await call('security_metasploit_info',{module:'auxiliary/scanner/http/http_version'});
    assert.match(resource,/use auxiliary\/scanner\/http\/http_version\ninfo\nshow options\nexit -y/);
    await assert.rejects(call('security_metasploit_info',{module:'exploit/x; shell evil'}),/invalid/);
    await assert.rejects(call('security_metasploit_run',{module:'exploit/test',target:'127.0.0.1',options:{RHOSTS:'elsewhere'}}),/reserved/);
    await assert.rejects(call('security_metasploit_run',{module:'exploit/test',target:'127.0.0.1',options:{TARGETURI:'/; shell evil'}}),/unsupported/);
  },async(cmd,args)=>{resource=await fs.readFile(args[2],'utf8');return ok('module info');});
});
test('osquery constrains a read-only query and reports its actual namespace', async () => {
  await fixture(async({call,calls})=>{
    const r=await call('security_osquery',{query:'SELECT * FROM listening_ports;',limit:1});
    assert.equal(r.truncated,true); assert.match(r.visibility,/container/);
    assert.ok(calls[0].args.includes('--disable_extensions')); assert.match(calls[0].args.at(-1),/LIMIT 2/);
    await assert.rejects(call('security_osquery',{query:'SELECT 1; DELETE FROM x;'}),/read-only/);
  },async()=>ok('[{"port":"22"},{"port":"80"}]'));
});
test('Radare2 operations cannot inject arbitrary commands', async () => {
  await fixture(async({call,workspace,calls})=>{
    await fs.writeFile(path.join(workspace,'sample.bin'),'sample');
    const r=await call('security_binary_analyze',{path:'sample.bin',operation:'disassemble',address:'0x1000',count:8});
    assert.deepEqual(r.result,[]); assert.ok(calls[0].args.includes('e cfg.sandbox=true;pdj 8 @ 0x1000')); assert.ok(!calls[0].args.includes('-w'));
    await assert.rejects(call('security_binary_analyze',{path:'sample.bin',address:'0;!sh'}),/address/);
  },async()=>ok('[]'));
});
test('Tshark extracts selected fields and marks the packet examination limit', async () => {
  await fixture(async({call,workspace,calls})=>{
    await fs.writeFile(path.join(workspace,'sample.pcap'),'fixture');
    const r=await call('security_pcap_fields',{path:'sample.pcap',fields:['ip.src','ip.dst'],display_filter:'tcp',packet_limit:10});
    assert.deepEqual(r.rows,[{'ip.src':'127.0.0.1','ip.dst':'127.0.0.2'}]); assert.equal(r.exhaustive,false);
    assert.ok(calls[0].args.includes('-T')); assert.ok(calls[0].args.includes('-Y'));
  },async()=>ok('127.0.0.1\t127.0.0.2\n'));
});
test('Suricata custom-rule validation and PCAP hit rate use the supplied rules', async () => {
  await fixture(async({call,workspace})=>{
    await fs.writeFile(path.join(workspace,'custom.rules'),'alert ip any any -> any any (sid:1;)');
    await fs.writeFile(path.join(workspace,'sample.pcap'),'fixture');
    const r=await call('security_suricata_test_rules',{rules:'custom.rules',pcap:'sample.pcap'});
    assert.equal(r.valid,true); assert.equal(r.alert_count,2); assert.equal(r.matched_packets,1); assert.equal(r.packet_hit_rate,0.5);
  },async(cmd,args)=>{
    assert.ok(args.includes('-S'));
    if(args.includes('-r')) await fs.writeFile(path.join(args[args.indexOf('-l')+1],'eve.json'),[
      {event_type:'alert',pcap_cnt:1,alert:{signature_id:1,signature:'one'}},
      {event_type:'alert',pcap_cnt:1,alert:{signature_id:2,signature:'two'}},
      {event_type:'stats',stats:{decoder:{pkts:2}}},
    ].map(JSON.stringify).join('\n'));
    return ok('');
  });
});
test('Subfinder filters out-of-domain records; invalid JSON never becomes a clean empty result', async () => {
  await fixture(async({call,calls})=>{
    const r=await call('security_subdomain_enum',{domain:'example.com'});
    assert.deepEqual(r.subdomains,['a.example.com']); assert.equal(r.complete,false); assert.ok(calls[0].args.includes('-json'));
    assert.ok(!calls[0].args.includes('-active'));
  },async()=>ok('{"host":"a.example.com"}\n{"host":"badexample.com"}\ninvalid\n'));
});
test('Firecrawl uses Markdown/JSON modes; credentials are never tool arguments', async () => {
  const old=process.env.FIRECRAWL_API_URL; process.env.FIRECRAWL_API_URL='http://127.0.0.1:3002';
  try {
    await fixture(async({call,calls})=>{
      const scrape=await call('security_firecrawl_scrape',{url:'https://example.com'}); assert.equal(scrape.markdown,'# Page');
      const map=await call('security_firecrawl_map',{url:'https://example.com',limit:2}); assert.equal(map.links.length,1);
      assert.ok(calls[0].args.includes('markdown')); assert.ok(calls[1].args.includes('--json'));
      assert.ok(calls.every(c=>!c.args.includes('--api-key')));
    },async(cmd,args)=>ok(args[0]==='scrape'?'# Page':'{"links":["https://example.com/a"]}'));
  } finally { if(old===undefined) delete process.env.FIRECRAWL_API_URL; else process.env.FIRECRAWL_API_URL=old; }
});

test('MCP protocol validates calls, parses Nmap/ffuf, preserves large JSON and rejects target bypasses', async () => {
  const dir=await fs.mkdtemp(path.join(os.tmpdir(),'security-protocol-'));
  await fs.mkdir(path.join(dir,'bin')); await fs.mkdir(path.join(dir,'workspace'));
  for(const [binary,output] of Object.entries({nmap:'Host: 127.0.0.1 ()\tPorts: 80/open/tcp//http//fixture/\n',ffuf:'{"url":"http://127.0.0.1/a","status":200}\n{"url":"http://127.0.0.1/b","status":403}\n'})) {
    await fs.writeFile(path.join(dir,'bin',binary),`#!${process.execPath}\nprocess.stdout.write(${JSON.stringify(output)});`,{mode:0o755});
  }
  const child=spawn(process.execPath,[path.join(root,'scripts/security-tools.mjs')],{env:{...process.env,PATH:path.join(dir,'bin')+':'+process.env.PATH,MCP_WORKSPACE:path.join(dir,'workspace'),SECURITY_TARGET_ALLOWLIST:'127.0.0.0/8,::1/128',SECURITY_ALLOW_PUBLIC_TARGETS:'false',SECURITY_MAX_OUTPUT:'1024'},stdio:['pipe','pipe','pipe']});
  const pending=new Map(); let seq=0;
  const lines=createInterface({input:child.stdout}); lines.on('line',line=>{const m=JSON.parse(line);pending.get(m.id)?.(m.result);pending.delete(m.id);});
  const rpc=(method,params)=>new Promise(resolve=>{const id=++seq;pending.set(id,resolve);child.stdin.write(JSON.stringify({jsonrpc:'2.0',id,method,params})+'\n');});
  const call=(name,args)=>rpc('tools/call',{name,arguments:args});
  try {
    const catalog=await rpc('tools/list',{}); assert.equal(catalog.tools.length,43);
    const bad=await call('security_sqlmap',{}); assert.equal(bad.isError,true);
    for(const target of ['8.8.8.8','127.0.0.1/99','fd00::1','--script=default']) {
      const r=await call('security_network_discover',{target}); assert.equal(r.isError,true,target);
    }
    const ports=JSON.parse((await call('security_port_scan',{target:'127.0.0.1'})).content[0].text);assert.equal(ports.open_ports[0].port,80);
    const fuzz=JSON.parse((await call('security_web_content_discover',{url:'http://127.0.0.1/'})).content[0].text);assert.equal(fuzz.count,1);assert.equal(fuzz.results[0].status,200);
    await fs.writeFile(path.join(dir,'workspace','big.json'),JSON.stringify({value:'x'.repeat(4000)}));
    const large=JSON.parse((await call('security_jq',{path:'big.json'})).content[0].text);assert.equal(large.truncated,true);
    const full=JSON.parse(await fs.readFile(path.join(dir,'workspace',large.output_file),'utf8'));assert.equal(full.records[0].value.length,4000);
  } finally { child.kill(); lines.close(); await fs.rm(dir,{recursive:true,force:true}); }
});
