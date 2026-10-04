#!/usr/bin/env node
// Offline checks inside the built image: no target scanning or cloud requests.
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import assert from 'node:assert/strict';
import { createExtendedSecurity } from './security-extended.mjs';
import { runStatus, confinedPath } from './security-runtime.mjs';

const dir=await fs.mkdtemp(path.join(os.tmpdir(),'security-smoke-'));
const api=createExtendedSecurity({runStatus,safeWorkspace:(p,o)=>confinedPath(dir,p,o)});
try {
  const status=await api.call('status',{});
  const missing=Object.entries(status.installed).filter(([,present])=>!present).map(([name])=>name);
  assert.deepEqual(missing,[],`missing binaries: ${missing.join(', ')}`);
  await fs.writeFile(path.join(dir,'events.jsonl'),'{"status":200}\n{"status":403}\n');
  assert.equal((await api.call('jq',{path:'events.jsonl',filter:'select(.status == 200)'})).returned,1);
  const endpoint=await api.call('osquery',{query:'SELECT version FROM osquery_info;'});
  assert.ok(endpoint.rows[0]?.version);
  await fs.copyFile('/bin/true',path.join(dir,'sample.bin'));
  for(const operation of ['info','imports','exports','strings','functions','disassemble']) {
    const r=await api.call('binary_analyze',{path:'sample.bin',operation,count:4});
    assert.ok(r.result !== null);
  }
  const exploitSearch=await api.call('exploit_search',{query:'CVE-2021-44228',limit:1});
  assert.ok(Array.isArray(exploitSearch.results));
  const check=await runStatus('sqlmap',['--help'],{timeout:30000});assert.equal(check.code,0);assert.match(check.stdout,/--batch/);
  const fuzz=await runStatus('ffuf',['-h'],{timeout:30000});assert.match(fuzz.stdout+fuzz.stderr,/-json/);
  const msf=await runStatus('msfconsole',['--version'],{timeout:120000});assert.equal(msf.code,0);
  console.log(JSON.stringify({ok:true,installed:Object.keys(status.installed),osquery_version:endpoint.rows[0].version,metasploit:msf.stdout.trim(),checks:'binary presence, jq, osquery, six Radare2 operations, Searchsploit JSON, sqlmap/ffuf flags, Metasploit startup',cloud_requests:0,target_scans:0},null,2));
} finally { api.jobs.stopAll();await fs.rm(dir,{recursive:true,force:true}); }
