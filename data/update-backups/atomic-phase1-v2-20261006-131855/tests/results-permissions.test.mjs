import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import {spawnSync} from 'node:child_process';
import {prepareResults} from '../scripts/prepare-security-results.mjs';
test('provision results without changing workspace or unrelated file permissions',async()=>{
 const dir=await fs.mkdtemp(path.join(os.tmpdir(),'results-permissions-'));
 try{
  await fs.writeFile(path.join(dir,'keep'),'unchanged',{mode:0o640});const before=await fs.stat(dir);
  await prepareResults(dir,{uid:process.getuid(),gid:process.getgid(),provision:true});await prepareResults(dir);
  assert.equal((await fs.stat(dir)).mode,before.mode);assert.equal((await fs.stat(path.join(dir,'keep'))).mode&0o777,0o640);
  assert.deepEqual(await fs.readdir(path.join(dir,'.security-results/observations')),[]);
 }finally{await fs.rm(dir,{recursive:true,force:true});}
});
test('provision rejects symlink results instead of changing external paths',async()=>{
 const dir=await fs.mkdtemp(path.join(os.tmpdir(),'results-symlink-'));const outside=await fs.mkdtemp(path.join(os.tmpdir(),'results-outside-'));
 try{await fs.symlink(outside,path.join(dir,'.security-results'));const before=await fs.stat(outside);await assert.rejects(prepareResults(dir,{uid:process.getuid(),gid:process.getgid(),provision:true}),/Refusing/);assert.equal((await fs.stat(outside)).mode,before.mode);}finally{await fs.rm(dir,{recursive:true,force:true});await fs.rm(outside,{recursive:true,force:true});}
});
test('non-owner can write only the provisioned results subtree', {skip:process.getuid()!==0},async(t)=>{
 const dir=await fs.mkdtemp(path.join(os.tmpdir(),'results-owner-'));
 try{
  await fs.chmod(dir,0o755);
  const script=`const fs=require('fs');try{fs.mkdirSync(process.argv[1]+'/.security-results');process.exit(3)}catch(e){if(e.code!=='EACCES')throw e}`;
  const denied=spawnSync(process.execPath,['-e',script,dir],{uid:65534,gid:65534,encoding:'utf8'});if(['EPERM','EINVAL'].includes(denied.error?.code)){t.skip('Execution environment prohibits changing child UID/GID');return;}assert.equal(denied.status,0,denied.stderr||denied.error?.message);
  await prepareResults(dir,{uid:65534,gid:65534,provision:true});
  const allowed=spawnSync(process.execPath,['-e',`require('fs').writeFileSync(process.argv[1]+'/.security-results/observations/test.json','{}')`,dir],{uid:65534,gid:65534,encoding:'utf8'});assert.equal(allowed.status,0,allowed.stderr);
 }finally{await fs.rm(dir,{recursive:true,force:true});}
});
