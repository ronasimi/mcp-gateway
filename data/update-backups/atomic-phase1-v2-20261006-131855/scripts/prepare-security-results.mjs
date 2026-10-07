#!/usr/bin/env node
import fs from 'node:fs/promises';
import path from 'node:path';
import {pathToFileURL} from 'node:url';
export async function prepareResults(root, {uid, gid, provision=false}={}) {
  const base=await fs.realpath(root);
  // Only these two application-owned directories may change ownership/mode.
  for(const relative of ['.security-results','.security-results/observations']) {
    const dir=path.join(base,relative);
    try {await fs.mkdir(dir,{mode:0o750});} catch(error) {if(error.code!=='EEXIST')throw error;}
    const stat=await fs.lstat(dir);
    if(stat.isSymbolicLink()||!stat.isDirectory())throw Error(`Refusing non-directory or symlink: ${relative}`);
    if(provision){await fs.chown(dir,uid,gid);await fs.chmod(dir,0o2750);}
  }
  const probe=await fs.mkdtemp(path.join(base,'.security-results/observations/.write-check-'));
  try{await fs.writeFile(path.join(probe,'probe'),'ok',{mode:0o600});}finally{await fs.rm(probe,{recursive:true,force:true});}
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){
 const provision=process.argv.includes('--provision');
 const uid=Number(process.env.RESULTS_UID),gid=Number(process.env.RESULTS_GID);
 if(provision&&(!Number.isInteger(uid)||uid<0||!Number.isInteger(gid)||gid<0))throw Error('Valid RESULTS_UID and RESULTS_GID required');
 await prepareResults(process.env.MCP_WORKSPACE||'/workspace',{uid,gid,provision});
 console.log('Security results directory write check passed.');
}
