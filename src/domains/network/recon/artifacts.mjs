import fsp from 'node:fs/promises';
import path from 'node:path';
import { NETWORK_RECON_HOST_TOOL_NAMES } from './tools.mjs';

export function normalizeReconInput(data){
  if(!data||typeof data!=='object'||Array.isArray(data))throw new Error('Map input must be a recon JSON object');
  const aliases={discovery:'perform_network_discovery',network_discovery:'perform_network_discovery',interface_info:'get_host_interface_info',host_interface:'get_host_interface_info',topology:'analyze_network_topology',wireless:'analyze_wireless_environment'};
  const result={};
  for(const [key,value] of Object.entries(data)){
    const name=aliases[key]||key;
    if(NETWORK_RECON_HOST_TOOL_NAMES.has(name)){
      if(!value||typeof value!=='object'||Array.isArray(value)||!Object.keys(value).length)throw new Error(`Empty or invalid observation: ${name}`);
      result[name]=value;
    }
  }
  if(Object.keys(result).length)return result;
  const matches=[];
  if(Array.isArray(data.hosts))matches.push('perform_network_discovery');
  if(data.current_connection&&Array.isArray(data.nearby_access_points))matches.push('analyze_wireless_environment');
  if(data.mdns_reflector_assessment||data.client_isolation_assessment)matches.push('analyze_network_topology');
  if(data.selected_interface&&Array.isArray(data.interfaces))matches.push('get_host_interface_info');
  if(matches.length!==1)throw new Error('Map requires collected observations: unrecognized or ambiguous recon JSON; use observation_path artifacts, not previews or arbitrary output files');
  return {[matches[0]]:data};
}

export function resultEnvelope(value,outputFile,totalBytes,preview){
  const result={truncated:true,output_file:outputFile,total_bytes:totalBytes};
  for(const key of ['observation_path','report_path','read_hint','observation_save_error','map_ready','map_hint','status','available','coverage','coverage_limitations','evidence_available','complete','next_offset','observation_mode','observation_duration_seconds','duration_note','outputs','included_observations','missing_observations','warnings','evidence_notes'])if(value[key]!==undefined)result[key]=value[key];
  return {...result,preview};
}

export function normalizeMapOutputBase(value){
  const input=value??'.security-results/network-map';
  if(typeof input!=='string'||!input.trim()||input.includes('\0')||input.includes('\\')||path.posix.isAbsolute(input)||/^[A-Za-z]:/.test(input)||input.split('/').includes('..'))throw new Error('output_base must be a relative basename without traversal');
  const normalized=path.posix.normalize(input);
  if(normalized==='.'||normalized==='.security-results'||input.endsWith('/'))throw new Error('output_base requires a file basename');
  return normalized.startsWith('.security-results/')?normalized:'.security-results/'+normalized;
}

export async function prepareMapOutput(workspaceRoot,baseRel){
  let dir=workspaceRoot;
  for(const component of path.dirname(baseRel).split('/')){
    dir=path.join(dir,component);
    const stat=await fsp.lstat(dir).catch(error=>{if(error.code==='ENOENT')return null;throw error;});
    if(stat){if(stat.isSymbolicLink()||!stat.isDirectory())throw new Error('Map output directory must be a real directory under .security-results');}
    else{await fsp.mkdir(dir,{mode:0o2750});await fsp.chmod(dir,0o2750);}
  }
  for(const extension of ['.dot','.svg','.html']){
    const stat=await fsp.lstat(path.join(workspaceRoot,baseRel)+extension).catch(error=>{if(error.code==='ENOENT')return null;throw error;});
    if(stat&&(stat.isSymbolicLink()||!stat.isFile()))throw new Error('Map output must be a regular file under .security-results');
  }
}
