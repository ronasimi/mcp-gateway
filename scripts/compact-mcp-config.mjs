#!/usr/bin/env node
// Update descriptions only; preserve endpoints, authentication, exposure and gates.
import fs from 'node:fs';
const file=process.argv[2];
if(!file)throw new Error('Usage: node scripts/compact-mcp-config.mjs /path/to/mcp.json');
const original=fs.readFileSync(file,'utf8'),config=JSON.parse(original);
const descriptions={system:'System utilities.',security:'Security assessment.',google:'Google Workspace.',playwright:'Browser automation.',memory:'Persistent graph memory.',searxng:'Web search.'};
if(!config.mcpServers||Array.isArray(config.mcpServers))throw new Error('Expected mcpServers object');
const changed=[];
for(const [name,description] of Object.entries(descriptions)){
 if(config.mcpServers[name]&&config.mcpServers[name].description!==description){config.mcpServers[name].description=description;changed.push(name);}
}
if(changed.length){
 fs.copyFileSync(file,file+'.catalog-backup-'+Date.now(),fs.constants.COPYFILE_EXCL);
 fs.writeFileSync(file,JSON.stringify(config,null,2)+'\n');
}
console.log(JSON.stringify({changed}));
