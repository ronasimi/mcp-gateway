import test from 'node:test';
import assert from 'node:assert/strict';
import {PassThrough} from 'node:stream';
import {startMcpStdioServer} from '../src/core/mcp-stdio.mjs';
test('MCP redacts before encoding/persistence, retains schemas and emits object structuredContent',async()=>{
 const input=new PassThrough(),output=new PassThrough();let wire='',encoded;
 output.on('data',data=>wire+=data);
 const tools=[{name:'read',inputSchema:{type:'object',properties:{password:{type:'string'}}}}];
 const server=startMcpStdioServer({serverName:'fixture',tools,input,output,callTool:async()=>({key:'wifi-secret',version:'1.2.3',stdout:"option key 'uci-secret'"}),encodeResult:value=>{encoded=value;return JSON.stringify(value);}});
 await server.handleMessage({id:1,method:'tools/list'});assert.match(wire,/password/);wire='';
 await server.handleMessage({id:2,method:'tools/call',params:{name:'read',arguments:{}}});
 assert.doesNotMatch(wire,/wifi-secret|uci-secret/);assert.equal(encoded.key,'[redacted]');assert.equal(JSON.parse(wire).result.structuredContent.version,'1.2.3');
});
test('error encoder receives sanitized error and arguments; arrays have no invalid structuredContent',async()=>{
 const input=new PassThrough(),output=new PassThrough();let wire='',seen;
 output.on('data',data=>wire+=data);let fail=true;
 const server=startMcpStdioServer({serverName:'fixture',tools:[{name:'read'}],input,output,callTool:async()=>{if(fail)throw new Error('password=error-secret');return [1,2];},encodeError:(error,meta)=>{seen={message:error.message,args:meta.args};return error.stack;}});
 await server.handleMessage({id:1,method:'tools/call',params:{name:'read',arguments:{token:'arg-secret'}}});
 assert.doesNotMatch(JSON.stringify(seen)+wire,/error-secret|arg-secret/);assert.equal(JSON.parse(wire).result.isError,true);
 fail=false;wire='';await server.handleMessage({id:2,method:'tools/call',params:{name:'read'}});assert.equal(JSON.parse(wire).result.structuredContent,undefined);assert.equal(JSON.parse(wire).result.content[0].text,'[1,2]');
});
