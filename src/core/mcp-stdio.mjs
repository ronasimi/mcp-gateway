/**
 * Minimal JSON-RPC/MCP stdio server used by the local domain processes.
 * Domain modules own catalog metadata, argument validation, execution policy,
 * and result encoding; this module owns transport framing and MCP dispatch only.
 */
export function startMcpStdioServer({
  serverName,
  serverVersion='1.0.0',
  instructions,
  tools,
  callTool,
  validateCall,
  encodeResult=value => typeof value==='string' ? value : JSON.stringify(value),
  encodeError=error => error?.stack || error?.message || String(error),
  input=process.stdin,
  output=process.stdout,
}) {
  if(!serverName) throw new Error('serverName is required');
  if(!Array.isArray(tools)) throw new Error('tools must be an array');
  if(typeof callTool!=='function') throw new Error('callTool must be a function');

  const toolMap=new Map(tools.map(tool=>[tool.name,tool]));
  const response=(id,result)=>output.write(JSON.stringify({jsonrpc:'2.0',id,result})+'\n');
  const errorResponse=(id,code,message,data)=>output.write(JSON.stringify({jsonrpc:'2.0',id,error:{code,message,...(data?{data}:{})}})+'\n');

  async function handleMessage(msg){
    if(msg?.method==='notifications/initialized'||msg?.method==='notifications/cancelled') return;
    if(msg?.id==null) return;
    try{
      if(msg.method==='initialize') return response(msg.id,{
        protocolVersion:msg.params?.protocolVersion||'2025-06-18',
        capabilities:{tools:{listChanged:false}},
        serverInfo:{name:serverName,version:serverVersion},
        ...(instructions?{instructions}:{}),
      });
      if(msg.method==='ping') return response(msg.id,{});
      if(msg.method==='tools/list') return response(msg.id,{tools});
      if(msg.method==='tools/call'){
        const name=msg.params?.name;
        const args=msg.params?.arguments||{};
        const tool=toolMap.get(name);
        if(!tool) throw new Error(`unknown tool: ${name}`);
        try{
          if(validateCall) await validateCall(tool,args,name);
          const value=await callTool(name,args);
          const text=await encodeResult(value,{tool,name,args});
          return response(msg.id,{content:[{type:'text',text:String(text)}],isError:false});
        }catch(error){
          const text=await encodeError(error,{tool,name,args});
          return response(msg.id,{content:[{type:'text',text:String(text)}],isError:true});
        }
      }
      return errorResponse(msg.id,-32601,`Method not found: ${msg.method}`);
    }catch(error){
      return errorResponse(msg.id,-32603,error?.message||String(error));
    }
  }

  async function handleLine(line){
    let msg;
    try{msg=JSON.parse(line);}catch{return;}
    await handleMessage(msg);
  }

  let buffer='';
  input.setEncoding('utf8');
  input.on('data',chunk=>{
    buffer+=chunk;
    let idx;
    while((idx=buffer.indexOf('\n'))>=0){
      const line=buffer.slice(0,idx).trim();
      buffer=buffer.slice(idx+1);
      if(line) void handleLine(line);
    }
  });

  return {handleMessage,handleLine,toolMap};
}
