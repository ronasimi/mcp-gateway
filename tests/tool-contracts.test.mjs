import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { PassThrough } from 'node:stream';
import { adaptToolContracts } from '../src/core/tool-contracts.mjs';
import { startMcpStdioServer } from '../src/core/mcp-stdio.mjs';
import { createWeatherRssTools } from '../scripts/weather-rss-adapter.mjs';

const read=name=>JSON.parse(fs.readFileSync(new URL(`../src/contracts/${name}.json`,import.meta.url),'utf8'));
const migrations=read('migration-map');
function fixture(domain) {
  const tools=read(`${domain}-tools`);
  const entries=migrations.filter(item=>item.server===domain);
  const originals=entries.map(item=>({name:item.old_name,inputSchema:{type:'object'}}));
  const calls=[];
  const adapter=adaptToolContracts(domain,originals,(name,args)=>{calls.push({name,args});return {name,args};});
  async function call(name,args) {
    const canonical=adapter.canonicalize(name,args);
    const tool=tools.find(tool=>tool.name===canonical.name);
    await adapter.validateCall(tool,canonical.args,canonical.name);
    return adapter.callTool(canonical.name,canonical.args);
  }
  return {adapter,calls,call};
}

test('all 144 canonical names dispatch to retained handlers; no defaults injected',()=>{
  for(const domain of ['system','security','google']) {
    const {adapter}=fixture(domain);
    for(const entry of migrations.filter(item=>item.server===domain)) {
      const args={};
      assert.deepEqual(adapter.callTool(entry.new_name,args),{name:entry.old_name,args:{}});
      assert.deepEqual(args,{});
    }
  }
});

test('seconds parameters and typed ubus payload translate in both directions',async()=>{
  const {call}=fixture('system');
  const expected={name:'network_ping',args:{host:'example.com',timeout:5}};
  assert.deepEqual(await call('network_ping_host',{host:'example.com',timeout_seconds:5}),expected);
  assert.deepEqual(await call('network_ping',{host:'example.com',timeout:5}),expected);
  const args={target:'anansi',object:'system',method:'board',arguments:{hello:['world',1]}};
  const result=await call('openwrt_call_ubus',args);
  assert.equal(result.name,'openwrt_ubus_call');
  assert.equal(result.args.args,'{"hello":["world",1]}');
  assert.deepEqual(await call('openwrt_ubus_call',{target:'anansi',object:'system',method:'board',args:result.args.args}),result);
  assert.deepEqual(args.arguments,{hello:['world',1]});
});

test('all domains reject unknown fields, fractional counts, invalid formats and conditionals before dispatch',async()=>{
  const system=fixture('system'),security=fixture('security'),google=fixture('google');
  const invalid=[
    [system,'network_ping_host',{host:'example.com',count:1.5}],
    [system,'network_ping_host',{host:'example.com',timeout:5}],
    [system,'network_lookup_dns',{name:'example.com',type:'A',types:['MX']}],
    [system,'openwrt_call_ubus',{target:'anansi',object:'system',method:'board',arguments:'{}'}],
    [security,'network_render_map',{}],
    [security,'network_render_map',{data:{},input_path:'saved.json'}],
    [security,'network_discover_hosts',{port_profile:'full'}],
    [google,'gmail_modify_labels',{message_id:'abc'}],
    [google,'gmail_create_draft',{to:['invalid'],subject:'x',body:'test'}],
    [google,'calendar_update_event',{event_id:'abc'}],
  ];
  for(const [api,name,args] of invalid) await assert.rejects(api.call(name,args),/arguments/);
  assert.deepEqual([system.calls.length,security.calls.length,google.calls.length],[0,0,0]);
});

test('actual system transport serves weather/RSS and preserves tool errors',async()=>{
  let fetched=0;
  const weather=createWeatherRssTools({fetchImpl:async url=>{
    fetched++;
    if(String(url).includes('geocoding'))return Response.json({results:[]});
    return new Response('<rss version="2.0"><channel><title>Local news</title><link>https://example.com</link><description>News</description><item><title>London</title><description>Example headline</description></item></channel></rss>');
  }});
  const {adapter}=fixture('system');
  const legacy=migrations.filter(item=>item.server==='system').map(item=>({name:item.old_name,inputSchema:{type:'object'}}));
  const input=new PassThrough(),output=new PassThrough();
  let text='';output.on('data',chunk=>text+=chunk);
  const rpc=startMcpStdioServer({serverName:'test',contractDomain:'system',tools:[...legacy,...weather.tools],callTool:(name,args)=>weather.callTool(name,args),input,output});
  await rpc.handleMessage({jsonrpc:'2.0',id:1,method:'tools/list'});
  await rpc.handleMessage({jsonrpc:'2.0',id:2,method:'tools/call',params:{name:'get_rss_feed',arguments:{feedUrl:'https://example.com/feed'}}});
  await rpc.handleMessage({jsonrpc:'2.0',id:3,method:'tools/call',params:{name:'get_weather',arguments:{city:'London'}}});
  await rpc.handleMessage({jsonrpc:'2.0',id:4,method:'tools/call',params:{name:'get_rss_feed',arguments:{feedUrl:'https://example.com/feed',maxResults:1.5}}});
  const rows=text.trim().split('\n').map(JSON.parse);
  assert.equal(rows[0].result.tools.length,adapter.tools.length+2);
  assert.equal(JSON.parse(rows[1].result.content[0].text).entries[0].title,'London');
  assert.equal(rows[1].result.isError,false);
  assert.equal(rows[2].result.isError,true);
  assert.match(rows[2].result.content[0].text,/No location matched/);
  assert.equal(rows[3].result.isError,true);
  assert.equal(fetched,2);
  input.destroy();output.destroy();
});
