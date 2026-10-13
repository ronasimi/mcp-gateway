import test from 'node:test';
import assert from 'node:assert/strict';
import { registerWeatherRssTools, weatherSchema, rssSchema } from '../scripts/weather-rss.mjs';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';

const geo={results:[{name:'London',admin1:'Ontario',country:'Canada',country_code:'CA',latitude:42.98,longitude:-81.23}]};
const weather={timezone:'America/Toronto',current:{time:'2026-10-13T09:00',temperature_2m:0,apparent_temperature:-1,weather_code:0,wind_speed_10m:5},daily:{time:['2026-10-13','2026-10-14','2026-10-15'],temperature_2m_max:[10,11,12],temperature_2m_min:[0,1,2],weather_code:[0,1,3]}};
const rss='<rss version="2.0"><channel><title>News</title><link>https://example.com</link><description>Local</description><item><title>Old Weather</title><pubDate>Mon, 12 Oct 2026 09:00:00 GMT</pubDate><description>Rain</description></item><item><title>New</title><pubDate>Tue, 13 Oct 2026 09:00:00 GMT</pubDate><description>&lt;p&gt;WEATHER &amp;amp; sun&lt;/p&gt;</description></item></channel></rss>';
async function withClient(fetchImpl, fn, extra={}) {
 const server=new McpServer({name:'test',version:'1.0.0'});
 registerWeatherRssTools(server,{fetchImpl,...extra});
 const client=new Client({name:'test-client',version:'1.0.0'});
 const [a,b]=InMemoryTransport.createLinkedPair();
 await server.connect(a);await client.connect(b);
 try {return await fn(client);}finally{await client.close();await server.close();}
}
const call=(fetchImpl,name,args,options)=>withClient(fetchImpl,c=>c.callTool({name,arguments:args}),options);

test('weather parameters, units, zero temperature and code',async()=>{
 const r=await call(async url=>{const u=new URL(url);
  if(u.host.includes('geocoding')){assert.equal(u.searchParams.get('name'),'London, Ontario');assert.equal(u.searchParams.get('countryCode'),'CA');return Response.json(geo);}
  assert.equal(u.searchParams.get('forecast_days'),'3');assert.equal(u.searchParams.get('temperature_unit'),'celsius');assert.equal(u.searchParams.get('wind_speed_unit'),'kmh');return Response.json(weather);
 },'get_weather',{city:'London',provinceOrState:'Ontario',country:'Canada'});
 assert.ok(!r.isError);assert.match(r.content[0].text,/0\.0 °C/);assert.match(r.content[0].text,/Clear sky/);assert.match(r.content[0].text,/2026-10-15/);
});
test('location failures, unknown country, invalid upstream JSON',async()=>{
 for(const [body,expected] of [[{},/No location matched/],[{results:[{}]},/invalid location/]]){
  const r=await call(async()=>Response.json(body),'get_weather',{city:'London'});assert.equal(r.isError,true);assert.match(r.content[0].text,expected);
 }
 const r=await call(async()=>{throw Error('should not fetch');},'get_weather',{city:'London',country:'ZZ'});assert.equal(r.isError,true);assert.match(r.content[0].text,/Country not recognized/);
 const bad=await call(async()=>new Response('no JSON'),'get_weather',{city:'London'});assert.equal(bad.isError,true);assert.match(bad.content[0].text,/malformed JSON/);
});
test('malformed or partial forecast is an error',async()=>{
 const r=await call(async url=>Response.json(String(url).includes('geocoding')?geo:{}),'get_weather',{city:'London'});assert.equal(r.isError,true);assert.match(r.content[0].text,/incomplete/);
});
test('feed HTML cleanup, case-insensitive filter and newest-first cap',async()=>{
 const r=await call(async()=>new Response(rss),'get_rss_feed',{feedUrl:'https://example.com/feed',searchQuery:'weather',maxResults:1});
 const data=JSON.parse(r.content[0].text);assert.equal(data.matchingEntries,2);assert.equal(data.entries[0].title,'New');assert.equal(data.entries[0].summary,'WEATHER & sun');
});
test('filter full summary before truncation',async()=>{
 const body=`<rss version="2.0"><channel><title>T</title><item><title>A</title><description>${'x'.repeat(1000)} needle</description></item></channel></rss>`;
 const r=await call(async()=>new Response(body),'get_rss_feed',{feedUrl:'https://example.com/feed',searchQuery:'needle'});
 const data=JSON.parse(r.content[0].text);assert.equal(data.matchingEntries,1);assert.ok(data.entries[0].summary.length<=800);
});
test('Atom updated date and relative link',async()=>{
 const xml='<feed xmlns="http://www.w3.org/2005/Atom"><title>Atom</title><entry><id>1</id><title>Update</title><link href="article"/><updated>2026-10-13T09:00:00Z</updated><summary type="html">&lt;b&gt;Hello&lt;/b&gt;</summary></entry></feed>';
 const r=await call(async()=>new Response(xml),'get_rss_feed',{feedUrl:'https://example.com/feed.xml'});
 const data=JSON.parse(r.content[0].text);assert.equal(data.entries[0].link,'https://example.com/article');assert.ok(data.entries[0].date);assert.equal(data.entries[0].summary,'Hello');
});
test('valid empty feeds and malformed XML',async()=>{
 let r=await call(async()=>new Response('<rss version="2.0"><channel><title>Empty</title></channel></rss>'),'get_rss_feed',{feedUrl:'https://example.com/feed'});
 assert.deepEqual(JSON.parse(r.content[0].text).entries,[]);
 for(const xml of ['<html>not RSS</html>','<rss><channel>']){
  r=await call(async()=>new Response(xml),'get_rss_feed',{feedUrl:'https://example.com/feed'});assert.equal(r.isError,true);assert.match(r.content[0].text,/malformed XML|unsupported/);
 }
});
test('schema bounds/types and registered names',async()=>{
 for(const value of [0,51,1.5,'5',true])assert.equal(rssSchema.safeParse({feedUrl:'https://example.com/feed',maxResults:value}).success,false);
 for(const url of ['not-url','file:///etc/passwd','https://user:pass@example.com/feed'])assert.equal(rssSchema.safeParse({feedUrl:url}).success,false);
 assert.equal(weatherSchema.safeParse({city:'London',invented:true}).success,false);
 await withClient(async()=>new Response(rss),async c=>{const {tools}=await c.listTools();assert.deepEqual(tools.map(t=>t.name),['get_weather','get_rss_feed']);for(const t of tools)for(const p of Object.values(t.inputSchema.properties))assert.ok(p.description);const r=await c.callTool({name:'get_rss_feed',arguments:{feedUrl:'file:///tmp/a'}});assert.equal(r.isError,true);});
});
test('HTTP failures, unreachable servers, empty and oversized bodies',async()=>{
 for(const [fetcher,expected] of [[async()=>new Response('x',{status:503}),/HTTP 503/],[async()=>{throw Error('secret URL');},/could not be reached/],[async()=>new Response(''),/empty response/],[async()=>new Response('x'.repeat(2*1024*1024+1)),/response limit/]]){
  const r=await call(fetcher,'get_rss_feed',{feedUrl:'https://example.com/feed'});assert.equal(r.isError,true);assert.match(r.content[0].text,expected);assert.doesNotMatch(r.content[0].text,/secret URL/);
 }
});
test('deadline cancels a slow fetch',async()=>{
 const fetcher=async(_url,{signal})=>new Promise((_,reject)=>signal.addEventListener('abort',()=>reject(new DOMException('Aborted','AbortError')),{once:true}));
 const r=await call(fetcher,'get_rss_feed',{feedUrl:'https://example.com/feed'},{timeoutMs:10});assert.equal(r.isError,true);assert.match(r.content[0].text,/timed out/);
});
