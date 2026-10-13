import { zodToJsonSchema } from 'zod-to-json-schema';
import { registerWeatherRssTools, weatherSchema, rssSchema } from './weather-rss.mjs';

/** Reuse the supplied SDK registration handlers with the stack's stdio transport. */
export function createWeatherRssTools(options={}) {
  const tools=[];
  const handlers=new Map();
  const schemas={get_weather:weatherSchema,get_rss_feed:rssSchema};
  const aliases={get_weather:['current city weather','three day forecast'],get_rss_feed:['RSS news headlines','Atom feed entries']};
  registerWeatherRssTools({tool(name,description,_shape,handler) {
    const inputSchema=zodToJsonSchema(schemas[name],{target:'jsonSchema7',$refStrategy:'none'});
    inputSchema.description=`Arguments for ${name.replaceAll('_',' ')}.`;
    inputSchema.required ||= [];
    tools.push({name,description:`${description} Aliases: ${aliases[name].join('; ')}.`,inputSchema,
      annotations:{readOnlyHint:true,destructiveHint:false,idempotentHint:true,openWorldHint:true},
      _meta:{'ai.catalog':{domain:'system',scope:description,preferredFor:description,aliases:aliases[name]}}});
    handlers.set(name,handler);
  }},options);
  return {tools,has:name=>handlers.has(name),async callTool(name,args) {
    const handler=handlers.get(name);
    if(!handler) throw new Error(`unknown weather/RSS tool: ${name}`);
    const result=await handler(args);
    const text=result.content.filter(item=>item.type==='text').map(item=>item.text).join('\n');
    if(result.isError) throw new Error(text);
    return text;
  }};
}
