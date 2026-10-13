#!/usr/bin/env python3
"""Read-only MCP inventory. No tools/call, scans, capture or credential collection."""
import argparse
import json
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

def rpc(url, payload, session=None):
    headers={'Content-Type':'application/json','Accept':'application/json, text/event-stream','MCP-Protocol-Version':'2025-03-26'}
    if session: headers['Mcp-Session-Id']=session
    with urlopen(Request(url, json.dumps(payload).encode(),headers),timeout=20) as response:
        raw=response.read(8*1024*1024+1).decode()
        if len(raw.encode())>8*1024*1024: raise ValueError('Catalog exceeds 8 MiB')
        session=response.headers.get('Mcp-Session-Id',session)
        if not raw.strip():return None,session
        if 'text/event-stream' in response.headers.get('Content-Type',''):
            for event in raw.replace('\r\n','\n').split('\n\n'):
                data='\n'.join(line[5:].lstrip() for line in event.splitlines() if line.startswith('data:'))
                if data:
                    message=json.loads(data)
                    if message.get('id')==payload.get('id'):return message,session
            raise ValueError('No matching JSON-RPC response in SSE')
        return json.loads(raw),session

def inventory(url):
    response,session=rpc(url,{'jsonrpc':'2.0','id':1,'method':'initialize','params':{'protocolVersion':'2025-03-26','capabilities':{},'clientInfo':{'name':'gateway-catalog-audit','version':'1.0'}}})
    if 'error' in response:raise ValueError(response['error'].get('message','Initialize failed'))
    rpc(url,{'jsonrpc':'2.0','method':'notifications/initialized'},session)
    tools=[]; cursor=None; seen=set()
    for page in range(100):
        result,session=rpc(url,{'jsonrpc':'2.0','id':page+2,'method':'tools/list','params':{'cursor':cursor} if cursor else {}},session)
        if 'error' in result:raise ValueError(result['error'].get('message','tools/list failed'))
        tools.extend(result['result']['tools'])
        cursor=result['result'].get('nextCursor')
        if not cursor:break
        if cursor in seen:raise ValueError('Repeated catalog cursor')
        seen.add(cursor)
    else:raise ValueError('Catalog pagination exceeded 100 pages')
    return {'serverInfo':response['result'].get('serverInfo'), 'count':len(tools), 'tools':tools}

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--google',action='store_true',help='Include optional Google server')
    parser.add_argument('--endpoint',action='append',default=[],metavar='NAME=URL',help='Override/add a server endpoint')
    parser.add_argument('--output',required=True,help='Save catalog JSON to this local path')
    args=parser.parse_args()
    endpoints={'playwright':'http://127.0.0.1:8931/mcp','memory':'http://127.0.0.1:8932/mcp','system':'http://127.0.0.1:8933/mcp','security':'http://127.0.0.1:8935/mcp','searxng':'http://127.0.0.1:8888/mcp/'}
    if args.google:endpoints['google']='http://127.0.0.1:8934/mcp'
    for item in args.endpoint:
        name,url=item.split('=',1);endpoints[name]=url
    report={'method':'initialize + paginated tools/list only; advertised tools are not proof of backend availability or Pi search rank','servers':{}}
    failed=False
    for name,url in endpoints.items():
        try:
            data=inventory(url); report['servers'][name]={'status':'PASS',**data}
            print(f'{name}: {data["count"]} advertised tools')
        except (HTTPError,URLError,TimeoutError,ValueError,KeyError,TypeError) as error:
            # Do not echo endpoint URLs, request headers or response bodies.
            reason=f'HTTP {error.code}' if isinstance(error,HTTPError) else type(error).__name__
            report['servers'][name]={'status':'FAILED','error':reason};failed=True
            print(f'{name}: FAILED ({reason})')
    with open(args.output,'w') as stream:json.dump(report,stream,indent=2);stream.write('\n')
    return int(failed)

if __name__=='__main__':raise SystemExit(main())
