import importlib.util
import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from threading import Thread
import unittest
spec=importlib.util.spec_from_file_location('audit',Path(__file__).resolve().parents[1]/'scripts/audit-live-catalog.py')
audit=importlib.util.module_from_spec(spec);spec.loader.exec_module(audit)

class CatalogTests(unittest.TestCase):
    def test_json_sse_session_and_pagination_without_tool_execution(self):
        requests=[]
        class Handler(BaseHTTPRequestHandler):
            def log_message(self,*args):pass
            def do_POST(self):
                req=json.loads(self.rfile.read(int(self.headers['Content-Length'])))
                requests.append(req['method'])
                if req['method']=='initialize':
                    result={'protocolVersion':'2025-03-26','serverInfo':{'name':'fixture'}}
                    self.send_response(200);self.send_header('Mcp-Session-Id','fixture')
                    body=json.dumps({'jsonrpc':'2.0','id':req['id'],'result':result}).encode()
                    self.send_header('Content-Type','application/json')
                elif req['method']=='notifications/initialized':
                    assert self.headers['Mcp-Session-Id']=='fixture'
                    self.send_response(202);body=b''
                else:
                    assert req['method']=='tools/list'
                    assert self.headers['Mcp-Session-Id']=='fixture'
                    result={'tools':[{'name':'second'}]} if req['params'].get('cursor')=='next' else {'tools':[{'name':'first'}],'nextCursor':'next'}
                    self.send_response(200);self.send_header('Content-Type','text/event-stream')
                    body=('event: message\ndata: '+json.dumps({'jsonrpc':'2.0','id':req['id'],'result':result})+'\n\n').encode()
                self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
        server=HTTPServer(('127.0.0.1',0),Handler);thread=Thread(target=server.serve_forever);thread.start()
        try:
            data=audit.inventory(f'http://127.0.0.1:{server.server_port}/mcp')
            self.assertEqual(data['count'],2)
            self.assertEqual([t['name'] for t in data['tools']],['first','second'])
            self.assertEqual(requests,['initialize','notifications/initialized','tools/list','tools/list'])
        finally:server.shutdown();thread.join();server.server_close()

if __name__=='__main__':unittest.main()
