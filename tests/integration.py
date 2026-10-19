"""Run against the deployed CPA image with fake keys/upstream; never mounts production data.
Linux prerequisites: Docker, Python 3, websocket-client. Run: python3 tests/integration.py --library dist/key-model-access.so --image <image-id>
"""
import argparse
import hashlib
import http.server
import json
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.request

parser = argparse.ArgumentParser()
parser.add_argument('--library', required=True)
parser.add_argument('--image', required=True)
args = parser.parse_args()
root = Path(tempfile.mkdtemp(prefix='kma-global-test-'))
container = root.name

class Upstream(http.server.BaseHTTPRequestHandler):
    calls = 0
    def log_message(self, *args): pass
    def do_POST(self):
        type(self).calls += 1
        self.rfile.read(int(self.headers.get('Content-Length', 0)))
        body = json.dumps({'id':'chatcmpl-test','object':'chat.completion','model':'allowed','choices':[{'index':0,'message':{'role':'assistant','content':'ok'},'finish_reason':'stop'}],'usage':{'prompt_tokens':1,'completion_tokens':1,'total_tokens':2}}).encode()
        self.send_response(200)
        self.send_header('Content-Type','application/json')
        self.end_headers()
        self.wfile.write(body)

server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Upstream)
threading.Thread(target=server.serve_forever, daemon=True).start()
sock = socket.socket()
sock.bind(('127.0.0.1', 0))
port = sock.getsockname()[1]
sock.close()
(root/'plugins').mkdir()
(root/'auths').mkdir()
shutil.copy2(args.library, root/'plugins/key-model-access.so')
scope = hashlib.sha256(b'cli-proxy-api:caller-scope:v1\0test-client-a').hexdigest()
policy = {'version':3,'global_deny_models':['blocked'], 'policies':[{'caller_scope':scope,'allow_models':['*'],'deny_models':[]}]}
(root/'policy.json').write_text(json.dumps(policy))
provider = {'name':'fake','base-url':f'http://127.0.0.1:{server.server_port}/v1','keys':[{'api-key':'fake-upstream'}],'models':[{'name':'blocked','alias':'public-blocked'},{'name':'allowed','alias':'allowed'}]}
warmup = dict(provider, name='fake-warmup', prefix='warmup-test')
config = {'host':'127.0.0.1','port':port,'auth-dir':'/test/auths','api-keys':['test-client-a','test-client-b'], 'remote-management':{'allow-remote':False,'secret-key':'test-management-secret'}, 'plugins':{'enabled':True,'dir':'/test/plugins','configs':{'key-model-access':{'enabled':True,'version':3,'policy_file':'/test/policy.json'}}},'openai-compatibility':[provider,warmup],'request-retry':0}
(root/'config.yaml').write_text(json.dumps(config))

def call(path, payload=None, key='test-client-a', method=None):
    req = urllib.request.Request(f'http://127.0.0.1:{port}'+path, data=None if payload is None else json.dumps(payload).encode(), headers={'Authorization':'Bearer '+key,'Content-Type':'application/json'},method=method)
    try:
        response = urllib.request.urlopen(req, timeout=10)
        return response.status, response.read().decode()
    except urllib.error.HTTPError as error:
        return error.code, error.read().decode()

try:
    subprocess.run(['docker','run','--rm','-d','--name',container,'--network','host','-v',str(root)+':/test','-v',str(root/'config.yaml')+':/CLIProxyAPI/config.yaml',args.image], check=True, stdout=subprocess.DEVNULL)
    for _ in range(40):
        try:
            code, body = call('/v0/management/plugins/key-model-access/status',key='test-management-secret')
            if code == 200: break
        except OSError: pass
        time.sleep(.5)
    else: raise AssertionError('isolated CPA did not start')
    assert json.loads(body)['version']=='0.4.0', body
    code, body = call('/v1/chat/completions',{'model':'allowed','messages':[{'role':'user','content':'hi'}]})
    assert code==200,(code,body)
    print('PASS allowed model reaches fake upstream')
    cases=0
    for key in ['test-client-a','test-client-b']:
        for path in ['/v1/chat/completions','/v1/responses','/v1/messages','/v1beta/models/public-blocked:generateContent']:
            for model in ['public-blocked','warmup-test/public-blocked','public-blocked(high)','warmup-test/public-blocked(8192)']:
                if 'v1beta' in path and model!='public-blocked': continue
                for stream in [False,True]:
                    payload={'model':model,'messages':[{'role':'user','content':'hi'}],'input':'hi','max_tokens':1,'stream':stream}
                    before=Upstream.calls
                    code, body=call(path,payload,key)
                    assert code==403 and 'global_deny' in body,(path,model,stream,code,body[:300])
                    assert Upstream.calls==before,'denied request reached upstream'
                    cases+=1
    print(f'PASS {cases} HTTP denial cases; key allow cannot override, unconfigured key denied; zero upstream calls for denied requests')
    # WebSocket Responses requests use the same execution path; verify actual frames.
    try:
        import websocket
    except ImportError:
        raise AssertionError('websocket-client is required for WebSocket integration verification')
    for model in ['public-blocked','warmup-test/public-blocked(high)']:
        ws=websocket.create_connection(f'ws://127.0.0.1:{port}/v1/responses',header=['Authorization: Bearer test-client-b'],timeout=10)
        try:
            before=Upstream.calls
            ws.send(json.dumps({'type':'response.create','model':model,'input':[{'role':'user','content':'hi'}]}))
            try:
                event=ws.recv()
                assert not event or 'global_deny' in event,(model,event)
            except websocket.WebSocketConnectionClosedException:
                pass  # CPA v8.0.33 may close the socket on interceptor termination.
            assert Upstream.calls==before
        finally:
            ws.close()
    print('PASS WebSocket denied routes: error or connection close, zero upstream calls')
    # Explicit clear persists, survives restart, and enables the formerly blocked model.
    code,body=call('/v0/management/plugins/key-model-access/policies',dict(policy,global_deny_models=[]),key='test-management-secret',method='PUT')
    assert code==200,(code,body)
    subprocess.run(['docker','restart',container],check=True,stdout=subprocess.DEVNULL)
    for _ in range(40):
        try:
            code,body=call('/v0/management/plugins/key-model-access/status',key='test-management-secret')
            if code==200: break
        except OSError: pass
        time.sleep(.5)
    assert json.loads(body)['global_deny_count']==0
    code,body=call('/v1/chat/completions',{'model':'public-blocked','messages':[{'role':'user','content':'hi'}]})
    assert code==200,(code,body)
    print('PASS explicit clear, restart persistence, and restored access')
except Exception:
    print(subprocess.run(["docker","logs","--tail","50",container],capture_output=True,text=True).stdout)
    raise
finally:
    subprocess.run(['docker','rm','-f',container],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    server.shutdown()
    shutil.rmtree(root)
