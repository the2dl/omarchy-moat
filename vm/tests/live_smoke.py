#!/usr/bin/python3 -I
"""Exercise an already-running disposable VM; writes only synthetic guest files."""
import importlib.machinery
import importlib.util
import json
from pathlib import Path
import shlex
import socket
import sys

loader = importlib.machinery.SourceFileLoader('moat_vm', str(Path(__file__).resolve().parents[1] / 'moat-vm'))
spec = importlib.util.spec_from_loader(loader.name, loader)
vm = importlib.util.module_from_spec(spec)
loader.exec_module(vm)
p = vm.session(sys.argv[1])

# Host positive control: this real local service accepts connections here.
with socket.socket() as host:
    host.bind(('127.0.0.1', 0))
    host.listen()
    port = host.getsockname()[1]
    with socket.create_connection(('127.0.0.1', port), timeout=2):
        pass
    code = r'''
import json, os, pathlib, socket, subprocess, sys
root = pathlib.Path('/home/dev/project')
assert not pathlib.Path(HOST_PROJECT).exists(), 'host project path exposed'
assert not (root / '.env').exists(), 'fake .env was imported'
assert not pathlib.Path('/run/moat/control.sock').exists()
assert not pathlib.Path('/var/run/docker.sock').exists()
assert 'SSH_AUTH_SOCK' not in os.environ
subprocess.run(['python3', 'hello.py'], check=True)
print('PASS: project runs; host project, sockets and fake secret absent', flush=True)
for target in [('10.0.2.2', HOST_PORT), ('192.0.2.1', 443)]:
    try:
        with socket.create_connection(target, timeout=2): pass
    except OSError: pass
    else: raise AssertionError('direct network unexpectedly reachable: ' + str(target))
print('PASS: host-positive-control TCP service inaccessible from guest', flush=True)
for target in ['127.0.0.1:443', '169.254.169.254:80', '192.168.1.1:80']:
    with socket.create_connection(('10.0.2.100', 3128), timeout=3) as s:
        s.sendall(('CONNECT ' + target + ' HTTP/1.1\r\n\r\n').encode())
        assert b'403 Forbidden' in s.recv(4096), target
subprocess.run(['curl', '-fsS', '--max-time', '20', '-o', '/dev/null', 'https://example.com'], check=True)
print('PASS: public HTTPS works; proxy denies private/loopback/metadata targets', flush=True)

# A minimal local MCP stdio server using the ordinary JSON-RPC transport.
# It exercises child execution and file writes, without an agent login or SDK.
server = r"""
import json,pathlib,sys
for line in sys.stdin:
    req=json.loads(line)
    if req['method']=='initialize':
        result={'protocolVersion':'2024-11-05','capabilities':{'tools':{}},
                'serverInfo':{'name':'moat-vm-smoke','version':'1'}}
    elif req['method']=='tools/list':
        result={'tools':[{'name':'write_marker','description':'Write a synthetic marker',
                         'inputSchema':{'type':'object','properties':{}}}]}
    elif req['method']=='tools/call':
        pathlib.Path('mcp-proof.txt').write_text('local MCP works\n')
        result={'content':[{'type':'text','text':'created mcp-proof.txt'}]}
    else: continue
    print(json.dumps({'jsonrpc':'2.0','id':req['id'],'result':result}),flush=True)
"""
(root / 'smoke_mcp.py').write_text(server)
(root / '.mcp.json').write_text(json.dumps({'mcpServers': {'moat-vm-smoke': {
    'command': 'python3', 'args': ['/home/dev/project/smoke_mcp.py']}}}, indent=2))
child = subprocess.Popen(['python3', 'smoke_mcp.py'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
try:
    for i, method in enumerate(['initialize', 'tools/list', 'tools/call']):
        child.stdin.write(json.dumps({'jsonrpc':'2.0','id':i,'method':method,
                                     'params':{'name':'write_marker','arguments':{}}})+'\n')
        child.stdin.flush()
        assert json.loads(child.stdout.readline())['id'] == i
finally:
    child.terminate(); child.wait(timeout=5)
assert (root / 'mcp-proof.txt').read_text() == 'local MCP works\n'
skill = root / '.claude/skills/moat-smoke'
skill.mkdir(parents=True, exist_ok=True)
(skill / 'SKILL.md').write_text('---\nname: moat-smoke\ndescription: Synthetic VM test\n---\n'
                              'Run python3 .claude/skills/moat-smoke/proof.py.\n')
(skill / 'proof.py').write_text('from pathlib import Path\nPath("skill-proof.txt").write_text("skill script works\\n")\n')
subprocess.run(['python3', str(skill / 'proof.py')], check=True)
assert (root / 'skill-proof.txt').exists()
print('PASS: local MCP JSON-RPC tool call and skill script execute normally', flush=True)
'''
    source = 'HOST_PROJECT=' + repr(vm.metadata(p)['workspace']) + '\nHOST_PORT=' + str(port) + '\n' + code
    vm.remote(p, 'cd /home/dev/project && python3 -', input=source, text=True, timeout=90)

print('Live smoke passed. Agent interpretation/authentication is a separate interactive test.')
