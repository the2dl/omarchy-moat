import argparse
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

SCRIPT = Path(__file__).resolve().parents[1] / 'moat-agent'
loader = importlib.machinery.SourceFileLoader('moat_agent', str(SCRIPT))
spec = importlib.util.spec_from_loader(loader.name, loader)
module = importlib.util.module_from_spec(spec)
loader.exec_module(module)


class AgentBrokerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='moat-broker-test-')
        self.root = Path(self.tmp.name)
        self.workspace = self.root / 'project'
        self.workspace.mkdir()
        self.broker = module.Broker(self.workspace, timeout=2)

    def tearDown(self):
        self.broker.close()
        self.tmp.cleanup()

    def test_protocol_and_real_isolated_tool_execution(self):
        requests = [
            {'id': 1, 'method': 'initialize', 'params': {'protocolVersion': '2025-06-18'}},
            {'method': 'notifications/initialized'},
            {'id': 2, 'method': 'tools/list'},
            {'id': 3, 'method': 'tools/call', 'params': {'name': 'shell', 'arguments': {
                'command': "test -z \"$ANTHROPIC_API_KEY\" && printf tested > result.txt && printf ok"}}},
        ]
        data = ''.join(json.dumps(dict(r, jsonrpc='2.0')) + '\n' for r in requests)
        result = subprocess.run(['/usr/bin/python3', '-I', str(SCRIPT), 'serve', '--workspace', str(self.workspace)],
                                input=data, capture_output=True, text=True, timeout=10,
                                env=dict(os.environ, ANTHROPIC_API_KEY='test-secret'))
        self.assertEqual(result.returncode, 0, result.stderr)
        responses = [json.loads(line) for line in result.stdout.splitlines()]
        self.assertEqual([r['id'] for r in responses], [1, 2, 3])
        self.assertEqual(responses[1]['result']['tools'][0]['name'], 'shell')
        self.assertFalse(responses[2]['result']['isError'])
        self.assertEqual((self.workspace / 'result.txt').read_text(), 'tested')

    def test_requests_cannot_widen_grants_or_invoke_other_tools(self):
        for extra in ({'network': True}, {'workspace': '/'}, {'read_only': '/home'}):
            with self.assertRaises(ValueError):
                self.broker.execute({'command': 'true', **extra})
        with self.assertRaises(ValueError):
            self.broker.dispatch({'jsonrpc': '2.0', 'method': 'tools/call', 'params': {'name': 'Bash'}})
        result = self.broker.execute({'command': 'cat /etc/shadow'})
        self.assertTrue(result['isError'])

    def test_workspace_grant_stays_pinned_across_requests(self):
        moved = self.root / 'original'
        self.workspace.rename(moved)
        self.workspace.mkdir()
        (self.workspace / 'new-secret').write_text('must-not-be-granted')
        result = self.broker.execute({'command': 'test ! -f new-secret && printf ok > pinned'})
        self.assertFalse(result['isError'], result)
        self.assertTrue((moved / 'pinned').exists())
        self.assertFalse((self.workspace / 'pinned').exists())

    def test_timeout_and_output_limits(self):
        self.broker.timeout = 0.1
        result = self.broker.execute({'command': 'exec 1>&- 2>&-; sleep 30'})
        self.assertTrue(result['isError'])
        self.assertIn('timed out', result['content'][0]['text'])
        self.broker.timeout = 2
        result = self.broker.execute({'command': 'yes noisy'})
        self.assertTrue(result['isError'])
        self.assertLess(len(result['content'][0]['text']), module.MAX_OUTPUT + 200)
        self.assertIn('output limit', result['content'][0]['text'])

    def test_malformed_protocol_does_not_execute_and_recovers(self):
        data = 'not-json\n[]\n' + json.dumps({'jsonrpc': '2.0', 'id': 4, 'method': 'ping'}) + '\n'
        result = subprocess.run(['/usr/bin/python3', '-I', str(SCRIPT), 'serve', '--workspace', str(self.workspace)],
                                input=data, capture_output=True, text=True, timeout=10)
        rows = [json.loads(line) for line in result.stdout.splitlines()]
        self.assertIn('error', rows[0])
        self.assertIn('error', rows[1])
        self.assertEqual(rows[2]['result'], {})

    def test_launcher_only_exposes_broker_and_has_no_arbitrary_flag_passthrough(self):
        args = argparse.Namespace(workspace=str(self.workspace), read_only=[], network=False,
                                  timeout=120, model=None, prompt='hello')
        with mock.patch.object(module.shutil, 'which', return_value='/usr/bin/true'):
            cmd, cwd = module.launch_plan(args, self.broker)
        self.assertEqual(cwd, str(self.workspace))
        self.assertEqual(cmd[cmd.index('--tools') + 1], '')
        self.assertIn('--restricted', cmd)
        self.assertIn('--strict-mcp-config', cmd)
        self.assertEqual(cmd[cmd.index('--setting-sources') + 1], '')
        mcp = json.loads(cmd[cmd.index('--mcp-config') + 1])
        self.assertEqual(list(mcp['mcpServers']), ['moat'])
        self.assertIn('--expected-mounts', mcp['mcpServers']['moat']['args'])
        result = subprocess.run(['/usr/bin/python3', '-I', str(SCRIPT), 'claude', '--workspace', str(self.workspace),
                                 '--dangerously-skip-permissions'], capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)

    def test_changed_grants_between_launch_and_server_are_rejected(self):
        result = subprocess.run(['/usr/bin/python3', '-I', str(SCRIPT), 'serve', '--workspace', str(self.workspace),
                                 '--expected-mounts', '[]'], capture_output=True, text=True, timeout=10)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('mount sources changed', result.stderr)

    def test_oversized_protocol_request_is_bounded(self):
        result = subprocess.run(['/usr/bin/python3', '-I', str(SCRIPT), 'serve', '--workspace', str(self.workspace)],
                                input='x' * (module.MAX_REQUEST + 1), capture_output=True, text=True, timeout=10)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('size limit', result.stderr)


if __name__ == '__main__':
    unittest.main()
