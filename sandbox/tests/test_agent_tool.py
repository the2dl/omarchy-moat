import importlib.machinery
import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / 'moat-agent-tool'
loader = importlib.machinery.SourceFileLoader('moat_agent_tool', str(SCRIPT))
spec = importlib.util.spec_from_loader(loader.name, loader)
module = importlib.util.module_from_spec(spec)
loader.exec_module(module)


class AgentToolTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='moat-agent-tool-test-')
        self.root = Path(self.tmp.name)
        self.workspace = self.root / 'project'
        self.workspace.mkdir()
        self.secret = self.root / 'outside-secret'
        self.secret.write_text('private-test-value')

    def tearDown(self):
        self.tmp.cleanup()

    def run_tool(self, code, extra=(), pass_fds=()):
        env = dict(os.environ, MOAT_SANDBOX='0', MOAT_SANDBOX_ACTIVE='1',
                   ANTHROPIC_API_KEY='private-test-value', SSH_AUTH_SOCK='/tmp/fake-agent.sock')
        return subprocess.run(['/usr/bin/python3', '-I', str(SCRIPT), '--workspace', str(self.workspace),
                               *extra, '--', '/usr/bin/python3', '-c', code],
                              env=env, pass_fds=pass_fds, capture_output=True, text=True)

    def test_isolates_files_environment_and_host_processes(self):
        code = """import os,pathlib
assert 'ANTHROPIC_API_KEY' not in os.environ
assert 'SSH_AUTH_SOCK' not in os.environ
assert 'MOAT_SANDBOX' not in os.environ
assert os.environ['HOME'] == '/home/tool'
assert not pathlib.Path(%r).exists()
assert not pathlib.Path('/proc/%s/environ').exists()
pathlib.Path('output.txt').write_text('ok')
""" % (str(self.secret), os.getpid())
        result = self.run_tool(code)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.workspace / 'output.txt').read_text(), 'ok')

    def test_read_grant_is_explicit_and_not_writable(self):
        code = """import pathlib
p=pathlib.Path(%r)
assert p.read_text() == 'private-test-value'
try: p.write_text('changed')
except OSError: pass
else: raise AssertionError('read-only grant was writable')
""" % str(self.secret)
        result = self.run_tool(code, ['--read-only', str(self.secret)])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.secret.read_text(), 'private-test-value')

    def test_inherited_secret_descriptor_is_closed(self):
        with self.secret.open() as secret:
            fd = secret.fileno()
            result = self.run_tool("""import os
try: data=os.read(%d, 1024)
except OSError: pass
else: assert b'private-test-value' not in data
""" % fd, pass_fds=(fd,))
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_network_is_off_by_default(self):
        result = self.run_tool("""import socket,os
assert os.stat('/proc/self/ns/net').st_ino != %d
s=socket.socket(); s.settimeout(0.5)
try: s.connect(('192.0.2.1', 443))
except OSError: pass
else: raise AssertionError('network unexpectedly reachable')
""" % os.stat('/proc/self/ns/net').st_ino)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_home_and_broad_read_grants_are_rejected(self):
        for workspace in [str(Path.home()), '/']:
            with self.assertRaises(ValueError):
                module.command(workspace, ['true'])
        with self.assertRaises(ValueError):
            module.command(str(self.workspace), ['true'], ['/'])
        with self.assertRaises(ValueError):
            module.command(str(self.workspace), ['true'], [str(self.workspace)])

    def test_mount_sources_are_pinned_and_path_swaps_are_refused(self):
        cmd = module.command(str(self.workspace), ['true'])
        moved = self.root / 'moved'
        self.workspace.rename(moved)
        self.workspace.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(ValueError):
            module.pin_mounts(cmd)

    def test_exit_status_propagates(self):
        result = self.run_tool('import sys;sys.exit(23)')
        self.assertEqual(result.returncode, 23, result.stderr)


if __name__ == '__main__':
    unittest.main()
