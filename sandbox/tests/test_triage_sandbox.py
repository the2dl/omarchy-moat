import importlib.machinery
import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

SCRIPT = Path(__file__).resolve().parents[1] / 'moat-triage-sandbox'
loader = importlib.machinery.SourceFileLoader('moat_triage_sandbox', str(SCRIPT))
spec = importlib.util.spec_from_loader(loader.name, loader)
m = importlib.util.module_from_spec(spec)
loader.exec_module(m)


class TriageSandboxTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='moat-triage-test-')
        self.root = Path(self.tmp.name)
        self.home = self.root / 'home'
        self.home.mkdir()
        (self.home / '.claude').mkdir()
        (self.home / '.claude/auth').write_text('own-auth')
        (self.home / '.env.production').write_text('decoy-test')
        (self.home / 'vault-recovery.txt').write_text('decoy-test')
        self.incident = self.root / 'incident'
        self.incident.mkdir()
        self.bundle = self.incident / 'bundle.md'
        self.bundle.write_text('staged-evidence')
        (self.incident / 'escape').symlink_to(self.home / 'vault-recovery.txt')

    def tearDown(self):
        self.tmp.cleanup()

    def plan(self, code):
        with mock.patch.object(m.Path, 'home', return_value=self.home), mock.patch.object(m.shutil, 'which', return_value='/usr/bin/bash'):
            return m.command('claude', self.bundle, ['claude', '-c', code])

    def run_plan(self, code):
        cmd, fds = m.pin_mounts(self.plan(code))
        try:
            return subprocess.run(cmd, env={'HOME': str(self.home), 'PATH': '/usr/bin:/bin', 'MOAT_SANDBOX': '0', 'MOAT_SANDBOX_ACTIVE': '1'},
                                  capture_output=True, text=True, pass_fds=fds, timeout=10)
        finally:
            for fd in fds:
                os.close(fd)

    def test_recursive_search_sees_evidence_but_not_home_decoys(self):
        result = self.run_plan('test "$PWD" = ' + str(self.incident) +
            '; test "$(cat bundle.md)" = staged-evidence && test ! -e escape && '
            'test ! -e "$HOME/.env.production" && test ! -e "$HOME/vault-recovery.txt" && '
            'test ! -e /var/tmp/session-keys.json && test ! -e /run/moat/control.sock && '
            'test "$(cat "$HOME/.claude/auth")" = own-auth && '
            '! grep -R decoy-test "$HOME" /var 2>/dev/null')
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_evidence_and_auth_are_read_only(self):
        result = self.run_plan('! echo changed > bundle.md; ! echo changed > "$HOME/.claude/auth"')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.bundle.read_text(), 'staged-evidence')
        self.assertEqual((self.home / '.claude/auth').read_text(), 'own-auth')

    def test_mount_replacement_after_plan_is_rejected(self):
        cmd = self.plan('true')
        self.incident.rename(self.root / 'original')
        self.incident.symlink_to(self.home)
        with self.assertRaises(ValueError):
            m.pin_mounts(cmd)

    def test_script_shim_does_not_widen_runtime_access(self):
        shim = self.root / 'claude'
        shim.write_text('#!/bin/bash\ntrue\n')
        with mock.patch.object(m.shutil, 'which', return_value=str(shim)):
            with self.assertRaisesRegex(ValueError, 'native agent'):
                m.command('claude', self.bundle, ['claude'])


if __name__ == '__main__':
    unittest.main()
