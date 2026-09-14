import importlib.machinery
import importlib.util
import io
import json
from pathlib import Path
import socket
import tarfile
import tempfile
import unittest


def load(name, path):
    loader = importlib.machinery.SourceFileLoader(name, str(path))
    spec = importlib.util.spec_from_loader(name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


ROOT = Path(__file__).resolve().parents[1]
vm = load('moat_vm', ROOT / 'moat-vm')
proxy = load('web_proxy', ROOT / 'web_proxy.py')


class SnapshotTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.project = self.root / 'project'
        self.project.mkdir()

    def tearDown(self):
        self.tmp.cleanup()

    def test_project_copied_without_links_or_common_secrets(self):
        (self.root / 'secret').write_text('fake secret')
        (self.project / 'link').symlink_to(self.root / 'secret')
        (self.project / 'directory-link').symlink_to(self.root, target_is_directory=True)
        (self.project / 'hello.py').write_text('print("hello")')
        (self.project / '.env').write_text('fake token')
        (self.project / '.env.example').write_text('TOKEN=')
        (self.project / '.mcp.json').write_text('{"mcpServers":{}}')
        manifest, skipped = vm.snapshot(self.project, self.root / 'in.tar')
        self.assertEqual(set(manifest), {'hello.py', '.env.example', '.mcp.json'})
        self.assertIn('.env', skipped)
        self.assertIn('link', skipped)
        with tarfile.open(self.root / 'in.tar') as tar:
            self.assertEqual(set(tar.getnames()), set(manifest))

    def test_git_ignored_files_and_metadata_not_copied(self):
        vm.run(['/usr/bin/git', 'init', '-q', self.project])
        (self.project / '.gitignore').write_text('ignored\n')
        (self.project / 'ignored').write_text('not copied')
        (self.project / 'source').write_text('copied')
        manifest, _ = vm.snapshot(self.project, self.root / 'in.tar')
        self.assertEqual(set(manifest), {'.gitignore', 'source'})

    def archive(self, entries):
        path = self.root / 'out.tar'
        with tarfile.open(path, 'w') as tar:
            for name, kind in entries:
                m = tarfile.TarInfo(name)
                if kind == 'link':
                    m.type, m.linkname = tarfile.SYMTYPE, '/tmp/outside'
                    tar.addfile(m)
                elif kind == 'hardlink':
                    m.type, m.linkname = tarfile.LNKTYPE, 'source'
                    tar.addfile(m)
                else:
                    m.size, m.mode = 4, 0o7777
                    tar.addfile(m, io.BytesIO(b'test'))
        return path

    def test_hostile_guest_exports_rejected(self):
        cases = [[('../escape', 'file')], [('/absolute', 'file')], [('x', 'link')],
                 [('x', 'hardlink')], [('x', 'file'), ('x', 'file')], [('.git/config', 'file')]]
        for i, entries in enumerate(cases):
            with self.subTest(entries=entries), self.assertRaises(ValueError):
                vm.extract_review(self.archive(entries), self.root / f'review-{i}')

    def test_review_does_not_overwrite_or_make_guest_files_executable(self):
        manifest = vm.extract_review(self.archive([('./dir/file', 'file')]), self.root / 'review')
        self.assertIn('dir/file', manifest)
        self.assertEqual((self.root / 'review/dir/file').stat().st_mode & 0o7777, 0o600)
        with self.assertRaises(FileExistsError):
            vm.extract_review(self.root / 'out.tar', self.root / 'review')

    def test_broad_workspace_rejected(self):
        with self.assertRaises(ValueError):
            vm.snapshot(Path.home(), self.root / 'in.tar')


class ProxyTests(unittest.TestCase):
    def resolver(self, addresses):
        return lambda host, port, *args: [(socket.AF_INET, socket.SOCK_STREAM, 6, '', (a, port))
                                         for a in addresses]

    def test_public_web_only(self):
        self.assertEqual(proxy.public_addresses('example.org', 443, self.resolver(['93.184.215.14'])),
                         ['93.184.215.14'])
        for port in (22, 2375, 3000, 6443):
            with self.assertRaises(ValueError):
                proxy.public_addresses('example.org', port, self.resolver(['93.184.215.14']))

    def test_private_loopback_metadata_and_mixed_dns_denied(self):
        for ip in ('127.0.0.1', '10.0.2.2', '192.168.1.1', '172.16.0.1',
                   '169.254.169.254', '100.64.0.1', '0.0.0.0', '192.0.2.1', '224.0.0.1'):
            for addresses in ([ip], ['93.184.215.14', ip]):
                with self.subTest(addresses=addresses), self.assertRaises(ValueError):
                    proxy.public_addresses('example.org', 443, self.resolver(addresses))

    def test_connect_target_is_validated_separately_from_header_claims(self):
        host, port, out = proxy.request(b'CONNECT example.org:443 HTTP/1.1\r\nHost: localhost\r\n\r\n')
        self.assertEqual((host, port, out), ('example.org', 443, None))

    def test_http_proxy_credentials_and_host_override_not_forwarded(self):
        host, port, out = proxy.request(b'GET http://example.org/a?q=1 HTTP/1.1\r\n'
                                       b'Host: localhost\r\nProxy-Authorization: secret\r\n\r\n')
        self.assertEqual((host, port), ('example.org', 80))
        self.assertIn(b'GET /a?q=1 HTTP/1.1', out)
        self.assertNotIn(b'secret', out)
        self.assertNotIn(b'localhost', out)
        self.assertIn(b'Connection: close', out)

    def test_bad_protocols_and_userinfo_rejected(self):
        for url in ('file:///etc/passwd', 'http://user:password@example.org/', 'https://example.org/'):
            with self.assertRaises(ValueError):
                proxy.request(f'GET {url} HTTP/1.1\r\n\r\n'.encode())


class LaunchTests(unittest.TestCase):
    def test_only_explicit_forwarding_and_vm_files_exposed(self):
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as tmp, patch.object(vm, 'state_root', return_value=Path(tmp)):
            p = Path(tmp) / 'dev-test'
            m = {'port': 22222, 'offline': False, 'cpus': 2, 'memory': 4096}
            cmd = vm.qemu_command(p, m)
            net = cmd[cmd.index('-netdev') + 1]
            self.assertIn('restrict=on', net)
            self.assertIn('hostfwd=tcp:127.0.0.1:', net)
            self.assertIn('guestfwd=tcp:10.0.2.100:3128-cmd:', net)
            self.assertNotIn('client-key', ' '.join(cmd))
            self.assertNotIn('-virtfs', cmd)
            self.assertNotIn('--ro-bind / /', ' '.join(cmd))
            self.assertIn('ringbuf,id=serial0,size=1048576', cmd)
            m['offline'] = True
            cmd = vm.qemu_command(p, m)
            self.assertNotIn('guestfwd=', cmd[cmd.index('-netdev') + 1])


if __name__ == '__main__':
    unittest.main()
