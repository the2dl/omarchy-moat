"""Tests for the JavaScript package-manager shims' scan contract.

These drive the real sandbox/shims/{npm,pnpm,yarn,bun} scripts with a stub
scanner and a stub "real" binary, so they check the contract itself:

    exit 0 -> continue silently        exit 2 -> refuse when not interactive
    exit 1 -> warn and continue        anything else / missing -> warn, continue

That contract is the makepkg shim's, and it is the difference between a
security tool people keep and one they uninstall: only an unambiguous finding
may stop the work.

Run with:  python3 -m unittest discover scanner/tests
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
SHIMS = os.path.join(REPO, "sandbox", "shims")

STUB_REAL = '#!/usr/bin/env bash\necho "REAL %s argv:$*"\n'
STUB_SCANNER = '#!/usr/bin/env bash\necho "SCAN ran: $*"\nexit %d\n'


def write_exe(path, body):
    with open(path, "w") as fh:
        fh.write(body)
    os.chmod(path, 0o755)


class ShimCase(unittest.TestCase):
    """A temp project, a stub real binary and a stub scanner on PATH."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="moat-shim-test.")
        self.bin = os.path.join(self.tmp, "bin")
        self.proj = os.path.join(self.tmp, "proj")
        os.makedirs(self.bin)
        os.makedirs(self.proj)
        with open(os.path.join(self.proj, "package.json"), "w") as fh:
            fh.write('{"name":"demo","version":"1.0.0"}\n')

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def stub_real(self, name):
        write_exe(os.path.join(self.bin, name), STUB_REAL % name.upper())

    def stub_scanner(self, code):
        write_exe(os.path.join(self.bin, "moat-scan-npm"), STUB_SCANNER % code)

    def run_shim(self, name, args, env=None, cwd=None):
        environ = dict(os.environ)
        environ.pop("MOAT_QUIET", None)
        environ.update({
            "PATH": "%s:%s:/usr/bin:/bin" % (SHIMS, self.bin),
            "HOME": self.tmp,
            "XDG_CONFIG_HOME": os.path.join(self.tmp, ".config"),
            # Skip the bubblewrap layer but keep the scan: the contract says
            # a nested install is still a tree the outer one never saw.
            "MOAT_SANDBOX_ACTIVE": "1",
        })
        environ.update(env or {})
        proc = subprocess.run(
            [os.path.join(SHIMS, name)] + args,
            cwd=cwd or self.proj, env=environ, stdin=subprocess.DEVNULL,
            capture_output=True, text=True, timeout=60,
        )
        return proc.returncode, proc.stdout + proc.stderr


class TestScanContract(ShimCase):
    def test_clean_scan_continues_silently(self):
        self.stub_real("npm")
        self.stub_scanner(0)
        rc, out = self.run_shim("npm", ["install", "left-pad"])
        self.assertEqual(rc, 0, out)
        self.assertIn("REAL NPM argv:install left-pad", out)
        self.assertNotIn("[moat]", out)

    def test_medium_findings_warn_and_continue(self):
        self.stub_real("npm")
        self.stub_scanner(1)
        rc, out = self.run_shim("npm", ["ci"])
        self.assertEqual(rc, 0, out)
        self.assertIn("medium findings", out)
        self.assertIn("REAL NPM argv:ci", out)

    def test_high_findings_refuse_when_not_interactive(self):
        self.stub_real("npm")
        self.stub_scanner(2)
        rc, out = self.run_shim("npm", ["install"])
        self.assertEqual(rc, 1, out)
        self.assertIn("HIGH severity", out)
        self.assertIn("MOAT_SANDBOX=0", out)
        self.assertNotIn("REAL NPM", out)

    def test_a_broken_scanner_never_blocks(self):
        self.stub_real("npm")
        self.stub_scanner(7)
        rc, out = self.run_shim("npm", ["install"])
        self.assertEqual(rc, 0, out)
        self.assertIn("exit 7", out)
        self.assertIn("REAL NPM", out)

    def test_a_missing_scanner_never_blocks(self):
        # Simulate absence explicitly rather than by relying on the scanner not
        # being installed. This test used to pass only because
        # /usr/bin/moat-scan-npm did not exist yet; packaging the scanner made
        # its precondition silently false, and the failure looked like a shim
        # bug rather than a test that had been asserting nothing.
        self.stub_real("npm")
        rc, out = self.run_shim(
            "npm", ["install"],
            env={"MOAT_SCANNER_moat_scan_npm": os.path.join(self.tmp, "nope")},
        )
        self.assertEqual(rc, 0, out)
        self.assertIn("skipping the npm scan", out)
        self.assertIn("REAL NPM", out)

    def test_moat_sandbox_0_skips_the_scan_as_well(self):
        """The refusal message and the scanner footer both promise this."""
        self.stub_real("npm")
        self.stub_scanner(2)
        rc, out = self.run_shim("npm", ["install"], env={"MOAT_SANDBOX": "0"})
        self.assertEqual(rc, 0, out)
        self.assertNotIn("SCAN ran", out)
        self.assertIn("REAL NPM", out)


class TestWhenTheScanRuns(ShimCase):
    """Scanning a command that unpacks nothing is pure cost."""

    def test_npm_run_is_not_scanned(self):
        self.stub_real("npm")
        self.stub_scanner(2)
        rc, out = self.run_shim("npm", ["run", "build"])
        self.assertEqual(rc, 0, out)
        self.assertNotIn("SCAN ran", out)
        self.assertIn("REAL NPM argv:run build", out)

    def test_npm_ls_and_test_are_not_scanned(self):
        self.stub_real("npm")
        self.stub_scanner(2)
        for args in (["ls"], ["test"], ["--version"], ["exec", "tsc"]):
            rc, out = self.run_shim("npm", args)
            self.assertEqual(rc, 0, out)
            self.assertNotIn("SCAN ran", out)

    def test_npm_install_aliases_are_scanned(self):
        self.stub_real("npm")
        self.stub_scanner(1)
        for args in (["i"], ["install"], ["ci"], ["add", "x"], ["update"],
                     ["rebuild"], ["it"]):
            rc, out = self.run_shim("npm", args)
            self.assertEqual(rc, 0, out)
            self.assertIn("SCAN ran", "%s %s" % (args, out))

    def test_options_before_the_subcommand_are_skipped(self):
        self.stub_real("npm")
        self.stub_scanner(1)
        rc, out = self.run_shim("npm", ["--no-audit", "--prefer-offline", "install"])
        self.assertEqual(rc, 0, out)
        self.assertIn("SCAN ran", out)

    def test_global_install_is_not_scanned(self):
        """`npm i -g x` unpacks nothing from this directory."""
        self.stub_real("npm")
        self.stub_scanner(2)
        for flag in ("-g", "--global", "--location=global"):
            rc, out = self.run_shim("npm", ["install", flag, "typescript"])
            self.assertEqual(rc, 0, out)
            self.assertNotIn("SCAN ran", out)

    def test_a_directory_with_no_package_tree_is_not_scanned(self):
        self.stub_real("npm")
        self.stub_scanner(2)
        empty = os.path.join(self.tmp, "empty")
        os.makedirs(empty)
        rc, out = self.run_shim("npm", ["install", "left-pad"], cwd=empty)
        self.assertEqual(rc, 0, out)
        self.assertNotIn("SCAN ran", out)

    def test_a_lockfile_alone_is_enough_to_scan(self):
        """npm ci from a fresh clone: the lockfile is the whole signal."""
        self.stub_real("npm")
        self.stub_scanner(1)
        onlylock = os.path.join(self.tmp, "onlylock")
        os.makedirs(onlylock)
        with open(os.path.join(onlylock, "package-lock.json"), "w") as fh:
            fh.write('{"lockfileVersion":3,"packages":{}}\n')
        rc, out = self.run_shim("npm", ["ci"], cwd=onlylock)
        self.assertEqual(rc, 0, out)
        self.assertIn("SCAN ran", out)


class TestOtherManagers(ShimCase):
    def test_pnpm_yarn_bun_refuse_on_high(self):
        for name in ("pnpm", "yarn", "bun"):
            with self.subTest(manager=name):
                self.stub_real(name)
                self.stub_scanner(2)
                rc, out = self.run_shim(name, ["install"])
                self.assertEqual(rc, 1, out)
                self.assertIn("HIGH severity", out)
                self.assertNotIn("REAL %s" % name.upper(), out)

    def test_bare_yarn_is_an_install(self):
        self.stub_real("yarn")
        self.stub_scanner(1)
        rc, out = self.run_shim("yarn", [])
        self.assertEqual(rc, 0, out)
        self.assertIn("SCAN ran", out)

    def test_bare_bun_is_the_runtime_not_an_install(self):
        self.stub_real("bun")
        self.stub_scanner(2)
        rc, out = self.run_shim("bun", ["run", "index.ts"])
        self.assertEqual(rc, 0, out)
        self.assertNotIn("SCAN ran", out)

    def test_yarn_run_is_not_scanned(self):
        self.stub_real("yarn")
        self.stub_scanner(2)
        rc, out = self.run_shim("yarn", ["run", "build"])
        self.assertEqual(rc, 0, out)
        self.assertNotIn("SCAN ran", out)

    def test_pnpm_add_is_scanned(self):
        self.stub_real("pnpm")
        self.stub_scanner(1)
        rc, out = self.run_shim("pnpm", ["add", "left-pad"])
        self.assertEqual(rc, 0, out)
        self.assertIn("SCAN ran", out)


class TestEndToEnd(ShimCase):
    """The real scanner behind the real shim, no stub in between."""

    def setUp(self):
        super().setUp()
        # Put the real scanner on PATH under its installed name.
        shutil.copy(os.path.join(REPO, "scanner", "moat-scan-npm"),
                    os.path.join(self.bin, "moat-scan-npm"))
        self.stub_real("npm")

    def test_an_ordinary_project_installs_without_a_word(self):
        fixture = os.path.join(HERE, "fixtures", "npm", "ordinary-app")
        proj = os.path.join(self.tmp, "ordinary")
        shutil.copytree(fixture, proj)
        rc, out = self.run_shim("npm", ["ci"], cwd=proj,
                                env={"MOAT_SCANNER_ALLOW": "/nonexistent"})
        self.assertEqual(rc, 0, out)
        self.assertIn("REAL NPM", out)
        self.assertNotIn("HIGH", out)

    def test_a_token_stealer_is_refused(self):
        fixture = os.path.join(HERE, "fixtures", "npm", "token-theft")
        proj = os.path.join(self.tmp, "theft")
        shutil.copytree(fixture, proj)
        rc, out = self.run_shim("npm", ["ci"], cwd=proj,
                                env={"MOAT_SCANNER_ALLOW": "/nonexistent"})
        self.assertEqual(rc, 1, out)
        self.assertIn("npm.script-credential-path", out)
        self.assertNotIn("REAL NPM", out)


if __name__ == "__main__":
    unittest.main()
