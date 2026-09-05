"""Tests for the cargo / pip / uv / go shims' scan contract.

These drive the real sandbox/shims/{cargo,pip,pip3,uv,go} scripts with a stub
scanner and a stub "real" binary, so they check the contract itself:

    exit 0 -> continue silently        exit 2 -> refuse when not interactive
    exit 1 -> warn and continue        anything else / missing -> warn, continue

That contract is the makepkg shim's, and it is the difference between a
security tool people keep and one they uninstall: only an unambiguous finding
may stop the work. In particular a scanner that is missing or broken must
never be able to stop a build.

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
FIXTURES = os.path.join(HERE, "fixtures", "build")

STUB_REAL = '#!/usr/bin/env bash\necho "REAL %s argv:$*"\n'
STUB_SCANNER = '#!/usr/bin/env bash\necho "SCAN ran: $*"\nexit %d\n'

# shim name -> the scanner it must call, and the MOAT_SCANNER_* override.
SCANNER_FOR = {
    "cargo": "moat-scan-cargo",
    "pip": "moat-scan-pip",
    "pip3": "moat-scan-pip",
    "uv": "moat-scan-pip",
    "go": "moat-scan-go",
}


def write_exe(path, body):
    with open(path, "w") as fh:
        fh.write(body)
    os.chmod(path, 0o755)


class ShimCase(unittest.TestCase):
    """A temp project, a stub real binary and a stub scanner on PATH."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="moat-build-shim-test.")
        self.bin = os.path.join(self.tmp, "bin")
        self.proj = os.path.join(self.tmp, "proj")
        os.makedirs(self.bin)
        os.makedirs(self.proj)
        # A tree that looks like all three ecosystems, so one project serves
        # every shim.
        for name, body in (
            ("Cargo.toml", '[package]\nname = "demo"\nversion = "0.1.0"\n'),
            ("pyproject.toml", '[project]\nname = "demo"\nversion = "0.1.0"\n'),
            ("go.mod", "module example.com/demo\n\ngo 1.22\n"),
        ):
            with open(os.path.join(self.proj, name), "w") as fh:
                fh.write(body)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def stub_real(self, name):
        write_exe(os.path.join(self.bin, name), STUB_REAL % name.upper())

    def stub_scanner(self, shim, code):
        write_exe(os.path.join(self.bin, SCANNER_FOR[shim]), STUB_SCANNER % code)

    def run_shim(self, name, args, env=None, cwd=None):
        environ = dict(os.environ)
        environ.pop("MOAT_QUIET", None)
        environ.update({
            "PATH": "%s:%s:/usr/bin:/bin" % (SHIMS, self.bin),
            "HOME": self.tmp,
            "XDG_CONFIG_HOME": os.path.join(self.tmp, ".config"),
            "GOPATH": os.path.join(self.tmp, "go"),
            # Skip the bubblewrap layer but keep the scan: the contract says
            # a nested build is still a tree the outer one never saw.
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
    """Exactly the ladder the makepkg and npm shims established."""

    CASES = (("cargo", ["build"]), ("pip", ["install", "."]),
             ("pip3", ["install", "-r", "requirements.txt"]),
             ("uv", ["sync"]), ("go", ["build", "./..."]))

    def test_clean_scan_continues_silently(self):
        for shim, args in self.CASES:
            with self.subTest(shim=shim):
                self.stub_real(shim)
                self.stub_scanner(shim, 0)
                rc, out = self.run_shim(shim, args)
                self.assertEqual(rc, 0, out)
                self.assertIn("REAL %s" % shim.upper(), out)
                self.assertNotIn("[moat]", out)

    def test_medium_findings_warn_and_continue(self):
        for shim, args in self.CASES:
            with self.subTest(shim=shim):
                self.stub_real(shim)
                self.stub_scanner(shim, 1)
                rc, out = self.run_shim(shim, args)
                self.assertEqual(rc, 0, out)
                self.assertIn("medium findings", out)
                self.assertIn("REAL %s" % shim.upper(), out)

    def test_high_findings_refuse_when_not_interactive(self):
        for shim, args in self.CASES:
            with self.subTest(shim=shim):
                self.stub_real(shim)
                self.stub_scanner(shim, 2)
                rc, out = self.run_shim(shim, args)
                self.assertEqual(rc, 1, out)
                self.assertIn("HIGH severity", out)
                self.assertIn("MOAT_SANDBOX=0", out)
                self.assertNotIn("REAL %s" % shim.upper(), out)

    def test_a_broken_scanner_never_blocks(self):
        for shim, args in self.CASES:
            with self.subTest(shim=shim):
                self.stub_real(shim)
                self.stub_scanner(shim, 7)
                rc, out = self.run_shim(shim, args)
                self.assertEqual(rc, 0, out)
                self.assertIn("exit 7", out)
                self.assertIn("REAL %s" % shim.upper(), out)

    def test_a_missing_scanner_never_blocks(self):
        """Absence is simulated explicitly, never by relying on packaging."""
        for shim, args in self.CASES:
            with self.subTest(shim=shim):
                self.stub_real(shim)
                var = "MOAT_SCANNER_" + SCANNER_FOR[shim].replace("-", "_")
                rc, out = self.run_shim(
                    shim, args, env={var: os.path.join(self.tmp, "nope")})
                self.assertEqual(rc, 0, out)
                self.assertIn("skipping the", out)
                self.assertIn("REAL %s" % shim.upper(), out)

    def test_moat_sandbox_0_skips_the_scan_as_well(self):
        """The refusal message and the scanner footer both promise this."""
        for shim, args in self.CASES:
            with self.subTest(shim=shim):
                self.stub_real(shim)
                self.stub_scanner(shim, 2)
                rc, out = self.run_shim(shim, args, env={"MOAT_SANDBOX": "0"})
                self.assertEqual(rc, 0, out)
                self.assertNotIn("SCAN ran", out)
                self.assertIn("REAL %s" % shim.upper(), out)


class TestWhenTheScanRuns(ShimCase):
    """Scanning a command that builds nothing is pure cost."""

    def test_cargo_fmt_is_neither_sandboxed_nor_scanned(self):
        self.stub_real("cargo")
        self.stub_scanner("cargo", 2)
        rc, out = self.run_shim("cargo", ["fmt"])
        self.assertEqual(rc, 0, out)
        self.assertNotIn("SCAN ran", out)

    def test_cargo_build_aliases_are_scanned(self):
        self.stub_real("cargo")
        self.stub_scanner("cargo", 1)
        for args in (["build"], ["b"], ["test"], ["check"], ["run"],
                     ["+nightly", "build"], ["clippy"], ["bench"]):
            with self.subTest(args=args):
                rc, out = self.run_shim("cargo", args)
                self.assertEqual(rc, 0, out)
                self.assertIn("SCAN ran", out)

    def test_cargo_install_outside_a_crate_is_not_scanned(self):
        """`cargo install ripgrep` from $HOME reads nothing local."""
        self.stub_real("cargo")
        self.stub_scanner("cargo", 2)
        empty = os.path.join(self.tmp, "empty")
        os.makedirs(empty)
        rc, out = self.run_shim("cargo", ["install", "ripgrep"], cwd=empty)
        self.assertEqual(rc, 0, out)
        self.assertNotIn("SCAN ran", out)

    def test_the_scan_runs_for_cargo_before_the_real_cargo(self):
        self.stub_real("cargo")
        self.stub_scanner("cargo", 0)
        rc, out = self.run_shim("cargo", ["build"])
        self.assertLess(out.index("SCAN ran"), out.index("REAL CARGO"), out)

    def test_pip_list_and_uninstall_are_not_scanned(self):
        self.stub_real("pip")
        self.stub_scanner("pip", 2)
        for args in (["list"], ["show", "requests"], ["uninstall", "x"],
                     ["--version"], ["freeze"]):
            with self.subTest(args=args):
                rc, out = self.run_shim("pip", args)
                self.assertEqual(rc, 0, out)
                self.assertNotIn("SCAN ran", out)

    def test_pip_install_in_a_bare_directory_is_not_scanned(self):
        """`pip install requests` from $HOME builds nothing from here."""
        self.stub_real("pip")
        self.stub_scanner("pip", 2)
        empty = os.path.join(self.tmp, "empty")
        os.makedirs(empty)
        rc, out = self.run_shim("pip", ["install", "requests"], cwd=empty)
        self.assertEqual(rc, 0, out)
        self.assertNotIn("SCAN ran", out)

    def test_a_requirements_file_alone_is_enough_to_scan(self):
        self.stub_real("pip")
        self.stub_scanner("pip", 1)
        only = os.path.join(self.tmp, "onlyreq")
        os.makedirs(only)
        with open(os.path.join(only, "requirements.txt"), "w") as fh:
            fh.write("requests==2.31.0\n")
        rc, out = self.run_shim("pip", ["install", "-r", "requirements.txt"],
                                cwd=only)
        self.assertEqual(rc, 0, out)
        self.assertIn("SCAN ran", out)

    def test_uv_pip_list_is_not_scanned_but_uv_pip_install_is(self):
        self.stub_real("uv")
        self.stub_scanner("uv", 1)
        rc, out = self.run_shim("uv", ["pip", "list"])
        self.assertEqual(rc, 0, out)
        self.assertNotIn("SCAN ran", out)
        rc, out = self.run_shim("uv", ["pip", "install", "-e", "."])
        self.assertEqual(rc, 0, out)
        self.assertIn("SCAN ran", out)

    def test_uv_venv_and_python_are_not_scanned(self):
        self.stub_real("uv")
        self.stub_scanner("uv", 2)
        for args in (["venv"], ["python", "list"], ["cache", "clean"],
                     ["tool", "list"]):
            with self.subTest(args=args):
                rc, out = self.run_shim("uv", args)
                self.assertEqual(rc, 0, out)
                self.assertNotIn("SCAN ran", out)

    def test_go_generate_is_scanned(self):
        """The one subcommand that actually executes the directives."""
        self.stub_real("go")
        self.stub_scanner("go", 1)
        rc, out = self.run_shim("go", ["generate", "./..."])
        self.assertEqual(rc, 0, out)
        self.assertIn("SCAN ran", out)

    def test_go_env_and_version_pass_through_unsandboxed(self):
        self.stub_real("go")
        self.stub_scanner("go", 2)
        for args in (["env"], ["version"], ["fmt", "./..."], ["doc", "fmt"]):
            with self.subTest(args=args):
                rc, out = self.run_shim("go", args)
                self.assertEqual(rc, 0, out)
                self.assertNotIn("SCAN ran", out)
                self.assertIn("REAL GO", out)

    def test_go_build_without_a_go_mod_is_not_scanned(self):
        self.stub_real("go")
        self.stub_scanner("go", 2)
        empty = os.path.join(self.tmp, "empty")
        os.makedirs(empty)
        rc, out = self.run_shim("go", ["build", "./..."], cwd=empty)
        self.assertEqual(rc, 0, out)
        self.assertNotIn("SCAN ran", out)


class TestEachShimCallsItsOwnScanner(ShimCase):
    """The three names exist so one ecosystem's outage is not all three."""

    def test_the_cargo_shim_does_not_call_the_python_scanner(self):
        # The cargo scanner's absence is simulated with the documented
        # override, exactly as test_a_missing_scanner_never_blocks does, and
        # NOT by hoping the host has no moat-scan-cargo: PATH here ends in
        # /usr/bin, so this passed only on a machine where omarchy-moat was
        # not installed and failed the moment it was.
        self.stub_real("cargo")
        self.stub_scanner("pip", 2)          # only moat-scan-pip exists
        var = "MOAT_SCANNER_" + SCANNER_FOR["cargo"].replace("-", "_")
        rc, out = self.run_shim(
            "cargo", ["build"], env={var: os.path.join(self.tmp, "nope")})
        # rc 0 is the assertion that matters: the pip stub exits 2, so a cargo
        # shim that reached for the wrong ecosystem's scanner would block here.
        self.assertEqual(rc, 0, out)
        self.assertIn("REAL CARGO", out)

    def test_each_shim_asks_for_its_own_ecosystem(self):
        for shim, args, eco in (("cargo", ["build"], "cargo"),
                                ("pip", ["install", "."], "python"),
                                ("go", ["build"], "go")):
            with self.subTest(shim=shim):
                self.stub_real(shim)
                self.stub_scanner(shim, 0)
                _, out = self.run_shim(shim, args)
                self.assertIn("SCAN ran: --for %s ." % eco, out)


class TestEndToEnd(ShimCase):
    """The real scanner behind the real shim, no stub in between."""

    def install_real_scanner(self, name):
        shutil.copy(os.path.join(REPO, "scanner", "moat-scan-build"),
                    os.path.join(self.bin, name))

    def copy_fixture(self, fixture):
        proj = os.path.join(self.tmp, fixture)
        shutil.copytree(os.path.join(FIXTURES, fixture), proj)
        return proj

    def test_an_ordinary_crate_builds_without_a_word(self):
        self.install_real_scanner("moat-scan-cargo")
        self.stub_real("cargo")
        proj = self.copy_fixture("cargo-clean")
        rc, out = self.run_shim("cargo", ["build"], cwd=proj,
                                env={"MOAT_SCANNER_ALLOW": "/nonexistent"})
        self.assertEqual(rc, 0, out)
        self.assertIn("REAL CARGO", out)
        self.assertNotIn("HIGH", out)

    def test_a_build_script_that_phones_home_is_refused(self):
        self.install_real_scanner("moat-scan-cargo")
        self.stub_real("cargo")
        proj = self.copy_fixture("cargo-build-rs")
        rc, out = self.run_shim("cargo", ["build"], cwd=proj,
                                env={"MOAT_SCANNER_ALLOW": "/nonexistent"})
        self.assertEqual(rc, 1, out)
        self.assertIn("exec.build-rs-network", out)
        self.assertNotIn("REAL CARGO", out)

    def test_an_ordinary_python_project_installs_without_a_word(self):
        self.install_real_scanner("moat-scan-pip")
        self.stub_real("pip")
        proj = self.copy_fixture("py-clean")
        rc, out = self.run_shim("pip", ["install", "."], cwd=proj,
                                env={"MOAT_SCANNER_ALLOW": "/nonexistent"})
        self.assertEqual(rc, 0, out)
        self.assertIn("REAL PIP", out)

    def test_a_setup_py_dropper_is_refused(self):
        self.install_real_scanner("moat-scan-pip")
        self.stub_real("pip")
        proj = self.copy_fixture("py-setup")
        rc, out = self.run_shim("pip", ["install", "."], cwd=proj,
                                env={"MOAT_SCANNER_ALLOW": "/nonexistent"})
        self.assertEqual(rc, 1, out)
        self.assertIn("cred.build-read", out)
        self.assertNotIn("REAL PIP", out)

    def test_an_ordinary_go_module_builds_without_a_word(self):
        self.install_real_scanner("moat-scan-go")
        self.stub_real("go")
        proj = self.copy_fixture("go-clean")
        rc, out = self.run_shim("go", ["build", "./..."], cwd=proj,
                                env={"MOAT_SCANNER_ALLOW": "/nonexistent"})
        self.assertEqual(rc, 0, out)
        self.assertIn("REAL GO", out)

    def test_a_hostile_go_generate_is_refused(self):
        self.install_real_scanner("moat-scan-go")
        self.stub_real("go")
        proj = self.copy_fixture("go-hostile")
        rc, out = self.run_shim("go", ["generate", "./..."], cwd=proj,
                                env={"MOAT_SCANNER_ALLOW": "/nonexistent"})
        self.assertEqual(rc, 1, out)
        self.assertIn("net.curl-pipe-shell", out)
        self.assertNotIn("REAL GO", out)


if __name__ == "__main__":
    unittest.main()
