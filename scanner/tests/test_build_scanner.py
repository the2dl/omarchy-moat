"""Tests for moat-scan-build (moat-scan-cargo / moat-scan-pip / moat-scan-go).

Every rule gets a hostile fixture that must fire and a benign fixture that
must not. The benign half matters as much as the hostile half: a false
positive here stops a build.

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
SCANNER_PATH = os.path.join(os.path.dirname(HERE), "moat-scan-build")
FIXTURES = os.path.join(HERE, "fixtures", "build")


def _load_scanner():
    spec = importlib.util.spec_from_loader(
        "moat_scan_build",
        importlib.machinery.SourceFileLoader("moat_scan_build", SCANNER_PATH),
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


# ==========================================================================
# cargo
# ==========================================================================


class TestCargoBuildScript(unittest.TestCase):
    """build.rs is the PKGBUILD of the Rust world: it runs on `cargo build`."""

    def setUp(self):
        self.code, self.payload = scan_fixture("cargo-build-rs")

    def test_high_findings_refuse(self):
        self.assertEqual(self.code, 2)

    def test_network_in_a_build_script_is_reported(self):
        self.assertIn("exec.build-rs-network", ids(self.payload))

    def test_an_ordinary_host_is_medium_and_a_webhook_is_high(self):
        sevs = {f["severity"] for f in by_id(self.payload, "exec.build-rs-network")}
        self.assertEqual(sevs, {"high", "medium"})

    def test_the_paste_bin_ladder_names_the_host(self):
        hits = by_id(self.payload, "net.suspicious-host")
        self.assertTrue(hits)
        self.assertEqual(hits[0]["severity"], "high")

    def test_credential_read_from_a_build_script(self):
        self.assertIn("cred.build-read", ids(self.payload))

    def test_curl_pipe_shell_uses_the_shared_rule_id(self):
        self.assertIn("net.curl-pipe-shell", ids(self.payload))

    def test_a_decoded_blob_reaching_a_process_sink(self):
        hits = by_id(self.payload, "obf.eval-decoded")
        self.assertTrue(hits)
        # The finding prints what the blob says so nobody has to run it.
        self.assertIn("decodes to", hits[0]["evidence"])


class TestCargoConfig(unittest.TestCase):
    """.cargo/config.toml decides where every crate comes from."""

    def setUp(self):
        self.code, self.payload = scan_fixture("cargo-config")

    def test_high(self):
        self.assertEqual(self.code, 2)

    def test_crates_io_replacement_is_high(self):
        hits = by_id(self.payload, "cargo.registry-replaced")
        self.assertTrue(hits)
        self.assertIn("high", {h["severity"] for h in hits})

    def test_runner_and_rustc_wrapper_are_reported(self):
        ev = " ".join(f["evidence"] for f in by_id(self.payload, "cargo.build-runner"))
        self.assertIn("runner", ev)
        self.assertIn("rustc-wrapper", ev)

    def test_a_linker_override_is_only_medium(self):
        """Cross-compilation sets this legitimately."""
        self.assertEqual(sev_of(self.payload, "cargo.linker-override"), {"medium"})

    def test_a_bare_ip_registry_is_flagged(self):
        self.assertIn("net.suspicious-host", ids(self.payload))


class TestCargoManifest(unittest.TestCase):
    def setUp(self):
        self.code, self.payload = scan_fixture("cargo-manifest")

    def test_build_key_outside_the_package_is_high(self):
        self.assertEqual(sev_of(self.payload, "cargo.build-script-outside"), {"high"})

    def test_path_dependency_outside_the_tree(self):
        self.assertIn("cargo.dep-outside-tree", ids(self.payload))

    def test_an_unpinned_git_build_dependency_is_medium(self):
        hits = by_id(self.payload, "cargo.dep-git")
        self.assertTrue(hits)
        self.assertEqual(hits[0]["severity"], "medium")

    def test_a_paste_bin_git_dependency_is_high(self):
        self.assertIn("net.suspicious-host", ids(self.payload))

    def test_proc_macro_is_noted(self):
        self.assertIn("cargo.proc-macro", ids(self.payload))

    def test_lockfile_rules_reuse_the_npm_scanner_ids(self):
        self.assertIn("lock.foreign-registry", ids(self.payload))
        self.assertIn("lock.missing-integrity", ids(self.payload))

    def test_the_lock_finding_names_the_package_not_the_project(self):
        hit = by_id(self.payload, "lock.foreign-registry")[0]
        self.assertEqual(hit["pkg"], "backdoor")


class TestCargoBenign(unittest.TestCase):
    """An ordinary Rust workspace. A single finding here blocks real work."""

    def test_clean(self):
        code, payload = scan_fixture("cargo-clean")
        self.assertEqual(code, 0, payload)
        self.assertEqual(payload["findings"], [])

    def test_a_cc_and_pkg_config_build_script_is_silent(self):
        _, payload = scan_fixture("cargo-clean")
        self.assertNotIn("exec.build-rs-network", ids(payload))

    def test_a_pinned_forge_git_dependency_is_silent(self):
        _, payload = scan_fixture("cargo-clean")
        self.assertNotIn("cargo.dep-git", ids(payload))

    def test_a_workspace_member_path_dep_is_not_outside_the_tree(self):
        _, payload = scan_fixture("cargo-clean")
        self.assertNotIn("cargo.dep-outside-tree", ids(payload))

    def test_crates_io_lock_entries_with_checksums_are_silent(self):
        _, payload = scan_fixture("cargo-clean")
        self.assertNotIn("lock.foreign-registry", ids(payload))
        self.assertNotIn("lock.missing-integrity", ids(payload))


class TestCargoRegression(unittest.TestCase):
    """Shapes that fired against real crates on this machine and must not."""

    def make(self, body):
        d = tempfile.mkdtemp(prefix="moat-build-test.")
        with open(os.path.join(d, "Cargo.toml"), "w") as fh:
            fh.write('[package]\nname = "t"\nversion = "0.1.0"\n')
        with open(os.path.join(d, "build.rs"), "w") as fh:
            fh.write(body)
        return d

    def scan(self, body):
        d = self.make(body)
        code, out, _ = run([d, "--json", "--no-allow", "--for", "cargo"])
        return code, json.loads(out)

    def test_rustc_version_probing_is_not_an_eval(self):
        """`.arg("--version")` next to a `version` variable is not a decode.

        Ten real crates (libc, serde, quote, proc-macro2, thiserror, ...)
        reported obf.eval-decoded before String::from_utf8 stopped counting as
        a decoder and before string literals stopped counting as identifiers.
        """
        code, payload = self.scan(
            'use std::process::Command;\n'
            'fn main() {\n'
            '    let out = Command::new("rustc").arg("--version").output().unwrap();\n'
            '    let version = String::from_utf8(out.stdout).unwrap();\n'
            '    println!("{}", version);\n'
            '}\n'
        )
        self.assertEqual(payload["findings"], [])
        self.assertEqual(code, 0)

    def test_a_url_in_a_comment_is_not_a_fetch(self):
        code, payload = self.scan(
            '// see https://pastebin.com/raw/whatever for the format\n'
            'fn main() { println!("cargo:rerun-if-changed=build.rs"); }\n'
        )
        self.assertEqual(payload["findings"], [])
        self.assertEqual(code, 0)


# ==========================================================================
# python
# ==========================================================================


class TestPythonSetupPy(unittest.TestCase):
    """setup.py is executed by pip; it is the ecosystem's build.rs."""

    def setUp(self):
        self.code, self.payload = scan_fixture("py-setup")

    def test_high(self):
        self.assertEqual(self.code, 2)

    def test_network_in_setup_py(self):
        self.assertIn("exec.setup-py-network", ids(self.payload))

    def test_spawning_curl_is_high_whatever_the_host(self):
        hits = [f for f in by_id(self.payload, "exec.setup-py-network")
                if "curl" in f["evidence"]]
        self.assertTrue(hits)
        self.assertEqual(hits[0]["severity"], "high")

    def test_credential_read(self):
        self.assertIn("cred.build-read", ids(self.payload))

    def test_the_obfuscation_engine_covers_python(self):
        hits = by_id(self.payload, "obf.eval-decoded")
        self.assertTrue(hits)
        self.assertIn("decodes to", hits[0]["evidence"])

    def test_setup_requires_is_medium(self):
        self.assertEqual(sev_of(self.payload, "py.setup-requires"), {"medium"})


class TestPythonPth(unittest.TestCase):
    """A .pth `import` line runs on every interpreter start, forever."""

    def setUp(self):
        self.code, self.payload = scan_fixture("py-pth")

    def test_high(self):
        self.assertEqual(self.code, 2)

    def test_an_exec_or_fetch_line_is_high(self):
        hits = [f for f in by_id(self.payload, "py.startup-hook")
                if f["severity"] == "high"]
        self.assertEqual(len(hits), 2)

    def test_the_editable_install_idiom_is_demoted_to_low(self):
        hits = [f for f in by_id(self.payload, "py.startup-hook")
                if "__editable__" in f["file"]]
        self.assertEqual([h["severity"] for h in hits], ["low"])

    def test_a_path_only_pth_is_not_reported_at_all(self):
        """Only a line starting with `import ` is exec'd by site.py."""
        hits = [f for f in self.payload["findings"] if "paths-only" in f["file"]]
        self.assertEqual(hits, [])


class TestPythonBackendAndIndexes(unittest.TestCase):
    def setUp(self):
        self.code, self.payload = scan_fixture("py-backend")

    def test_high(self):
        self.assertEqual(self.code, 2)

    def test_a_backend_path_escaping_the_package_is_high(self):
        self.assertEqual(sev_of(self.payload, "py.build-backend-path"), {"high"})

    def test_extra_index_url_on_a_bare_ip_is_high(self):
        self.assertIn("net.suspicious-host", ids(self.payload))

    def test_trusted_host_is_medium(self):
        hits = [f for f in by_id(self.payload, "py.index-override")
                if "trusted-host" in f["evidence"]]
        self.assertEqual([h["severity"] for h in hits], ["medium"])

    def test_a_direct_url_requirement_is_medium_and_a_forge_one_is_low(self):
        self.assertEqual(sev_of(self.payload, "py.direct-url-requirement"),
                         {"medium", "low"})

    def test_a_build_requirement_fetched_from_a_file_locker_is_flagged(self):
        hits = [f for f in by_id(self.payload, "net.suspicious-host")
                if "pyproject.toml" in f["file"]]
        self.assertTrue(hits)


class TestPythonBenign(unittest.TestCase):
    def setUp(self):
        self.code, self.payload = scan_fixture("py-clean")

    def test_never_blocks(self):
        self.assertEqual(self.code, 0)
        self.assertEqual(sev_of(self.payload, "py.startup-hook"), {"low"})

    def test_an_ordinary_setup_py_is_silent(self):
        hits = [f for f in self.payload["findings"] if f["file"].endswith("setup.py")]
        self.assertEqual(hits, [])

    def test_the_standard_build_backend_is_not_reported(self):
        self.assertNotIn("py.build-backend-path", ids(self.payload))

    def test_the_default_index_url_is_not_an_override(self):
        self.assertNotIn("py.index-override", ids(self.payload))

    def test_distutils_precedence_pth_is_low(self):
        hits = [f for f in by_id(self.payload, "py.startup-hook")
                if "distutils-precedence" in f["file"]]
        self.assertEqual([h["severity"] for h in hits], ["low"])


class TestPythonRegression(unittest.TestCase):
    """Shapes that fired against real files on this machine and must not."""

    def scan_text(self, name, body):
        d = tempfile.mkdtemp(prefix="moat-build-test.")
        with open(os.path.join(d, name), "w") as fh:
            fh.write(body)
        code, out, _ = run([d, "--json", "--no-allow", "--for", "python"])
        return code, json.loads(out)

    def test_pip_install_in_a_message_string_is_not_a_network_call(self):
        """ruamel.yaml's setup.py said this five times."""
        code, payload = self.scan_text(
            "setup.py",
            'from setuptools import setup\n'
            'import os\n'
            '# arg is either develop (pip install -e) or install\n'
            'if False:\n'
            '    print(\'error: you have to install with "pip install ."\')\n'
            '    os.system("pip install .")\n'
            'setup(name="x", version="1")\n'
        )
        self.assertNotIn("exec.setup-py-network", ids(payload))

    def test_importing_urllib_without_calling_it_is_not_a_fetch(self):
        code, payload = self.scan_text(
            "setup.py",
            'import urllib.request\n'
            'from setuptools import setup\n'
            'setup(name="x", version="1")\n'
        )
        self.assertNotIn("exec.setup-py-network", ids(payload))
        self.assertEqual(code, 0)

    def test_a_pytorch_style_index_url_is_low_not_medium(self):
        """Eight requirements files on this machine do exactly this."""
        code, payload = self.scan_text(
            "requirements.txt",
            "--index-url https://download.pytorch.org/whl/cu124\ntorch==2.3.0\n",
        )
        self.assertEqual(sev_of(payload, "py.index-override"), {"low"})
        self.assertEqual(code, 0)


# ==========================================================================
# go
# ==========================================================================


class TestGo(unittest.TestCase):
    def setUp(self):
        self.code, self.payload = scan_fixture("go-hostile")

    def test_high(self):
        self.assertEqual(self.code, 2)

    def test_a_generate_directive_piping_curl_into_sh_is_high(self):
        self.assertIn("net.curl-pipe-shell", ids(self.payload))

    def test_a_generate_directive_reading_an_ssh_key(self):
        self.assertIn("cred.build-read", ids(self.payload))

    def test_a_generate_directive_fetching_from_a_bare_ip(self):
        self.assertIn("net.suspicious-host", ids(self.payload))

    def test_replace_outside_the_module(self):
        hits = by_id(self.payload, "go.replace-outside-tree")
        self.assertEqual(len(hits), 1)
        self.assertIn("../../../elsewhere", hits[0]["evidence"])

    def test_an_in_tree_replace_is_not_reported(self):
        ev = " ".join(f["evidence"] for f in self.payload["findings"])
        self.assertNotIn("./internal/other", ev)

    def test_linkname(self):
        self.assertEqual(sev_of(self.payload, "go.linkname"), {"medium"})


class TestGoBenign(unittest.TestCase):
    def test_ordinary_codegen_directives_are_silent(self):
        code, payload = scan_fixture("go-clean")
        self.assertEqual(code, 0, payload)
        self.assertEqual(payload["findings"], [])

    def test_an_unrecognised_generator_is_reported_at_low_only(self):
        d = tempfile.mkdtemp(prefix="moat-build-test.")
        with open(os.path.join(d, "go.mod"), "w") as fh:
            fh.write("module example.com/x\n\ngo 1.22\n")
        with open(os.path.join(d, "a.go"), "w") as fh:
            fh.write("package main\n\n//go:generate ./tools/weirdgen -o out.go\n")
        code, out, _ = run([d, "--json", "--no-allow", "--for", "go"])
        payload = json.loads(out)
        self.assertEqual(sev_of(payload, "go.generate-directive"), {"low"})
        self.assertEqual(code, 0)


# ==========================================================================
# the contract shared with the other two scanners
# ==========================================================================


class TestContract(unittest.TestCase):
    def test_exit_codes(self):
        self.assertEqual(scan_fixture("cargo-clean")[0], 0)      # nothing
        self.assertEqual(scan_fixture("cargo-manifest")[0], 2)   # high
        self.assertEqual(scan_fixture("go-clean")[0], 0)

    def test_medium_only_exits_1(self):
        code, _, _ = run([os.path.join(FIXTURES, "cargo-manifest"),
                          "--json", "--no-allow", "--min-severity", "medium",
                          "--max-per-rule", "0"])
        # cargo-manifest still has highs; filter them out with an allow rule.
        self.assertEqual(code, 2)
        d = tempfile.mkdtemp(prefix="moat-build-test.")
        allow = os.path.join(d, "allow.conf")
        with open(allow, "w") as fh:
            fh.write("rule=cargo.build-script-outside\nrule=net.*\n")
        code, _, _ = run([os.path.join(FIXTURES, "cargo-manifest"), "--quiet",
                          "--allow-file", allow])
        self.assertEqual(code, 1)

    def test_the_finding_shape_matches_the_other_scanners(self):
        _, payload = scan_fixture("cargo-manifest")
        for f in payload["findings"]:
            self.assertEqual(
                set(f),
                {"id", "severity", "file", "line", "evidence", "why", "proceed", "pkg"},
            )
            self.assertIn(f["severity"], ("high", "medium", "low"))
            self.assertGreaterEqual(f["line"], 1)
            self.assertTrue(f["why"] and f["proceed"])
        self.assertEqual(set(payload["summary"]), {"high", "medium", "low"})

    def test_every_rule_id_is_in_the_catalogue(self):
        for name in os.listdir(FIXTURES):
            _, payload = scan_fixture(name)
            for f in payload["findings"]:
                self.assertIn(f["id"], S.RULES, f["id"])

    def test_ids_follow_the_family_dot_rule_convention(self):
        for rule in S.RULES:
            self.assertRegex(rule, r"^[a-z]+\.[a-z0-9\-]+$")

    def test_allow_file_by_rule_and_by_pkg(self):
        d = tempfile.mkdtemp(prefix="moat-build-test.")
        allow = os.path.join(d, "allow.conf")
        with open(allow, "w") as fh:
            fh.write("rule=obf.*\nrule=net.*\nrule=cred.*\nrule=exec.*\n")
        code, out, _ = run([os.path.join(FIXTURES, "cargo-build-rs"),
                            "--json", "--allow-file", allow])
        self.assertEqual(json.loads(out)["findings"], [])
        self.assertEqual(code, 0)

    def test_allow_file_by_host(self):
        d = tempfile.mkdtemp(prefix="moat-build-test.")
        allow = os.path.join(d, "allow.conf")
        with open(allow, "w") as fh:
            fh.write("host=webhook.site\n")
        _, out, _ = run([os.path.join(FIXTURES, "cargo-build-rs"),
                         "--json", "--allow-file", allow])
        self.assertNotIn("net.suspicious-host", ids(json.loads(out)))

    def test_suppressed_findings_are_still_counted_in_the_human_output(self):
        d = tempfile.mkdtemp(prefix="moat-build-test.")
        allow = os.path.join(d, "allow.conf")
        with open(allow, "w") as fh:
            fh.write("rule=net.*\n")
        _, out, _ = run([os.path.join(FIXTURES, "cargo-build-rs"),
                         "--no-color", "--allow-file", allow])
        self.assertIn("hidden by allow rules", out)

    def test_quiet_prints_nothing(self):
        code, out, _ = run([os.path.join(FIXTURES, "cargo-build-rs"), "-q"])
        self.assertEqual(out, "")
        self.assertEqual(code, 2)

    def test_a_missing_path_warns_and_does_not_crash(self):
        code, _, err = run(["/nonexistent/moat/path", "--json"])
        self.assertEqual(code, 0)
        self.assertIn("no such file", err)

    def test_a_directory_with_nothing_to_scan_warns(self):
        d = tempfile.mkdtemp(prefix="moat-build-test.")
        code, _, err = run([d, "--json"])
        self.assertEqual(code, 0)
        self.assertIn("nothing to scan", err)


class TestEcosystemSelection(unittest.TestCase):
    def test_for_restricts_the_scan(self):
        code, out, _ = run([os.path.join(FIXTURES, "go-hostile"),
                            "--json", "--no-allow", "--for", "cargo"])
        self.assertEqual(json.loads(out)["findings"], [])
        self.assertEqual(code, 0)

    def test_auto_detection_covers_a_polyglot_tree(self):
        d = tempfile.mkdtemp(prefix="moat-build-test.")
        with open(os.path.join(d, "Cargo.toml"), "w") as fh:
            fh.write('[package]\nname = "poly"\nversion = "0.1.0"\n'
                     'build = "/etc/evil.rs"\n')
        with open(os.path.join(d, "go.mod"), "w") as fh:
            fh.write("module example.com/poly\n\nreplace a => ../../b\n")
        _, out, _ = run([d, "--json", "--no-allow"])
        found = ids(json.loads(out))
        self.assertIn("cargo.build-script-outside", found)
        self.assertIn("go.replace-outside-tree", found)

    def test_a_single_file_argument_works(self):
        code, out, _ = run([os.path.join(FIXTURES, "py-pth", "pwn.pth"),
                            "--json", "--no-allow"])
        self.assertIn("py.startup-hook", ids(json.loads(out)))
        self.assertEqual(code, 2)


class TestItNeverExecutesWhatItReads(unittest.TestCase):
    """The non-negotiable one. These scanners run on hostile input."""

    # Grepping for these words is useless: half of them are in the detection
    # regexes. Parse the scanner instead and look at what it can actually do.
    ALLOWED_IMPORTS = {
        "__future__", "argparse", "base64", "binascii", "dataclasses",
        "fnmatch", "json", "os", "re", "sys", "unicodedata",
    }
    FORBIDDEN_CALLS = {"eval", "exec", "compile", "__import__", "input",
                       "breakpoint", "execfile"}
    FORBIDDEN_ATTRS = {"system", "popen", "fork", "spawn", "spawnl", "spawnv",
                       "execv", "execve", "execvp", "execl", "posix_spawn"}

    def scanner_ast(self):
        import ast
        with open(SCANNER_PATH, encoding="utf-8") as fh:
            return ast.parse(fh.read(), filename=SCANNER_PATH)

    def test_it_imports_nothing_that_can_run_or_fetch(self):
        import ast
        tree = self.scanner_ast()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    self.assertIn(a.name.split(".")[0], self.ALLOWED_IMPORTS, a.name)
            elif isinstance(node, ast.ImportFrom):
                self.assertIn((node.module or "").split(".")[0],
                              self.ALLOWED_IMPORTS, node.module)

    def test_it_never_calls_an_execution_primitive(self):
        import ast
        tree = self.scanner_ast()
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            fn = node.func
            if isinstance(fn, ast.Name):
                self.assertNotIn(fn.id, self.FORBIDDEN_CALLS, fn.id)
            elif isinstance(fn, ast.Attribute):
                self.assertNotIn(fn.attr, self.FORBIDDEN_ATTRS, fn.attr)

    def test_it_never_opens_a_file_for_writing(self):
        """It reads hostile trees; it must not be able to modify one."""
        import ast
        tree = self.scanner_ast()
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                    and node.func.id == "open"):
                continue
            mode = ""
            if len(node.args) > 1 and isinstance(node.args[1], ast.Constant):
                mode = str(node.args[1].value)
            for kw in node.keywords:
                if kw.arg == "mode" and isinstance(kw.value, ast.Constant):
                    mode = str(kw.value.value)
            self.assertNotRegex(mode or "r", r"[wax+]", ast.dump(node)[:120])

    def test_a_hostile_fixture_leaves_no_trace(self):
        """Scanning the droppers must not create the files they name."""
        for name in ("cargo-build-rs", "py-setup", "py-pth", "go-hostile"):
            scan_fixture(name)
        self.assertFalse(os.path.exists("/tmp/k"))
        self.assertFalse(os.path.exists("/tmp/.cache/runner"))


if __name__ == "__main__":
    unittest.main()
