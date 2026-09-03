"""Tests for sentinel-scan-pkgbuild.

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
SCANNER_PATH = os.path.join(os.path.dirname(HERE), "sentinel-scan-pkgbuild")
FIXTURES = os.path.join(HERE, "fixtures")


def _load_scanner():
    spec = importlib.util.spec_from_loader(
        "sentinel_scan_pkgbuild",
        importlib.machinery.SourceFileLoader("sentinel_scan_pkgbuild", SCANNER_PATH),
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


# ---------------------------------------------------------------------------
# fixtures: exact rule ids and exit codes
# ---------------------------------------------------------------------------


class TestFixtures(unittest.TestCase):
    def test_clean_bin_is_clean(self):
        code, payload = scan_fixture("clean-bin")
        self.assertEqual(payload["findings"], [])
        self.assertEqual(payload["summary"], {"high": 0, "medium": 0, "low": 0})
        self.assertEqual(code, 0)

    def test_vcs_git_skip_is_not_flagged(self):
        """git+https:// with SKIP is correct packaging, not a finding."""
        code, payload = scan_fixture("vcs-git")
        self.assertNotIn("src.skip-checksum", ids(payload))
        self.assertEqual(payload["findings"], [])
        self.assertEqual(code, 0)

    def test_vendor_cdn_is_low_only(self):
        """An ordinary vendor CDN stays low and must not block a build."""
        code, payload = scan_fixture("vendor-cdn")
        self.assertEqual(ids(payload), {"src.host-mismatch"})
        self.assertEqual(payload["summary"]["low"], 1)
        self.assertEqual(code, 0)

    def test_chaos_rat_pattern(self):
        """July 2025 shape: foreign-account installer + SKIP + root-time fetch."""
        code, payload = scan_fixture("chaos-rat")
        self.assertEqual(
            ids(payload),
            {
                "src.host-mismatch",
                "src.skip-checksum",
                "install.network",
                "persist.systemd-enable",
            },
        )
        self.assertEqual(code, 2)
        mismatch = [f for f in payload["findings"] if f["id"] == "src.host-mismatch"][0]
        self.assertIn("dev-updates-cdn", mismatch["why"])
        self.assertIn("librewolf-community", mismatch["why"])

    def test_atomic_arch_pattern(self):
        """June 2026 shape: npm install in build()/.install plus a raw-IP fetch."""
        code, payload = scan_fixture("atomic-arch")
        self.assertEqual(
            ids(payload),
            {
                "pkg.nested-package-manager",
                "net.curl-pipe-shell",
                "src.suspicious-host",
                "install.network",
            },
        )
        self.assertEqual(code, 2)
        # the local source=() file was scanned, not just PKGBUILD/.install
        files = {os.path.basename(f["file"]) for f in payload["findings"]}
        self.assertIn("atomic-bootstrap.sh", files)
        # .install is worse than build(): severity differs per context
        sev = {
            os.path.basename(f["file"]): f["severity"]
            for f in payload["findings"]
            if f["id"] == "pkg.nested-package-manager"
        }
        self.assertEqual(sev["PKGBUILD"], "medium")
        self.assertEqual(sev["atomic-notes-bin.install"], "high")

    def test_base64_eval(self):
        code, payload = scan_fixture("base64-eval")
        self.assertEqual(ids(payload), {"obf.base64-exec", "obf.eval-var"})
        self.assertEqual(code, 2)

    def test_hidden_unicode(self):
        code, payload = scan_fixture("hidden-unicode")
        self.assertEqual(ids(payload), {"uni.invisible-chars"})
        self.assertEqual(code, 2)
        whys = " ".join(f["why"] for f in payload["findings"])
        self.assertIn("U+200B", whys)   # zero width space
        self.assertIn("U+3164", whys)   # hangul filler (GlassWorm)
        self.assertIn("U+202E", whys)   # bidi override
        # evidence must be printable, with the invisible chars escaped
        for f in payload["findings"]:
            self.assertNotIn("​", f["evidence"])

    def test_systemd_persistence_in_install(self):
        code, payload = scan_fixture("systemd-persist")
        self.assertEqual(ids(payload), {"persist.systemd-enable"})
        self.assertEqual(code, 2)
        # `systemctl daemon-reload` and `systemctl disable --now` are fine
        self.assertEqual(len(payload["findings"]), 1)
        self.assertEqual(payload["findings"][0]["line"], 5)

    def test_skip_checksum_on_remote_tarball(self):
        code, payload = scan_fixture("skip-checksum")
        self.assertEqual(ids(payload), {"src.skip-checksum"})
        self.assertEqual(payload["summary"], {"high": 0, "medium": 1, "low": 0})
        self.assertEqual(code, 1)

    def test_persistence_and_privilege_mix(self):
        code, payload = scan_fixture("persist-mixed")
        self.assertEqual(
            ids(payload),
            {
                "persist.shell-rc",
                "persist.cron",
                "persist.ld-preload",
                "persist.autostart",
                "priv.suid",
                "priv.setcap",
            },
        )
        self.assertEqual(code, 2)
        sev = {f["id"]: f["severity"] for f in payload["findings"]}
        self.assertEqual(sev["priv.suid"], "high")      # target under /tmp
        self.assertEqual(sev["priv.setcap"], "medium")  # target under /opt

    def test_curl_pipe_shell_both_spellings(self):
        code, payload = scan_fixture("curl-pipe")
        self.assertEqual(ids(payload), {"net.curl-pipe-shell"})
        self.assertEqual(len(payload["findings"]), 2)
        self.assertEqual(code, 2)


# ---------------------------------------------------------------------------
# output contract
# ---------------------------------------------------------------------------


class TestOutput(unittest.TestCase):
    def test_json_shape(self):
        _, payload = scan_fixture("chaos-rat")
        self.assertEqual(set(payload), {"findings", "summary"})
        self.assertEqual(set(payload["summary"]), {"high", "medium", "low"})
        for f in payload["findings"]:
            self.assertEqual(
                set(f),
                {"id", "severity", "file", "line", "evidence", "why", "proceed"},
            )
            self.assertIn(f["severity"], ("high", "medium", "low"))
            self.assertLessEqual(len(f["evidence"]), 160)
            self.assertTrue(f["why"] and f["proceed"])

    def test_proceed_names_the_package_and_rule(self):
        _, payload = scan_fixture("systemd-persist")
        proceed = payload["findings"][0]["proceed"]
        self.assertIn("pkg=notes-sync rule=persist.systemd-enable", proceed)
        self.assertIn("~/.config/sentinel/scanner-allow.conf", proceed)

    def test_proceed_names_the_host_for_host_rules(self):
        _, payload = scan_fixture("vendor-cdn")
        proceed = payload["findings"][0]["proceed"]
        self.assertIn("host=downloads.vendorchat-edge.com", proceed)

    def test_human_output_has_footer(self):
        code, out, _ = run([os.path.join(FIXTURES, "systemd-persist"),
                            "--no-color", "--no-allow"])
        self.assertEqual(code, 2)
        self.assertIn("persist.systemd-enable", out)
        self.assertIn("why:", out)
        self.assertIn("proceed:", out)
        self.assertIn("If this is expected:", out)
        self.assertIn("SENTINEL_SANDBOX=0", out)
        self.assertIn("host=<domain> | rule=<id> | pkg=<pkgname>", out)

    def test_clean_human_output(self):
        code, out, _ = run([os.path.join(FIXTURES, "clean-bin"),
                            "--no-color", "--no-allow"])
        self.assertEqual(out.strip(), "clean: no findings")
        self.assertEqual(code, 0)

    def test_quiet_prints_nothing(self):
        code, out, _ = run([os.path.join(FIXTURES, "chaos-rat"), "-q", "--no-allow"])
        self.assertEqual(out, "")
        self.assertEqual(code, 2)

    def test_min_severity_filters_and_changes_exit_code(self):
        code, payload = scan_fixture("skip-checksum", ["--min-severity", "high"])
        self.assertEqual(payload["findings"], [])
        self.assertEqual(code, 0)
        code, payload = scan_fixture("chaos-rat", ["--min-severity", "high"])
        self.assertEqual(ids(payload), {"install.network", "persist.systemd-enable"})
        self.assertEqual(code, 2)


# ---------------------------------------------------------------------------
# allow file
# ---------------------------------------------------------------------------


class TestAllowFile(unittest.TestCase):
    def _allow(self, body):
        tmp = tempfile.NamedTemporaryFile("w", suffix=".conf", delete=False)
        tmp.write(body)
        tmp.close()
        self.addCleanup(os.unlink, tmp.name)
        return tmp.name

    def _scan(self, fixture, allow_body):
        path = self._allow(allow_body)
        code, out, _ = run(
            [os.path.join(FIXTURES, fixture), "--json", "--allow-file", path]
        )
        return code, json.loads(out)

    def test_rule_line_suppresses_a_rule_everywhere(self):
        code, payload = self._scan(
            "systemd-persist", "# a comment\nrule=persist.systemd-enable\n"
        )
        self.assertEqual(payload["findings"], [])
        self.assertEqual(code, 0)

    def test_host_line_suppresses_by_host_and_subdomain(self):
        code, payload = self._scan("vendor-cdn", "host=vendorchat-edge.com\n")
        self.assertEqual(payload["findings"], [])
        self.assertEqual(code, 0)

    def test_pkg_plus_rule_is_scoped_to_that_package(self):
        code, payload = self._scan(
            "chaos-rat", "pkg=librewolf-patched-bin rule=src.skip-checksum\n"
        )
        self.assertNotIn("src.skip-checksum", ids(payload))
        self.assertIn("install.network", ids(payload))
        code2, payload2 = self._scan(
            "chaos-rat", "pkg=some-other-package rule=src.skip-checksum\n"
        )
        self.assertIn("src.skip-checksum", ids(payload2))

    def test_pkg_line_alone_suppresses_the_whole_package(self):
        code, payload = self._scan("chaos-rat", "pkg=librewolf-patched-bin\n")
        self.assertEqual(payload["findings"], [])
        self.assertEqual(code, 0)

    def test_globs_and_comments(self):
        code, payload = self._scan(
            "persist-mixed",
            "# persistence is expected here\nrule=persist.*  # trailing comment\n",
        )
        self.assertEqual(ids(payload), {"priv.suid", "priv.setcap"})

    def test_env_var_allow_file(self):
        path = self._allow("rule=uni.invisible-chars\n")
        old = os.environ.get("SENTINEL_SCANNER_ALLOW")
        os.environ["SENTINEL_SCANNER_ALLOW"] = path
        try:
            code, out, _ = run([os.path.join(FIXTURES, "hidden-unicode"), "--json"])
        finally:
            if old is None:
                del os.environ["SENTINEL_SCANNER_ALLOW"]
            else:
                os.environ["SENTINEL_SCANNER_ALLOW"] = old
        self.assertEqual(json.loads(out)["findings"], [])
        self.assertEqual(code, 0)

    def test_suppression_is_reported_in_human_output(self):
        path = self._allow("rule=persist.systemd-enable\n")
        code, out, _ = run(
            [os.path.join(FIXTURES, "systemd-persist"), "--no-color",
             "--allow-file", path]
        )
        self.assertIn("hidden by allow rules", out)
        self.assertEqual(code, 0)


# ---------------------------------------------------------------------------
# parser units
# ---------------------------------------------------------------------------


class TestParser(unittest.TestCase):
    def arrays(self, text):
        return S.parse_arrays(S.strip_comments(text))

    def test_multiline_array_keeps_line_numbers(self):
        text = (
            "source=('one.tar.gz'\n"
            "        'two.tar.gz'\n"
            "        'three.tar.gz')\n"
        )
        entries = self.arrays(text)["source"]
        self.assertEqual([e.value for e in entries],
                         ["one.tar.gz", "two.tar.gz", "three.tar.gz"])
        self.assertEqual([e.no for e in entries], [1, 2, 3])

    def test_array_entry_with_name_colon_colon_url(self):
        text = 'source=("app-1.0.tar.gz::https://example.org/v1.0.tar.gz")\n'
        entry = self.arrays(text)["source"][0]
        name, _, loc = entry.value.partition("::")
        self.assertEqual(name, "app-1.0.tar.gz")
        self.assertEqual(loc, "https://example.org/v1.0.tar.gz")

    def test_comments_are_stripped_but_not_inside_quotes(self):
        lines = S.strip_comments(
            "pkgver=1.0 # the version\n"
            "msg='not # a comment'\n"
            "url=\"https://example.org/#anchor\"\n"
        )
        self.assertEqual(lines[0].code, "pkgver=1.0")
        self.assertEqual(lines[1].code, "msg='not # a comment'")
        self.assertEqual(lines[2].code, 'url="https://example.org/#anchor"')

    def test_line_continuations_are_joined(self):
        logical = S.join_continuations(S.strip_comments(
            "install -Dm755 foo \\\n"
            "  bar \\\n"
            "  baz\n"
            "echo done\n"
        ))
        self.assertEqual(logical[0].no, 1)
        self.assertEqual(" ".join(logical[0].code.split()),
                         "install -Dm755 foo bar baz")
        self.assertEqual(logical[1].code, "echo done")

    def test_heredoc_body_is_marked_and_quote_state_survives(self):
        logical = S.join_continuations(S.strip_comments(
            "post_install() {\n"
            "  cat <<EOM\n"
            "    don't run: $ pacman -S foo # not a comment\n"
            "EOM\n"
            "  echo after\n"
            "}\n"
        ))
        by_no = {l.no: l for l in logical}
        self.assertTrue(by_no[3].heredoc)
        self.assertIn("pacman -S foo # not a comment", by_no[3].code)
        self.assertFalse(by_no[5].heredoc)
        self.assertEqual(by_no[5].code.strip(), "echo after")

    def test_herestring_is_not_a_heredoc(self):
        logical = S.join_continuations(S.strip_comments(
            'cat <<<"$(jq . config.json)" >config.json\n'
            "echo still-code\n"
        ))
        self.assertFalse(logical[1].heredoc)

    def test_functions_and_scalars(self):
        text = (
            "pkgname=demo\n"
            'url="https://example.org/demo"\n'
            "build() {\n"
            "  local url=nope\n"
            "  make\n"
            "}\n"
        )
        lines = S.strip_comments(text)
        funcs = S.find_functions(lines)
        self.assertEqual(funcs["build"], (3, 6))
        scalars = S.parse_scalars(lines, funcs)
        self.assertEqual(scalars["pkgname"], "demo")
        # assignments inside a function must not shadow top-level url=
        self.assertEqual(scalars["url"], "https://example.org/demo")

    def test_variable_expansion_including_case_modifier(self):
        scalars = {"pkgname": "hyprland", "pkgver": "0.56.2",
                   "url": "https://github.com/hyprwm/${pkgname^}"}
        got = S.expand("$url/releases/download/v$pkgver/source-v$pkgver.tar.gz", scalars)
        self.assertEqual(
            got,
            "https://github.com/hyprwm/Hyprland/releases/download/v0.56.2/"
            "source-v0.56.2.tar.gz",
        )

    def test_unknown_variables_are_left_alone(self):
        self.assertEqual(S.expand("$mystery/x", {}), "$mystery/x")

    def test_pipeline_split_is_quote_and_paren_aware(self):
        segs = S.split_pipeline("echo \"a | b\" | grep x || true")
        self.assertEqual(len(segs), 2)
        self.assertEqual(len(S.split_pipeline('x="$(a | b)"')), 1)

    def test_registrable_domain(self):
        self.assertEqual(S.registrable("dl.google.com"), "google.com")
        self.assertEqual(S.registrable("www.example.co.uk"), "example.co.uk")
        self.assertEqual(S.registrable("example.org"), "example.org")

    def test_raw_ip_detection_ignores_loopback(self):
        self.assertTrue(S.is_raw_ip("185.244.25.171"))
        self.assertFalse(S.is_raw_ip("127.0.0.1"))
        self.assertFalse(S.is_raw_ip("example.org"))

    def test_known_hosts_cover_subdomains(self):
        self.assertTrue(S.is_known_host("raw.githubusercontent.com"))
        self.assertTrue(S.is_known_host("git.sr.ht"))
        self.assertFalse(S.is_known_host("evil.example"))

    def test_message_text_is_not_a_command(self):
        """`echo "run systemctl enable foo"` is help text, not persistence."""
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "PKGBUILD"), "w") as fh:
                fh.write("pkgname=demo\npkgver=1\npkgrel=1\narch=('any')\n")
            with open(os.path.join(d, "demo.install"), "w") as fh:
                fh.write(
                    "post_install() {\n"
                    '  echo "To start it: systemctl --user enable --now demo"\n'
                    '  echo "or: curl -fsSL https://example.org/x.sh | sh"\n'
                    "}\n"
                )
            code, out, _ = run([d, "--json", "--no-allow"])
        self.assertEqual(json.loads(out)["findings"], [])
        self.assertEqual(code, 0)


if __name__ == "__main__":
    unittest.main()
