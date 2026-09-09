"""Tests for the malicious-package feed wiring in moat-scan-npm and
moat-scan-build (moat-scan-cargo / moat-scan-pip / moat-scan-go).

The case that matters most is the one that must NOT fire: a package that is
in the feed at a version other than the one being installed. 32,866 records
name specific versions, and many of those are ordinarily-legitimate packages
compromised for a single release. If those warned on every version, the
warning would be worthless within a week.

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
import time
import unittest
from contextlib import redirect_stdout, redirect_stderr

HERE = os.path.dirname(os.path.abspath(__file__))
SCANNER_DIR = os.path.dirname(HERE)
FEED_FIXTURE = os.path.join(HERE, "fixtures", "feed")


def _load(name, filename):
    path = os.path.join(SCANNER_DIR, filename)
    spec = importlib.util.spec_from_loader(
        name, importlib.machinery.SourceFileLoader(name, path))
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


NPM = _load("moat_scan_npm", "moat-scan-npm")
BUILD = _load("moat_scan_build", "moat-scan-build")


def run(mod, argv):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = mod.main(argv)
    return code, out.getvalue(), err.getvalue()


def scan(mod, path, extra=None, feed=FEED_FIXTURE):
    """Scan `path` with the feed dir pointed at `feed`. -> (code, payload, err)."""
    old = os.environ.get("MOAT_SCANNER_FEED_DIR")
    if feed is None:
        os.environ.pop("MOAT_SCANNER_FEED_DIR", None)
    else:
        os.environ["MOAT_SCANNER_FEED_DIR"] = feed
    try:
        code, out, err = run(mod, [path, "--json", "--no-allow"] + (extra or []))
    finally:
        if old is None:
            os.environ.pop("MOAT_SCANNER_FEED_DIR", None)
        else:
            os.environ["MOAT_SCANNER_FEED_DIR"] = old
    return code, json.loads(out), err


def feed_findings(payload):
    return [f for f in payload["findings"] if f["id"] == "feed.malicious-package"]


def _write(path, body):
    with open(path, "w") as fh:
        fh.write(body)


def write(root, rel, body):
    full = os.path.join(root, rel)
    os.makedirs(os.path.dirname(full), exist_ok=True)
    with open(full, "w") as fh:
        fh.write(body)
    return full


def npm_project(root, deps, lock_pkgs):
    """A package.json + a lockfileVersion 3 package-lock.json.

    `lock_pkgs` is {'node_modules/...': version}; the key's node_modules depth
    is what makes an entry direct or transitive.
    """
    write(root, "package.json", json.dumps(
        {"name": "demo", "version": "1.0.0", "dependencies": deps}, indent=2))
    packages = {"": {"name": "demo", "version": "1.0.0", "dependencies": deps}}
    for key, ver in lock_pkgs.items():
        packages[key] = {"version": ver,
                         "resolved": "https://registry.npmjs.org/x/-/x.tgz",
                         "integrity": "sha512-" + "a" * 86}
    write(root, "package-lock.json", json.dumps(
        {"name": "demo", "lockfileVersion": 3, "packages": packages}, indent=2))


# ==========================================================================
# the clause grammar, on its own
# ==========================================================================


class TestSpecGrammar(unittest.TestCase):
    """spec_match is the whole false-positive story; test it directly."""

    def match(self, spec, version, eco="npm"):
        return BUILD.spec_match(spec, version, eco)

    def test_star_matches_every_version(self):
        for v in ("0.0.1", "9.9.9", "1.2.3-beta.1", ""):
            got = self.match("*", v)
            self.assertIsNotNone(got, v)
            self.assertEqual(got[0], BUILD.FEED_YES, v)

    def test_exact_matches_only_that_version(self):
        self.assertEqual(self.match("=5.3.0", "5.3.0")[0], BUILD.FEED_YES)
        self.assertIsNone(self.match("=5.3.0", "5.3.1"))
        self.assertIsNone(self.match("=5.3.0", "5.2.9"))

    def test_exact_survives_without_a_comparator(self):
        """`=V` is string equality and must work for any ecosystem at all."""
        self.assertEqual(
            self.match("=1.0.0", "1.0.0", eco="rubygems")[0], BUILD.FEED_YES)
        self.assertIsNone(self.match("=1.0.0", "1.0.1", eco="rubygems"))

    def test_open_lower_bound(self):
        self.assertEqual(self.match(">=1.4.1", "1.4.1")[0], BUILD.FEED_YES)
        self.assertEqual(self.match(">=1.4.1", "2.0.0")[0], BUILD.FEED_YES)
        self.assertIsNone(self.match(">=1.4.1", "1.4.0"))

    def test_introduced_and_fixed(self):
        spec = ">=3.3.6,<3.3.7"
        self.assertEqual(self.match(spec, "3.3.6")[0], BUILD.FEED_YES)
        self.assertIsNone(self.match(spec, "3.3.7"))   # fixed in
        self.assertIsNone(self.match(spec, "3.3.5"))   # before it landed

    def test_introduced_and_last_affected(self):
        spec = ">=2.0.0,<=2.1.0"
        self.assertEqual(self.match(spec, "2.1.0")[0], BUILD.FEED_YES)
        self.assertIsNone(self.match(spec, "2.1.1"))

    def test_clauses_are_ored(self):
        spec = "=1.0.0|=2.0.0"
        self.assertEqual(self.match(spec, "1.0.0")[1], "=1.0.0")
        self.assertEqual(self.match(spec, "2.0.0")[1], "=2.0.0")
        self.assertIsNone(self.match(spec, "1.5.0"))

    def test_uncomparable_range_is_reduced_confidence_not_silence(self):
        """The contract forbids dropping a clause we cannot evaluate."""
        got = self.match(">=not-a-version", "1.0.0")
        self.assertIsNotNone(got)
        self.assertEqual(got[0], BUILD.FEED_MAYBE)

    def test_unknown_ecosystem_range_is_reduced_confidence(self):
        got = self.match(">=1.0.0", "2.0.0", eco="rubygems")
        self.assertEqual(got[0], BUILD.FEED_MAYBE)

    def test_unknown_version_is_reduced_confidence(self):
        got = self.match("=5.3.0", "")
        self.assertEqual(got[0], BUILD.FEED_MAYBE)

    def test_a_confident_clause_beats_an_unsure_one(self):
        got = self.match(">=nonsense|=1.0.0", "1.0.0")
        self.assertEqual(got, (BUILD.FEED_YES, "=1.0.0"))

    def test_empty_and_junk_specs_never_match(self):
        for spec in ("", "   ", "|", ",", "<"):
            self.assertIsNone(self.match(spec, "1.0.0"), spec)

    def test_semver_prerelease_ordering(self):
        # 1.0.0-beta is before 1.0.0, so a `>=1.0.0` record must not claim it.
        self.assertIsNone(self.match(">=1.0.0", "1.0.0-beta.1"))
        self.assertEqual(self.match(">=1.0.0-alpha", "1.0.0")[0], BUILD.FEED_YES)

    def test_pep440_ordering(self):
        m = lambda s, v: self.match(s, v, eco="pypi")
        self.assertEqual(m(">=2.0,<3.0", "2.0.1")[0], BUILD.FEED_YES)
        self.assertIsNone(m(">=2.0,<3.0", "3.0"))
        self.assertIsNone(m(">=2.0,<3.0", "1.9.9"))
        self.assertEqual(m(">=1.0", "1.0.post1")[0], BUILD.FEED_YES)
        self.assertIsNone(m(">=1.0", "1.0rc1"))       # rc precedes the release
        self.assertEqual(m("=1.0", "1.0.0")[0], BUILD.FEED_YES)   # same release

    def test_go_v_prefix_is_not_a_different_version(self):
        got = self.match("=1.2.3", "v1.2.3", eco="go")
        self.assertEqual(got[0], BUILD.FEED_YES)


# ==========================================================================
# the index
# ==========================================================================


class TestPackageFeedIndex(unittest.TestCase):

    def feed(self, path=None):
        return BUILD.PackageFeed(
            path or os.path.join(FEED_FIXTURE, "packages.txt"),
            os.path.join(FEED_FIXTURE, "meta.json"))

    def test_it_finds_every_entry_in_the_file(self):
        f = self.feed()
        self.addCleanup(f.close)
        self.assertTrue(f.available)
        with open(os.path.join(FEED_FIXTURE, "packages.txt")) as fh:
            rows = [l.rstrip("\n").split("\t") for l in fh
                    if not l.startswith("#") and l.count("\t") == 2]
        self.assertTrue(rows)
        for eco, name, spec in rows:
            if not name or not spec:
                continue
            self.assertIn(spec, f.specs(eco, name), (eco, name))

    def test_a_name_that_is_not_there_returns_nothing(self):
        f = self.feed()
        self.addCleanup(f.close)
        for name in ("", "zzz-absent", "chalk", "chalk-nex", "chalk-nextt",
                     "@scope/evil", "aaaa"):
            self.assertEqual(f.specs("npm", name), [], name)

    def test_a_prefix_of_a_real_name_is_not_a_match(self):
        """'chalk-next' must not answer a lookup for 'chalk'."""
        f = self.feed()
        self.addCleanup(f.close)
        self.assertEqual(f.specs("npm", "chalk"), [])
        self.assertEqual(f.specs("npm", "colors"), [])

    def test_ecosystems_do_not_bleed_into_each_other(self):
        f = self.feed()
        self.addCleanup(f.close)
        self.assertEqual(f.specs("pypi", "chalk-next"), [])
        self.assertEqual(f.specs("npm", "requestss"), [])

    def test_malformed_lines_are_ignored_and_do_not_break_neighbours(self):
        f = self.feed()
        self.addCleanup(f.close)
        # a two-field line, an empty spec, an empty name, a one-field line
        self.assertEqual(f.specs("npm", "no-spec-field"), [])
        self.assertEqual(f.specs("npm", "empty-spec"), [])
        self.assertEqual(f.specs("npm", ""), [])
        self.assertIsNone(f.match("npm", "no-spec-field", "1.0.0"))
        # the entries sorted either side of them still resolve
        self.assertEqual(f.specs("npm", "colors-fix"), [">=1.4.1"])
        self.assertEqual(f.specs("npm", "event-stream"), [">=3.3.6,<=3.3.6"])

    def test_pypi_names_are_matched_per_pep503(self):
        """However the project spells it, it finds the feed's entry.

        Normalisation runs on the query only. Byte order over the raw name is
        what makes the binary search possible, so the feed side cannot be
        normalised at lookup time - the aggregator is expected to emit PyPI
        names already normalised, which is what upstream OSV records carry.
        """
        f = self.feed()
        self.addCleanup(f.close)
        for spelling in ("flask-evil", "Flask_Evil", "Flask.Evil", "FLASK-EVIL",
                         "flask_evil"):
            self.assertIsNotNone(f.match("pypi", spelling, "1.0"), spelling)
        # and that leniency is PyPI-only: npm names are case-sensitive
        self.assertIsNone(f.match("npm", "CHALK-NEXT", "5.3.0"))
        self.assertIsNone(f.match("pypi", "flask-evil-two", "1.0"))

    def test_a_missing_file_is_an_empty_feed_not_an_error(self):
        f = BUILD.PackageFeed("/nonexistent/moat/packages.txt", "/nonexistent/m.json")
        self.addCleanup(f.close)
        self.assertFalse(f.available)
        self.assertIn("unavailable", f.note)
        self.assertEqual(f.specs("npm", "chalk-next"), [])
        self.assertIsNone(f.match("npm", "chalk-next", "5.3.0"))

    def test_an_empty_file_is_an_empty_feed_not_a_crash(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "packages.txt")
            open(p, "w").close()
            f = BUILD.PackageFeed(p, os.path.join(d, "meta.json"))
            self.addCleanup(f.close)
            self.assertFalse(f.available)
            self.assertEqual(f.specs("npm", "chalk-next"), [])

    def test_a_file_without_a_trailing_newline_still_resolves_its_last_line(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "packages.txt")
            _write(p, "npm\taaa\t*\nnpm\tzzz\t=1.0.0")
            f = BUILD.PackageFeed(p, os.path.join(d, "meta.json"))
            self.addCleanup(f.close)
            self.assertEqual(f.specs("npm", "zzz"), ["=1.0.0"])

    def test_a_fresh_feed_reports_no_staleness(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "packages.txt")
            _write(p, "npm\taaa\t*\n")
            _write(os.path.join(d, "meta.json"),
                   json.dumps({"generated": time.strftime(
                       "%Y-%m-%dT%H:%M:%SZ", time.gmtime())}))
            f = BUILD.PackageFeed(p, os.path.join(d, "meta.json"))
            self.addCleanup(f.close)
            self.assertEqual(f.note, "")

    def test_a_stale_feed_says_how_old_it_is(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "packages.txt")
            _write(p, "npm\taaa\t*\n")
            _write(os.path.join(d, "meta.json"),
                   json.dumps({"generated": time.strftime(
                       "%Y-%m-%dT%H:%M:%SZ",
                       time.gmtime(time.time() - 30 * 86400))}))
            f = BUILD.PackageFeed(p, os.path.join(d, "meta.json"))
            self.addCleanup(f.close)
            self.assertIn("30 days old", f.note)

    def test_a_garbage_meta_json_falls_back_to_the_mtime(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "packages.txt")
            _write(p, "npm\taaa\t*\n")
            _write(os.path.join(d, "meta.json"), "{not json")
            f = BUILD.PackageFeed(p, os.path.join(d, "meta.json"))
            self.addCleanup(f.close)
            self.assertTrue(f.available)
            self.assertEqual(f.note, "")     # just written, so not stale

    def test_the_search_agrees_with_a_linear_scan_over_a_large_feed(self):
        """The binary search is the only risky part; prove it exhaustively."""
        import random
        rnd = random.Random(20260909)
        names = set()
        while len(names) < 4000:
            names.add("".join(rnd.choice("abc-_.@/0Z") for _ in
                              range(rnd.randint(1, 12))))
        rows = sorted(("npm\t%s\t*" % n).encode() for n in names if n)
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "packages.txt")
            with open(p, "wb") as fh:
                fh.write(b"\n".join(rows) + b"\n")
            f = BUILD.PackageFeed(p, os.path.join(d, "meta.json"))
            self.addCleanup(f.close)
            present = {r.decode().split("\t")[1] for r in rows}
            for n in present:
                self.assertEqual(f.specs("npm", n), ["*"], n)
            for n in ("absent", "aaaa-nope", "", "~", "zzzzz"):
                if n not in present:
                    self.assertEqual(f.specs("npm", n), [], n)


# ==========================================================================
# npm
# ==========================================================================


class TestNpmFeedWiring(unittest.TestCase):

    def test_a_direct_dependency_at_the_named_version_is_high(self):
        with tempfile.TemporaryDirectory() as d:
            npm_project(d, {"chalk-next": "5.3.0"},
                        {"node_modules/chalk-next": "5.3.0"})
            code, payload, _ = scan(NPM, d)
            hits = feed_findings(payload)
            self.assertEqual(len(hits), 1, payload["findings"])
            self.assertEqual(hits[0]["severity"], "high")
            self.assertIn("chalk-next@5.3.0", hits[0]["evidence"])
            self.assertIn("=5.3.0", hits[0]["evidence"])       # matched clause
            self.assertIn("package feed", hits[0]["evidence"])
            self.assertIn("direct", hits[0]["evidence"])
            self.assertEqual(code, 2)

    def test_the_same_package_at_another_version_says_nothing(self):
        """The false-positive case the clause grammar exists to prevent."""
        with tempfile.TemporaryDirectory() as d:
            npm_project(d, {"chalk-next": "5.3.1"},
                        {"node_modules/chalk-next": "5.3.1"})
            code, payload, _ = scan(NPM, d)
            self.assertEqual(feed_findings(payload), [])

    def test_a_star_record_fires_at_any_version(self):
        for ver in ("0.0.1", "1.0.0", "99.1.2"):
            with tempfile.TemporaryDirectory() as d:
                npm_project(d, {"@scope/evil-scoped": ver},
                            {"node_modules/@scope/evil-scoped": ver})
                code, payload, _ = scan(NPM, d)
                hits = feed_findings(payload)
                self.assertEqual(len(hits), 1, ver)
                self.assertEqual(hits[0]["severity"], "high", ver)
                self.assertEqual(code, 2, ver)

    def test_a_transitive_dependency_is_reported_as_seriously_as_a_direct_one(self):
        with tempfile.TemporaryDirectory() as d:
            npm_project(
                d, {"innocent": "1.0.0"},
                {"node_modules/innocent": "1.0.0",
                 "node_modules/innocent/node_modules/chalk-next": "5.3.0"})
            code, payload, _ = scan(NPM, d)
            hits = feed_findings(payload)
            self.assertEqual(len(hits), 1, payload["findings"])
            self.assertEqual(hits[0]["severity"], "high")
            self.assertIn("transitive", hits[0]["evidence"])
            self.assertEqual(code, 2)

    def test_direct_and_transitive_are_distinguishable_in_the_evidence(self):
        with tempfile.TemporaryDirectory() as d:
            npm_project(d, {"chalk-next": "5.3.0"},
                        {"node_modules/chalk-next": "5.3.0"})
            _, direct, _ = scan(NPM, d)
        with tempfile.TemporaryDirectory() as d:
            npm_project(d, {"innocent": "1.0.0"},
                        {"node_modules/innocent": "1.0.0",
                         "node_modules/innocent/node_modules/chalk-next": "5.3.0"})
            _, trans, _ = scan(NPM, d)
        a, b = feed_findings(direct)[0], feed_findings(trans)[0]
        self.assertIn("direct dependency", a["evidence"])
        self.assertIn("transitive", b["evidence"])
        self.assertEqual(a["severity"], b["severity"])

    def test_a_range_record_respects_its_bounds(self):
        cases = {"3.3.5": 0, "3.3.6": 1, "3.3.7": 0}
        for ver, want in cases.items():
            with tempfile.TemporaryDirectory() as d:
                npm_project(d, {"event-stream": ver},
                            {"node_modules/event-stream": ver})
                _, payload, _ = scan(NPM, d)
                self.assertEqual(len(feed_findings(payload)), want, ver)

    def test_a_declared_dependency_with_no_lockfile_is_unconfirmed(self):
        """A range in package.json is not a version; say so, do not guess."""
        with tempfile.TemporaryDirectory() as d:
            write(d, "package.json", json.dumps(
                {"name": "demo", "dependencies": {"chalk-next": "^5.0.0"}}))
            write(d, "package-lock.json", json.dumps(
                {"name": "demo", "lockfileVersion": 3, "packages": {}}))
            code, payload, _ = scan(NPM, d)
            hits = feed_findings(payload)
            self.assertEqual(len(hits), 1, payload["findings"])
            self.assertEqual(hits[0]["severity"], "medium")
            self.assertIn("unconfirmed", hits[0]["why"])
            self.assertEqual(code, 1)

    def test_a_resolved_version_wins_over_the_declared_range(self):
        """Named in both places, safe once resolved -> nothing at all."""
        with tempfile.TemporaryDirectory() as d:
            npm_project(d, {"chalk-next": "^5.0.0"},
                        {"node_modules/chalk-next": "5.3.1"})
            code, payload, _ = scan(NPM, d)
            self.assertEqual(feed_findings(payload), [])
            self.assertEqual(code, 0)

    def test_devdependencies_are_checked_too(self):
        with tempfile.TemporaryDirectory() as d:
            write(d, "package.json", json.dumps(
                {"name": "demo", "devDependencies": {"requestss": "1.0.0"}}))
            write(d, "package-lock.json", json.dumps(
                {"name": "demo", "lockfileVersion": 3, "packages": {
                    "node_modules/requestss": {"version": "1.0.0", "dev": True}}}))
            # `requestss` is a pypi record, not an npm one: no cross-ecosystem hit
            _, payload, _ = scan(NPM, d)
            self.assertEqual(feed_findings(payload), [])

    def test_a_clean_project_stays_clean(self):
        with tempfile.TemporaryDirectory() as d:
            npm_project(d, {"lodash": "4.17.21"},
                        {"node_modules/lodash": "4.17.21"})
            code, payload, _ = scan(NPM, d)
            self.assertEqual(feed_findings(payload), [])
            self.assertEqual(code, 0)

    def test_a_missing_feed_changes_nothing_and_never_blocks(self):
        with tempfile.TemporaryDirectory() as d:
            npm_project(d, {"chalk-next": "5.3.0"},
                        {"node_modules/chalk-next": "5.3.0"})
            code, payload, err = scan(NPM, d, feed="/nonexistent/moat/feeds")
            self.assertEqual(feed_findings(payload), [])
            self.assertEqual(code, 0)
            self.assertIn("feed unavailable", err)

    def test_the_finding_is_allow_filterable_by_package_name(self):
        with tempfile.TemporaryDirectory() as d:
            npm_project(d, {"chalk-next": "5.3.0"},
                        {"node_modules/chalk-next": "5.3.0"})
            allow = write(d, "allow.conf", "pkg=chalk-next rule=feed.*\n")
            os.environ["MOAT_SCANNER_FEED_DIR"] = FEED_FIXTURE
            try:
                code, out, _ = run(NPM, [d, "--json", "--allow-file", allow])
            finally:
                os.environ.pop("MOAT_SCANNER_FEED_DIR", None)
            self.assertEqual(feed_findings(json.loads(out)), [])
            self.assertEqual(code, 0)


# ==========================================================================
# cargo / pip / go
# ==========================================================================


class TestCargoFeedWiring(unittest.TestCase):

    def cargo_project(self, root, deps, lock=None):
        body = "[package]\nname = \"demo\"\nversion = \"0.1.0\"\n\n[dependencies]\n"
        for name, req in deps.items():
            body += "%s = \"%s\"\n" % (name, req)
        write(root, "Cargo.toml", body)
        if lock is not None:
            out = "version = 3\n"
            for name, ver in lock.items():
                out += ('\n[[package]]\nname = "%s"\nversion = "%s"\n'
                        'source = "registry+https://github.com/rust-lang/'
                        'crates.io-index"\nchecksum = "%s"\n' % (name, ver, "0" * 64))
            write(root, "Cargo.lock", out)

    def test_the_lockfile_version_is_what_is_matched(self):
        with tempfile.TemporaryDirectory() as d:
            self.cargo_project(d, {"serde-plus": "1.0"},
                               {"serde-plus": "1.0.99"})
            code, payload, _ = scan(BUILD, d, ["--for", "cargo"])
            hits = feed_findings(payload)
            self.assertEqual(len(hits), 1, payload["findings"])
            self.assertEqual(hits[0]["severity"], "high")
            self.assertIn("crates.io", hits[0]["evidence"])
            self.assertIn("serde-plus@1.0.99", hits[0]["evidence"])
            self.assertIn("Cargo.lock", hits[0]["evidence"])
            self.assertEqual(code, 2)

    def test_a_lockfile_at_a_safe_version_silences_the_manifest_range(self):
        with tempfile.TemporaryDirectory() as d:
            self.cargo_project(d, {"serde-plus": "1.0"},
                               {"serde-plus": "1.0.98"})
            code, payload, _ = scan(BUILD, d, ["--for", "cargo"])
            self.assertEqual(feed_findings(payload), [])

    def test_a_manifest_with_no_lockfile_is_unconfirmed(self):
        with tempfile.TemporaryDirectory() as d:
            self.cargo_project(d, {"serde-plus": "1.0"})
            code, payload, _ = scan(BUILD, d, ["--for", "cargo"])
            hits = feed_findings(payload)
            self.assertEqual(len(hits), 1, payload["findings"])
            self.assertEqual(hits[0]["severity"], "medium")
            self.assertEqual(code, 1)

    def test_a_star_crate_fires_from_the_manifest_alone(self):
        with tempfile.TemporaryDirectory() as d:
            self.cargo_project(d, {"evil-crate": "0.1"})
            code, payload, _ = scan(BUILD, d, ["--for", "cargo"])
            hits = feed_findings(payload)
            self.assertEqual(len(hits), 1)
            self.assertEqual(hits[0]["severity"], "high")
            self.assertEqual(code, 2)

    def test_a_clean_crate_stays_clean(self):
        with tempfile.TemporaryDirectory() as d:
            self.cargo_project(d, {"serde": "1.0"}, {"serde": "1.0.203"})
            code, payload, _ = scan(BUILD, d, ["--for", "cargo"])
            self.assertEqual(feed_findings(payload), [])
            self.assertEqual(code, 0)

    def test_a_missing_feed_never_blocks_a_build(self):
        with tempfile.TemporaryDirectory() as d:
            self.cargo_project(d, {"evil-crate": "0.1"})
            code, payload, err = scan(BUILD, d, ["--for", "cargo"],
                                      feed="/nonexistent/moat/feeds")
            self.assertEqual(feed_findings(payload), [])
            self.assertEqual(code, 0)
            self.assertIn("feed unavailable", err)


class TestPipFeedWiring(unittest.TestCase):

    def test_a_pinned_requirement_at_the_named_version(self):
        with tempfile.TemporaryDirectory() as d:
            write(d, "requirements.txt", "ranged-pypi==2.5.0\n")
            code, payload, _ = scan(BUILD, d, ["--for", "python"])
            hits = feed_findings(payload)
            self.assertEqual(len(hits), 1, payload["findings"])
            self.assertEqual(hits[0]["severity"], "high")
            self.assertIn("pypi", hits[0]["evidence"])
            self.assertEqual(code, 2)

    def test_a_pinned_requirement_outside_the_range_is_silent(self):
        for ver in ("1.9.9", "3.0", "3.1.4"):
            with tempfile.TemporaryDirectory() as d:
                write(d, "requirements.txt", "ranged-pypi==%s\n" % ver)
                code, payload, _ = scan(BUILD, d, ["--for", "python"])
                self.assertEqual(feed_findings(payload), [], ver)
                self.assertEqual(code, 0, ver)

    def test_an_unpinned_requirement_is_unconfirmed_not_silent(self):
        with tempfile.TemporaryDirectory() as d:
            write(d, "requirements.txt", "ranged-pypi>=1.0\n")
            code, payload, _ = scan(BUILD, d, ["--for", "python"])
            hits = feed_findings(payload)
            self.assertEqual(len(hits), 1, payload["findings"])
            self.assertEqual(hits[0]["severity"], "medium")
            self.assertEqual(code, 1)

    def test_a_star_record_fires_unpinned(self):
        with tempfile.TemporaryDirectory() as d:
            write(d, "requirements.txt", "requestss\n")
            code, payload, _ = scan(BUILD, d, ["--for", "python"])
            hits = feed_findings(payload)
            self.assertEqual(len(hits), 1)
            self.assertEqual(hits[0]["severity"], "high")
            self.assertEqual(code, 2)

    def test_extras_markers_and_comments_do_not_hide_the_name(self):
        with tempfile.TemporaryDirectory() as d:
            write(d, "requirements.txt",
                  "requestss[security] ; python_version >= '3.8'  # pinned\n")
            _, payload, _ = scan(BUILD, d, ["--for", "python"])
            self.assertEqual(len(feed_findings(payload)), 1)

    def test_pyproject_project_dependencies_are_checked(self):
        with tempfile.TemporaryDirectory() as d:
            write(d, "pyproject.toml",
                  "[project]\nname = \"demo\"\n"
                  "dependencies = [\"requestss\", \"flask\"]\n")
            code, payload, _ = scan(BUILD, d, ["--for", "python"])
            self.assertEqual(len(feed_findings(payload)), 1, payload["findings"])
            self.assertEqual(code, 2)

    def test_setup_py_install_requires_is_checked(self):
        with tempfile.TemporaryDirectory() as d:
            write(d, "setup.py",
                  "from setuptools import setup\n"
                  "setup(name='demo', install_requires=['requestss', 'six'])\n")
            code, payload, _ = scan(BUILD, d, ["--for", "python"])
            self.assertEqual(len(feed_findings(payload)), 1, payload["findings"])

    def test_a_clean_requirements_file_stays_clean(self):
        with tempfile.TemporaryDirectory() as d:
            write(d, "requirements.txt",
                  "requests==2.32.3\nflask>=3.0\n# a comment\n")
            code, payload, _ = scan(BUILD, d, ["--for", "python"])
            self.assertEqual(feed_findings(payload), [])
            self.assertEqual(code, 0)

    def test_a_pypi_name_is_matched_however_it_is_spelled(self):
        with tempfile.TemporaryDirectory() as d:
            write(d, "requirements.txt", "Flask_Evil==1.0\n")
            _, payload, _ = scan(BUILD, d, ["--for", "python"])
            self.assertEqual(len(feed_findings(payload)), 1)


class TestGoFeedWiring(unittest.TestCase):

    def test_a_require_inside_the_range(self):
        with tempfile.TemporaryDirectory() as d:
            write(d, "go.mod", "module demo\n\ngo 1.22\n\nrequire (\n"
                               "\tgithub.com/evil/mod v1.2.3\n)\n")
            code, payload, _ = scan(BUILD, d, ["--for", "go"])
            hits = feed_findings(payload)
            self.assertEqual(len(hits), 1, payload["findings"])
            self.assertEqual(hits[0]["severity"], "high")
            self.assertIn("go.mod require", hits[0]["evidence"])
            self.assertEqual(code, 2)

    def test_a_require_outside_the_range_is_silent(self):
        for ver in ("v1.1.9", "v1.2.5", "v2.0.0"):
            with tempfile.TemporaryDirectory() as d:
                write(d, "go.mod", "module demo\n\nrequire (\n"
                                   "\tgithub.com/evil/mod %s\n)\n" % ver)
                code, payload, _ = scan(BUILD, d, ["--for", "go"])
                self.assertEqual(feed_findings(payload), [], ver)

    def test_a_single_line_require_is_read_too(self):
        with tempfile.TemporaryDirectory() as d:
            write(d, "go.mod",
                  "module demo\n\nrequire github.com/evil/mod v1.2.4\n")
            code, payload, _ = scan(BUILD, d, ["--for", "go"])
            self.assertEqual(len(feed_findings(payload)), 1)

    def test_a_clean_go_mod_stays_clean(self):
        with tempfile.TemporaryDirectory() as d:
            write(d, "go.mod", "module demo\n\nrequire (\n"
                               "\tgithub.com/stretchr/testify v1.9.0\n)\n")
            code, payload, _ = scan(BUILD, d, ["--for", "go"])
            self.assertEqual(feed_findings(payload), [])
            self.assertEqual(code, 0)


# ==========================================================================
# cost
# ==========================================================================


class TestLookupCost(unittest.TestCase):
    """These scanners run in the hot path of an install. If startup cost
    scales with the feed, they get switched off and detect nothing."""

    ENTRIES = 242_000

    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.mkdtemp()
        cls.path = os.path.join(cls.dir, "packages.txt")
        rows = []
        for i in range(cls.ENTRIES):
            rows.append("npm\tpkg-%07d\t%s" % (
                i, "*" if i % 7 else "=1.%d.0" % (i % 50)))
        rows.sort()
        with open(cls.path, "w") as fh:
            fh.write("# moat-packages v1\n")
            fh.write("\n".join(rows) + "\n")
        cls.bytes = os.path.getsize(cls.path)

    @classmethod
    def tearDownClass(cls):
        import shutil
        shutil.rmtree(cls.dir, ignore_errors=True)

    def test_opening_the_feed_does_not_read_it(self):
        t0 = time.perf_counter()
        f = BUILD.PackageFeed(self.path, os.path.join(self.dir, "meta.json"))
        open_ms = (time.perf_counter() - t0) * 1000
        self.addCleanup(f.close)
        self.assertTrue(f.available)
        print("\n  feed: %d entries, %.1f MB" % (self.ENTRIES, self.bytes / 1e6))
        print("  open+mmap:        %.3f ms" % open_ms)
        self.assertLess(open_ms, 50, "opening the feed should be O(1)")

    def test_a_lookup_is_fast_enough_to_run_per_dependency(self):
        f = BUILD.PackageFeed(self.path, os.path.join(self.dir, "meta.json"))
        self.addCleanup(f.close)
        names = ["pkg-%07d" % (i * 977 % self.ENTRIES) for i in range(2000)]
        for n in names[:50]:
            f.specs("npm", n)                 # warm the page cache
        t0 = time.perf_counter()
        for n in names:
            f.specs("npm", n)
        hit_us = (time.perf_counter() - t0) / len(names) * 1e6

        misses = ["absent-%07d" % i for i in range(2000)]
        t0 = time.perf_counter()
        for n in misses:
            f.specs("npm", n)
        miss_us = (time.perf_counter() - t0) / len(misses) * 1e6

        print("  lookup (hit):     %.1f us" % hit_us)
        print("  lookup (miss):    %.1f us" % miss_us)
        print("  1000 deps:        %.1f ms" % (hit_us * 1000 / 1000))
        self.assertLess(hit_us, 500, "a lookup must stay well under a ms")
        self.assertLess(miss_us, 500)

    def test_memory_does_not_scale_with_the_feed(self):
        """A dict of 242k entries would be tens of MB; an mmap is not."""
        import tracemalloc
        tracemalloc.start()
        base = tracemalloc.get_traced_memory()[0]
        f = BUILD.PackageFeed(self.path, os.path.join(self.dir, "meta.json"))
        self.addCleanup(f.close)
        for i in range(500):
            f.specs("npm", "pkg-%07d" % (i * 101 % self.ENTRIES))
        peak = tracemalloc.get_traced_memory()[1] - base
        tracemalloc.stop()
        print("  python heap:      %.0f KB (feed is %.1f MB on disk)"
              % (peak / 1024, self.bytes / 1e6))
        self.assertLess(peak, 2 * 1024 * 1024,
                        "the feed must not be loaded into the heap")


if __name__ == "__main__":
    unittest.main()
