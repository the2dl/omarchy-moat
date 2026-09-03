import QtQuick
import QtTest
import "../MoatModel.js" as Model

// Wire-level tests: MoatModel.js against output the REAL daemon actually
// produced, not hand-written examples of what it ought to produce.
//
// fixtures/wire/* were captured from a live `moatd run` (release build)
// tailing a synthetic Tetragon export that fires one cred policy, one persist
// policy, one pkg policy, a kill+exit pair and a dedupe repeat, then driven
// through moatctl status/list/explain/ignore/allowlist/set --json. Only two
// substitutions were made: the scratch directory became the installed paths
// from CONTRACT 2, and the socket group became `moat`. Everything else is
// byte-for-byte what the daemon wrote.
//
// tst_model.qml checks the model's own rules. This file checks the SEAM: that
// the field names, nesting and vocabulary the daemon emits are the ones the
// panel reads. Regenerate the fixtures whenever the alert record or a socket
// response changes shape.
//
//   QT_QPA_PLATFORM=offscreen QML_XHR_ALLOW_FILE_READ=1 \
//     /usr/lib/qt6/bin/qmltestrunner -input shell/tests/tst_wire.qml
TestCase {
  id: suite
  name: "MoatWire"

  property string alertsText: ""
  property var statusRaw: ""
  property var listRaw: ""
  property var explainRaw: ""
  property var allowlistRaw: ""
  property var ignoreRaw: ""
  property var setModeRaw: ""
  property var setSandboxRaw: ""

  function read(name) {
    var request = new XMLHttpRequest()
    request.open("GET", Qt.resolvedUrl("fixtures/wire/" + name), false)
    request.send(null)
    return String(request.responseText || "")
  }

  function initTestCase() {
    suite.alertsText = read("alerts.jsonl")
    suite.statusRaw = read("status.json")
    suite.listRaw = read("list.json")
    suite.explainRaw = read("explain.json")
    suite.allowlistRaw = read("allowlist.json")
    suite.ignoreRaw = read("ignore.json")
    suite.setModeRaw = read("set-mode-no-tetra.json")
    suite.setSandboxRaw = read("set-sandbox.json")
    verify(suite.alertsText.length > 0, "fixtures/wire/alerts.jsonl is unreadable")
  }

  function alerts() { return Model.foldText(suite.alertsText) }

  function byRule(list, rule) {
    for (var i = 0; i < list.length; i++) if (list[i].rule === rule) return list[i]
    return null
  }

  // ------------------------------------------------------- alerts.jsonl fold

  // The daemon wrote four alerts and four update lines; folding must produce
  // exactly the four alerts, newest first.
  function test_real_log_folds_to_the_alerts_the_daemon_emitted() {
    var list = alerts()
    compare(list.length, 4)
    for (var i = 1; i < list.length; i++) {
      verify(list[i - 1].id > list[i].id, "newest first by ULID")
    }
    verify(byRule(list, "moat-cred-ssh-private-key-read") !== null)
    verify(byRule(list, "moat-persist-shell-rc-write") !== null)
    verify(byRule(list, "moat-pkg-subtree-downloader") !== null)
  }

  // Every field the panel reads unconditionally must survive normalization
  // with a real value, not a default that papers over a renamed field.
  function test_every_alert_carries_the_panel_facing_fields() {
    var list = alerts()
    for (var i = 0; i < list.length; i++) {
      var a = list[i]
      verify(a.id.length === 26, "ULID id: " + a.id)
      verify(Model.severityRank(a.severity) >= 0, "known severity: " + a.severity)
      verify(a.rule.indexOf("moat-") === 0, "rule id: " + a.rule)
      verify(a.family.length > 0, "family on " + a.rule)
      verify(a.title.length > 0, "title on " + a.rule)
      verify(a.summary.length > 0, "summary on " + a.rule)
      verify(!isNaN(Date.parse(a.ts)), "parseable ts: " + a.ts)
      verify(a.process.pid > 0, "pid on " + a.rule)
      verify(a.process.exe.length > 0, "exe on " + a.rule)
      verify(!isNaN(Date.parse(a.process.start_ts)), "start_ts: " + a.process.start_ts)
      verify(a.mode === "monitor" || a.mode === "enforce", "mode: " + a.mode)
      verify(["none", "killed", "quarantined"].indexOf(a.action_taken) !== -1,
             "action_taken: " + a.action_taken)
      verify(a.actions.length > 0, "actions on " + a.rule)
      verify(a.actions.indexOf("ignore") !== -1, "ignore is always offered")
      verify(a.count >= 1)
    }
  }

  // The policy configured Sigkill and the matching process_exit reported
  // SIGKILL, so the daemon appended {"action_taken":"killed"}. The panel must
  // fold that onto the alert, not show "none" next to a dead process.
  function test_kill_confirmation_folds_onto_the_alert() {
    var list = alerts()
    var killed = null
    for (var i = 0; i < list.length; i++) {
      if (list[i].file && String(list[i].file.path).indexOf("id_ed25519") > 0) killed = list[i]
    }
    verify(killed !== null, "the fixture's Sigkill alert is present")
    compare(killed.rule, "moat-cred-ssh-private-key-read")
    compare(killed.action_taken, "killed")
    compare(killed.acked, true, "the ignore in the transcript acked it")
  }

  // CONTRACT 6.3: a repeat inside the dedupe window is a count update, not a
  // second alert. The daemon's update carries `ts` alongside `count`, so the
  // folded alert must move forward in time as well as up in count.
  function test_dedupe_count_and_timestamp_both_fold() {
    var list = alerts()
    var repeated = null
    for (var i = 0; i < list.length; i++) if (list[i].count > 1) repeated = list[i]
    verify(repeated !== null, "the fixture contains a deduped alert")
    compare(repeated.count, 2)

    // The daemon's count update carries `ts` as well. The fixture drained the
    // whole export inside one millisecond so both stamps are equal there; what
    // matters is that the update's stamp is the one that survives, because a
    // real repeat minutes later must not still read as the first sighting.
    var updateTs = ""
    var lines = suite.alertsText.split("\n")
    for (var j = 0; j < lines.length; j++) {
      var record = Model.parseLine(lines[j])
      if (record && record.id === repeated.id && Model.isUpdate(record) && record.update.ts)
        updateTs = String(record.update.ts)
    }
    verify(updateTs !== "", "the daemon's count update carries a ts")
    compare(repeated.ts, updateTs, "the update's ts must win")

    var aged = Model.foldText(suite.alertsText)[0]
    Model.applyUpdate(aged, { count: 9, ts: "2026-12-25T00:00:00.000Z" })
    compare(aged.count, 9)
    compare(aged.ts, "2026-12-25T00:00:00.000Z")
    // ...but an update line still cannot rewrite what the sensor saw.
    Model.applyUpdate(aged, { severity: "critical", title: "hostile", process: {} })
    verify(aged.severity !== "critical", "severity is not updatable")
    verify(aged.title !== "hostile", "title is not updatable")
  }

  // ------------------------------------------------------------- explain seam

  function test_explain_block_shape_matches_the_panel() {
    var list = alerts()
    for (var i = 0; i < list.length; i++) {
      var a = list[i]
      verify(Model.hasExplain(a), "no explain on " + a.rule)
      var e = a.explain
      verify(e.what.length > 0, "explain.what on " + a.rule)
      verify(e.why.length > 0, "explain.why on " + a.rule)
      verify(e.expected.length > 0, "explain.expected on " + a.rule)
      verify(e.evidence.length >= 3, "explain.evidence on " + a.rule)
      verify(e.next.length >= 2, "explain.next on " + a.rule)
      verify(e.if_expected.file.indexOf("user.toml") > 0, "allowlist target file")
      verify(Model.isIgnoreScope(e.if_expected.hint), "fp-hint: " + e.if_expected.hint)
    }
  }

  // Every if_expected option the daemon emits must survive normalizeIfExpected
  // (an unrecognized scope string is dropped silently, which would quietly
  // remove a button), and each must carry both the command and the TOML.
  function test_if_expected_options_survive_normalization() {
    var list = alerts()
    for (var i = 0; i < list.length; i++) {
      var a = list[i]
      var raw = JSON.parse(suite.explainRaw)  // shape check below; count here
      var options = Model.ignoreOptions(a)
      verify(options.length >= 3, a.rule + " offers " + options.length + " scopes")
      var recommended = 0
      for (var j = 0; j < options.length; j++) {
        var o = options[j]
        verify(Model.isIgnoreScope(o.scope), "scope " + o.scope)
        compare(o.cmd, "moatctl ignore " + a.id + " --scope " + o.scope)
        verify(o.line.indexOf("[[rule]]\n") === 0, "TOML block for " + o.scope)
        verify(o.line.indexOf('name = "' + a.rule + '"') > 0, "block names the rule")
        verify(o.label.length > 0, "button label for " + o.scope)
        if (o.recommended) recommended++
      }
      compare(recommended, 1, "exactly one recommended scope")
      compare(options[0].recommended, true, "recommended scope renders first")
      compare(options[0].scope, a.explain.if_expected.hint, "the policy's fp-hint wins")
      verify(raw.ok === true)
    }
  }

  // CONTRACT 5's explain response is {"ok":true,"alert":{...}} — one level of
  // nesting the merge path has to know about.
  function test_explain_socket_response_merges() {
    var stripped = Model.foldText(suite.alertsText)[0]
    var id = JSON.parse(suite.explainRaw).alert.id
    var target = null
    var list = alerts()
    for (var i = 0; i < list.length; i++) if (list[i].id === id) target = list[i]
    verify(target !== null, "the explain fixture names an alert in the log")
    target.explain = Model.normalizeExplain(null)
    verify(!Model.hasExplain(target))
    Model.mergeExplainResponse(target, suite.explainRaw)
    verify(Model.hasExplain(target), "explain must be recoverable from the socket")
    verify(target.explain.evidence.length >= 3)
    verify(stripped !== null)
  }

  // The pkg-family policies all hook bprm_check_security, so the file in the
  // event is the binary being executed. The `what` sentence must read that way.
  function test_pkg_family_what_describes_an_exec() {
    var pkg = byRule(alerts(), "moat-pkg-subtree-downloader")
    verify(pkg.explain.what.indexOf("package install") >= 0, pkg.explain.what)
    verify(pkg.explain.what.indexOf("read /usr/bin/curl") < 0,
           "a bprm hit is not a secret read: " + pkg.explain.what)
    verify(pkg.summary.indexOf("touched") < 0, pkg.summary)
  }

  // --------------------------------------------------------------- rotate

  // The rotate vocabulary is whatever policies/*.yaml annotate. If the plugin
  // does not know a kind the daemon ships, the panel tells someone a secret
  // leaked and then offers a shrug. This is the full set the policies emit.
  readonly property var policyRotateKinds: [
    "anthropic-token", "aws-key", "azure-token", "browser-cookies",
    "browser-passwords", "cargo-token", "docker-token", "gcp-token",
    "git-credentials", "github-token", "google-token", "gpg-key", "keyring",
    "kubeconfig", "local-password", "npm-token", "openai-token", "pypi-token",
    "session-cookies", "ssh-key"
  ]

  function test_every_policy_rotate_kind_has_specific_guidance() {
    var generic = Model.rotateGuidance("a-kind-no-policy-uses")
    verify(generic.length > 0)
    for (var i = 0; i < suite.policyRotateKinds.length; i++) {
      var kind = suite.policyRotateKinds[i]
      var text = Model.rotateGuidance(kind)
      verify(text.length > 0, "no guidance for " + kind)
      verify(text !== generic, "only the generic fallback for " + kind)
    }
  }

  function test_rotate_items_come_from_the_real_alert() {
    var cred = byRule(alerts(), "moat-cred-ssh-private-key-read")
    var items = Model.rotateItems(cred)
    compare(items.length, 1)
    compare(items[0].kind, "ssh-key")
    verify(items[0].guidance.indexOf("ssh-keygen") >= 0)
  }

  // ---------------------------------------------------------------- status

  function test_status_response_maps_onto_the_status_strip() {
    var s = Model.normalizeStatus(suite.statusRaw)
    compare(s.ok, true)
    compare(s.version, "0.1.0")
    compare(s.mode, "monitor")
    compare(s.tetragon, "running")
    compare(s.policies, 32)
    compare(s.policies_failed.length, 0)
    // The daemon emits feeds.updated as JSON null before the first refresh.
    compare(s.feeds.updated, "")
    compare(s.feeds.hashes, 0)
    verify(s.unacked !== null)
    verify(s.unacked.high >= 1)
    compare(s.sandbox, false)
    // CONTRACT 5's example says group_ok; the daemon ships socket_group and
    // omits group_ok. Absent must not read as "not in the group".
    compare(s.group_ok, true)
    compare(s.socket_group, "moat")
    compare(s.error, "")
  }

  function test_status_summary_and_widget_state_from_real_status() {
    var s = Model.normalizeStatus(suite.statusRaw)
    var counts = Model.unackedCounts(alerts())
    var summary = Model.statusSummary(suite.statusRaw, counts, Date.now())
    verify(summary.indexOf("mode monitor") > 0, summary)
    verify(summary.indexOf("tetragon running") > 0, summary)
    verify(summary.indexOf("32 policies") > 0, summary)
    verify(summary.indexOf("feeds never") > 0, summary)
    compare(Model.widgetState({ available: true, groupOk: true, daemonOk: s.ok,
                                unacked: counts }), "red", "unacked high is red")
    compare(Model.setupSteps(false, true, s.socket_group)[0].command,
            "sudo usermod -aG moat $USER")
  }

  // ----------------------------------------------------------------- list

  // `list` is the same alert records over the socket. The panel folds the log,
  // but the setup path reads list when the log is unreadable, so the two must
  // normalize identically.
  function test_list_response_normalizes_like_the_log() {
    var response = JSON.parse(suite.listRaw)
    compare(response.ok, true)
    verify(response.alerts.length >= 3)
    var fromSocket = Model.foldRecords(response.alerts)
    var fromLog = alerts()
    compare(fromSocket.length, fromLog.length)
    for (var i = 0; i < fromSocket.length; i++) {
      compare(fromSocket[i].id, fromLog[i].id)
      compare(fromSocket[i].title, fromLog[i].title)
      compare(fromSocket[i].severity, fromLog[i].severity)
      // list serves the folded alert, so state changes are already applied.
      compare(fromSocket[i].action_taken, fromLog[i].action_taken)
      compare(fromSocket[i].count, fromLog[i].count)
    }
  }

  // ------------------------------------------------------------- allowlist

  function test_allowlist_response_renders() {
    var parsed = Model.parseAllowlist(suite.allowlistRaw)
    compare(parsed.ok, true)
    compare(parsed.error, "")
    // The daemon calls it user_file; the panel's "writes to" label reads .file.
    compare(parsed.file, "/etc/moat/allowlist.d/user.toml")
    compare(parsed.dir, "/etc/moat/allowlist.d")
    compare(parsed.rules.length, 1)
    var rule = parsed.rules[0]
    // CONTRACT 5: the index is the handle `unignore` takes; never renumber it.
    compare(rule.index, 1)
    compare(rule.removable, true)
    compare(rule.name, "moat-cred-ssh-private-key-read")
    compare(rule.comment.indexOf("added "), 0)
    verify(rule.comment.indexOf("Private SSH key") > 0, "the comment explains itself")
    // The daemon's per-rule `file` is the SOURCE fragment and `path` is the
    // rule's file glob; reading `file` as the glob printed the wrong thing.
    compare(rule.detail, "exe = /usr/bin/node")
    // ...and the block itself comes back as `toml`, not `line`.
    verify(rule.line.indexOf("[[rule]]\n") === 0, "the exact TOML block: " + rule.line)
    verify(rule.line.indexOf('exe = "/usr/bin/node"') > 0)
  }

  // Service.qml shows the block `ignore` says it wrote, verbatim.
  function test_ignore_response_carries_the_block_it_wrote() {
    var response = JSON.parse(suite.ignoreRaw)
    compare(response.ok, true)
    compare(response.scope, "exe")
    compare(response.acked, true)
    compare(response.file, "/etc/moat/allowlist.d/user.toml")
    var block = String(response.block || response.line || response.rule || "")
    verify(block.indexOf("# added ") === 0, block)
    verify(block.indexOf("[[rule]]") > 0)
    var parsed = Model.parseAllowlist(suite.allowlistRaw)
    verify(block.indexOf(parsed.rules[0].line) > 0,
           "the block written and the block listed must agree")
  }

  // -------------------------------------------------------------- set/mode

  // `set mode` answers ok:true even when tetra could not be run at all, so
  // ok alone is not enough to tell the user the sensor changed mode.
  function test_set_mode_without_tetra_is_reported_but_not_applied() {
    var response = JSON.parse(suite.setModeRaw)
    compare(response.ok, true)
    compare(response.mode, "enforce")
    compare(response.applied, 0)
    compare(response.policies, 32)
    verify(response.failed.length > 0, "the failures are enumerated, not swallowed")
    verify(String(response.failed[0].error).length > 0)
    // Service.qml turns exactly this shape into an error rather than a success.
    verify(Number(response.policies) > 0 && Number(response.applied) === 0)
  }

  function test_set_sandbox_reports_the_flag_state() {
    var response = JSON.parse(suite.setSandboxRaw)
    compare(response.ok, true)
    compare(response.sandbox, true)
    compare(response.flag, "/etc/moat/sandbox.enabled")
    verify(String(response.note).length > 0, "the re-login caveat is carried")
  }
}
