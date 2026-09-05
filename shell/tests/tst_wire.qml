import QtQuick
import QtTest
import "../MoatModel.js" as Model

// Wire-level tests: MoatModel.js against output the REAL daemon actually
// produced, not hand-written examples of what it ought to produce.
//
// fixtures/wire/* are captured by shell/tests/capture-wire-fixtures.sh, which
// runs a real `moatd run` over a synthetic Tetragon export (see
// shell/tests/gen-export-log.py) and drives it through moatctl. The scenario:
// a cloud-credential read from an interactive chain and the same read from
// inside `npm install`, an interpreter spawn, an SSH key read the kernel
// killed, netcat and curl under the package root, the connection curl opened,
// the package root exiting (an install receipt), persistence writes by an
// official binary, a burst of one low rule (the noise guard demoting it), and
// a recurring official tuple that the learning window learned and a second one
// it proposed. Only two substitutions were made: the scratch directory became
// the installed paths from CONTRACT 2, and the socket group became `moat`.
//
// tst_model.qml checks the model's own rules. This file checks the SEAM: that
// the field names, nesting and vocabulary the daemon emits are the ones the
// panel reads. Regenerate the fixtures whenever the alert record or a socket
// response changes shape:
//
//   shell/tests/capture-wire-fixtures.sh
//
// Run just this file:
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
  property var receiptsRaw: ""
  property var incidentsRaw: ""
  property var bundleRaw: ""
  property var baselineListRaw: ""
  property var baselineExportRaw: ""
  property string bundleMd: ""

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
    suite.receiptsRaw = read("receipts.json")
    suite.incidentsRaw = read("incidents.json")
    suite.bundleRaw = read("bundle.json")
    suite.baselineListRaw = read("baseline-list.json")
    suite.baselineExportRaw = read("baseline-export.json")
    suite.bundleMd = read("bundle.md")
    verify(suite.alertsText.length > 0, "fixtures/wire/alerts.jsonl is unreadable")
  }

  function alerts() { return Model.foldText(suite.alertsText) }

  function byRule(list, rule) {
    for (var i = 0; i < list.length; i++) if (list[i].rule === rule) return list[i]
    return null
  }

  // The one alert that is both a credential read and a package install: the
  // BASELINE 2b comparison this whole capture exists to make.
  function credInInstall() {
    var list = alerts()
    for (var i = 0; i < list.length; i++) {
      if (list[i].rule === "moat-cred-cloud-credentials-read"
          && list[i].context === "pkg-install") return list[i]
    }
    return null
  }

  function credInteractive() {
    var list = alerts()
    for (var i = 0; i < list.length; i++) {
      if (list[i].rule === "moat-cred-cloud-credentials-read"
          && list[i].context === "interactive") return list[i]
    }
    return null
  }

  // ------------------------------------------------------- alerts.jsonl fold

  // The log the daemon wrote folds to exactly the alerts it logged, newest
  // first, with the update lines applied and none of them materialized as an
  // alert of its own.
  function test_real_log_folds_to_the_alerts_the_daemon_emitted() {
    var list = alerts()
    var response = JSON.parse(suite.listRaw)
    compare(list.length, response.alerts.length,
            "the fold and the socket agree on how many alerts there are")
    for (var i = 1; i < list.length; i++) {
      verify(list[i - 1].id > list[i].id, "newest first by ULID")
    }
    // The scenario's landmarks, each a different code path in the daemon.
    verify(byRule(list, "moat-cred-cloud-credentials-read") !== null, "kernel cred policy")
    verify(byRule(list, "moat-cred-ssh-private-key-read") !== null, "an enforcing policy")
    verify(byRule(list, "moat-pkg-subtree-netcat-exec") !== null, "a userland pkg rule")
    verify(byRule(list, "moat-pkg-subtree-downloader") !== null, "a userland pkg rule")
    verify(byRule(list, "moat-net-suspicious-port-egress") !== null, "a kernel net policy")
    verify(byRule(list, "moat-x-noisy-rule") !== null, "the noise guard's own alert")
    verify(byRule(list, "moat-persist-desktop-entry-write") !== null, "an official actor")
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

  // ------------------------------------------------- BASELINE 8: the new fields

  // actor / context / severity_base / severity_reason / surface / rarity are
  // not optional extras: the panel renders a line for each. Every one must
  // arrive with a value the model recognizes rather than falling back to
  // "unknown", which is what a renamed field would look like.
  function test_every_alert_carries_actor_context_severity_base_and_rarity() {
    var list = alerts()
    var provenanceSeen = {}
    var contextSeen = {}
    for (var i = 0; i < list.length; i++) {
      var a = list[i]
      verify(["official", "foreign", "user", "unknown"].indexOf(a.actor.provenance) !== -1,
             "provenance on " + a.rule + ": " + a.actor.provenance)
      verify(["interactive", "pkg-install", "service", "unknown"].indexOf(a.context) !== -1,
             "context on " + a.rule + ": " + a.context)
      verify(Model.severityRank(a.severity_base) >= 0, "severity_base on " + a.rule)
      verify(a.severity_reason.length > 0, "severity_reason on " + a.rule)
      verify(["first_seen", "rare", "common"].indexOf(a.rarity) !== -1,
             "rarity on " + a.rule + ": " + a.rarity)
      verify(Model.rarityLine(a).length > 0, "rarity sentence on " + a.rule)
      verify(Model.rarityPill(a.rarity) !== null, "rarity pill on " + a.rule)
      provenanceSeen[a.actor.provenance] = true
      contextSeen[a.context] = true
    }
    // The capture is only worth anything if it actually exercises the axes.
    verify(provenanceSeen["official"] === true, "an official actor is in the capture")
    verify(provenanceSeen["user"] === true, "a user actor is in the capture")
    verify(contextSeen["interactive"] === true)
    verify(contextSeen["pkg-install"] === true)
    verify(contextSeen["service"] === true)
  }

  // BASELINE 2b, the row the document opens with: the SAME rule, the same
  // actor binary, the same directory, one step apart in the process tree.
  // If the context matrix ever stops working this is the test that says so.
  function test_context_matrix_scores_the_same_read_two_ways() {
    var interactive = credInteractive()
    var install = credInInstall()
    verify(interactive !== null, "the interactive credential read is in the capture")
    verify(install !== null, "the pkg-install credential read is in the capture")

    compare(interactive.process.exe, install.process.exe, "same actor binary")
    compare(interactive.severity_base, "high", "the policy says high")
    compare(install.severity_base, "high", "the policy says high")

    // BASELINE 2b: interactive -> medium, pkg-install -> critical.
    compare(interactive.severity, "medium")
    compare(install.severity, "critical")
    verify(interactive.severity_reason.indexOf("interactive") >= 0, interactive.severity_reason)
    verify(install.severity_reason.indexOf("pkg-install") >= 0, install.severity_reason)

    // ...and that difference is what decides which tab each one lands on.
    compare(Model.alertSurface(interactive, []), "timeline")
    compare(Model.alertSurface(install, []), "alerts")
  }

  // BASELINE 2: an official actor takes one step off the persist family, and
  // the alert says which package made it official.
  function test_provenance_downgrade_is_recorded_and_explained() {
    var a = byRule(alerts(), "moat-persist-desktop-entry-write")
    verify(a !== null)
    compare(a.actor.provenance, "official")
    verify(a.actor.package.length > 0, "the package that owns the binary is named")
    compare(a.severity_base, "medium")
    compare(a.severity, "low")
    verify(a.severity_reason.indexOf("official") >= 0, a.severity_reason)
    verify(Model.actorLine(a).indexOf(a.actor.package) >= 0, Model.actorLine(a))
    verify(Model.severityChangeLine(a).indexOf("medium") >= 0, Model.severityChangeLine(a))

    // BASELINE 1: an interpreter carries the provenance of its script, and the
    // script path is what the timeline groups on.
    var install = credInInstall()
    verify(install.actor.script.length > 0, "the script is the actor for an interpreter")
    compare(install.actor.provenance, "user")
  }

  // BASELINE 8 pins `surface` on the record. The plugin computes its own from
  // severity + suppression + the live demoted-rule list, so the two must agree
  // on every alert the daemon actually wrote — a divergence here means one of
  // them is deciding which tab an alert lands on differently from the other.
  function test_reported_surface_agrees_with_the_computed_one() {
    var records = JSON.parse(suite.listRaw).alerts
    var demoted = JSON.parse(suite.statusRaw).demoted_rules
    for (var i = 0; i < records.length; i++) {
      var reported = String(records[i].surface || "")
      verify(reported === "alerts" || reported === "timeline",
             "surface on " + records[i].rule + ": " + reported)
      var computed = Model.alertSurface(Model.normalizeAlert(records[i]), demoted)
      compare(computed, reported, records[i].rule + " " + records[i].severity)
    }
  }

  // BASELINE 4: the noise guard demotes a flooding rule instead of deleting
  // it. Its alerts keep being written, keep their severity, and move to the
  // timeline; the badge must not count them.
  function test_the_demoted_rule_is_quiet_but_not_hidden() {
    var status = Model.normalizeStatus(suite.statusRaw)
    compare(status.demoted_rules.length, 1)
    var rule = status.demoted_rules[0]
    var options = { demotedRules: status.demoted_rules }

    var list = Model.decorateAlerts(alerts(), options)
    var seen = 0
    for (var i = 0; i < list.length; i++) {
      if (list[i].rule !== rule) continue
      seen++
      compare(list[i].demoted, true)
      compare(list[i].surface, "timeline")
      compare(list[i].visible, true, "demoted is quiet, not hidden")
    }
    verify(seen > 1, "the flooding rule's alerts are all still in the log")

    // Not counted in the badge -- because the DAEMON stamped every one of them
    // `timeline`, not because the panel read the list: the count is the same
    // with and without `demoted_rules`, and none of the rule's unacked alerts
    // is on the Alerts surface.
    var counts = Model.unackedCounts(alerts(), options)
    var uncounted = Model.unackedCounts(alerts(), {})
    compare(counts.badge, uncounted.badge, "the list is not a second surfacing decision")
    var onBadge = 0, unackedOfRule = 0
    for (var j = 0; j < list.length; j++) {
      if (list[j].rule !== rule || list[j].acked) continue
      unackedOfRule++
      if (Model.alertSurface(list[j], status.demoted_rules) === "alerts") onBadge++
    }
    verify(unackedOfRule > 0)
    compare(onBadge, 0, "a demoted rule is not counted in the badge")

    // ...and the guard's own alert names the rule it demoted.
    var guard = byRule(alerts(), "moat-x-noisy-rule")
    verify(guard.explain.what.indexOf(rule) >= 0, guard.explain.what)
    // The guard's own alert is medium, and BASELINE 5 says a medium does not
    // notify — but this is the one deliberate exception: it is the announcement
    // that a detection just went quiet, and it toasts once.
    compare(Model.shouldNotify(guard, "high", false, options), true,
            "the noise guard announces itself once")
    // Everything the flood produced stays silent, which is the point.
    var silenced = 0
    for (var k = 0; k < list.length; k++) {
      if (list[k].rule !== rule) continue
      compare(Model.shouldNotify(list[k], "low", false, options), false,
              "a demoted rule never notifies, at any threshold")
      silenced++
    }
    verify(silenced > 1)
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

  // CONTRACT 3: the policy carried matchActions Sigkill, so the kprobe event
  // reported KPROBE_ACTION_SIGKILL — which in monitor mode means nothing on
  // its own. The daemon only wrote {"action_taken":"killed"} after the
  // matching process_exit said SIGKILL, and the fold must apply it.
  function test_kill_confirmation_folds_onto_the_alert() {
    var killed = byRule(alerts(), "moat-cred-ssh-private-key-read")
    verify(killed !== null, "the fixture's Sigkill alert is present")
    compare(killed.action_taken, "killed")
    compare(killed.mode, "monitor", "a monitor-mode run still records a confirmed kill")
    // The snapshot was taken before the kill (LEARNING 4), so the evidence
    // survives the process.
    verify(killed.incident !== null, "the snapshot outlived the process")
  }

  // ------------------------------------------------- LEARNING 4: incidents

  // Every high and critical alert carries an incident block naming the
  // snapshot the daemon took before anything could be killed; nothing below
  // that threshold does.
  function test_incident_blocks_are_on_exactly_the_high_and_critical_alerts() {
    var list = alerts()
    var withIncident = 0
    for (var i = 0; i < list.length; i++) {
      var a = list[i]
      if (!Model.severityAtLeast(a.severity, "high")) {
        compare(a.incident, null, a.rule + " (" + a.severity + ") has no snapshot")
        continue
      }
      verify(a.incident !== null, "no incident block on " + a.rule)
      withIncident++
      verify(a.incident.dir.indexOf("/var/lib/moat/incidents/" + a.id) === 0,
             "incident dir is <bundle_dir>/<alert id>: " + a.incident.dir)
      compare(a.incident.count, a.incident.files.length)
      verify(a.incident.files.length >= 3, a.rule + " captured " + a.incident.files.length)
      var names = {}
      for (var f = 0; f < a.incident.files.length; f++) {
        var file = a.incident.files[f]
        verify(file.name.length > 0)
        verify(file.path.indexOf(a.incident.dir + "/") === 0, "file path: " + file.path)
        verify(file.size > 0, file.name + " size " + file.size)
        compare(file.sha256.length, 64, file.name + " sha256")
        verify(Model.formatBytes(file.size).length > 0)
        names[file.name] = true
      }
      verify(names["process.json"] === true, "process.json is always captured")
      verify(names["tree.txt"] === true, "tree.txt is always captured")
      verify(names["net.txt"] === true, "net.txt is always captured")
    }
    verify(withIncident >= 3, "the capture has several snapshots")
  }

  // The `incidents` response lists the same snapshots from disk. The ids, the
  // directories and the file lists must be the ones the alerts named.
  function test_incidents_response_matches_the_alerts_incident_blocks() {
    var response = JSON.parse(suite.incidentsRaw)
    compare(response.ok, true)
    compare(String(response.dir), "/var/lib/moat/incidents")
    verify(response.incidents.length >= 3)
    var list = alerts()
    for (var i = 0; i < response.incidents.length; i++) {
      var row = response.incidents[i]
      var alert = null
      for (var j = 0; j < list.length; j++) if (list[j].id === row.id) alert = list[j]
      verify(alert !== null, "incident " + row.id + " has no alert")
      compare(row.rule, alert.rule)
      compare(row.severity, alert.severity)
      compare(String(row.dir), alert.incident.dir)
      // normalizeIncident reads the socket row the same way it reads the
      // alert's own block, so the panel can render either.
      var normalized = Model.normalizeIncident(row)
      compare(normalized.dir, alert.incident.dir)
      compare(normalized.count, alert.incident.count)
    }
  }

  // ---------------------------------------------- LEARNING 3: install receipts

  // The install receipt shares alerts.jsonl with the alerts, which is what
  // makes "receipts never notify and never count" true by construction: the
  // fold must produce a receipt and NOT an alert from the same line.
  function test_receipt_folds_out_of_the_log_and_not_into_the_alerts() {
    var receipts = Model.receiptsFromText(suite.alertsText)
    compare(receipts.length, 1)
    var r = receipts[0]
    compare(r.kind, "receipt")
    verify(r.id.length === 26, "receipts carry a top-level ULID: " + r.id)
    compare(r.root_exe, "/usr/bin/node")
    verify(r.root_args.indexOf("npm-cli.js") >= 0, r.root_args)
    compare(r.cwd, "/home/moattest/proj")
    compare(r.exit, 0)
    verify(r.duration_s > 0, "duration_s " + r.duration_s)
    verify(!isNaN(Date.parse(r.started)), "started: " + r.started)
    // What the install actually did, which is the point of the whole record.
    verify(r.postinstall_scripts.length >= 1, "postinstall scripts")
    verify(r.credential_reads.length >= 1, "the credential read is on the receipt")
    verify(r.network.length >= 1, "the connection curl opened is on the receipt")
    verify(Model.receiptCommand(r).indexOf("node") === 0, Model.receiptCommand(r))
    verify(Model.receiptSummary(r).length > 0)
    var block = Model.receiptBlock(r)
    verify(block.headline.indexOf(r.cwd) > 0, block.headline)
    verify(block.lines.join("\n").indexOf("postinstall scripts") >= 0, block.lines.join("\n"))

    // The receipt line is not an alert.
    var alertIds = {}
    var list = alerts()
    for (var i = 0; i < list.length; i++) alertIds[list[i].id] = true
    compare(alertIds[r.id], undefined, "a receipt never becomes an alert")

    // ...and it takes its own row in the timeline, interleaved by time.
    var rows = Model.timelineRows(list, receipts, {})
    var receiptRows = 0
    for (var k = 0; k < rows.length; k++) if (rows[k].kind === "receipt") receiptRows++
    compare(receiptRows, 1)
  }

  // The `receipts` socket command answers with the same objects UNWRAPPED.
  // Reading them as if they were log lines produced an empty receipt.
  function test_receipts_socket_response_normalizes_like_the_log() {
    var fromSocket = Model.receiptsFromResponse(suite.receiptsRaw)
    var fromLog = Model.receiptsFromText(suite.alertsText)
    compare(fromSocket.length, fromLog.length)
    for (var i = 0; i < fromSocket.length; i++) {
      compare(fromSocket[i].id, fromLog[i].id)
      compare(fromSocket[i].root_exe, fromLog[i].root_exe)
      compare(fromSocket[i].duration_s, fromLog[i].duration_s)
      compare(fromSocket[i].credential_reads.length, fromLog[i].credential_reads.length)
    }
    // The daemon also renders each receipt itself; the two must describe the
    // same install, or the CLI and the panel disagree in front of the user.
    var rendered = String(JSON.parse(suite.receiptsRaw).rendered[0])
    verify(rendered.indexOf(fromLog[0].cwd) > 0, rendered)
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
      // BASELINE 1/2b put the actor, the context and the rarity in the
      // evidence list too, so the panel's EVIDENCE block explains the score.
      var evidence = e.evidence.join("\n")
      verify(evidence.indexOf("actor: ") >= 0, "actor evidence on " + a.rule)
      verify(evidence.indexOf("context: ") >= 0, "context evidence on " + a.rule)
      verify(evidence.indexOf("rarity: ") >= 0, "rarity evidence on " + a.rule)
    }
  }

  // Every if_expected option the daemon emits must survive normalization
  // (an unrecognized scope string used to be dropped silently, which quietly
  // removed a button), and each must carry both the command and the TOML.
  function test_if_expected_options_survive_normalization() {
    var list = alerts()
    for (var i = 0; i < list.length; i++) {
      var a = list[i]
      var options = Model.ignoreOptions(a)
      verify(options.length >= 2, a.rule + " offers " + options.length + " scopes")
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
    }
  }

  // BASELINE 4's noise-guard alert offers two options that are not allowlist
  // scopes at all: "propose baseline entries for exactly those tuples" and
  // "keep watching". They are the only reason that alert exists. They cannot
  // become Ignore buttons (there is no `--scope keep-watching`), so they are
  // carried separately with the command that performs them.
  function test_the_noise_guards_non_ignore_options_are_carried() {
    var guard = byRule(alerts(), "moat-x-noisy-rule")
    verify(guard !== null)
    var other = Model.otherOptions(guard)
    compare(other.length, 2)
    var byScope = {}
    for (var i = 0; i < other.length; i++) {
      byScope[other[i].scope] = other[i]
      verify(other[i].cmd.length > 0, other[i].scope + " has no command")
      verify(other[i].label.length > 0, other[i].scope + " has no label")
      verify(!Model.isIgnoreScope(other[i].scope),
             other[i].scope + " must not reach the ignore buttons")
    }
    verify(byScope["these-are-expected"] !== undefined, "the baseline proposal option")
    verify(byScope["keep-watching"] !== undefined, "the clear-the-demotion option")
    verify(byScope["these-are-expected"].cmd.indexOf("moatctl baseline") === 0,
           byScope["these-are-expected"].cmd)
    verify(byScope["keep-watching"].cmd.indexOf("moatctl baseline") === 0,
           byScope["keep-watching"].cmd)
    // ...and none of them leaked into the ignore options.
    var ignore = Model.ignoreOptions(guard)
    for (var j = 0; j < ignore.length; j++) verify(Model.isIgnoreScope(ignore[j].scope))
  }

  // CONTRACT 5's explain response is {"ok":true,"alert":{...}} — one level of
  // nesting the merge path has to know about.
  function test_explain_socket_response_merges() {
    var raw = JSON.parse(suite.explainRaw)
    compare(raw.ok, true)
    var id = raw.alert.id
    var target = null
    var list = alerts()
    for (var i = 0; i < list.length; i++) if (list[i].id === id) target = list[i]
    verify(target !== null, "the explain fixture names an alert in the log")
    target.explain = Model.normalizeExplain(null)
    verify(!Model.hasExplain(target))
    Model.mergeExplainResponse(target, suite.explainRaw)
    verify(Model.hasExplain(target), "explain must be recoverable from the socket")
    verify(target.explain.evidence.length >= 3)
  }

  // The userland pkg rules fire on an exec inside a package-manager subtree,
  // so the `what` sentence must read as an exec, not as a secret being read.
  function test_pkg_family_what_describes_an_exec() {
    var pkg = byRule(alerts(), "moat-pkg-subtree-downloader")
    verify(pkg.explain.what.indexOf("install ran") >= 0, pkg.explain.what)
    verify(pkg.explain.what.indexOf("read /usr/bin/curl") < 0,
           "an exec is not a secret read: " + pkg.explain.what)
    verify(pkg.summary.indexOf("touched") < 0, pkg.summary)
    compare(pkg.context, "pkg-install")
  }

  // A net alert carries the destination the panel prints.
  function test_net_alert_carries_the_destination() {
    var net = byRule(alerts(), "moat-net-suspicious-port-egress")
    verify(net.net !== null, "no net block")
    verify(String(net.net.dst_ip).length > 0)
    verify(Number(net.net.dst_port) > 0)
    verify(net.explain.what.indexOf(String(net.net.dst_ip)) >= 0, net.explain.what)
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
    var ssh = byRule(alerts(), "moat-cred-ssh-private-key-read")
    var items = Model.rotateItems(ssh)
    compare(items.length, 1)
    compare(items[0].kind, "ssh-key")
    verify(items[0].guidance.indexOf("ssh-keygen") >= 0)

    // ...and a policy that names four kinds produces four rows, every one of
    // them with specific guidance.
    var cloud = Model.rotateItems(credInInstall())
    verify(cloud.length >= 3, "the cloud policy rotates several kinds")
    for (var i = 0; i < cloud.length; i++) {
      verify(cloud[i].guidance !== Model.rotateGuidance("a-kind-no-policy-uses"),
             "generic guidance for " + cloud[i].kind)
    }
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

  // BASELINE 8's resolved shape: `status` carries proposals[] and
  // demoted_rules[] at the top level PLUS a nested baseline block, and the two
  // have to agree — the panel binds the counts and the list side by side.
  function test_status_carries_the_baseline_block_proposals_and_demotions() {
    var s = Model.normalizeStatus(suite.statusRaw)
    compare(s.baseline.learning, false, "the capture closed the window with `baseline relearn --days 0`")
    verify(!isNaN(Date.parse(s.baseline.learning_ends)), s.baseline.learning_ends)
    compare(s.baseline.learned, 1)
    compare(s.baseline.proposals, s.proposals.length)
    compare(s.proposals.length, 1)
    compare(s.baseline.demoted.length, s.demoted_rules.length)
    compare(s.demoted_rules.length, 1)

    var p = s.proposals[0]
    verify(p.id.length > 0, "a proposal without an id cannot be accepted")
    compare(p.actionable, true)
    verify(p.rule.indexOf("moat-") === 0)
    verify(p.exe.length > 0)
    verify(p.parent.length > 0)
    verify(p.dir.length > 0)
    verify(p.count >= 1)
    verify(p.days >= 1)
    verify(p.toml.indexOf("[[rule]]\n") === 0, "the exact block accepting would write")
    verify(p.toml.indexOf('name = "' + p.rule + '"') > 0)
    verify(Model.proposalDetail(p).indexOf(p.exe) > 0, Model.proposalDetail(p))
    verify(Model.learningSummary(suite.statusRaw, Date.now()).indexOf("proposal") > 0,
           Model.learningSummary(suite.statusRaw, Date.now()))
  }

  // `baseline list` is the same three things over the socket, and the CLI and
  // the panel must not disagree about what is proposed or demoted.
  function test_baseline_list_agrees_with_status() {
    var b = JSON.parse(suite.baselineListRaw)
    var s = Model.normalizeStatus(suite.statusRaw)
    compare(b.ok, true)
    compare(b.learning, s.baseline.learning)
    compare(b.proposals.length, s.proposals.length)
    compare(String(b.proposals[0].id), s.proposals[0].id)
    compare(b.learned.length, s.baseline.learned)
    compare(b.demoted_rules.length, s.demoted_rules.length)
    compare(String(b.demoted_rules[0]), s.demoted_rules[0])
    verify(String(b.baseline_file).indexOf("baseline.toml") > 0, String(b.baseline_file))
    // Every learned entry says what it was and when it was written.
    verify(String(b.learned[0].rule).indexOf("moat-") === 0)
    verify(!isNaN(Date.parse(String(b.learned[0].written))))
  }

  // LEARNING 8 step 1: the export a reviewer reads before shipping a baseline.
  function test_baseline_export_carries_reviewable_tuples() {
    var e = JSON.parse(suite.baselineExportRaw)
    compare(e.ok, true)
    var rows = e.tuples || e.entries || e.export || []
    verify(rows.length > 0, "the export is empty")
    var official = 0
    for (var i = 0; i < rows.length; i++) {
      var t = rows[i]
      verify(String(t.rule).indexOf("moat-") === 0, "rule on row " + i)
      verify(String(t.exe).length > 0, "exe on row " + i)
      verify(["official", "foreign", "user", "unknown"].indexOf(String(t.provenance)) !== -1,
             "provenance on row " + i + ": " + t.provenance)
      verify(["interactive", "pkg-install", "service", "unknown"].indexOf(String(t.context)) !== -1,
             "context on row " + i)
      verify(Model.severityRank(String(t.severity)) >= 0, "severity on row " + i)
      verify(Number(t.count) >= 1, "count on row " + i)
      verify(Number(t.days) >= 1, "days on row " + i)
      if (String(t.provenance) === "official") official++
    }
    verify(official > 0, "LEARNING 8 only ships official tuples; the export must mark them")
  }

  // LEARNING 9: `status` carries the digest switch the settings row binds to,
  // and the {due, text} block the user timer delivers.
  function test_status_carries_the_weekly_digest() {
    var raw = JSON.parse(suite.statusRaw)
    compare(raw.digest, true)
    verify(raw.digest_summary !== undefined, "the digest summary is published in status")
    compare(raw.digest_summary.enabled, true)
    verify(!isNaN(Date.parse(String(raw.digest_summary.due))), String(raw.digest_summary.due))
    verify(String(raw.digest_summary.text).indexOf("moat:") === 0, raw.digest_summary.text)
    // The sentence is the one LEARNING 5 specifies: incidents, installs
    // watched, proposals to review.
    verify(String(raw.digest_summary.text).indexOf("incident") > 0, raw.digest_summary.text)
    verify(String(raw.digest_summary.text).indexOf("install") > 0, raw.digest_summary.text)
    verify(String(raw.digest_summary.text).indexOf("proposal") > 0, raw.digest_summary.text)
    compare(Number(raw.digest_summary.proposals), JSON.parse(suite.statusRaw).proposals.length)
  }

  function test_status_summary_and_widget_state_from_real_status() {
    var s = Model.normalizeStatus(suite.statusRaw)
    var counts = Model.unackedCounts(alerts(), { demotedRules: s.demoted_rules })
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
      compare(fromSocket[i].severity_base, fromLog[i].severity_base)
      compare(fromSocket[i].context, fromLog[i].context)
      compare(fromSocket[i].actor.provenance, fromLog[i].actor.provenance)
      compare(fromSocket[i].rarity, fromLog[i].rarity)
      // list serves the folded alert, so state changes are already applied.
      compare(fromSocket[i].action_taken, fromLog[i].action_taken)
      compare(fromSocket[i].count, fromLog[i].count)
    }
  }

  // ------------------------------------------------------------- allowlist

  // BASELINE 8: the response lists every fragment in allowlist.d with `file`,
  // a per-file `index`, `source` (user | learned | shipped) and `removable`.
  // All four matter: the index alone names three different rules, and a
  // shipped entry carries an index but cannot be removed.
  function test_allowlist_response_renders_all_three_origins() {
    var parsed = Model.parseAllowlist(suite.allowlistRaw)
    compare(parsed.ok, true)
    compare(parsed.error, "")
    // The daemon calls it user_file; the panel's "writes to" label reads .file.
    compare(parsed.file, "/etc/moat/allowlist.d/user.toml")
    compare(parsed.dir, "/etc/moat/allowlist.d")
    verify(parsed.rules.length >= 6, parsed.rules.length + " rules")

    var sections = Model.allowlistSections(parsed.rules)
    compare(sections.user.length, 1)
    compare(sections.learned.length, 1)
    verify(sections.shipped.length >= 4, "omarchy-default.toml is listed")

    var user = sections.user[0]
    compare(user.source, "user")
    compare(user.removable, true)
    compare(user.index, 1)
    compare(user.sourceName, "user.toml")
    compare(user.name, "moat-cred-cloud-credentials-read")
    compare(user.comment.indexOf("added "), 0)
    verify(user.comment.indexOf("wire fixture") > 0, "the ignore comment survives")
    // The daemon's per-rule `file` is the SOURCE fragment and `path` is the
    // rule's file glob; reading `file` as the glob printed the wrong thing.
    compare(user.detail, "exe = /usr/bin/node")
    verify(user.line.indexOf("[[rule]]\n") === 0, "the exact TOML block: " + user.line)

    var learned = sections.learned[0]
    compare(learned.source, "learned")
    compare(learned.learned, true)
    compare(learned.removable, true)
    compare(learned.sourceName, "baseline.toml")
    verify(learned.comment.indexOf("learned ") === 0, learned.comment)
    verify(learned.comment.indexOf("distinct day") > 0, "the counts are in the comment")
    verify(learned.detail.indexOf("file = ") >= 0, "the rule's glob, not its source file")

    // Every shipped entry has an index AND removable:false. Believing the
    // index put a Remove button on a file the daemon refuses to edit.
    for (var i = 0; i < sections.shipped.length; i++) {
      var s = sections.shipped[i]
      compare(s.source, "shipped")
      compare(s.shipped, true)
      compare(s.removable, false, s.name + " is shipped and cannot be removed")
      verify(s.index >= 1, "shipped entries still carry an index: " + s.index)
      compare(s.sourceName, "omarchy-default.toml")
      verify(s.comment.length > 0, "every shipped entry explains itself")
    }

    // The index restarts at 1 in every file, which is why `unignore` needs the
    // file name alongside it.
    compare(sections.user[0].index, sections.learned[0].index)
    verify(sections.user[0].sourceName !== sections.learned[0].sourceName)
  }

  // Service.qml shows the block `ignore` says it wrote, verbatim.
  function test_ignore_response_carries_the_block_it_wrote() {
    var response = JSON.parse(suite.ignoreRaw)
    compare(response.ok, true)
    compare(response.scope, "exe")
    compare(response.acked, true)
    compare(response.file, "/etc/moat/allowlist.d/user.toml")
    var block = String(response.block || response.line || response.rule || "")
    verify(block.indexOf("[[rule]]") > 0, block)
    verify(block.indexOf("# added ") > 0, block)
    var parsed = Model.parseAllowlist(suite.allowlistRaw)
    var user = Model.allowlistSections(parsed.rules).user[0]
    verify(block.indexOf(user.line) > 0,
           "the block written and the block listed must agree")
    // ...and the alert it came from is now acked in the log.
    var list = alerts()
    for (var i = 0; i < list.length; i++) {
      if (list[i].id === String(response.id)) compare(list[i].acked, true)
    }
  }

  // ----------------------------------------------------------------- bundle

  // LEARNING 9: `moatctl bundle <id> --json` answers {"ok":true,"path":...},
  // and that path is the only thing the plugin passes to the agent launcher.
  function test_bundle_response_parses_to_a_path() {
    var parsed = Model.parseBundleResponse(suite.bundleRaw)
    compare(parsed.ok, true)
    compare(parsed.error, "")
    var raw = JSON.parse(suite.bundleRaw)
    compare(parsed.path, String(raw.path))
    verify(parsed.path.indexOf("/var/lib/moat/incidents/") === 0, parsed.path)
    verify(parsed.path.indexOf("/bundle.md") === parsed.path.length - 10, parsed.path)
    // The path names the alert's own incident directory.
    var alert = credInInstall()
    compare(parsed.path, alert.incident.dir + "/bundle.md")
    compare(String(raw.id), alert.id)

    // A daemon that just prints the path still works; anything else is an error
    // rather than a path the panel would hand to an agent.
    compare(Model.parseBundleResponse(parsed.path + "\n").path, parsed.path)
    compare(Model.parseBundleResponse('{"ok":false,"error":"no such alert"}').ok, false)
    compare(Model.parseBundleResponse('{"ok":true,"path":"relative/bundle.md"}').ok, false)
  }

  // The bundle itself is what the user's agent reads. LEARNING 2.3: every
  // string that came out of a process sits inside a DATA fence, because an
  // alert about a malicious postinstall must not become an injection channel.
  function test_the_bundle_fences_process_output_and_links_the_snapshot() {
    verify(suite.bundleMd.length > 0, "fixtures/wire/bundle.md is unreadable")
    verify(suite.bundleMd.indexOf("```DATA") > 0, "no DATA fences in the bundle")
    verify(suite.bundleMd.indexOf("untrusted") > 0, "the preamble names the fences untrusted")
    verify(suite.bundleMd.indexOf("## Incident snapshot") > 0, "the snapshot is linked")
    var alert = credInInstall()
    verify(suite.bundleMd.indexOf(alert.id) > 0, "the bundle names its alert")
    verify(suite.bundleMd.indexOf(alert.rule) > 0, "the bundle names the rule")
    // The argv of the acting process is inside a fence, not loose in prose.
    var fenced = suite.bundleMd.split("```DATA")
    var found = false
    for (var i = 1; i < fenced.length; i++) {
      if (fenced[i].split("```")[0].indexOf(alert.process.args) >= 0) found = true
    }
    verify(found, "the process argv must be inside a DATA fence")
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
