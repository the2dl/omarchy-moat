import QtQuick
import QtTest
import "../SentinelModel.js" as Model

// Unit tests for SentinelModel.js. No shell, no daemon, no /var/lib/sentinel:
// the model is pure functions over plain values precisely so the folding,
// severity and notification rules can be checked here.
//
//   QT_QPA_PLATFORM=offscreen /usr/lib/qt6/bin/qmltestrunner \
//     -input shell/tests/tst_model.qml
TestCase {
  id: suite
  name: "SentinelModel"

  // ------------------------------------------------------------ fixture load

  property string fixtureText: ""

  function readFixture(name) {
    var request = new XMLHttpRequest()
    request.open("GET", Qt.resolvedUrl("fixtures/" + name), false)
    request.send(null)
    return String(request.responseText || "")
  }

  function initTestCase() {
    suite.fixtureText = readFixture("alerts.jsonl")
    verify(suite.fixtureText.length > 0, "fixture alerts.jsonl is empty or unreadable")
  }

  function alertsFromFixture() {
    return Model.foldText(suite.fixtureText)
  }

  function findAlert(alerts, id) {
    for (var i = 0; i < alerts.length; i++) if (alerts[i].id === id) return alerts[i]
    return null
  }

  // --------------------------------------------------------------- severity

  function test_severity_ranks_low_to_critical() {
    compare(Model.severityRank("low"), 0)
    compare(Model.severityRank("medium"), 1)
    compare(Model.severityRank("high"), 2)
    compare(Model.severityRank("critical"), 3)
    // An unrecognized severity ranks below everything so it can never satisfy
    // a threshold and escalate itself into a notification.
    compare(Model.severityRank("catastrophic"), -1)
    compare(Model.severityRank(""), -1)
    compare(Model.severityRank(null), -1)
  }

  function test_severity_threshold() {
    verify(Model.severityAtLeast("critical", "high"))
    verify(Model.severityAtLeast("high", "high"))
    verify(!Model.severityAtLeast("medium", "high"))
    verify(!Model.severityAtLeast("low", "medium"))
    verify(Model.severityAtLeast("low", "low"))
    // Garbage on either side fails closed.
    verify(!Model.severityAtLeast("bogus", "low"))
    verify(!Model.severityAtLeast("medium", "bogus"))   // bogus threshold -> high
  }

  function test_notify_urgency() {
    compare(Model.notifyUrgency("critical"), "critical")
    compare(Model.notifyUrgency("high"), "normal")
    compare(Model.notifyUrgency("medium"), "normal")
    compare(Model.notifyUrgency("low"), "low")
  }

  function test_widget_state() {
    // Grey outranks the counts: stale numbers must not read as green.
    compare(Model.widgetState({ available: false, groupOk: true, daemonOk: true, unacked: {} }), "grey")
    compare(Model.widgetState({ available: true, groupOk: false, daemonOk: true, unacked: {} }), "grey")
    compare(Model.widgetState({ available: true, groupOk: true, daemonOk: false, unacked: {} }), "grey")
    compare(Model.widgetState({ available: true, groupOk: true, daemonOk: true, unacked: {} }), "green")
    compare(Model.widgetState({ available: true, groupOk: true, daemonOk: true,
                                unacked: { medium: 3 } }), "amber")
    compare(Model.widgetState({ available: true, groupOk: true, daemonOk: true,
                                unacked: { medium: 3, high: 1 } }), "red")
    compare(Model.widgetState({ available: true, groupOk: true, daemonOk: true,
                                unacked: { critical: 1 } }), "red")
  }

  // ---------------------------------------------------------------- folding

  function test_fixture_folds_to_distinct_alerts() {
    var alerts = alertsFromFixture()
    // 13 base records + 5 update lines in the fixture; updates must fold, not
    // materialize alerts of their own.
    compare(alerts.length, 13)
    for (var i = 0; i < alerts.length; i++) verify(alerts[i].title.length > 0)
  }

  function test_updates_fold_by_id() {
    var alerts = alertsFromFixture()

    // A plain ack update.
    var tmpBuild = findAlert(alerts, "01J8ZK6B4Q3M7N9P2R5S8T1V40")
    verify(tmpBuild !== null)
    compare(tmpBuild.acked, true)

    // An action result: the reverse shell was killed from the panel.
    var reverseShell = findAlert(alerts, "01J8ZK6B4Q3M7N9P2R5S8T1V45")
    verify(reverseShell !== null)
    compare(reverseShell.acked, true)
    compare(reverseShell.action_taken, "killed")

    // The dedupe count update from CONTRACT 6.3.
    var egress = findAlert(alerts, "01J8ZK6B4Q3M7N9P2R5S8T1V4B")
    verify(egress !== null)
    compare(egress.count, 4)

    // Later updates win over earlier ones for the same key.
    var sshKey = findAlert(alerts, "01J8ZK6B4Q3M7N9P2R5S8T1V42")
    verify(sshKey !== null)
    compare(sshKey.acked, false)
    // An update may not rewrite what the sensor saw.
    compare(sshKey.severity, "high")
    compare(sshKey.rule, "sentinel-cred-ssh-private-key-read")
  }

  function test_update_before_base_is_parked_then_applied() {
    var text = [
      JSON.stringify({ v: 1, id: "B", update: { acked: true, action_taken: "quarantined" } }),
      JSON.stringify({ v: 1, id: "A", severity: "low", title: "First", ts: "2026-09-03T10:00:00Z" }),
      JSON.stringify({ v: 1, id: "B", severity: "high", title: "Second", ts: "2026-09-03T11:00:00Z" })
    ].join("\n")

    var alerts = Model.foldText(text)
    compare(alerts.length, 2)
    var b = findAlert(alerts, "B")
    compare(b.acked, true)
    compare(b.action_taken, "quarantined")
  }

  function test_orphan_update_never_becomes_an_alert() {
    var text = JSON.stringify({ v: 1, id: "GHOST", update: { acked: true } })
    compare(Model.foldText(text).length, 0)
  }

  function test_torn_line_is_skipped_not_fatal() {
    var text = [
      JSON.stringify({ v: 1, id: "A", severity: "low", title: "Good", ts: "2026-09-03T10:00:00Z" }),
      '{"v":1,"id":"B","severity":"hi',
      "",
      JSON.stringify({ v: 1, id: "C", severity: "high", title: "Also good", ts: "2026-09-03T12:00:00Z" })
    ].join("\n")

    var alerts = Model.foldText(text)
    compare(alerts.length, 2)
    compare(alerts[0].id, "C")
  }

  function test_newest_first_by_ulid() {
    var alerts = alertsFromFixture()
    for (var i = 1; i < alerts.length; i++) {
      verify(alerts[i - 1].id > alerts[i].id,
             "alert " + (i - 1) + " (" + alerts[i - 1].id + ") should sort before " + alerts[i].id)
    }
  }

  // ----------------------------------------------------------------- counts

  function test_unacked_counts() {
    var counts = Model.unackedCounts(alertsFromFixture())
    // Fixture: 13 alerts, of which V40 (low) and V45 (critical) are acked by
    // update lines. V42 is acked and then un-acked, so it counts.
    compare(counts.critical, 2)   // V46, V49; V45 is acked
    compare(counts.high, 5)       // V42, V43, V47, V48, V4A
    compare(counts.medium, 3)     // V41, V44, V4B
    compare(counts.low, 1)        // V4C; V40 is acked
    compare(counts.total, 11)
    compare(Model.badgeCount(counts), 7)
  }

  function test_unacked_ignores_unknown_severity() {
    var alerts = [{ id: "A", severity: "spicy", acked: false },
                  { id: "B", severity: "high", acked: false }]
    var counts = Model.unackedCounts(alerts)
    compare(counts.total, 1)
    compare(counts.high, 1)
  }

  // ---------------------------------------------- store, priming, rotation

  function test_no_notify_on_initial_load() {
    var store = Model.createStore()
    var result = Model.ingestText(store, suite.fixtureText)

    compare(result.initialLoad, true)
    compare(result.newIds.length, 0, "alerts present at startup are history, not events")
    compare(result.reloaded, false)
    compare(result.alerts.length, 13)

    // shouldNotify must independently refuse on the initial load, so a caller
    // that ignores newIds still cannot toast a backlog.
    var critical = findAlert(result.alerts, "01J8ZK6B4Q3M7N9P2R5S8T1V46")
    verify(critical !== null)
    verify(!Model.shouldNotify(critical, "low", true))
    verify(Model.shouldNotify(critical, "low", false))
  }

  function test_new_alert_after_priming_notifies() {
    var store = Model.createStore()
    Model.ingestText(store, suite.fixtureText)

    var appended = suite.fixtureText + JSON.stringify({
      v: 1, id: "01J8ZK6B4Q3M7N9P2R5S8T1V4Z", ts: "2026-09-03T17:00:00.000Z",
      severity: "critical", rule: "sentinel-shell-reverse-shell", family: "shell",
      title: "Fresh reverse shell", summary: "new", actions: ["kill"]
    }) + "\n"

    var result = Model.ingestText(store, appended)
    compare(result.initialLoad, false)
    compare(result.newIds.length, 1)
    compare(result.newIds[0], "01J8ZK6B4Q3M7N9P2R5S8T1V4Z")

    // Ingesting the same text again yields nothing new.
    var again = Model.ingestText(store, appended)
    compare(again.newIds.length, 0)
  }

  function test_new_ids_are_oldest_first() {
    var store = Model.createStore()
    Model.ingestText(store, "")

    var text = [
      JSON.stringify({ v: 1, id: "A", severity: "high", title: "one", ts: "2026-09-03T10:00:00Z" }),
      JSON.stringify({ v: 1, id: "B", severity: "high", title: "two", ts: "2026-09-03T11:00:00Z" }),
      JSON.stringify({ v: 1, id: "C", severity: "high", title: "three", ts: "2026-09-03T12:00:00Z" })
    ].join("\n") + "\n"

    var result = Model.ingestText(store, text)
    compare(result.newIds, ["A", "B", "C"], "a burst should notify in the order it happened")
  }

  function test_rotation_reload() {
    var store = Model.createStore()
    var first = Model.ingestText(store, suite.fixtureText)
    compare(first.reloaded, false)

    // sentineld renamed alerts.jsonl to alerts.1.jsonl and opened a fresh file.
    // The new file is shorter, which is the only rotation signal a whole-file
    // reader gets.
    var rotated = JSON.stringify({
      v: 1, id: "01J8ZK6B4Q3M7N9P2R5S8T1W00", ts: "2026-09-03T18:00:00.000Z",
      severity: "medium", rule: "sentinel-net-suspicious-egress", family: "net",
      title: "After rotation", summary: "post-rotation alert", actions: ["ignore"]
    }) + "\n"

    var result = Model.ingestText(store, rotated)
    compare(result.reloaded, true)
    compare(result.alerts.length, 1, "the fold must come from the new file only")
    compare(result.alerts[0].id, "01J8ZK6B4Q3M7N9P2R5S8T1W00")
    compare(result.newIds.length, 1)

    // Growing again from the rotated file is not a rotation.
    var grown = rotated + JSON.stringify({
      v: 1, id: "01J8ZK6B4Q3M7N9P2R5S8T1W01", ts: "2026-09-03T18:01:00.000Z",
      severity: "low", rule: "sentinel-exec-new-binary-home", family: "exec",
      title: "Later", summary: "", actions: []
    }) + "\n"
    var after = Model.ingestText(store, grown)
    compare(after.reloaded, false)
    compare(after.alerts.length, 2)
    compare(after.newIds.length, 1)
  }

  function test_rotation_does_not_replay_rotated_out_alerts() {
    var store = Model.createStore()
    Model.ingestText(store, suite.fixtureText)

    // A truncation that leaves one of the alerts we already saw. It is shorter,
    // so it reads as a rotation — but the id is not new and must not notify.
    var oneLine = suite.fixtureText.split("\n")[0] + "\n"
    var result = Model.ingestText(store, oneLine)
    compare(result.reloaded, true)
    compare(result.newIds.length, 0)
  }

  function test_should_notify_respects_threshold_and_ack() {
    var alerts = alertsFromFixture()
    var medium = findAlert(alerts, "01J8ZK6B4Q3M7N9P2R5S8T1V41")
    var high = findAlert(alerts, "01J8ZK6B4Q3M7N9P2R5S8T1V42")
    var ackedCritical = findAlert(alerts, "01J8ZK6B4Q3M7N9P2R5S8T1V45")

    verify(!Model.shouldNotify(medium, "high", false))
    verify(Model.shouldNotify(medium, "medium", false))
    verify(Model.shouldNotify(high, "high", false))
    verify(!Model.shouldNotify(ackedCritical, "low", false), "an acked alert is already handled")
    verify(!Model.shouldNotify(null, "low", false))
  }

  // ---------------------------------------------------------------- explain

  function test_explain_block_is_normalized() {
    var alert = findAlert(alertsFromFixture(), "01J8ZK6B4Q3M7N9P2R5S8T1V42")
    verify(Model.hasExplain(alert))
    compare(alert.explain.what, "node read your private SSH key.")
    compare(alert.explain.evidence.length, 4)
    compare(alert.explain.next.length, 2)
    verify(alert.explain.expected.length > 0)
    compare(alert.explain.if_expected.file, "/etc/sentinel/allowlist.d/user.toml")
  }

  function test_alert_without_explain_still_normalizes() {
    var alerts = Model.foldText(JSON.stringify({
      v: 1, id: "A", severity: "high", title: "No explain", ts: "2026-09-03T10:00:00Z"
    }))
    compare(alerts.length, 1)
    verify(!Model.hasExplain(alerts[0]))
    compare(alerts[0].explain.evidence.length, 0)
    compare(alerts[0].explain.if_expected.options.length, 0)
    compare(Model.ignoreOptions(alerts[0]).length, 0)
  }

  function test_ignore_options_put_the_recommended_scope_first() {
    var alert = findAlert(alertsFromFixture(), "01J8ZK6B4Q3M7N9P2R5S8T1V42")
    var options = Model.ignoreOptions(alert)
    compare(options.length, 4)
    compare(options[0].scope, "exe", "if_expected.hint names exe")
    compare(options[0].recommended, true)
    verify(options[0].line.indexOf("[[rule]]") === 0)
    verify(options[0].cmd.indexOf("--scope exe") > 0)
    for (var i = 1; i < options.length; i++) compare(options[i].recommended, false)
  }

  function test_ignore_options_fall_back_to_the_narrowest_scope() {
    // No hint: the recommendation must not default to "rule", which would
    // silence the detection everywhere.
    var alert = Model.foldText(JSON.stringify({
      v: 1, id: "A", severity: "high", title: "t", ts: "2026-09-03T10:00:00Z",
      explain: {
        if_expected: {
          options: [{ scope: "rule", cmd: "c", line: "l" },
                    { scope: "parent", cmd: "c", line: "l" },
                    { scope: "exe", cmd: "c", line: "l" }]
        }
      }
    }))[0]

    var options = Model.ignoreOptions(alert)
    compare(options[0].scope, "exe")
    compare(options[0].recommended, true)
    compare(options[1].scope, "parent")
    compare(options[2].scope, "rule")
  }

  function test_ignore_options_drop_unknown_scopes_and_duplicates() {
    var alert = Model.foldText(JSON.stringify({
      v: 1, id: "A", severity: "high", title: "t", ts: "2026-09-03T10:00:00Z",
      explain: {
        if_expected: {
          hint: "exe",
          options: [{ scope: "exe", cmd: "a", line: "a" },
                    { scope: "exe", cmd: "b", line: "b" },
                    { scope: "everything", cmd: "c", line: "c" }]
        }
      }
    }))[0]
    var options = Model.ignoreOptions(alert)
    compare(options.length, 1)
    compare(options[0].cmd, "a")
  }

  function test_ignore_scope_normalization_narrows_not_widens() {
    compare(Model.normalizeIgnoreScope("exe"), "exe")
    compare(Model.normalizeIgnoreScope("exe+file"), "exe+file")
    compare(Model.normalizeIgnoreScope("parent"), "parent")
    compare(Model.normalizeIgnoreScope("rule"), "rule")
    compare(Model.normalizeIgnoreScope("RULE"), "rule")
    compare(Model.normalizeIgnoreScope("everything"), "exe")
    compare(Model.normalizeIgnoreScope(""), "exe")
    compare(Model.normalizeIgnoreScope(null), "exe")
  }

  function test_alerts_with_no_ignore_path_offer_none() {
    // The reverse shell and the rootkit have no expected version, so the
    // fixture gives them no options and the panel renders no ignore buttons.
    var alerts = alertsFromFixture()
    compare(Model.ignoreOptions(findAlert(alerts, "01J8ZK6B4Q3M7N9P2R5S8T1V45")).length, 0)
    compare(Model.ignoreOptions(findAlert(alerts, "01J8ZK6B4Q3M7N9P2R5S8T1V49")).length, 0)
  }

  // -------------------------------------------------------------- allowlist

  function test_parse_allowlist_keeps_daemon_indices() {
    var parsed = Model.parseAllowlist(JSON.stringify({
      ok: true,
      file: "/etc/sentinel/allowlist.d/user.toml",
      rules: [
        { index: 0, name: "sentinel-cred-ssh-private-key-read", scope: "exe",
          comment: "# added 2026-09-01 from alert 01J8...: Private SSH key read",
          exe: "/usr/bin/git" },
        { index: 3, name: "sentinel-x-mass-read", scope: "rule", comment: "" }
      ]
    }))

    compare(parsed.ok, true)
    compare(parsed.rules.length, 2)
    compare(parsed.rules[0].index, 0)
    // The gap is the daemon's; renumbering would make unignore remove the
    // wrong block.
    compare(parsed.rules[1].index, 3)
    compare(parsed.rules[0].detail, "exe = /usr/bin/git")
    compare(parsed.rules[1].scope, "rule")
  }

  function test_parse_allowlist_survives_garbage() {
    var parsed = Model.parseAllowlist("not json at all")
    compare(parsed.ok, false)
    compare(parsed.rules.length, 0)
  }

  function test_merge_explain_response_only_touches_explain() {
    var alert = Model.foldText(JSON.stringify({
      v: 1, id: "A", severity: "high", title: "Original", ts: "2026-09-03T10:00:00Z"
    }))[0]

    Model.mergeExplainResponse(alert, JSON.stringify({
      ok: true,
      id: "A",
      severity: "low",
      title: "Rewritten by the response",
      explain: { what: "filled in", evidence: ["one"] }
    }))

    compare(alert.title, "Original", "the log line is what the sensor saw")
    compare(alert.severity, "high")
    compare(alert.explain.what, "filled in")
    compare(alert.explain.evidence.length, 1)
  }

  // --------------------------------------------------------------- guidance

  function test_rotate_guidance_is_specific_where_it_can_be() {
    verify(Model.rotateGuidance("ssh-key").indexOf("ssh-keygen") >= 0)
    verify(Model.rotateGuidance("github-token").indexOf("github.com/settings/tokens") >= 0)
    verify(Model.rotateGuidance("npm-token").indexOf("npmjs.com") >= 0)
    verify(Model.rotateGuidance("aws").indexOf("IAM") >= 0)
    verify(Model.rotateGuidance("gh").indexOf("gh auth") >= 0)
    verify(Model.rotateGuidance("claude").indexOf("Claude") >= 0)
    // An unknown kind still says something actionable rather than nothing.
    verify(Model.rotateGuidance("some-new-thing").length > 0)
    compare(Model.rotateGuidance(""), "")
  }

  function test_rotate_items_from_alert() {
    var alert = findAlert(alertsFromFixture(), "01J8ZK6B4Q3M7N9P2R5S8T1V4A")
    var items = Model.rotateItems(alert)
    compare(items.length, 3)
    compare(items[0].kind, "gh")
    verify(items[0].guidance.length > 0)
  }

  // -------------------------------------------------------------- formatting

  function test_basename() {
    compare(Model.basename("/usr/bin/node"), "node")
    compare(Model.basename("node"), "node")
    compare(Model.basename(""), "")
    compare(Model.basename("/"), "")
  }

  function test_ancestry_chain_reads_oldest_first() {
    var alert = findAlert(alertsFromFixture(), "01J8ZK6B4Q3M7N9P2R5S8T1V42")
    compare(Model.ancestryChain(alert), "npm → sh → node")
  }

  function test_relative_time() {
    var base = Date.parse("2026-09-03T12:00:00Z")
    compare(Model.relativeTime("2026-09-03T12:00:00Z", base), "now")
    compare(Model.relativeTime("2026-09-03T11:55:00Z", base), "5m ago")
    compare(Model.relativeTime("2026-09-03T09:00:00Z", base), "3h ago")
    compare(Model.relativeTime("2026-08-31T12:00:00Z", base), "3d ago")
    compare(Model.relativeTime("", base), "")
    compare(Model.relativeTime("not a date", base), "")
    // A clock skew that puts an alert in the future reads as now, not as a
    // negative age.
    compare(Model.relativeTime("2026-09-03T12:05:00Z", base), "now")
  }

  // ----------------------------------------------------------------- status

  function test_normalize_status_degrades_honestly() {
    var missing = Model.normalizeStatus(null)
    compare(missing.ok, false)
    compare(missing.mode, "unknown")
    compare(missing.tetragon, "unknown")
    compare(missing.policies, 0)
    compare(missing.sandbox, false)

    var real = Model.normalizeStatus(JSON.stringify({
      ok: true, version: "0.1.0", mode: "monitor", tetragon: "running", policies: 17,
      policies_failed: [], feeds: { updated: "2026-09-03T11:00:00Z", hashes: 123456, domains: 5432 },
      unacked: { critical: 0, high: 2, medium: 5, low: 11 }, sandbox: false, group_ok: true
    }))
    compare(real.ok, true)
    compare(real.mode, "monitor")
    compare(real.policies, 17)
    compare(real.feeds.hashes, 123456)
    compare(real.group_ok, true)
  }

  function test_status_summary() {
    var status = Model.normalizeStatus(JSON.stringify({
      ok: true, mode: "monitor", tetragon: "running", policies: 17,
      feeds: { updated: "2026-09-03T11:00:00Z" }, group_ok: true
    }))
    var summary = Model.statusSummary(status, { total: 9 }, Date.parse("2026-09-03T12:00:00Z"))
    compare(summary, "Sentinel: mode monitor, tetragon running, 17 policies, feeds 1h ago, 9 unacked")
    compare(Model.statusSummary(null, {}, 0), "Sentinel: daemon not reachable")
  }

  function test_normalize_mode() {
    compare(Model.normalizeMode("enforce"), "enforce")
    compare(Model.normalizeMode("ENFORCE"), "enforce")
    compare(Model.normalizeMode("monitor"), "monitor")
    compare(Model.normalizeMode("nonsense"), "monitor")
  }

  // ------------------------------------------------------------------ setup

  function test_setup_steps() {
    var both = Model.setupSteps(true, true)
    compare(both.length, 4)
    verify(both[0].command.indexOf("makepkg -si") >= 0)
    verify(both[1].command.indexOf("systemctl enable --now tetragon sentineld sentinel-feeds.timer") >= 0)
    verify(both[2].command.indexOf("usermod -aG sentinel $USER") >= 0)

    compare(Model.setupSteps(false, true).length, 2)
    compare(Model.setupSteps(false, false).length, 0)
  }
}
