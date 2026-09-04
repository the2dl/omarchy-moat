import QtQuick
import QtTest
import "../MoatModel.js" as Model

// Unit tests for MoatModel.js. No shell, no daemon, no /var/lib/moat:
// the model is pure functions over plain values precisely so the folding,
// severity and notification rules can be checked here.
//
//   QT_QPA_PLATFORM=offscreen /usr/lib/qt6/bin/qmltestrunner \
//     -input shell/tests/tst_model.qml
TestCase {
  id: suite
  name: "MoatModel"

  // ------------------------------------------------------------ fixture load

  property string fixtureText: ""
  property string statusText: ""

  // The rule the fixture's status.json reports as demoted (BASELINE 4), and the
  // options object every surfacing call takes.
  readonly property string demotedRule: "moat-persist-hypr-config-write"
  readonly property var demoted: ({ demotedRules: [suite.demotedRule] })

  function readFixture(name) {
    var request = new XMLHttpRequest()
    request.open("GET", Qt.resolvedUrl("fixtures/" + name), false)
    request.send(null)
    return String(request.responseText || "")
  }

  function initTestCase() {
    suite.fixtureText = readFixture("alerts.jsonl")
    verify(suite.fixtureText.length > 0, "fixture alerts.jsonl is empty or unreadable")
    suite.statusText = readFixture("status.json")
    verify(suite.statusText.length > 0, "fixture status.json is empty or unreadable")
  }

  function alertsFromFixture() {
    return Model.foldText(suite.fixtureText)
  }

  function statusFromFixture() {
    return Model.normalizeStatus(suite.statusText)
  }

  function findGroup(groups, rule, exe) {
    for (var i = 0; i < groups.length; i++)
      if (groups[i].rule === rule && groups[i].exe === exe) return groups[i]
    return null
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

    // A sensor that is not loaded is red even when every counter is zero.
    // This is the 2026-09-03 outage: Tetragon crash-looped for 25 minutes with
    // no policies in the kernel, and a quiet machine would have shown green
    // over no protection at all. Quiet from a dead sensor is not good news.
    compare(Model.widgetState({ available: true, groupOk: true, daemonOk: true,
                                sensorUnhealthy: true, unacked: {} }), "red")
    compare(Model.widgetState({ available: true, groupOk: true, daemonOk: true,
                                sensorUnhealthy: true,
                                unacked: { medium: 3 } }), "red")
    // "cannot tell" is not "dead": absent or false must not force red.
    compare(Model.widgetState({ available: true, groupOk: true, daemonOk: true,
                                sensorUnhealthy: false, unacked: {} }), "green")
  }

  // ---------------------------------------------------------------- folding

  function test_fixture_folds_to_distinct_alerts() {
    var alerts = alertsFromFixture()
    // 21 base records + 5 update lines + 2 receipt lines in the fixture.
    // Updates must fold rather than materialize alerts of their own, and a
    // receipt must not become an alert at all.
    compare(alerts.length, 21)
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
    compare(sshKey.rule, "moat-cred-ssh-private-key-read")
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
    // With no demoted-rule list (an older daemon, or the status poll not back
    // yet) the three moat-persist-hypr-config-write alerts count normally.
    var counts = Model.unackedCounts(alertsFromFixture())
    // Fixture: 21 alerts, of which V40 (low) and V45 (critical) are acked by
    // update lines. V42 is acked and then un-acked, so it counts. V4F is
    // suppressed and is never counted, with or without the demoted list. The
    // two receipt lines are not alerts and never reach these counts at all.
    compare(counts.critical, 3)   // V46, V49, V4E; V45 is acked
    compare(counts.high, 9)       // V42, V43, V47, V48, V4A, V4G, V4H, V4J, V4M
    compare(counts.medium, 5)     // V41, V44, V4B, V4D, V4K
    compare(counts.low, 1)        // V4C; V40 is acked, V4F is suppressed
    compare(counts.total, 18)
    compare(Model.badgeCount(counts), 12)
  }

  // BASELINE 4 and 5: a demoted rule is "still logged, never notifies, not
  // counted in the badge". The three high alerts of the demoted rule therefore
  // leave the counts entirely once the daemon reports the demotion.
  function test_unacked_counts_drop_demoted_and_suppressed() {
    var counts = Model.unackedCounts(alertsFromFixture(), suite.demoted)
    compare(counts.critical, 3)
    compare(counts.high, 6, "the demoted rule's three high alerts stop counting")
    compare(counts.medium, 5)
    compare(counts.low, 1)
    compare(counts.total, 15)
    compare(counts.badge, 9)
    compare(Model.badgeCount(counts), 9)
  }

  // The badge is the number on the shield, and it must mean exactly "alerts on
  // the Alerts surface still waiting for a decision".
  function test_badge_counts_only_the_alerts_surface() {
    var alerts = alertsFromFixture()
    var counts = Model.unackedCounts(alerts, suite.demoted)
    var surface = Model.surfaceAlerts(alerts, "alerts", suite.demoted)

    var unackedOnSurface = 0
    for (var i = 0; i < surface.length; i++) if (!surface[i].acked) unackedOnSurface++
    compare(Model.badgeCount(counts), unackedOnSurface,
            "the badge and the Alerts tab must agree on what is waiting")

    // The daemon's own status.unacked carries no `badge` field; falling back to
    // critical+high is what keeps the shield honest when the log is unreadable.
    compare(Model.badgeCount({ critical: 1, high: 2, medium: 9 }), 3)
    compare(Model.badgeCount(null), 0)
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
    compare(result.alerts.length, 21)

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
      severity: "critical", rule: "moat-shell-reverse-shell", family: "shell",
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

    // moatd renamed alerts.jsonl to alerts.1.jsonl and opened a fresh file.
    // The new file is shorter, which is the only rotation signal a whole-file
    // reader gets.
    var rotated = JSON.stringify({
      v: 1, id: "01J8ZK6B4Q3M7N9P2R5S8T1W00", ts: "2026-09-03T18:00:00.000Z",
      severity: "medium", rule: "moat-net-suspicious-egress", family: "net",
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
      severity: "low", rule: "moat-exec-new-binary-home", family: "exec",
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

  // ------------------------------------------------- baseline: record fields
  //
  // BASELINE 8 extends the alert record. Every one of these fields is absent
  // from a log an older moatd wrote, so the defaults are load-bearing.

  function test_baseline_fields_default_safely_when_absent() {
    var alert = findAlert(alertsFromFixture(), "01J8ZK6B4Q3M7N9P2R5S8T1V42")
    compare(alert.actor.provenance, "unknown")
    compare(alert.actor.package, "")
    compare(alert.actor.script, "")
    compare(alert.context, "unknown")
    // No severity_base means nothing adjusted the severity, so base == shipped
    // and the panel's "high → medium" line stays empty.
    compare(alert.severity_base, "high")
    compare(alert.severity_reason, "")
    compare(alert.suppressed_by, "")
    compare(Model.severityChangeLine(alert), "")
    compare(alert.visible, true)
  }

  function test_actor_and_context_are_parsed_and_validated() {
    var alerts = alertsFromFixture()
    var interactive = findAlert(alerts, "01J8ZK6B4Q3M7N9P2R5S8T1V4D")
    compare(interactive.context, "interactive")
    compare(interactive.actor.provenance, "user")
    compare(interactive.actor.script, "/home/dan/Projects/infra/deploy.mjs")
    // BASELINE 8 writes `"script": null` for a non-interpreter actor.
    var demotedAlert = findAlert(alerts, "01J8ZK6B4Q3M7N9P2R5S8T1V4G")
    compare(demotedAlert.actor.script, "")
    compare(demotedAlert.actor.package, "hyprland 0.53-1")
    compare(Model.actorLine(demotedAlert),
            "context: service · actor: official (package hyprland 0.53-1)")

    // A provenance class nobody defined must not be trusted into "official",
    // and an unknown context must not be trusted into "interactive" (which is
    // the one that buys a two-step downgrade).
    var odd = Model.foldText(JSON.stringify({
      v: 1, id: "A", severity: "high", title: "t", ts: "2026-09-03T10:00:00Z",
      actor: { provenance: "trusted" }, context: "shell", severity_base: "apocalyptic"
    }))[0]
    compare(odd.actor.provenance, "unknown")
    compare(odd.context, "unknown")
    compare(odd.severity_base, "high", "an unparseable base falls back to the shipped severity")
  }

  function test_severity_change_line_reads_as_a_sentence() {
    var alerts = alertsFromFixture()
    compare(Model.severityChangeLine(findAlert(alerts, "01J8ZK6B4Q3M7N9P2R5S8T1V4D")),
            "severity high → medium: interactive session, script under ~/Projects/infra")
    var upgraded = findAlert(alerts, "01J8ZK6B4Q3M7N9P2R5S8T1V4E")
    verify(Model.severityChangeLine(upgraded).indexOf("severity high → critical:") === 0,
           Model.severityChangeLine(upgraded))
  }

  function test_suppressed_line_names_what_hid_the_alert() {
    var suppressed = findAlert(alertsFromFixture(), "01J8ZK6B4Q3M7N9P2R5S8T1V4F")
    compare(suppressed.suppressed_by, "baseline.toml#3")
    compare(Model.suppressedLine(suppressed), "suppressed by baseline.toml#3")
    // The noise guard's marker is not an allowlist line and must not read as one.
    compare(Model.suppressedLine({ suppressed_by: "demoted:moat-x-mass-read" }),
            "demoted rule moat-x-mass-read")
    compare(Model.suppressedLine({ suppressed_by: "" }), "")
  }

  // --------------------------------------------------------- surface selection

  function test_surface_follows_severity() {
    var alerts = Model.decorateAlerts(alertsFromFixture(), suite.demoted)
    // BASELINE 5: critical and high on the Alerts tab...
    compare(findAlert(alerts, "01J8ZK6B4Q3M7N9P2R5S8T1V46").surface, "alerts")   // critical
    compare(findAlert(alerts, "01J8ZK6B4Q3M7N9P2R5S8T1V42").surface, "alerts")   // high
    // ...medium and low on the Timeline.
    compare(findAlert(alerts, "01J8ZK6B4Q3M7N9P2R5S8T1V41").surface, "timeline") // medium
    compare(findAlert(alerts, "01J8ZK6B4Q3M7N9P2R5S8T1V4C").surface, "timeline") // low
  }

  function test_demoted_rule_goes_to_the_timeline_regardless_of_severity() {
    var alerts = Model.decorateAlerts(alertsFromFixture(), suite.demoted)
    var demotedAlert = findAlert(alerts, "01J8ZK6B4Q3M7N9P2R5S8T1V4G")
    compare(demotedAlert.severity, "high")
    compare(demotedAlert.demoted, true)
    compare(demotedAlert.surface, "timeline",
            "BASELINE 4: a demoted rule's alerts are timeline, whatever the severity")
    compare(demotedAlert.visible, true, "demoted is quiet, not hidden")

    // Without the demotion the same alert is an Alerts-tab alert, which is what
    // makes the demotion reversible from the daemon side alone.
    var undemoted = Model.decorateAlerts(alertsFromFixture(), {})
    compare(findAlert(undemoted, "01J8ZK6B4Q3M7N9P2R5S8T1V4G").surface, "alerts")
  }

  function test_suppressed_alerts_are_hidden_until_asked_for() {
    var hidden = Model.decorateAlerts(alertsFromFixture(), suite.demoted)
    var suppressed = findAlert(hidden, "01J8ZK6B4Q3M7N9P2R5S8T1V4F")
    compare(suppressed.visible, false)
    compare(suppressed.surface, "timeline")

    var shown = Model.decorateAlerts(alertsFromFixture(),
      { demotedRules: [suite.demotedRule], showSuppressed: true })
    compare(findAlert(shown, "01J8ZK6B4Q3M7N9P2R5S8T1V4F").visible, true)

    // Even when shown it stays on the timeline: a suppressed alert never
    // becomes something the Alerts tab is asking about.
    var suppressedHigh = Model.decorateAlerts(Model.foldText(JSON.stringify({
      v: 1, id: "A", severity: "critical", title: "t", ts: "2026-09-03T10:00:00Z",
      suppressed_by: "user.toml#1"
    })), { showSuppressed: true })[0]
    compare(suppressedHigh.surface, "timeline")
    compare(suppressedHigh.visible, true)
  }

  // BASELINE 8 allows suppressed_by = "demoted:<rule>", and BASELINE 5 puts a
  // demoted rule's alerts in the timeline, grouped. Hiding them would erase the
  // very thing the noise guard wants the user to be able to go and look at.
  function test_a_demotion_marker_is_quiet_not_hidden() {
    var alert = Model.decorateAlerts(Model.foldText(JSON.stringify({
      v: 1, id: "A", severity: "high", rule: "moat-x-mass-read", title: "t",
      ts: "2026-09-03T10:00:00Z", suppressed_by: "demoted:moat-x-mass-read"
    })), {})[0]
    compare(alert.demoted, true, "the marker alone marks it demoted")
    compare(alert.surface, "timeline")
    compare(alert.visible, true, "visible with show-suppressed off")
    verify(!Model.shouldNotify(alert, "low", false), "and still silent")

    var groups = Model.timelineGroups([alert], {})
    compare(groups.length, 1)
    compare(groups[0].suppressed, false, "a demoted row is not greyed out as suppressed")
    compare(groups[0].demoted, true)
  }

  function test_alerts_surface_puts_unacked_first_then_newest() {
    var surface = Model.surfaceAlerts(alertsFromFixture(), "alerts", suite.demoted)
    compare(surface.length, 10)
    // V45 is the only acked alert on this surface, so it sorts last even though
    // its id is newer than several unacked ones.
    compare(surface[surface.length - 1].id, "01J8ZK6B4Q3M7N9P2R5S8T1V45")
    var seenAcked = false
    for (var i = 0; i < surface.length; i++) {
      verify(Model.severityAtLeast(surface[i].severity, "high"), surface[i].severity)
      verify(!surface[i].suppressed_by)
      verify(!surface[i].demoted)
      if (surface[i].acked) seenAcked = true
      else verify(!seenAcked, "an unacked alert must not sort after an acked one")
    }
    for (var j = 1; j < surface.length; j++) {
      if (surface[j - 1].acked === surface[j].acked)
        verify(surface[j - 1].id > surface[j].id, "newest first within each half")
    }
  }

  // ------------------------------------------------------- timeline grouping

  function test_timeline_groups_by_rule_and_actor_exe() {
    var groups = Model.timelineGroups(alertsFromFixture(), suite.demoted)
    compare(groups.length, 9)

    // The two hyprctl writes of the demoted rule collapse into one row; the
    // count is the sum of their dedupe counts (1 + 3), not the row count.
    var hyprctl = findGroup(groups, suite.demotedRule, "/usr/bin/hyprctl")
    verify(hyprctl !== null, "the two hyprctl alerts share a group")
    compare(hyprctl.alerts.length, 2)
    compare(hyprctl.count, 4)
    compare(hyprctl.severity, "high")
    compare(hyprctl.demoted, true)
    compare(hyprctl.suppressed, false)
    compare(hyprctl.latestId, "01J8ZK6B4Q3M7N9P2R5S8T1V4H", "the group carries the latest time")
    compare(hyprctl.exeName, "hyprctl")

    // Same rule, different actor exe: a separate row, which is the whole point
    // of grouping by the pair rather than by the rule.
    var other = findGroup(groups, suite.demotedRule, "/home/dan/.local/bin/theme-sync")
    verify(other !== null)
    compare(other.alerts.length, 1)

    // Groups are newest first.
    for (var i = 1; i < groups.length; i++)
      verify(groups[i - 1].latestId > groups[i].latestId, "groups sort newest first")
  }

  function test_timeline_groups_by_the_script_when_an_interpreter_carries_one() {
    // BASELINE 1: an interpreter takes the provenance of the script it runs, so
    // two scripts under one /usr/bin/bash are two actors and two rows.
    var text = [
      JSON.stringify({ v: 1, id: "A", severity: "low", title: "one", rule: "r",
                       ts: "2026-09-03T10:00:00Z", process: { exe: "/usr/bin/bash" },
                       actor: { provenance: "user", script: "/tmp/a.sh" } }),
      JSON.stringify({ v: 1, id: "B", severity: "low", title: "two", rule: "r",
                       ts: "2026-09-03T10:01:00Z", process: { exe: "/usr/bin/bash" },
                       actor: { provenance: "user", script: "/tmp/b.sh" } })
    ].join("\n")
    var groups = Model.timelineGroups(Model.foldText(text), {})
    compare(groups.length, 2)
    compare(groups[0].exe, "/tmp/b.sh")
  }

  function test_timeline_includes_suppressed_only_when_asked() {
    var without = Model.timelineGroups(alertsFromFixture(), suite.demoted)
    var with_ = Model.timelineGroups(alertsFromFixture(),
      { demotedRules: [suite.demotedRule], showSuppressed: true })
    compare(with_.length, without.length + 1)
    var group = findGroup(with_, "moat-exec-untrusted-home",
                          "/home/dan/Projects/omarchy-moat/.git/hooks/pre-push")
    verify(group !== null, "the suppressed alert gets its own row when shown")
    compare(group.suppressed, true, "a wholly-suppressed group renders greyed out")
  }

  // ---------------------------------------------- baseline notification rules

  function test_demoted_rule_never_notifies() {
    var alert = findAlert(alertsFromFixture(), "01J8ZK6B4Q3M7N9P2R5S8T1V4G")
    // High, unacked, well above the default threshold — and still silent.
    verify(Model.shouldNotify(alert, "high", false), "high notifies before the demotion")
    verify(!Model.shouldNotify(alert, "high", false, suite.demoted))
    verify(!Model.shouldNotify(alert, "low", false, suite.demoted))
  }

  function test_suppressed_alert_never_notifies() {
    var alert = findAlert(alertsFromFixture(), "01J8ZK6B4Q3M7N9P2R5S8T1V4F")
    verify(!Model.shouldNotify(alert, "low", false, suite.demoted))
  }

  // BASELINE 4.2's deliberate exception: the noise guard's own alert is medium
  // but is the one thing the guard exists to put in front of the user.
  function test_noisy_rule_alert_notifies_despite_being_medium() {
    var alert = findAlert(alertsFromFixture(), "01J8ZK6B4Q3M7N9P2R5S8T1V4K")
    compare(alert.rule, "moat-x-noisy-rule")
    compare(alert.severity, "medium")

    // Any other medium alert is silent at the default threshold...
    verify(!Model.shouldNotify(findAlert(alertsFromFixture(), "01J8ZK6B4Q3M7N9P2R5S8T1V41"),
                               "high", false, suite.demoted))
    // ...this one is not, at any threshold.
    verify(Model.shouldNotify(alert, "high", false, suite.demoted))
    verify(Model.shouldNotify(alert, "critical", false, suite.demoted))

    // The exception is only to the severity threshold. Everything else that
    // silences an alert still silences this one.
    var acked = Model.foldText(JSON.stringify({
      v: 1, id: "A", severity: "medium", rule: "moat-x-noisy-rule", acked: true,
      title: "t", ts: "2026-09-03T10:00:00Z" }))[0]
    verify(!Model.shouldNotify(acked, "critical", false))
    verify(!Model.shouldNotify(alert, "critical", true), "not on the priming load")
    verify(!Model.shouldNotify(alert, "critical", false,
                               { demotedRules: ["moat-x-noisy-rule"] }),
           "a noise guard that itself floods can still be demoted into silence")
  }

  // ------------------------------------------- notification cooldown (BASELINE 5)

  // A minimal alert straight from the wire, so these tests exercise the same
  // normalization path a real line takes.
  function burstAlert(id, rule, severity, title, rarity) {
    var record = {
      v: 1, id: id, ts: "2026-09-03T10:00:00Z",
      severity: severity || "high", rule: rule,
      title: title || "Credential file read", summary: "s", actions: ["ignore"]
    }
    if (rarity) record.rarity = rarity
    return Model.foldText(JSON.stringify(record))[0]
  }

  // 10 minutes, the manifest default.
  readonly property var cooldown: ({ minNotifySeverity: "high", initialLoad: false,
                                     notifyCooldownMinutes: 10 })

  function test_cooldown_blocks_the_second_toast_and_allows_the_next_window() {
    var store = Model.createStore()
    var t0 = 1000000

    var first = Model.notifyDecision(store, burstAlert("A", "moat-cred-read"), t0, suite.cooldown)
    compare(first.toast, true)
    compare(first.reason, "first")
    compare(first.collapsed, 0)

    // Same rule, 1 ms later and 9 minutes later: counted, not toasted.
    var second = Model.notifyDecision(store, burstAlert("B", "moat-cred-read"), t0 + 1, suite.cooldown)
    compare(second.toast, false)
    compare(second.reason, "cooldown")
    compare(second.collapsed, 1)

    var third = Model.notifyDecision(store, burstAlert("C", "moat-cred-read"),
                                     t0 + 9 * 60000, suite.cooldown)
    compare(third.toast, false)
    compare(third.collapsed, 2)

    // A different rule has its own window and is unaffected.
    var other = Model.notifyDecision(store, burstAlert("D", "moat-net-egress"),
                                     t0 + 1, suite.cooldown)
    compare(other.toast, true)
    compare(other.reason, "first")

    // Past the window, the rule may toast again.
    var later = Model.notifyDecision(store, burstAlert("E", "moat-cred-read"),
                                     t0 + 10 * 60000 + 1, suite.cooldown)
    compare(later.toast, true)
    compare(later.reason, "window-reset")
  }

  // The window ends AT the cooldown, not one tick after it.
  function test_cooldown_window_boundary_is_inclusive() {
    var store = Model.createStore()
    var t0 = 0

    compare(Model.notifyDecision(store, burstAlert("A", "r"), t0, suite.cooldown).toast, true)
    // One millisecond short of the boundary: still inside.
    compare(Model.notifyDecision(store, burstAlert("B", "r"), t0 + 10 * 60000 - 1,
                                 suite.cooldown).toast, false)
    // Exactly on it: the window is over.
    var atBoundary = Model.notifyDecision(store, burstAlert("C", "r"), t0 + 10 * 60000,
                                          suite.cooldown)
    compare(atBoundary.toast, true)
    compare(atBoundary.reason, "window-reset")

    // The window that just ended still owed one summary, and rolling it over
    // did not lose it.
    var summaries = Model.flushCollapsed(store, t0 + 10 * 60000)
    compare(summaries.length, 1)
    compare(summaries[0].count, 1)
  }

  function test_flush_collapsed_summarises_the_burst_once() {
    var store = Model.createStore()
    var t0 = 500000

    Model.notifyDecision(store, burstAlert("A", "moat-cred-read", "high", "Credential file read"),
                         t0, suite.cooldown)
    for (var i = 0; i < 172; i++)
      Model.notifyDecision(store, burstAlert("id" + i, "moat-cred-read", "high", "Credential file read"),
                           t0 + 1000 + i, suite.cooldown)

    var window = Model.notifyWindowState(store, "moat-cred-read")
    compare(window.toasted, true)
    compare(window.suppressedCount, 172)
    compare(window.windowStart, t0)

    // Inside the window there is nothing to flush.
    compare(Model.flushCollapsed(store, t0 + 60000).length, 0)

    var summaries = Model.flushCollapsed(store, t0 + 10 * 60000)
    compare(summaries.length, 1)
    compare(summaries[0].rule, "moat-cred-read")
    compare(summaries[0].count, 172)
    compare(Model.collapsedSummaryText(summaries[0]),
            "172 more from Credential file read, see panel")

    // Drained: the same summary must not toast twice, and the window is gone.
    compare(Model.flushCollapsed(store, t0 + 20 * 60000).length, 0)
    compare(Model.notifyWindowState(store, "moat-cred-read"), null)

    // 173 alerts, two toasts. That is the whole point (BASELINE 5).
  }

  function test_flush_drops_an_empty_window_without_a_summary() {
    var store = Model.createStore()
    compare(Model.notifyDecision(store, burstAlert("A", "r"), 0, suite.cooldown).toast, true)
    compare(Model.flushCollapsed(store, 10 * 60000).length, 0,
            "a window that collapsed nothing has nothing to say")
    compare(Model.notifyWindowState(store, "r"), null)
  }

  function test_critical_first_seen_bypasses_the_cooldown() {
    var store = Model.createStore()
    var t0 = 0

    compare(Model.notifyDecision(store, burstAlert("A", "moat-x-new-exec-ioc", "critical"),
                                 t0, suite.cooldown).toast, true)

    // Critical alone does not bypass: a critical rule in a loop is exactly the
    // storm the cooldown exists for.
    var plain = Model.notifyDecision(store, burstAlert("B", "moat-x-new-exec-ioc", "critical"),
                                     t0 + 1000, suite.cooldown)
    compare(plain.toast, false)
    compare(plain.reason, "cooldown")

    // Critical + first_seen does.
    var rare = Model.notifyDecision(store,
                                    burstAlert("C", "moat-x-new-exec-ioc", "critical", "IOC", "first_seen"),
                                    t0 + 2000, suite.cooldown)
    compare(rare.toast, true)
    compare(rare.reason, "critical-first-seen")

    // High + first_seen does not: the bypass is critical-only.
    var high = Model.notifyDecision(store,
                                    burstAlert("D", "moat-x-new-exec-ioc", "high", "IOC", "first_seen"),
                                    t0 + 3000, suite.cooldown)
    compare(high.toast, false)

    // The bypass neither extends the window nor is counted into its summary:
    // only the two genuinely collapsed alerts are.
    var summaries = Model.flushCollapsed(store, t0 + 10 * 60000)
    compare(summaries.length, 1)
    compare(summaries[0].count, 2)
  }

  function test_noisy_rule_alert_ignores_the_cooldown() {
    var store = Model.createStore()
    var alert = findAlert(alertsFromFixture(), "01J8ZK6B4Q3M7N9P2R5S8T1V4K")
    compare(alert.rule, "moat-x-noisy-rule")

    // Its one-shot exception survives: each noise-guard alert toasts, and the
    // store's seen-set is what makes that once per alert.
    for (var i = 0; i < 3; i++) {
      var d = Model.notifyDecision(store, alert, i * 1000, suite.cooldown)
      compare(d.toast, true)
      compare(d.reason, "noisy-rule")
    }
    compare(Model.notifyWindowState(store, "moat-x-noisy-rule"), null,
            "the noise guard's alert opens no window and collapses nothing")
    compare(Model.flushCollapsed(store, 60 * 60000).length, 0)
  }

  function test_cooldown_never_reaches_an_alert_the_table_already_silences() {
    var store = Model.createStore()

    // Below the threshold, on the priming load, acked, suppressed, demoted:
    // all "filtered", and none of them opens a window that could later toast
    // a summary for something the user was never going to be told about.
    compare(Model.notifyDecision(store, burstAlert("A", "r", "medium"), 0, suite.cooldown).reason,
            "filtered")
    compare(Model.notifyDecision(store, burstAlert("B", "r"), 0,
                                 { minNotifySeverity: "high", initialLoad: true }).reason,
            "filtered")
    compare(Model.notifyDecision(store, burstAlert("C", suite.demotedRule), 0,
                                 { minNotifySeverity: "high", initialLoad: false,
                                   demotedRules: [suite.demotedRule] }).reason,
            "filtered")
    compare(Model.notifyWindowState(store, "r"), null)
    compare(Model.flushCollapsed(store, 60 * 60000).length, 0)
  }

  function test_cooldown_minutes_is_clamped_to_the_manifest_range() {
    compare(Model.notifyCooldownMinutes(undefined), 10, "missing falls back to the default")
    compare(Model.notifyCooldownMinutes("nonsense"), 10)
    compare(Model.notifyCooldownMinutes(0), 1)
    compare(Model.notifyCooldownMinutes(-5), 1)
    compare(Model.notifyCooldownMinutes(1000), 120)
    compare(Model.notifyCooldownMinutes("45"), 45)
    compare(Model.notifyCooldownMinutes(2.6), 3)

    // A one-minute cooldown is a one-minute window, not a ten-minute one.
    var store = Model.createStore()
    var opts = { minNotifySeverity: "high", initialLoad: false, notifyCooldownMinutes: 1 }
    compare(Model.notifyDecision(store, burstAlert("A", "r"), 0, opts).toast, true)
    compare(Model.notifyDecision(store, burstAlert("B", "r"), 30000, opts).toast, false)
    compare(Model.notifyDecision(store, burstAlert("C", "r"), 60000, opts).toast, true)
  }

  // A clock that jumps backwards (suspend, an NTP step) must not wedge a rule
  // into permanent silence.
  function test_cooldown_survives_a_backwards_clock() {
    var store = Model.createStore()
    compare(Model.notifyDecision(store, burstAlert("A", "r"), 1000000, suite.cooldown).toast, true)
    compare(Model.notifyDecision(store, burstAlert("B", "r"), 1000001, suite.cooldown).toast, false)
    var back = Model.notifyDecision(store, burstAlert("C", "r"), 5000, suite.cooldown)
    compare(back.toast, true)
    compare(back.reason, "window-reset")
  }

  function test_collapsed_summary_text_degrades_to_the_rule() {
    compare(Model.collapsedSummaryText({ rule: "moat-net-egress", count: 1 }),
            "1 more from moat-net-egress, see panel")
    compare(Model.collapsedSummaryText(null), "0 more from this rule, see panel")
  }

  // -------------------------------------------------------- baseline: status

  function test_status_carries_baseline_proposals_and_demoted_rules() {
    var status = statusFromFixture()
    compare(status.ok, true)
    compare(status.baseline.learning, false)
    compare(status.baseline.learned, 7)
    compare(status.baseline.proposals, 2)
    compare(status.demoted_rules.length, 1)
    compare(status.demoted_rules[0], suite.demotedRule)
    compare(status.baseline.demoted[0], suite.demotedRule)

    compare(status.proposals.length, 2)
    var first = status.proposals[0]
    compare(first.id, "p-01")
    compare(first.rule, "moat-exec-untrusted-home")
    compare(first.count, 41)
    compare(first.days, 5)
    compare(first.actionable, true)
    verify(first.toml.indexOf("[[rule]]\n") === 0, "the exact block accepting would write")
    verify(Model.proposalDetail(first).indexOf("exe /home/dan") === 0, Model.proposalDetail(first))
    verify(Model.proposalDetail(first).indexOf("41 alerts") > 0)
  }

  function test_status_without_a_baseline_block_degrades_quietly() {
    // Exactly what an older moatd answers. Nothing learning, nothing proposed,
    // nothing demoted — i.e. how the plugin behaved before baselining existed.
    var status = Model.normalizeStatus(JSON.stringify({ ok: true, mode: "monitor" }))
    compare(status.baseline.learning, false)
    compare(status.baseline.proposals, 0)
    compare(status.baseline.demoted.length, 0)
    compare(status.proposals.length, 0)
    compare(status.demoted_rules.length, 0)
    compare(Model.learningSummary(status, Date.now()), "baseline active")
  }

  function test_demoted_rules_are_accepted_nested_in_baseline_too() {
    // BASELINE 4 keeps the list inside the baseline block; the panel was
    // specified against a top-level demoted_rules. Either spelling has to work.
    var nested = Model.normalizeStatus(JSON.stringify({
      ok: true, baseline: { demoted: ["moat-x-mass-read"] }
    }))
    compare(nested.demoted_rules[0], "moat-x-mass-read")
    compare(nested.baseline.demoted[0], "moat-x-mass-read")
  }

  function test_proposal_without_an_id_is_not_actionable() {
    var status = Model.normalizeStatus(JSON.stringify({
      ok: true, proposals: [{ rule: "moat-x-mass-read", count: 3 }]
    }))
    compare(status.proposals.length, 1)
    compare(status.proposals[0].actionable, false,
            "accept/dismiss name an id; without one the panel must not send a blank")
    compare(status.baseline.proposals, 1, "the count follows the list that is actually there")
  }

  function test_learning_summary() {
    var now = Date.parse("2026-09-03T12:00:00Z")
    var learning = Model.normalizeStatus(JSON.stringify({
      ok: true, baseline: { learning: true, learning_ends: "2026-09-08T12:00:00Z" }
    }))
    compare(Model.learningSummary(learning, now), "learning, 5 days left")

    var lastDay = Model.normalizeStatus(JSON.stringify({
      ok: true, baseline: { learning: true, learning_ends: "2026-09-04T09:00:00Z" }
    }))
    compare(Model.learningSummary(lastDay, now), "learning, 1 day left")

    var ending = Model.normalizeStatus(JSON.stringify({
      ok: true, baseline: { learning: true, learning_ends: "2026-09-03T11:00:00Z" }
    }))
    compare(Model.learningSummary(ending, now), "learning, ends today")

    compare(Model.learningSummary(statusFromFixture(), now), "baseline active · 2 proposals")
    var one = Model.normalizeStatus(JSON.stringify({ ok: true, baseline: { proposals: 1 } }))
    compare(Model.learningSummary(one, now), "baseline active · 1 proposal")
  }

  // ---------------------------------------------------------------- explain

  function test_explain_block_is_normalized() {
    var alert = findAlert(alertsFromFixture(), "01J8ZK6B4Q3M7N9P2R5S8T1V42")
    verify(Model.hasExplain(alert))
    compare(alert.explain.what, "node read your private SSH key.")
    compare(alert.explain.evidence.length, 4)
    compare(alert.explain.next.length, 2)
    verify(alert.explain.expected.length > 0)
    compare(alert.explain.if_expected.file, "/etc/moat/allowlist.d/user.toml")
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
      file: "/etc/moat/allowlist.d/user.toml",
      rules: [
        { index: 0, name: "moat-cred-ssh-private-key-read", scope: "exe",
          comment: "# added 2026-09-01 from alert 01J8...: Private SSH key read",
          exe: "/usr/bin/git" },
        { index: 3, name: "moat-x-mass-read", scope: "rule", comment: "" }
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

  // BASELINE 3: the learning window writes its own entries to baseline.toml.
  // They are listed with the user's, tagged, and removable the same way — a
  // suppression the machine chose is the one that most needs to be visible.
  function test_allowlist_tags_learned_entries() {
    var parsed = Model.parseAllowlist(JSON.stringify({
      ok: true,
      user_file: "/etc/moat/allowlist.d/user.toml",
      rules: [
        { index: 0, name: "moat-cred-ssh-private-key-read", scope: "exe",
          exe: "/usr/bin/git", file: "/etc/moat/allowlist.d/user.toml", path: null },
        { index: 1, name: "moat-exec-untrusted-home",
          comment: "# learned 2026-08-29: 12 alerts on 3 distinct days",
          exe: "/usr/bin/lefthook", file: "/etc/moat/allowlist.d/baseline.toml", path: null },
        { name: "moat-x-mass-read", learned: true }
      ]
    }))

    compare(parsed.rules.length, 3)
    compare(parsed.rules[0].learned, false)
    compare(parsed.rules[1].learned, true, "baseline.toml is the learning window's file")
    compare(parsed.rules[1].removable, true, "a learned entry with an index can be removed")
    compare(parsed.rules[2].learned, true, "the daemon may also say so outright")
    compare(parsed.rules[2].removable, false, "no index, no unignore handle")

    var sections = Model.allowlistSections(parsed.rules)
    compare(sections.user.length, 1)
    compare(sections.learned.length, 2)
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

  // ---------------------------------------------------- LEARNING 1: rarity

  function test_rarity_pill_maps_the_three_classes() {
    compare(Model.rarityPill("first_seen").label, "FIRST SEEN")
    compare(Model.rarityPill("first_seen").kind, "strong")
    compare(Model.rarityPill("rare").label, "RARE")
    compare(Model.rarityPill("rare").kind, "warn")
    compare(Model.rarityPill("common").label, "COMMON")
    compare(Model.rarityPill("common").kind, "quiet")
    // The spellings a hand-written policy is most likely to use.
    compare(Model.rarityPill("first-seen").rarity, "first_seen")
    compare(Model.rarityPill("FIRST SEEN").rarity, "first_seen")
    // Anything else renders no pill at all: a wrong pill ("common" over a tuple
    // nobody has ever seen) is worse than no pill.
    compare(Model.rarityPill("unheard-of"), null)
    compare(Model.rarityPill(""), null)
    compare(Model.rarityPill(null), null)
  }

  function test_rarity_rides_the_alert_and_reads_as_a_sentence() {
    var alert = findAlert(alertsFromFixture(), "01J8ZK6B4Q3M7N9P2R5S8T1V4M")
    verify(alert !== null)
    compare(alert.rarity, "first_seen")
    compare(Model.rarityLine(alert),
            "first time /usr/bin/node has read ~/.aws on this machine")
    compare(Model.rarityPill(alert.rarity).label, "FIRST SEEN")

    // Rarity is evidence, never a verdict: it does not touch the severity, the
    // surface or the notification decision.
    compare(alert.severity, "high")
    compare(alert.severity_base, "high")
  }

  function test_rarity_defaults_are_silent_not_wrong() {
    var none = Model.foldText(JSON.stringify({
      v: 1, id: "A", severity: "low", title: "t", ts: "2026-09-03T10:00:00Z"
    }))[0]
    compare(none.rarity, "")
    compare(none.rarity_text, "")
    compare(Model.rarityLine(none), "", "no rarity means no line")

    // A class with no sentence still says something, rather than showing a pill
    // with nothing next to it.
    var classified = Model.foldText(JSON.stringify({
      v: 1, id: "B", severity: "low", title: "t", ts: "2026-09-03T10:00:00Z",
      rarity: "rare"
    }))[0]
    verify(Model.rarityLine(classified).length > 0)
  }

  // ------------------------------------------------- LEARNING 4: incidents

  function test_incident_snapshot_normalizes() {
    var alert = findAlert(alertsFromFixture(), "01J8ZK6B4Q3M7N9P2R5S8T1V4M")
    verify(alert.incident !== null)
    compare(alert.incident.dir, "/var/lib/moat/incidents/01J8ZK6B4Q3M7N9P2R5S8T1V4M")
    compare(alert.incident.count, 5)
    compare(alert.incident.files[0].name, "process.json")
    compare(alert.incident.files[0].size, 8214)
    // A relative name is resolved against the incident directory, because the
    // path is the one thing the panel hands to the clipboard.
    compare(alert.incident.files[3].name, "file/postinstall.js")
    compare(alert.incident.files[3].path,
            "/var/lib/moat/incidents/01J8ZK6B4Q3M7N9P2R5S8T1V4M/file/postinstall.js")
    verify(alert.incident.files[3].sha256.length === 64)
  }

  function test_incident_is_null_when_nothing_was_captured() {
    var alert = findAlert(alertsFromFixture(), "01J8ZK6B4Q3M7N9P2R5S8T1V40")
    compare(alert.incident, null)
    compare(Model.normalizeIncident(null), null)
    compare(Model.normalizeIncident({}), null, "neither a dir nor a file is nothing to show")
    // A bare list of names is still a usable snapshot.
    var plain = Model.normalizeIncident({ dir: "/var/lib/moat/incidents/X",
                                          files: ["tree.txt", ""] })
    compare(plain.count, 1)
    compare(plain.files[0].path, "/var/lib/moat/incidents/X/tree.txt")
    compare(plain.files[0].size, -1, "an unstated size is -1, not 0")
  }

  function test_format_bytes() {
    compare(Model.formatBytes(612), "612 B")
    compare(Model.formatBytes(8214), "8.0 KB")
    compare(Model.formatBytes(40311), "39 KB")
    // A decimal below 10 of a unit, none above it: "8.0 MB" is worth the digit,
    // "39.4 KB" is not.
    compare(Model.formatBytes(8 * 1024 * 1024), "8.0 MB")
    compare(Model.formatBytes(64 * 1024 * 1024), "64 MB")
    compare(Model.formatBytes(-1), "", "an unstated size renders as nothing")
    compare(Model.formatBytes("nonsense"), "")
  }

  // -------------------------------------------------- LEARNING 3: receipts

  function test_receipts_are_never_alerts() {
    var records = Model.parseText(suite.fixtureText)
    var receipts = 0
    for (var i = 0; i < records.length; i++) if (Model.isReceipt(records[i])) receipts++
    compare(receipts, 2, "both receipt lines survive parsing")

    // ...and none of them reaches the alert path.
    var alerts = alertsFromFixture()
    for (var j = 0; j < alerts.length; j++) {
      compare(alerts[j].id.indexOf("01J8ZK6B4Q3M7N9P2R5S8T1V4N"), -1)
      compare(alerts[j].id.indexOf("01J8ZK6B4Q3M7N9P2R5S8T1V4P"), -1)
      verify(alerts[j].title.length > 0, "a receipt folded as an alert would be titleless")
    }
  }

  // LEARNING 3: "Receipts are informational, never notify". The store is the
  // place that could get this wrong, so it is asserted end to end: a receipt
  // appended after priming produces no new id and moves no count.
  function test_receipts_never_notify_and_never_count() {
    var store = Model.createStore()
    var primed = Model.ingestText(store, suite.fixtureText, suite.demoted)
    compare(primed.receipts.length, 2)
    var badgeBefore = primed.unacked.badge

    var appended = suite.fixtureText + JSON.stringify({
      v: 1, id: "01J8ZK6B4Q3M7N9P2R5S8T1V4Q", receipt: {
        root_exe: "/usr/bin/cargo", root_args: "build", cwd: "~/Projects/moat",
        started: "2026-09-03T18:00:00.000Z", duration_s: 12, exit: 0
      }
    }) + "\n"

    var after = Model.ingestText(store, appended, suite.demoted)
    compare(after.newIds.length, 0, "a receipt is not an event to be toasted")
    compare(after.alerts.length, primed.alerts.length, "and not an alert either")
    compare(after.receipts.length, 3)
    compare(after.unacked.badge, badgeBefore, "the badge cannot move for a receipt")
    compare(after.unacked.total, primed.unacked.total)
  }

  function test_receipt_fields_parse() {
    var receipts = Model.receiptsFromText(suite.fixtureText)
    compare(receipts.length, 2)
    // Newest first, by timestamp: npm at 17:15 before pip at 16:10.
    var npm = receipts[0]
    compare(npm.root_exe, "/usr/bin/npm")
    compare(npm.root_args, "install")
    compare(npm.cwd, "~/Projects/app")
    compare(npm.started, "2026-09-03T17:15:02.000Z")
    compare(npm.duration_s, 41)
    compare(npm.exit, 0)
    compare(npm.postinstall_scripts.length, 3)
    compare(npm.postinstall_scripts[0], "esbuild")
    compare(npm.writes_outside_project.length, 2)
    compare(npm.network.length, 3)
    compare(npm.credential_reads.length, 0)
    compare(npm.persistence_writes.length, 1)
    compare(npm.persistence_writes[0].path, ".husky/pre-commit")
    compare(npm.persistence_writes[0].alerted, true)
    compare(npm.persistence_writes[0].severity, "low")
    compare(npm.execs_from_tree, 12)
    compare(npm.execs_from_tmp, 0)
  }

  // LEARNING 3 names the receipt's fields in prose, not as a schema, so the
  // other plausible spelling of each is accepted rather than rendering
  // "undefined" next to an install the user actually ran.
  function test_receipt_accepts_the_alternate_spellings() {
    var pip = Model.receiptsFromText(suite.fixtureText)[1]
    compare(pip.root_exe, "/usr/bin/pip", "exe stands in for root_exe")
    compare(pip.root_args, "install -r requirements.txt")
    compare(pip.cwd, "/home/dan/Projects/scanner", "project stands in for cwd")
    compare(pip.exit, 1)
    // Object entries as well as bare strings.
    compare(pip.writes_outside_project[0], "~/.cache/pip")
    compare(pip.network[0], "pypi.org")
    compare(pip.credential_reads[0], "~/.netrc")
  }

  function test_receipt_defaults_are_empty_not_undefined() {
    var bare = Model.receiptsFromText(JSON.stringify({ v: 1, receipt: {} }))[0]
    compare(bare.root_exe, "")
    compare(bare.duration_s, 0)
    compare(bare.exit, null, "an unstated exit is null, not a successful 0")
    compare(bare.postinstall_scripts.length, 0)
    compare(bare.network.length, 0)
    compare(bare.execs_from_tree, 0)
    // A receipt with no id still needs a stable key: the timeline is keyed, not
    // indexed, because it re-sorts on every append.
    verify(bare.key.length > 0)
  }

  function test_receipt_summary_is_the_one_line_row() {
    var npm = Model.receiptsFromText(suite.fixtureText)[0]
    compare(Model.receiptSummary(npm),
            "npm install in ~/Projects/app · 41 s · 3 postinstall · 3 hosts")

    // A failed install says so on the collapsed row: it is the one thing about
    // a receipt that is not routine.
    var pip = Model.receiptsFromText(suite.fixtureText)[1]
    verify(Model.receiptSummary(pip).indexOf("exit 1") >= 0)
    verify(Model.receiptSummary(pip).indexOf("1 host") >= 0, "singular for one host")
  }

  // The expanded block, byte for byte what LEARNING 3 prints.
  function test_receipt_block_matches_the_document() {
    var block = Model.receiptBlock(Model.receiptsFromText(suite.fixtureText)[0])
    compare(block.headline, "npm install in ~/Projects/app (41 s, exit 0)")
    compare(block.lines.length, 5)
    compare(block.lines[0], "postinstall scripts: 3 (esbuild, sharp, husky)")
    compare(block.lines[1], "wrote outside the project: ~/.npm/_cacache, ~/.cache/prisma")
    compare(block.lines[2],
            "network: registry.npmjs.org, github.com, objects.githubusercontent.com")
    compare(block.lines[3],
            "credential reads: none · persistence writes: .husky/pre-commit (alerted, low)")
    compare(block.lines[4], "binaries executed from the tree: 12 · from /tmp: 0")
  }

  function test_timeline_rows_interleave_receipts_newest_first() {
    var alerts = alertsFromFixture()
    var receipts = Model.receiptsFromText(suite.fixtureText)
    var rows = Model.timelineRows(alerts, receipts, suite.demoted)

    var groups = Model.timelineGroups(alerts, suite.demoted)
    compare(rows.length, groups.length + receipts.length)

    var kinds = { group: 0, receipt: 0 }
    for (var i = 0; i < rows.length; i++) kinds[rows[i].kind]++
    compare(kinds.group, groups.length)
    compare(kinds.receipt, 2)

    // Chronological, newest first, across both kinds — which is the reason they
    // share one list at all.
    for (var j = 1; j < rows.length; j++) {
      verify(Date.parse(rows[j - 1].ts) >= Date.parse(rows[j].ts),
             rows[j - 1].ts + " must not sort after " + rows[j].ts)
    }
    // The npm receipt (17:15) is the newest thing in the fixture's timeline.
    compare(rows[0].kind, "receipt")
    compare(rows[0].receipt.root_exe, "/usr/bin/npm")
    verify(rows[0].key.indexOf("r:") === 0, "row keys are namespaced per kind")
  }

  function test_timeline_rows_without_receipts_are_just_the_groups() {
    var alerts = alertsFromFixture()
    var rows = Model.timelineRows(alerts, [], suite.demoted)
    var groups = Model.timelineGroups(alerts, suite.demoted)
    compare(rows.length, groups.length)
    for (var i = 0; i < rows.length; i++) compare(rows[i].kind, "group")
  }

  // -------------------------------------------------- LEARNING 2: analysis

  function test_default_agent_name_is_a_name_or_nothing() {
    compare(Model.normalizeAgentName("claude\n"), "claude")
    compare(Model.normalizeAgentName("  codex  "), "codex")
    compare(Model.normalizeAgentName("opencode\nsomething else"), "opencode")
    // A message is not a name, and it would otherwise end up in a button label.
    compare(Model.normalizeAgentName("no default agent set"), "")
    compare(Model.normalizeAgentName("none"), "")
    compare(Model.normalizeAgentName("claude; rm -rf ~"), "")
    compare(Model.normalizeAgentName(""), "")
    compare(Model.normalizeAgentName(null), "")
  }

  function test_analyze_label_and_hint() {
    compare(Model.analyzeLabel("claude"), "Analyze with claude")
    compare(Model.analyzeLabel(""), "", "no default agent means no button")
    verify(Model.ANALYZE_HINT.indexOf("omarchy default agent") >= 0)
  }

  function test_parse_bundle_response() {
    var ok = Model.parseBundleResponse(JSON.stringify({
      ok: true, path: "/var/lib/moat/incidents/01J8/bundle.md"
    }))
    compare(ok.ok, true)
    compare(ok.path, "/var/lib/moat/incidents/01J8/bundle.md")

    // The alternate spellings, and a daemon that just prints the path.
    compare(Model.parseBundleResponse(JSON.stringify({ bundle: "/a/b.md" })).path, "/a/b.md")
    compare(Model.parseBundleResponse("/a/b.md\n").path, "/a/b.md")

    // Anything that is not an absolute path is refused rather than handed to
    // wl-copy: the only use for this value is to be pasted into a terminal.
    compare(Model.parseBundleResponse(JSON.stringify({ ok: true, path: "b.md" })).ok, false)
    compare(Model.parseBundleResponse(JSON.stringify({ ok: false, error: "no such alert" })).ok, false)
    compare(Model.parseBundleResponse("").ok, false)
    compare(Model.parseBundleResponse("not json at all").ok, false)
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
    compare(summary, "Moat: mode monitor, tetragon running, 17 policies, feeds 1h ago, 9 unacked")
    compare(Model.statusSummary(null, {}, 0), "Moat: daemon not reachable")
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
    verify(both[1].command.indexOf("systemctl enable --now tetragon moatd moat-feeds.timer") >= 0)
    verify(both[2].command.indexOf("usermod -aG moat $USER") >= 0)

    compare(Model.setupSteps(false, true).length, 2)
    compare(Model.setupSteps(false, false).length, 0)
  }

  // Quarantine holds rather than deletes, so the panel has to be able to show
  // what is held and offer it back. "What got me" is the question a user has
  // after an alert, and a store you cannot look into does not answer it.
  function test_quarantine_view_carries_what_the_user_needs_to_decide() {
    var r = Model.quarantineView({ quarantine: [{
      alert: "01ABC", rule: "moat-exec-untrusted-home", title: "t",
      original_path: "/home/dan/.cache/evil.so",
      held_at: "/var/lib/moat/quarantine/01ABC/evil.so",
      quarantined_at: "2026-09-03T23:00:00.000Z",
      sha256: "abc123", bytes: 7, present: true
    }] })
    compare(r.length, 1)
    compare(r[0].id, "01ABC")
    compare(r[0].originalPath, "/home/dan/.cache/evil.so")
    compare(r[0].heldAt, "/var/lib/moat/quarantine/01ABC/evil.so")
    compare(r[0].bytes, 7)
    compare(r[0].present, true)

    // A held file that vanished must read as missing, not as fine: it means
    // something removed it out from under moat.
    var gone = Model.quarantineView({ quarantine: [{
      alert: "01DEF", original_path: "/tmp/x", bytes: null, present: false
    }] })
    compare(gone[0].present, false)
    compare(gone[0].bytes, -1)

    // Nothing held, and a malformed answer, both mean an empty list.
    compare(Model.quarantineView({ quarantine: [] }).length, 0)
    compare(Model.quarantineView({}).length, 0)
    compare(Model.quarantineView(null).length, 0)
  }
}
