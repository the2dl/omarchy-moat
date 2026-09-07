import QtQuick
import QtTest
import "../MoatModel.js" as Model
import "../MoatCopy.js" as Copy

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
  /// The real chain off this machine: two alerts moatd correlated on
  /// 2026-09-04, copied verbatim out of /var/lib/moat/alerts.jsonl. Six lines
  /// -- two alert records, an `incident` snapshot update, the two `chain`
  /// updates moatd wrote back onto both members, and a `triage` update -- in
  /// the order they were appended.
  property string chainText: ""

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
    suite.chainText = readFixture("chain.jsonl")
    verify(suite.chainText.length > 0, "fixture chain.jsonl is empty or unreadable")
  }

  /// The two members of the real chain, folded the way the panel folds them.
  function chainAlerts() {
    return Model.foldText(suite.chainText)
  }

  function chainIncident(options) {
    var inc = Model.buildIncidents(suite.chainAlerts(), options || {})
    return inc.length > 0 ? inc[0] : null
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
    // Every number here is the SAME set -- unacked alerts on the Alerts
    // surface -- split by severity. The medium and low ones are on the
    // timeline, so they are not "unacked" in any sense the shield shows:
    // counting them in `total` while `badge` did not is what put a red
    // widget state over a badge of 0.
    compare(counts.critical, 3)   // V46, V49, V4E; V45 is acked
    compare(counts.high, 9)       // V42, V43, V47, V48, V4A, V4G, V4H, V4J, V4M
    compare(counts.medium, 0)     // V41, V44, V4B, V4D, V4K are on the timeline
    compare(counts.low, 0)        // V4C too; V40 is acked, V4F is suppressed
    compare(counts.total, 12)
    compare(counts.badge, 12, "total and badge are one number")
    compare(Model.badgeCount(counts), 12)
  }

  // BASELINE 4 and 5: a demoted rule is "still logged, never notifies, not
  // counted in the badge". The three high alerts of the demoted rule therefore
  // leave the counts entirely once the daemon reports the demotion.
  function test_unacked_counts_drop_demoted_and_suppressed() {
    var counts = Model.unackedCounts(alertsFromFixture(), suite.demoted)
    compare(counts.critical, 3)
    compare(counts.high, 6, "the demoted rule's three high alerts stop counting")
    compare(counts.medium, 0)
    compare(counts.low, 0)
    compare(counts.total, 9)
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

  /// The two ingest paths must agree.
  ///
  /// The panel reads the folded feed from moatd now; `ingestText` remains for
  /// the fallback and for these tests. If they drift, the panel and the daemon
  /// disagree about what is outstanding -- the exact class of bug that made a
  /// suppressed alert count on the badge.
  /// A proposal Moat is not vouching for must keep saying so.
  ///
  /// `normalizeProposal` is a whitelist, and a field it forgets vanishes in
  /// silence -- which for this one would mean the panel showing a repeat-
  /// offender offer as if the baseline were confident about it.
  function test_a_proposals_reason_survives_normalisation() {
    var confident = Model.normalizeProposal({ id: "01A", rule: "moat-x", toml: "[[rule]]" }, 0)
    compare(confident.reason, "", "the ordinary route carries no caveat")

    var offered = Model.normalizeProposal({
      id: "01B", rule: "moat-exec-untrusted-tmpfs", toml: "[[rule]]",
      reason: "the noise guard has had to quieten this pattern repeatedly"
    }, 1)
    verify(offered.reason.indexOf("quieten this pattern repeatedly") >= 0)
    compare(offered.actionable, true)
  }

  function test_the_feed_path_matches_the_text_path() {
    var fromText = Model.ingestText(Model.createStore(), suite.fixtureText)

    // What moatd sends: the same records, already folded, OLDEST first.
    var payload = { alerts: fromText.alerts.slice().reverse(), receipts: [] }
    var fromFeed = Model.ingestFeed(Model.createStore(), payload)

    compare(fromFeed.alerts.length, fromText.alerts.length, "same number of alerts")
    compare(fromFeed.initialLoad, true, "a first feed is history, not events")
    compare(fromFeed.newIds.length, 0)
    for (var i = 0; i < fromText.alerts.length; i++)
      compare(fromFeed.alerts[i].id, fromText.alerts[i].id, "same order at " + i)

    // The badge is the thing that must not drift.
    compare(fromFeed.unacked.critical, fromText.unacked.critical)
    compare(fromFeed.unacked.high, fromText.unacked.high)
    compare(fromFeed.unacked.medium, fromText.unacked.medium)
    compare(fromFeed.unacked.low, fromText.unacked.low)

    // And byId must be populated, because the notifier looks ids up in it.
    verify(fromFeed.byId[fromFeed.alerts[0].id] !== undefined)
  }

  function test_a_new_alert_in_the_feed_notifies() {
    var store = Model.createStore()
    var first = Model.ingestText(store, suite.fixtureText)
    var oldest = first.alerts.slice().reverse()

    // Same records back, plus one that was not there before.
    var extra = JSON.parse(JSON.stringify(oldest[oldest.length - 1]))
    extra.id = "01ZZZZZZZZZZZZZZZZZZZZZZZZ"
    var result = Model.ingestFeed(store, { alerts: oldest.concat([extra]), receipts: [] })

    compare(result.initialLoad, false, "the store was already primed")
    compare(result.newIds.length, 1, "only the unseen id is new")
    compare(result.newIds[0], "01ZZZZZZZZZZZZZZZZZZZZZZZZ")
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

  // ------------------------------------------------- the incremental fold
  //
  // FileView hands back the whole file on every change and moatd appends to it
  // every couple of seconds; re-parsing 19 MB of JSONL per append cost ~250 ms
  // of the GUI thread and was what made the panel's scrolling stutter. The fold
  // is now incremental, so what these pin is that it still produces EXACTLY
  // what a from-scratch fold of the same bytes produces.

  function stampAlerts(list) {
    var out = []
    for (var i = 0; i < list.length; i++) out.push(JSON.stringify(list[i]))
    return out.join("\n")
  }

  function test_incremental_fold_matches_a_full_refold_at_every_prefix() {
    var lines = suite.fixtureText.split("\n")
    var store = Model.createStore()
    for (var cut = 0; cut <= lines.length; cut++) {
      var body = lines.slice(0, cut).join("\n")
      if (cut > 0) body += "\n"
      var got = Model.ingestText(store, body, suite.demoted)
      var want = Model.decorateAlerts(Model.foldText(body), suite.demoted)
      compare(got.alerts.length, want.length, "alert count after " + cut + " lines")
      compare(suite.stampAlerts(got.alerts), suite.stampAlerts(want),
        "the incremental fold must equal a full refold after " + cut + " lines")
      compare(JSON.stringify(got.unacked), JSON.stringify(Model.unackedCounts(want, suite.demoted)),
        "counts after " + cut + " lines")
    }
  }

  function test_a_half_written_line_is_not_folded_until_it_is_complete() {
    var lines = suite.fixtureText.split("\n")
    var whole = lines.slice(0, 3).join("\n") + "\n"
    var store = Model.createStore()

    // A read that caught moatd mid-write: three whole lines plus the first
    // 30 characters of the fourth.
    var torn = whole + String(lines[3]).slice(0, 30)
    var first = Model.ingestText(store, torn)
    compare(first.alerts.length, Model.foldText(whole).length,
      "half a record is not an alert")

    // The rest of that line lands, and only then does the alert appear.
    var complete = lines.slice(0, 4).join("\n") + "\n"
    var second = Model.ingestText(store, complete)
    compare(suite.stampAlerts(second.alerts),
      suite.stampAlerts(Model.decorateAlerts(Model.foldText(complete), {})),
      "the completed line folds exactly once, with nothing lost or doubled")
  }

  function test_a_file_replaced_by_one_the_same_length_is_refolded_not_appended() {
    function line(id, day, title) {
      return JSON.stringify({ v: 1, id: id, ts: "2026-01-0" + day + "T00:00:00.000Z",
        severity: "high", rule: "r", title: title }) + "\n"
    }
    var first = line("AAA", 1, "a") + line("BBB", 2, "b")
    // Same byte count, entirely different alerts. A length check alone would
    // call this an append, find no new bytes, and hand back the old fold.
    var replaced = line("CCC", 3, "c") + line("DDD", 4, "d")
    compare(replaced.length, first.length, "the fixture must actually be the same length")

    var store = Model.createStore()
    compare(Model.ingestText(store, first).alerts.length, 2)

    var result = Model.ingestText(store, replaced)
    compare(result.alerts.length, 2, "a replaced file is refolded, not appended to")
    compare(result.alerts[0].id, "DDD")
    compare(result.alerts[1].id, "CCC")
    compare(suite.stampAlerts(result.alerts),
      suite.stampAlerts(Model.decorateAlerts(Model.foldText(replaced), {})))
  }

  function test_an_update_parked_in_one_ingest_still_applies_in_the_next() {
    // Rotation truncates the head of the file, so an update can legitimately
    // arrive before the alert it patches -- and across two reads, not one.
    var store = Model.createStore()
    var update = JSON.stringify({ v: 1, id: "ZZZ", update: { count: 9 } }) + "\n"
    var base = JSON.stringify({ v: 1, id: "ZZZ", ts: "2026-01-01T00:00:00.000Z",
      severity: "high", rule: "r", title: "z" }) + "\n"

    compare(Model.ingestText(store, update).alerts.length, 0,
      "an update with no base is not an alert")
    var result = Model.ingestText(store, update + base)
    compare(result.alerts.length, 1)
    compare(result.alerts[0].count, 9, "the parked patch survived the ingest boundary")
  }

  function test_a_reread_that_folded_nothing_returns_the_very_same_arrays() {
    // Service.qml's identity guard depends on this: FileView fires more than
    // once per append, and re-assigning an equal-but-new array would rebuild
    // every incident and every delegate on the panel for a file that did not
    // change.
    var store = Model.createStore()
    var first = Model.ingestText(store, suite.fixtureText, suite.demoted)
    var second = Model.ingestText(store, suite.fixtureText, suite.demoted)
    verify(first.alerts === second.alerts, "alerts array identity is stable")
    verify(first.receipts === second.receipts, "receipts array identity is stable")
    verify(Model.sameCounts(first.unacked, second.unacked))
  }

  function test_same_counts_compares_by_value() {
    var a = Model.unackedCounts(suite.alertsFromFixture(), suite.demoted)
    var b = Model.unackedCounts(suite.alertsFromFixture(), suite.demoted)
    verify(a !== b, "two calls really are two objects")
    verify(Model.sameCounts(a, b))
    b.high = a.high + 1
    verify(!Model.sameCounts(a, b))
    verify(!Model.sameCounts(a, null))
  }

  function test_should_notify_respects_threshold_and_ack() {
    var alerts = alertsFromFixture()
    var medium = findAlert(alerts, "01J8ZK6B4Q3M7N9P2R5S8T1V41")
    var high = findAlert(alerts, "01J8ZK6B4Q3M7N9P2R5S8T1V42")
    var ackedCritical = findAlert(alerts, "01J8ZK6B4Q3M7N9P2R5S8T1V45")

    verify(!Model.shouldNotify(medium, "high", false))
    // A medium lives on the timeline (BASELINE 5), so it is never `needsYou`
    // and 2h's "only needs-you may interrupt" stops it whatever the severity
    // floor says. Lowering minNotifySeverity below high therefore changes
    // nothing -- which is why 1f replaced that setting with three
    // consequence-based choices rather than a severity dial.
    verify(!Model.shouldNotify(medium, "medium", false),
           "a timeline alert does not interrupt, whatever the floor is set to")
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

  function test_status_carries_what_the_panel_needs_to_explain_a_missing_verdict() {
    // `IncidentCard` binds `service.autoTriageOn` to decide whether an incident
    // with no verdict is *waiting* for one or will never get one. That property
    // was referenced before it existed, so it read undefined, the "reading the
    // evidence..." state never rendered, and AI analysis was invisible in the
    // panel until a verdict happened to land. QML does not error on an unknown
    // property, so nothing caught it -- this does.
    var s = Model.normalizeStatus({
      auto_triage: "demote", triage_pending: 3,
      tetragon: "running", policies: 32, sensors_loaded: 32
    })
    compare(s.autoTriage, "demote")
    compare(s.triagePending, 3)

    // Off is the honest default for a daemon that does not send the field, so
    // an older daemon shows no pending state rather than a permanent spinner.
    var old = Model.normalizeStatus({ tetragon: "running", policies: 32 })
    compare(old.autoTriage, "off")
    compare(old.triagePending, 0)
  }

  function test_the_seen_set_ages_out_the_oldest_ids_not_the_newest() {
    // `alerts` is newest-first and rememberSeen evicts from the front of its
    // queue, so walking forwards remembered the newest id first and threw it
    // away first. Past SEEN_LIMIT the most recent alerts aged out of `seen` and
    // re-notified as new -- the exact noise the set exists to prevent.
    var store = Model.createStore()
    var text = ""
    var n = 4200   // over SEEN_LIMIT (4096)
    for (var i = 0; i < n; i++) {
      text += JSON.stringify({
        v: 1, id: "01" + String(100000 + i), severity: "high", rule: "r",
        title: "t", ts: "2026-09-04T10:00:00Z", surface: "alerts",
        process: { exe: "/usr/bin/p" }
      }) + "\n"
    }
    Model.ingestText(store, text, {})            // primes the store
    // The newest id must still be remembered; the oldest is the one allowed to
    // fall out of the window.
    var newest = "01" + String(100000 + n - 1)
    var oldest = "01100000"
    verify(store.seen[newest] === true, "the newest id must survive eviction")
    // The cap is on ids BEYOND the fold, so with nothing rotated out yet the
    // oldest is remembered too; what ages out is shown in the tests below.
    verify(store.seen[oldest] === true, "a folded id is always remembered")
    compare(store.seenOrder[0], oldest, "oldest first in the queue, so it is the first to age out")
  }

  function test_more_folded_alerts_than_the_cap_do_not_all_come_back_as_new() {
    // With more alerts in the fold than SEEN_LIMIT (4,620 once the rotated
    // half was folded too, against a cap of 4,096) the oldest-first walk
    // evicted, on every ingest, exactly the ids it was about to visit:
    // remembering the oldest dropped the (cap+1)th, which was walked next, was
    // "new", and pushed the next one out in turn. Every alert came back in
    // newIds on every ingest -- 4,620 lookups and notification decisions per
    // reload, twice a second, on 2026-09-05.
    var store = Model.createStore()
    var text = ""
    var n = 4600
    for (var i = 0; i < n; i++) {
      text += JSON.stringify({
        v: 1, id: "01" + String(100000 + i), severity: "high", rule: "r",
        title: "t", ts: "2026-09-04T10:00:00Z", surface: "alerts",
        process: { exe: "/usr/bin/p" }
      }) + "\n"
    }
    Model.ingestText(store, text, {})
    verify(store.seen["01100000"] === true, "every folded id is remembered, cap or no cap")
    var again = Model.ingestText(store, text, {})
    compare(again.newIds.length, 0, "nothing already folded is new")
    text += JSON.stringify({
      v: 1, id: "01999999", severity: "high", rule: "r", title: "t",
      ts: "2026-09-04T10:00:00Z", surface: "alerts", process: { exe: "/usr/bin/p" }
    }) + "\n"
    var more = Model.ingestText(store, text, {})
    compare(more.newIds.length, 1, "only the appended alert is new")
    compare(more.newIds[0], "01999999")
    compare(store.seenOrder.length, n + 1, "the fold itself never ages out")
  }

  function test_the_seen_set_still_ages_out_ids_that_left_the_fold() {
    var store = Model.createStore()
    var first = ""
    for (var i = 0; i < 10; i++) {
      first += JSON.stringify({ v: 1, id: "01A" + i, severity: "high", rule: "r", title: "t",
        ts: "2026-09-04T10:00:00Z", surface: "alerts", process: { exe: "/usr/bin/p" } }) + "\n"
    }
    Model.ingestText(store, first, {})
    // A truncation to a body of SEEN_LIMIT + 5 fresh ids: the fold is those,
    // and only 4096 rotated-out ids may stay on top of them.
    // A different exe, so no 64-char tail of `second` matches the guard and
    // it cannot pass for an append onto `first`.
    var second = ""
    for (var j = 0; j < 4096 + 5; j++) {
      second += JSON.stringify({ v: 1, id: "01B" + j, severity: "high", rule: "r", title: "t",
        ts: "2026-09-04T10:00:00Z", surface: "alerts", process: { exe: "/usr/bin/second-body" } }) + "\n"
    }
    var result = Model.ingestText(store, second, {})
    verify(!result.byId["01A0"], "a non-append body is re-folded from scratch")
    compare(result.alerts.length, 4096 + 5)
    compare(store.seenOrder.length, 10 + 4096 + 5, "ten rotated-out ids fit under the cap")
    verify(store.seen["01A0"] === true)
  }

  function test_nothing_already_seen_notifies_twice_within_the_cap() {
    var store = Model.createStore()
    var text = ""
    for (var i = 0; i < 50; i++) {
      text += JSON.stringify({
        v: 1, id: "01" + String(200000 + i), severity: "high", rule: "r",
        title: "t", ts: "2026-09-04T10:00:00Z", surface: "alerts",
        process: { exe: "/usr/bin/p" }
      }) + "\n"
    }
    Model.ingestText(store, text, {})
    var again = Model.ingestText(store, text, {})
    compare(again.newIds.length, 0, "nothing already seen may notify again")
  }

  // ------------------------------------------------- the daemon's decision

  function test_the_daemons_recorded_surface_is_not_second_guessed() {
    // On 2026-09-04 clearing the noise-guard demotions made 251 alerts the
    // daemon had put on the timeline re-surface in the panel, turning 8 real
    // incidents into 51 and burying a live supply-chain exec. The daemon knew
    // the demotion state when it raised each alert; the panel only knows the
    // state now, so it must not re-decide history.
    var demotedThen = Model.decorateAlerts(Model.foldText(JSON.stringify({
      v: 1, id: "A", severity: "high", rule: "moat-exec-untrusted-tmpfs",
      title: "t", ts: "2026-09-03T10:00:00Z", surface: "timeline"
    })), { demotedRules: [] })[0]
    compare(demotedThen.surface, "timeline",
            "an alert the daemon put on the timeline stays there")

    // And the other way round: an alert the daemon stamped `alerts` stays
    // there even when its rule is on the live demoted list. This used to be
    // the asymmetric exception ("a demotion in force NOW quietens the backlog
    // too"), and on 2026-09-05 it silenced a 64-step chain the daemon had
    // raised to high and re-surfaced on purpose, because the chain's rules
    // were in `demoted_rules`. The daemon quietens the backlog itself now,
    // per pattern, when the guard demotes -- so the list is no longer a
    // second implementation of that in the panel.
    var demotedNow = Model.decorateAlerts(Model.foldText(JSON.stringify({
      v: 1, id: "B", severity: "high", rule: "moat-exec-untrusted-tmpfs",
      title: "t", ts: "2026-09-04T10:00:00Z", surface: "alerts"
    })), { demotedRules: ["moat-exec-untrusted-tmpfs"] })[0]
    compare(demotedNow.surface, "alerts", "the daemon's stamp is not overruled by the list")

    // The list still stands in for a record that carries NO stamp at all -- a
    // log written by a daemon from before the field existed.
    var unstamped = Model.decorateAlerts(Model.foldText(JSON.stringify({
      v: 1, id: "B1", severity: "high", rule: "moat-exec-untrusted-tmpfs",
      title: "t", ts: "2026-09-04T10:00:00Z"
    })), { demotedRules: ["moat-exec-untrusted-tmpfs"] })[0]
    compare(unstamped.surface, "timeline", "no stamp: the live list is the best guess")

    // Clearing a demotion is a statement about future alerts and must not
    // resurrect a backlog.
    var clearedSince = Model.decorateAlerts(Model.foldText(JSON.stringify({
      v: 1, id: "B2", severity: "high", rule: "moat-exec-untrusted-tmpfs",
      title: "t", ts: "2026-09-04T10:00:00Z", surface: "timeline"
    })), { demotedRules: [] })[0]
    compare(clearedSince.surface, "timeline", "undemoting does not unbury history")

    // A record written before the daemon stamped the field still gets a sane
    // answer from severity.
    var legacy = Model.decorateAlerts(Model.foldText(JSON.stringify({
      v: 1, id: "C", severity: "high", rule: "r", title: "t",
      ts: "2026-09-04T10:00:00Z"
    })), {})[0]
    compare(legacy.surface, "alerts")
    var legacyLow = Model.decorateAlerts(Model.foldText(JSON.stringify({
      v: 1, id: "D", severity: "low", rule: "r", title: "t",
      ts: "2026-09-04T10:00:00Z"
    })), {})[0]
    compare(legacyLow.surface, "timeline")

    // Suppression and a triage demotion still win: those are per-alert facts,
    // not a global list being applied retroactively.
    var supp = Model.decorateAlerts(Model.foldText(JSON.stringify({
      v: 1, id: "E", severity: "high", rule: "r", title: "t",
      ts: "2026-09-04T10:00:00Z", surface: "alerts", suppressed_by: "user.toml#1"
    })), { showSuppressed: true })[0]
    compare(supp.surface, "timeline")
  }

  function test_an_alert_on_the_timeline_never_becomes_an_incident_needing_you() {
    // The bar counts needs-you INCIDENTS, so alertState is a fourth place the
    // "where does this belong" decision could disagree -- and did.
    var text = ""
    for (var i = 0; i < 4; i++) {
      text += JSON.stringify({
        v: 1, id: "S" + i, severity: "high", rule: "r" + i, title: "t",
        ts: "2026-09-04T10:0" + i + ":00Z",
        surface: i === 0 ? "alerts" : "timeline",
        process: { exe: "/usr/bin/x" }
      }) + "\n"
    }
    var inc = Model.buildIncidents(Model.foldText(text), {})
    compare(inc.length, 4, "all four are still incidents in the timeline")
    compare(Model.needsYouIncidents(inc).length, 1,
            "but only the one the daemon surfaced is waiting on the user")
    compare(Model.verdict(inc, { tetragon: "running", policies: 1,
                                 sensorsLoaded: 1, sensorUnhealthy: false }).count, 1)
  }

  function test_every_surface_consumer_agrees_with_alertSurface() {
    // The consistency test. Four copies of "does this need the user?" is what
    // made the shield say 51 while the daemon had surfaced 8, so this asserts
    // the badge, the tab, incidents and the verdict all land on the same
    // answer -- over a mix that would separate them if any one drifted back to
    // deriving it from severity.
    var rows = [
      { id: "X1", severity: "critical", surface: "alerts" },
      { id: "X2", severity: "high", surface: "alerts" },
      { id: "X3", severity: "high", surface: "timeline" },   // daemon demoted it
      { id: "X4", severity: "critical", surface: "timeline" },
      { id: "X5", severity: "medium", surface: "timeline" },
      { id: "X6", severity: "low", surface: "timeline" }
    ]
    var text = ""
    for (var i = 0; i < rows.length; i++) {
      text += JSON.stringify({
        v: 1, id: rows[i].id, severity: rows[i].severity, rule: "rule-" + rows[i].id,
        title: "t", ts: "2026-09-04T10:0" + i + ":00Z", surface: rows[i].surface,
        process: { exe: "/usr/bin/p" + i }
      }) + "\n"
    }
    var alerts = Model.foldText(text)
    var opts = {}

    var expected = 2   // X1 and X2, the only two the daemon surfaced
    compare(Model.surfaceAlerts(alerts, "alerts", opts).length, expected, "the tab")
    compare(Model.unackedCounts(alerts, opts).badge, expected, "the badge")

    var inc = Model.buildIncidents(alerts, opts)
    compare(Model.needsYouIncidents(inc).length, expected, "incidents")

    var healthy = { tetragon: "running", policies: 1, sensorsLoaded: 1, sensorUnhealthy: false }
    compare(Model.verdict(inc, healthy).count, expected, "the verdict line and the bar")
    compare(Model.barState(Model.verdict(inc, healthy).state, expected).label,
            String(expected), "the bar glyph")

    // And nothing that was timelined can interrupt.
    for (var j = 2; j < rows.length; j++) {
      var a = null
      for (var k = 0; k < alerts.length; k++) if (alerts[k].id === rows[j].id) a = alerts[k]
      verify(!Model.shouldNotify(a, "low", false, opts),
             rows[j].id + " is on the timeline and must not notify")
    }
  }

  function test_the_badge_asks_the_same_function_the_tab_does() {
    // Two copies of "where does this alert belong" is how the shield came to
    // say 51 while the daemon said 8.
    var text = ""
    for (var i = 0; i < 5; i++) {
      text += JSON.stringify({
        v: 1, id: "T" + i, severity: "high", rule: "r", title: "t",
        ts: "2026-09-04T10:0" + i + ":00Z",
        surface: i < 2 ? "alerts" : "timeline"
      }) + "\n"
    }
    var alerts = Model.foldText(text)
    var counts = Model.unackedCounts(alerts, {})
    compare(counts.badge, 2, "only what the daemon surfaced is counted")
    compare(Model.surfaceAlerts(alerts, "alerts", {}).length, 2,
            "and the tab agrees with it")
  }

  function test_an_incident_shows_the_newest_verdict_it_has_not_its_newest_members() {
    // Triage works oldest-first, so on a repeating incident the newest member
    // is the one NOT looked at yet. Reading the verdict off the head meant a
    // repeating incident displayed no analysis while carrying several
    // verdicts -- which made AI analysis look like it had never run.
    var text = ""
    var v = { verdict: "benign", confidence: "high", summary: "read it",
              reasoning: "r", outcome: "annotated" }
    text += JSON.stringify({ v: 1, id: "M1", severity: "high", rule: "r",
      title: "t", ts: "2026-09-04T10:00:00Z", surface: "alerts",
      process: { exe: "/usr/bin/p" }, triage: v }) + "\n"
    text += JSON.stringify({ v: 1, id: "M2", severity: "high", rule: "r",
      title: "t", ts: "2026-09-04T10:05:00Z", surface: "alerts",
      process: { exe: "/usr/bin/p" } }) + "\n"

    var inc = Model.buildIncidents(Model.foldText(text), {})
    compare(inc.length, 1)
    compare(inc[0].id, "M2", "the newest member still carries the incident")
    verify(!!inc[0].verdict, "but the verdict comes from whichever member has one")
    compare(inc[0].verdict.summary, "read it")
    compare(inc[0].awaitingVerdict, true, "and it still says one is outstanding")
  }

  // --------------------------------------------------------------- incidents

  function incAlert(over) {
    var base = {
      v: 1, id: "01A", severity: "high", rule: "moat-exec-untrusted-home",
      family: "exec", title: "Binary executed from a cache or download directory",
      ts: "2026-09-04T10:00:00Z", acked: false, action_taken: "none",
      process: { exe: "/usr/bin/quickshell" }
    }
    for (var k in over) base[k] = over[k]
    return base
  }

  function incidentsOf(list, options) {
    var text = ""
    for (var i = 0; i < list.length; i++) text += JSON.stringify(list[i]) + "\n"
    return Model.buildIncidents(Model.foldText(text), options || {})
  }

  function test_the_same_rule_and_program_collapse_into_one_incident() {
    // The wall of identical rows this redesign exists to remove: 3 records of
    // the same detection by the same program are ONE incident, not three.
    var inc = incidentsOf([
      incAlert({ id: "01A", ts: "2026-09-04T10:00:00Z" }),
      incAlert({ id: "01B", ts: "2026-09-04T10:05:00Z" }),
      incAlert({ id: "01C", ts: "2026-09-04T10:09:00Z" })
    ])
    compare(inc.length, 1)
    compare(inc[0].count, 3)
    compare(inc[0].firstSeen, "2026-09-04T10:00:00Z")
    compare(inc[0].lastSeen, "2026-09-04T10:09:00Z")
    // Actions name an alert id, and it has to be the newest -- the only member
    // whose process might still exist.
    compare(inc[0].id, "01C")
  }

  function test_a_different_program_is_a_different_incident() {
    var inc = incidentsOf([
      incAlert({ id: "01A", process: { exe: "/usr/bin/curl" } }),
      incAlert({ id: "01B", process: { exe: "/usr/bin/bsdtar" } })
    ])
    compare(inc.length, 2)
  }

  function test_an_interpreter_is_named_by_its_script_not_itself() {
    // Otherwise every postinstall in the product is an incident about "python3".
    var inc = incidentsOf([
      incAlert({ id: "01A", process: { exe: "/usr/bin/python3" },
                 actor: { provenance: "user", script: "/tmp/x/setup.py" } })
    ])
    compare(inc[0].program, "setup.py")
  }

  function test_the_daemons_own_repeat_count_is_carried_not_recounted() {
    // The daemon already folds identical repeats into one record with `count`.
    var inc = incidentsOf([incAlert({ id: "01A", count: 68 })])
    compare(inc[0].count, 68, "68 repeats is one incident of 68, not one of 1")
  }

  // --- the three states -----------------------------------------------------

  function test_state_says_what_is_wanted_from_the_user() {
    var quiet = incidentsOf([incAlert({ id: "01A", suppressed_by: "user.toml#1" })],
                            { showSuppressed: true })
    compare(quiet[0].state, "expected", "a rule covers it")

    var read = incidentsOf([incAlert({ id: "01A", triage: {
      verdict: "benign", confidence: "high", summary: "s", reasoning: "r",
      outcome: "demoted" } })])
    compare(read[0].state, "explained", "Moat read it and decided")

    var acted = incidentsOf([incAlert({ id: "01A", action_taken: "killed" })])
    compare(acted[0].state, "contained")

    compare(incidentsOf([incAlert({ id: "01A", acked: true })])[0].state, "closed")
    compare(incidentsOf([incAlert({ id: "01A" })])[0].state, "needsYou")
  }

  function test_a_user_rule_outranks_a_model_verdict() {
    // The model must never be able to overrule a decision the user made. An
    // allowlisted alert reads "expected" even when triage called it malicious.
    var inc = incidentsOf([incAlert({
      id: "01A", suppressed_by: "user.toml#1",
      triage: { verdict: "malicious", confidence: "high", summary: "s",
                reasoning: "r", outcome: "annotated" }
    })], { showSuppressed: true })
    compare(inc[0].state, "expected")
  }

  function test_one_resolved_repeat_does_not_close_the_incident() {
    // 67 acked and one still open is an incident that needs you.
    var inc = incidentsOf([
      incAlert({ id: "01A", acked: true }),
      incAlert({ id: "01B", acked: true }),
      incAlert({ id: "01C", acked: false })
    ])
    compare(inc.length, 1)
    compare(inc[0].state, "needsYou")
  }

  // --- the queue ordering ---------------------------------------------------

  function test_the_queue_is_ordered_by_uncertainty_not_severity() {
    // 3c: "a HIGH it is sure about matters less than a MEDIUM it can't place".
    var inc = incidentsOf([
      incAlert({ id: "01A", severity: "critical", rule: "moat-cred-ssh-private-key-read",
                 triage: { verdict: "suspicious", confidence: "high", summary: "s",
                           reasoning: "r", outcome: "annotated" } }),
      incAlert({ id: "01B", severity: "high", rule: "moat-exec-untrusted-tmpfs",
                 triage: { verdict: "unclear", confidence: "low", summary: "s",
                           reasoning: "r", outcome: "annotated" } })
    ])
    var q = Model.needsYouIncidents(inc)
    compare(q.length, 2)
    compare(q[0].rule, "moat-exec-untrusted-tmpfs",
            "the one nobody can place outranks the critical Moat is sure about")
    verify(q[0].uncertainty > q[1].uncertainty)
  }

  function test_a_confident_benign_verdict_leaves_the_queue_entirely() {
    // The other half of the same rule: once Moat has read something and is sure,
    // it stops being a thing the user is asked about. This is what makes the
    // needs-you count fall rather than just re-order.
    var inc = incidentsOf([incAlert({ id: "01A", severity: "critical",
      triage: { verdict: "benign", confidence: "high", summary: "s",
                reasoning: "r", outcome: "demoted" } })])
    compare(inc[0].state, "explained")
    compare(Model.needsYouIncidents(inc).length, 0)
    compare(Model.verdict(inc, healthy()).line, "Nothing needs you.")
  }

  // --- the verdict line -----------------------------------------------------

  function healthy() {
    return { tetragon: "running", policies: 32, sensors_loaded: 32, sensor_unhealthy: false }
  }

  function test_the_verdict_line_has_exactly_four_forms() {
    var none = Model.verdict([], healthy())
    compare(none.line, "Nothing needs you.")
    compare(none.tone, "calm")

    var one = Model.verdict(incidentsOf([incAlert({ id: "01A" })]), healthy())
    compare(one.line, "One thing needs you.")
    compare(one.tone, "alarm")

    var three = Model.verdict(incidentsOf([
      incAlert({ id: "01A", rule: "r1" }),
      incAlert({ id: "01B", rule: "r2" }),
      incAlert({ id: "01C", rule: "r3" })
    ]), healthy())
    compare(three.line, "Three things need you.")

    // Never a count of events: 68 repeats of one thing is still "One thing".
    var many = Model.verdict(incidentsOf([incAlert({ id: "01A", count: 68 })]), healthy())
    compare(many.line, "One thing needs you.")
  }

  function test_the_panel_will_not_claim_calm_it_cannot_prove() {
    // 2f: a blind sensor and a quiet machine look identical from here. On
    // 2026-09-03 tetragon was dead for 25 minutes and every surface said
    // "running", which is the whole reason this gate exists.
    var dead = { tetragon: "running", policies: 32, sensors_loaded: 11, sensor_unhealthy: true }
    var v = Model.verdict([], dead)
    compare(v.line, "Watching, with one gap.")
    compare(v.tone, "accent")
    verify(!Model.sensorHealthy(dead))
    verify(!Model.sensorHealthy({ tetragon: "running", policies: 32, sensors_loaded: 11 }),
           "fewer sensors loaded than policies is a gap even without the flag")
    verify(Model.sensorHealthy(healthy()))

    // Something needing you still outranks the gap -- the gap is what you say
    // when there is nothing else to say.
    var both = Model.verdict(incidentsOf([incAlert({ id: "01A" })]), dead)
    compare(both.line, "One thing needs you.")
  }

  // --- the copy contract ----------------------------------------------------

  function test_titles_name_a_consequence_not_a_detection() {
    compare(Copy.titleFor({ rule: "moat-persist-hypr-config-write" }),
            "Something added itself to your login")
    compare(Copy.titleFor({ rule: "moat-cred-ssh-private-key-read" }),
            "A program you don't recognise read your SSH key")
    // An unknown detection degrades to its own old wording, never to blank.
    compare(Copy.titleFor({ rule: "moat-not-written-yet", title: "Old string" }),
            "Old string")
    compare(Copy.stakeFor({ rule: "moat-not-written-yet" }), "")
  }

  // --- Advanced (`rawDetail`) -----------------------------------------------
  //
  // A rendering choice and nothing else. These pin both halves of that: that it
  // really does swap the voice, and that it reaches nothing which decides what
  // is surfaced, counted or notified.

  function rawAlert() {
    return {
      id: "01RAW", ts: "2026-09-03T10:00:00.000Z",
      rule: "moat-persist-hypr-config-write",
      title: "Hyprland configuration modified by a non-editor",
      summary: "sed (pid 4242) wrote /home/dan/.config/hypr/hyprland.conf.",
      severity: "high", severity_base: "medium",
      severity_reason: "actor is unpackaged",
      family: "persist", surface: "alerts", mode: "monitor", action_taken: "none",
      count: 3,
      process: { pid: 4242, uid: 1000, exe: "/usr/bin/sed", args: "-i s/a/b/ hyprland.conf",
                 cwd: "/home/dan/.config/hypr", start_ts: "2026-09-03T09:59:59.000Z",
                 ancestry: [{ pid: 40, exe: "/bin/bash" }, { pid: 1, exe: "/usr/lib/systemd/systemd" }] },
      actions: ["ignore"]
    }
  }

  function test_advanced_prints_the_detections_own_title_and_summary() {
    var alert = suite.rawAlert()

    // Off: the copy table wins, exactly as before.
    compare(Copy.titleFor(alert), "Something added itself to your login")
    compare(Copy.titleFor(alert, false), "Something added itself to your login")

    // On: the daemon's own words, table skipped even though copy exists.
    compare(Copy.titleFor(alert, true), "Hyprland configuration modified by a non-editor")
    compare(Copy.stakeFor(alert, true), alert.summary)
    verify(Copy.stakeFor(alert, false) !== alert.summary,
           "the default voice must not be the daemon's summary")

    // And it still degrades rather than blanking when the daemon sent nothing.
    compare(Copy.titleFor({ rule: "moat-nope" }, true), "moat-nope")
    compare(Copy.stakeFor({ rule: "moat-nope" }, true), "")
  }

  function test_advanced_reaches_the_title_and_the_stake_and_nothing_else() {
    var alerts = [suite.rawAlert()]
    var plain = Model.buildIncidents(alerts, {})
    var raw = Model.buildIncidents(alerts, { rawDetail: true })

    compare(plain.length, 1)
    compare(raw.length, 1)
    verify(plain[0].title !== raw[0].title, "the title is what the setting changes")
    compare(raw[0].title, "Hyprland configuration modified by a non-editor")

    // Everything that decides what happens to this incident is identical.
    compare(raw[0].key, plain[0].key)
    compare(raw[0].state, plain[0].state)
    compare(raw[0].severity, plain[0].severity)
    compare(raw[0].count, plain[0].count)
    compare(raw[0].coveredBy, plain[0].coveredBy)
    compare(raw[0].uncertainty, plain[0].uncertainty)
    compare(Model.needsYouIncidents(raw).length, Model.needsYouIncidents(plain).length)

    // Over the whole fixture, not one hand-made alert: every incident's key,
    // state, severity and covering rule is the same in both modes, and so is
    // the badge. Only the wording moves.
    var log = suite.alertsFromFixture()
    var a = Model.buildIncidents(log, suite.demoted)
    var b = Model.buildIncidents(log, { demotedRules: [suite.demotedRule], rawDetail: true })
    compare(b.length, a.length)
    var moved = 0
    for (var i = 0; i < a.length; i++) {
      compare(b[i].key, a[i].key)
      compare(b[i].state, a[i].state)
      compare(b[i].severity, a[i].severity)
      compare(b[i].coveredBy, a[i].coveredBy)
      compare(b[i].count, a[i].count)
      if (b[i].title !== a[i].title) moved++
    }
    verify(moved > 0, "the fixture must actually exercise a rule that has copy")
    compare(JSON.stringify(Model.unackedCounts(log, { demotedRules: [suite.demotedRule], rawDetail: true })),
            JSON.stringify(Model.unackedCounts(log, suite.demoted)),
            "the badge cannot notice a rendering setting")
  }

  function test_advanced_facts_are_the_recorded_fields() {
    var facts = Model.rawFacts(suite.rawAlert())
    function valueOf(label) {
      for (var i = 0; i < facts.length; i += 2) if (facts[i] === label) return facts[i + 1]
      return null
    }
    compare(valueOf("rule"), "moat-persist-hypr-config-write")
    compare(valueOf("exe"), "/usr/bin/sed")
    compare(valueOf("pid"), "4242")
    compare(valueOf("uid"), "1000")
    compare(valueOf("args"), "-i s/a/b/ hyprland.conf")
    compare(valueOf("cwd"), "/home/dan/.config/hypr")
    compare(valueOf("surface"), "alerts")
    // Severity as severity, with the base and the reason beside it.
    compare(valueOf("severity"), "high  (base medium — actor is unpackaged)")
    // uid 0 is a value, not an absence.
    var asRoot = suite.rawAlert()
    asRoot.process.uid = 0
    compare(Model.rawFacts(asRoot)[Model.rawFacts(asRoot).indexOf("uid") + 1], "0")

    // The chain, oldest first, with pids and full paths -- not the arrow line.
    var chain = Model.ancestryLines(suite.rawAlert())
    compare(chain.length, 3)
    compare(chain[0], "1  /usr/lib/systemd/systemd")
    compare(chain[2], "4242  /usr/bin/sed")

    compare(Model.rawFacts(null).length, 0)
  }

  function test_advanced_severity_line_says_the_severity_even_when_nothing_moved_it() {
    // severityChangeLine is the default voice's version and is silent here;
    // Advanced exists to print it anyway.
    var steady = { severity: "medium", severity_base: "medium" }
    compare(Model.severityChangeLine(steady), "")
    compare(Model.rawSeverityLine(steady), "medium")
    compare(Model.rawSeverityLine({ severity: "low", severity_base: "high",
                                    severity_reason: "actor is official" }),
            "low  (base high — actor is official)")
  }

  function test_no_title_or_stake_uses_a_word_the_panel_has_banned() {
    // 3g's list is only real if it fails a build. Every shipped string, checked.
    var rules = Object.keys(Copy.COPY)
    verify(rules.length >= 32, "every shipped detection needs copy, got " + rules.length)
    for (var i = 0; i < rules.length; i++) {
      var c = Copy.COPY[rules[i]]
      var badTitle = Copy.bannedWordsIn(c.title)
      var badStake = Copy.bannedWordsIn(c.stake)
      compare(badTitle.length, 0, rules[i] + " title says: " + badTitle.join(", "))
      compare(badStake.length, 0, rules[i] + " stake says: " + badStake.join(", "))
      verify(c.title.length > 0 && c.title.length < 80, rules[i] + " title length")
      verify(c.stake.length > 0, rules[i] + " needs a stake")
      // No rule id ever leaks into a title.
      verify(c.title.indexOf("moat-") === -1, rules[i] + " title carries a rule id")
    }
  }

  function test_advanced_is_an_escape_hatch_not_a_loophole_in_the_banned_words() {
    // The point of the list is that detection 33 cannot reintroduce log-speak
    // into the DEFAULT voice. Advanced must not become the way to do that.
    //
    // 1. The rule still binds every shipped string, whatever mode the panel is
    //    in -- Copy.COPY is one table and bannedWordsIn does not take a mode.
    var rules = Object.keys(Copy.COPY)
    for (var i = 0; i < rules.length; i++) {
      compare(Copy.bannedWordsIn(Copy.COPY[rules[i]].title).length, 0)
      compare(Copy.bannedWordsIn(Copy.COPY[rules[i]].stake).length, 0)
    }

    // 2. An alert whose daemon title is full of banned words renders clean in
    //    the default voice, and verbatim in Advanced. Both halves matter: the
    //    first is the rule holding, the second is Advanced actually working.
    var logSpeak = {
      rule: "moat-persist-hypr-config-write",
      title: "kprobe lsm hook: uid 1000 pid 42 exe /usr/bin/sed, severity high, allowlist miss",
      summary: "tetragon policy fired"
    }
    compare(Copy.bannedWordsIn(Copy.titleFor(logSpeak)).length, 0,
            "the default voice never prints the daemon's vocabulary")
    verify(Copy.bannedWordsIn(Copy.titleFor(logSpeak, true)).length > 0,
            "Advanced is where those words are allowed, and it is the only place")

    // 3. A detection with NO copy has always fallen back to the daemon's own
    //    string, in both modes. That is the pre-existing floor, not something
    //    Advanced introduced, and it is why the list is enforced over the table
    //    rather than over titleFor's output.
    var uncovered = { rule: "moat-not-written-yet", title: "severity high on pid 42" }
    verify(!Copy.hasCopy("moat-not-written-yet"))
    compare(Copy.titleFor(uncovered), Copy.titleFor(uncovered, true))
  }

  function test_every_detection_the_daemon_ships_has_copy() {
    // The 42 policies in policies/*.yaml. A new detection added without copy
    // fails here rather than shipping as log-speak.
    var shipped = [
      "moat-cred-registry-token-read", "moat-cred-etc-shadow-read",
      "moat-cred-browser-secrets-read", "moat-cred-ssh-private-key-read",
      "moat-cred-ai-credentials-read", "moat-persist-hypr-config-write",
      "moat-cred-gnupg-keyring-read", "moat-persist-omarchy-hooks-write",
      "moat-persist-desktop-entry-write", "moat-cred-vcs-token-read",
      "moat-persist-authorized-keys-write", "moat-cred-cloud-credentials-read",
      "moat-rootkit-kernel-module-load", "moat-persist-agent-config-write",
      "moat-exec-untrusted-home", "moat-rootkit-ldso-preload-write",
      "moat-persist-git-hook-write", "moat-priv-setcap-xattr",
      "moat-rootkit-bpffs-write", "moat-persist-autostart-write",
      "moat-priv-ptrace-attach", "moat-exec-untrusted-tmpfs",
      "moat-rootkit-bpf-prog-load", "moat-persist-omarchy-menu-extension-write",
      "moat-persist-omarchy-plugin-write", "moat-priv-setuid-chmod",
      "moat-net-suspicious-port-egress", "moat-net-tmpfs-binary-egress",
      "moat-shell-reverse-shell-connect", "moat-persist-shell-rc-write",
      "moat-persist-system-unit-write", "moat-priv-proc-mem-access",
      // self-protection, covering-tracks and project-local credentials
      "moat-rootkit-evidence-tamper", "moat-rootkit-sensor-tamper",
      "moat-rootkit-history-tamper", "moat-rootkit-system-log-tamper",
      "moat-rootkit-trust-store-write", "moat-cred-project-token-read",
      "moat-cred-ssh-agent-socket", "moat-cred-ssh-recon-read",
      "moat-priv-container-socket-connect", "moat-persist-git-config-write"
    ]
    var cov = Copy.coverage(shipped)
    compare(cov.missing.length, 0, "no copy for: " + cov.missing.join(", "))
    compare(cov.have, 42)
  }

  // ------------------------------------------------------------------ triage
  //
  // LEARNING 2c. The verdict is a model's opinion attached to kernel evidence,
  // so what is tested here is mostly what it is NOT allowed to look like.

  function triagedAlert(triage, severity) {
    return Model.decorateAlerts(Model.foldText(JSON.stringify({
      v: 1, id: "A", severity: severity || "high", rule: "moat-exec-untrusted-home",
      title: "t", ts: "2026-09-03T10:00:00Z", triage: triage
    })), {})[0]
  }

  function test_no_triage_is_the_normal_case() {
    var alert = triagedAlert(undefined)
    compare(alert.triage, null, "auto_triage off means every alert has none")
    compare(alert.surface, "alerts")
    compare(Model.triageChip(alert), "")
    compare(Model.triageOutcomeText(alert), "")
  }

  function test_a_demoting_verdict_moves_the_alert_to_the_timeline() {
    var alert = triagedAlert({
      agent: "claude", at: "2026-09-03T10:01:00Z", verdict: "benign",
      confidence: "high", summary: "your own AUR install", reasoning: "makepkg",
      outcome: "demoted"
    })
    compare(alert.triage.demoted, true)
    compare(alert.demoted, true)
    // The daemon sets surface on the alert, but the panel derives its own from
    // rule and severity — so without alertSurface reading the verdict, a triage
    // demotion would change nothing the user could see.
    compare(alert.surface, "timeline", "a triage demotion has to reach the tab")
    compare(alert.visible, true, "demoted is quiet, never hidden")
    // The ceiling: everything else about the alert is untouched.
    compare(alert.acked, false)
    compare(alert.severity, "high")
    compare(alert.suppressed_by, "")
  }

  function test_a_withheld_verdict_stays_in_the_badge_and_says_why() {
    var alert = triagedAlert({
      verdict: "benign", confidence: "high", summary: "s", reasoning: "r",
      outcome: "withheld: critical is above the high demote ceiling"
    }, "critical")
    compare(alert.triage.demoted, false)
    compare(alert.triage.withheld, "critical is above the high demote ceiling")
    compare(alert.surface, "alerts", "withheld means it stays where it was")
    verify(Model.triageOutcomeText(alert).indexOf("Left in the badge count") === 0)
    verify(Model.triageOutcomeText(alert).indexOf("above the high demote ceiling") > 0)
  }

  function test_an_annotating_verdict_changes_nothing_about_the_tab() {
    var alert = triagedAlert({
      verdict: "malicious", confidence: "high", summary: "s", reasoning: "r",
      outcome: "annotated"
    })
    compare(alert.surface, "alerts")
    compare(alert.demoted, false)
    compare(Model.triageChip(alert), "malicious · high")
    compare(Model.triageOutcomeText(alert), "Recorded against this alert. Nothing was changed.")

    // A raised outcome must say it raised, not "nothing changed" -- the agent
    // pushed it onto the badge (the safe direction of demote).
    var raised = triagedAlert({
      verdict: "malicious", confidence: "high", summary: "s", reasoning: "r",
      outcome: "raised"
    })
    verify(Model.triageOutcomeText(raised).indexOf("Raised to the badge") === 0)
  }

  // The verdict came from a language model that had just read hostile input,
  // so an unrecognized value must land somewhere harmless rather than being
  // rendered raw or believed.
  function test_an_unrecognized_verdict_degrades_to_unclear_not_to_benign() {
    var alert = triagedAlert({
      verdict: "definitely-fine", confidence: "absolute", summary: "s",
      reasoning: "r", outcome: "demoted"
    })
    compare(alert.triage.verdict, "unclear")
    compare(alert.triage.confidence, "low")
  }

  function test_a_verdict_with_nothing_said_is_not_a_verdict() {
    compare(Model.normalizeTriage(null), null)
    compare(Model.normalizeTriage({ verdict: "benign", confidence: "high" }), null)
    compare(Model.normalizeTriage({ verdict: "benign", summary: "   " }), null)
    // Reasoning alone is enough to be worth showing.
    verify(Model.normalizeTriage({ verdict: "benign", reasoning: "r" }) !== null)
  }

  function test_the_proposed_allowlist_is_carried_as_text_and_capped() {
    var t = Model.normalizeTriage({
      verdict: "benign", confidence: "high", summary: "s", reasoning: "r",
      proposed_allowlist: "  [[rule]]\nname = \"x\"  ",
      recommend: ["a", "b", "c", "d", "e", "f", "g", "h", "", "  "]
    })
    compare(t.proposed_allowlist, "[[rule]]\nname = \"x\"")
    compare(t.recommend.length, 6, "a model does not get an unbounded list")
    compare(t.outcome, "annotated", "a missing outcome is the harmless one")
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
    // The button never carries a vendor name: `omarchy default agent` may be
    // any of them, and the label has to describe what the button DOES rather
    // than which model happens to be configured. The name is a tooltip, which
    // is evidence and not a promise.
    compare(Model.analyzeLabel("claude"), "Open in the Omarchy agent")
    compare(Model.analyzeLabel("codex"), "Open in the Omarchy agent")
    compare(Model.analyzeLabel(""), "", "no default agent means no button")
    verify(Model.analyzeTooltip("codex").indexOf("codex") >= 0)
    verify(Model.analyzeTooltip("codex").indexOf("terminal") >= 0,
           "the tooltip says it leaves the panel, because it does")
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

  // ==========================================================================
  //  Stages 2, 3, 5 and 6 of docs/design/PLAN.md
  // ==========================================================================

  // --- the sensor gate, against the shape the panel actually passes ---------

  function test_the_sensor_gate_reads_the_shape_the_panel_hands_it() {
    // The live panel never passes a raw status: Service.status is the output of
    // normalizeStatus, which renames sensor_unhealthy -> sensorUnhealthy and
    // sensors_loaded -> sensorsLoaded. Reading only the snake_case names meant
    // the gate never fired on a real machine while every test that hand-wrote a
    // raw status passed, which is exactly the failure 2f exists to prevent.
    var raw = { ok: true, tetragon: "running", policies: 32,
                sensors_loaded: 11, sensor_unhealthy: true }
    verify(!Model.sensorHealthy(raw), "raw daemon shape")
    verify(!Model.sensorHealthy(Model.normalizeStatus(raw)), "normalized shape")
    compare(Model.verdict([], Model.normalizeStatus(raw)).line, "Watching, with one gap.")

    var loadedShort = Model.normalizeStatus({ ok: true, tetragon: "running",
                                              policies: 32, sensors_loaded: 11 })
    verify(!Model.sensorHealthy(loadedShort),
           "fewer sensors loaded than policies is a gap even without the flag")
    verify(Model.sensorHealthy(Model.normalizeStatus(
      { ok: true, tetragon: "running", policies: 32, sensors_loaded: 32 })))
  }

  // --- 1c, the silence choice ----------------------------------------------

  function scopedAlert(hint) {
    return incAlert({
      id: "01S",
      process: { exe: "/usr/bin/claude", ancestry: [{ pid: 2, exe: "/usr/bin/makepkg" }] },
      explain: {
        if_expected: {
          hint: hint,
          options: [
            { scope: "rule", line: "[[rule]]\nname = \"r\"\n" },
            { scope: "exe", line: "[[rule]]\nexe = \"/usr/bin/claude\"\n" },
            { scope: "parent", line: "[[rule]]\nparent = \"/usr/bin/makepkg\"\n" }
          ]
        }
      }
    })
  }

  function test_the_broadest_silence_is_never_first_and_never_recommended() {
    // 1c draws the machine-wide scope duller and last. It is the one choice
    // whose consequences cannot be seen from the screen, so even a daemon that
    // recommends it must not get it into the first (pre-selected) position.
    var alerts = Model.foldText(JSON.stringify(scopedAlert("rule")) + "\n")
    var scopes = Model.silenceScopes(alerts[0], 68)
    compare(scopes.length, 3)
    compare(scopes[scopes.length - 1].scope, "rule")
    verify(scopes[scopes.length - 1].broadest)
    for (var i = 0; i < scopes.length; i++) {
      if (scopes[i].scope === "rule") verify(!scopes[i].recommended,
        "the machine-wide scope must never arrive recommended")
    }
  }

  function test_scope_chips_are_consequences_and_the_toml_is_the_daemons() {
    var alerts = Model.foldText(JSON.stringify(scopedAlert("exe")) + "\n")
    var scopes = Model.silenceScopes(alerts[0], 68)
    compare(scopes[0].scope, "exe")
    compare(scopes[0].label, "when claude does it")
    // The parent chip names the parent the alert actually recorded.
    var parent = null
    for (var i = 0; i < scopes.length; i++) if (scopes[i].scope === "parent") parent = scopes[i]
    compare(parent.label, "anything makepkg starts")
    // Both halves of the consequence, always: what goes quiet AND what still
    // reaches you. A silence explained only by what it silences is how somebody
    // agrees to a rule they would not have written.
    verify(scopes[0].consequence.silences.indexOf("68") !== -1)
    verify(scopes[0].consequence.through.length > 0)
    // The TOML is the daemon's own string, carried through untouched. Nothing
    // in the panel composes one.
    compare(scopes[0].line, "[[rule]]\nexe = \"/usr/bin/claude\"\n")
  }

  function test_an_alert_with_no_offered_scope_offers_no_chip() {
    // No invented scopes. An alert the daemon has no rule for gets an empty
    // list, and the view says so instead of sending a scope nobody offered.
    compare(Model.silenceScopes(incAlert({}), 1).length, 0)
    compare(Model.silenceScopes(null, 1).length, 0)
  }

  // --- 1d, History ----------------------------------------------------------

  function test_history_groups_by_local_day_newest_first() {
    var now = Date.parse("2026-09-04T12:00:00Z")
    var inc = incidentsOf([
      incAlert({ id: "01A", rule: "r1", ts: "2026-09-04T10:00:00Z" }),
      incAlert({ id: "01B", rule: "r2", ts: "2026-09-03T10:00:00Z" }),
      incAlert({ id: "01C", rule: "r3", ts: "2026-08-20T10:00:00Z" })
    ])
    var days = Model.historyDays(inc, now)
    compare(days.length, 3)
    // Newest first, and named the way a person names a day they are trying to
    // remember: by how recent, then by weekday, then by date.
    compare(days[0].label, "Today")
    compare(days[1].label, "Yesterday")
    compare(days[2].label, "20 Aug")
    compare(days[0].incidents.length, 1)
  }

  function test_the_day_header_counts_decisions_not_events() {
    var now = Date.parse("2026-09-04T12:00:00Z")
    // One needing a decision, one covered by a rule, one already acted on --
    // and the covered one carrying 41 events, which must NOT become "41" in the
    // header. A number in this panel is a number of decisions.
    var inc = incidentsOf([
      incAlert({ id: "01A", rule: "r1", ts: "2026-09-04T10:00:00Z" }),
      incAlert({ id: "01B", rule: "r2", ts: "2026-09-04T10:01:00Z",
                 count: 41, suppressed_by: "user.toml#1" }),
      incAlert({ id: "01C", rule: "r3", ts: "2026-09-04T10:02:00Z", action_taken: "killed" })
    ], { showSuppressed: true })
    var days = Model.historyDays(inc, now)
    compare(days.length, 1)
    compare(days[0].needed, 1)
    compare(days[0].covered, 1)
    compare(days[0].contained, 1)
    verify(days[0].summary.indexOf("1 needed you") === 0)
    compare(days[0].summary.indexOf("41"), -1, "the header must not count events")

    // A day with nothing waiting says so first.
    var quiet = Model.daySummary({ needed: 0, explained: 3, covered: 41, contained: 0 })
    verify(quiet.indexOf("nothing needed you") === 0)
  }

  function test_history_filters_split_decisions_from_silence() {
    var inc = incidentsOf([
      incAlert({ id: "01A", rule: "r1" }),
      incAlert({ id: "01B", rule: "r2", suppressed_by: "baseline.toml#3" }),
      incAlert({ id: "01C", rule: "r3", action_taken: "killed" })
    ], { showSuppressed: true })
    compare(Model.filterHistory(inc, "everything").length, 3)
    // "Needed you" is the decisions column: still open, or already acted on.
    compare(Model.filterHistory(inc, "needsYou").length, 2)
    compare(Model.filterHistory(inc, "covered").length, 1)
  }

  function test_a_covered_row_names_whose_decision_silenced_it() {
    // 1d appends the covering rule to the title in a dimmer colour. The daemon
    // names it as a fragment and an index, which is a file path and an ordinal
    // -- the two things a title is not allowed to carry. What the user needs is
    // WHOSE decision it was.
    var mine = incidentsOf([incAlert({ id: "01A", count: 68, suppressed_by: "user.toml#1" })],
                           { showSuppressed: true })
    compare(Model.historyNote(mine[0]), "·  68 times  ·  a rule you added")
    var learned = incidentsOf([incAlert({ id: "01B", suppressed_by: "baseline.toml#3" })],
                              { showSuppressed: true })
    compare(Model.historyNote(learned[0]), "·  a rule Moat learned")
    var demoted = incidentsOf([incAlert({ id: "01C", suppressed_by: "demoted:moat-x" })],
                              { showSuppressed: true })
    compare(Model.historyNote(demoted[0]), "·  Moat stopped asking")

    // A rule the noise guard demoted carries NO marker on the alert -- it is
    // quiet because of `status.demoted_rules[]` -- so the phrase is resolved
    // against the same demoted set the state was. Without that, half the
    // covered rows in History said "covered" and explained nothing.
    var byGuard = incidentsOf([incAlert({ id: "01E", rule: "moat-x-quiet" })],
                              { demotedRules: ["moat-x-quiet"] })
    compare(byGuard[0].state, "expected")
    compare(Model.historyNote(byGuard[0]), "·  Moat stopped asking")
    // Nothing to qualify: no suffix at all rather than an empty separator.
    compare(Model.historyNote(incidentsOf([incAlert({ id: "01D" })])[0]), "")
  }

  // --- 1e, Rules ------------------------------------------------------------

  function shippedRule(over) {
    var base = { name: "moat-cred-ssh-private-key-read", exe: "/usr/bin/ssh",
                 source: "shipped", removable: false, index: 1, path: null,
                 file: "/etc/moat/allowlist.d/omarchy-default.toml" }
    for (var k in over) base[k] = over[k]
    return base
  }

  function test_sixteen_shipped_rules_become_about_five_lines() {
    var parsed = Model.parseAllowlist({ ok: true, rules: [
      shippedRule({ exe: "/usr/bin/ssh" }),
      shippedRule({ exe: "/usr/bin/ssh-agent" }),
      shippedRule({ exe: "/usr/bin/ssh-add" }),
      shippedRule({ exe: "/usr/bin/git", name: "moat-cred-vcs-token-read" }),
      shippedRule({ exe: "/usr/bin/pacman", name: "moat-pkg-downloader-exec" }),
      shippedRule({ exe: "/usr/bin/makepkg", name: "moat-pkg-downloader-exec" }),
      shippedRule({ exe: "/usr/bin/hyprctl", name: "moat-persist-hypr-config-write" }),
      shippedRule({ exe: "/usr/bin/firefox", name: "moat-cred-browser-secrets-read" })
    ] })
    var groups = Model.shippedRuleGroups(parsed.rules)
    // Five groups, named for what they cover rather than for a detection.
    var labels = groups.map(function (g) { return g.label })
    compare(groups.length, 5)
    verify(labels.indexOf("Your SSH tools") !== -1)
    verify(labels.indexOf("git") !== -1)
    verify(labels.indexOf("Your package manager") !== -1)
    verify(labels.indexOf("Your desktop") !== -1)
    verify(labels.indexOf("Browsers") !== -1)
    // Biggest group first, and every group carries the entries it collapsed.
    compare(groups[0].label, "Your SSH tools")
    compare(groups[0].count, 3)
    compare(groups[0].rules.length, 3)
    // No rule id anywhere in a group name or its reason.
    for (var i = 0; i < groups.length; i++) {
      compare(groups[i].label.indexOf("moat-"), -1)
      compare(groups[i].reason.indexOf("moat-"), -1)
    }
  }

  function test_everything_unrecognised_lands_in_one_group_and_lands_last() {
    var parsed = Model.parseAllowlist({ ok: true, rules: [
      shippedRule({ exe: "/opt/vendor/thing", name: "moat-exec-untrusted-home" }),
      shippedRule({ exe: "/opt/vendor/other", name: "moat-exec-untrusted-home" }),
      shippedRule({ exe: "/usr/bin/ssh" })
    ] })
    var groups = Model.shippedRuleGroups(parsed.rules)
    compare(groups.length, 2)
    // A group of one is a card again, so unmatched programs share one line --
    // and it sorts last however many entries it holds.
    compare(groups[groups.length - 1].key, "other")
    compare(groups[groups.length - 1].count, 2)
  }

  function test_a_rule_you_added_carries_what_it_has_silenced_since() {
    // The silenced-count column is the ONLY way a user can tell whether a rule
    // they wrote was a good idea. It comes from the daemon's own per-tuple
    // counters, which keep counting after an allowlist entry starts hiding the
    // tuple -- which is exactly what makes them the right number.
    var parsed = Model.parseAllowlist({ ok: true, rules: [{
      index: 1, file: "/etc/moat/allowlist.d/user.toml", source: "user",
      removable: true, name: "moat-ai-cli-in-pkg-subtree", exe: "/usr/bin/claude",
      // `path: null` the way moatd sends it: the key is always present, and
      // that is what tells normalizeAllowlistRule that `file` is the FRAGMENT
      // rather than the rule's own file glob.
      path: null,
      comment: "added 2026-09-03 from alert 01M: An install started an AI tool"
    }] })
    var exported = Model.parseBaselineExport({ tuples: [
      { rule: "moat-ai-cli-in-pkg-subtree", exe: "/usr/bin/claude",
        count: 68, suppressed: true, last_seen: "2026-09-04T10:00:00Z" },
      { rule: "moat-ai-cli-in-pkg-subtree", exe: "/usr/bin/claude",
        count: 4, suppressed: true, parent: "/usr/bin/bash",
        last_seen: "2026-09-04T11:00:00Z" }
    ] })
    var rows = Model.userRuleRows(parsed.rules, exported.tuples)
    compare(rows.length, 1)
    compare(rows[0].silenced, 72)
    compare(rows[0].label, "claude, running during package installs")
    // The provenance line is parsed, not printed: the daemon's comment carries
    // an alert id and an old log-speak title, and neither belongs on screen.
    compare(rows[0].provenance, "you added this on 2026-09-03")
    compare(rows[0].provenance.indexOf("01M"), -1)
    compare(rows[0].index, 1)
    compare(rows[0].file, "user.toml")
    verify(rows[0].removable)
  }

  function test_a_script_only_rule_names_the_script_not_an_empty_program() {
    // 2026-09-07: `script` shipped as a matcher before the panel knew about it.
    // An entry written by `moatctl allow --script` has no `exe` at all, so the
    // Rules tab rendered it with an empty program name and no matcher lines --
    // a grant displayed as though it covered everything. The whole point of
    // `script` is that it says the true, narrow thing (gcloud, not python3.14),
    // so the panel showing it as wider than it is defeats the feature.
    var parsed = Model.parseAllowlist({ ok: true, rules: [{
      index: 1, file: "/etc/moat/allowlist.d/user.toml", source: "user",
      removable: true, name: "moat-cred-cloud-credential-read",
      exe: null, path: null, parent: null,
      script: "/opt/google-cloud-cli/lib/gcloud.py",
      comment: "added 2026-09-07: gcloud reading gcloud's own store"
    }] })
    compare(parsed.rules[0].script, "/opt/google-cloud-cli/lib/gcloud.py")
    verify(parsed.rules[0].detail.indexOf("script = /opt/google-cloud-cli/lib/gcloud.py") >= 0)
    var rows = Model.userRuleRows(parsed.rules, [])
    compare(rows[0].program, "gcloud.py")
    verify(rows[0].label.indexOf("gcloud.py") === 0)

    // And when both are present the script still wins: `exe` is the
    // interpreter, and naming python3.14 on screen is the misreading this
    // matcher exists to prevent.
    compare(Model.ruleProgram({ exe: "/usr/bin/python3.14",
                                script: "/opt/google-cloud-cli/lib/gcloud.py" }),
            "gcloud.py")
  }

  function test_an_untracked_rule_says_not_counted_rather_than_zero() {
    // "the daemon is not counting this one" and "it has silenced nothing" are
    // different answers, and a 0 in that column would be a lie about the second.
    var parsed = Model.parseAllowlist({ ok: true, rules: [{
      index: 1, file: "/etc/moat/allowlist.d/user.toml", source: "user",
      removable: true, name: "moat-cred-ssh-private-key-read", exe: "/usr/bin/rsync",
      path: null
    }] })
    compare(Model.userRuleRows(parsed.rules, []).length, 1)
    compare(Model.userRuleRows(parsed.rules, [])[0].silenced, -1)
  }

  function test_a_hand_written_comment_survives_and_a_machine_one_does_not() {
    var hand = Model.ruleProvenance({ comment: "keeps my deploy script quiet" })
    compare(hand, "keeps my deploy script quiet")
    // A machine comment it cannot parse is dropped rather than printed: those
    // are the ones carrying alert ids and file paths.
    compare(Model.ruleProvenance({ comment: "added by something else entirely" }), "")
    compare(Model.ruleProvenance({ comment: "learned 2026-09-03: seen 4 times on 1 day" }),
            "Moat learned this on 2026-09-03, after 4 alerts")
  }

  // --- 2e, programs Moat knows ---------------------------------------------

  function test_trusted_programs_are_only_the_ones_a_rule_covers() {
    var exported = Model.parseBaselineExport({ tuples: [
      { rule: "moat-cred-ssh-private-key-read", exe: "/usr/bin/ssh",
        count: 204, learned: true, last_seen: "2026-09-04T09:00:00Z" },
      { rule: "moat-persist-hypr-config-write", exe: "/usr/bin/nvim",
        dir: "/home/dan/.config", count: 96, suppressed: true,
        last_seen: "2026-09-04T11:00:00Z" },
      // Observed but not trusted by anything: it is a log line, not a program
      // Moat treats as yours, and listing it here would make this a log again.
      { rule: "moat-exec-untrusted-home", exe: "/usr/bin/curl", count: 3 }
    ] })
    var rows = Model.trustedPrograms(exported.tuples, [])
    compare(rows.length, 2)
    var names = rows.map(function (r) { return r.program })
    compare(names.indexOf("curl"), -1)
    // Busiest first, and the scope is stated as a permission in plain words.
    compare(rows[0].program, "ssh")
    compare(rows[0].silenced, 204)
    compare(rows[0].scope, "reading your keys")
    compare(rows[1].scope, "writing under ~/.config")
    compare(rows[1].scope.indexOf("/home/dan"), -1, "a home path is shortened")
  }

  function test_an_open_incident_marks_a_trusted_row_and_never_creates_one() {
    // The handoff draws 2e with a `flea` row reading "nothing yet — one
    // incident waiting on you". On a real machine with nine things waiting
    // that inverts the screen: most of the rows under "programs Moat treats as
    // yours" become programs it trusts for nothing. A program with no trust is
    // an incident, and incidents live on Now.
    var trusted = Model.parseBaselineExport({ tuples: [
      { rule: "moat-persist-hypr-config-write", exe: "/usr/bin/nvim",
        dir: "/home/dan/.config", count: 96, learned: true }
    ] }).tuples

    var waiting = incidentsOf([incAlert({ id: "01A", process: { exe: "/usr/bin/nvim" } })])
    var rows = Model.trustedPrograms(trusted, waiting)
    compare(rows.length, 1)
    compare(rows[0].program, "nvim")
    verify(rows[0].open)
    verify(rows[0].trusted, "it still has its real permissions")
    verify(rows[0].scope.indexOf("writing under ~/.config") === 0)
    verify(rows[0].scope.indexOf("one thing waiting on you") !== -1)

    // A program that is trusted for nothing gets no row, however loud it is.
    var stranger = incidentsOf([incAlert({ id: "01B", process: { exe: "/tmp/x/nc" } })])
    compare(Model.trustedPrograms(trusted, stranger).length, 1)
    compare(Model.trustedPrograms(trusted, stranger)[0].program, "nvim")
    compare(Model.trustedPrograms([], stranger).length, 0)
  }

  function test_one_verb_over_many_places_is_one_permission() {
    // The verb said once and the places counted. Printed a sentence per tuple,
    // this row read "writing under ~/.config/dir0, writing under
    // ~/.config/dir1, writing und…" -- three quarters of the cell spent
    // re-reading the verb, and the paths cut off just before they differed.
    var tuples = []
    for (var i = 0; i < 8; i++) {
      tuples.push({ rule: "moat-persist-hypr-config-write", exe: "/usr/bin/quickshell",
                    dir: "/home/dan/.config/dir" + i, count: 3, learned: true })
    }
    var rows = Model.trustedPrograms(Model.parseBaselineExport({ tuples: tuples }).tuples, [])
    compare(rows.length, 1)
    verify(rows[0].trusted)
    compare(rows[0].scope, "writing under 8 places in ~/.config")
    compare(rows[0].scope.indexOf("\n"), -1)

    // One place still names it: a count is only worth more than a path when
    // there is more than one path.
    var single = Model.trustedPrograms(Model.parseBaselineExport({ tuples: [
      { rule: "moat-exec-untrusted-home", exe: "/usr/bin/bwrap",
        dir: "/tmp/build", count: 3, learned: true }
    ] }).tuples, [])
    compare(single[0].scope, "running from /tmp/build")

    // Paths that share nothing above the root are counted without a place,
    // because "3 places in /" tells a reader less than "3 places" does.
    var scattered = Model.trustedPrograms(Model.parseBaselineExport({ tuples: [
      { rule: "moat-exec-untrusted-home", exe: "/usr/bin/sh", dir: "/tmp/a", count: 1, learned: true },
      { rule: "moat-exec-untrusted-home", exe: "/usr/bin/sh", dir: "/opt/b", count: 1, learned: true },
      { rule: "moat-exec-untrusted-home", exe: "/usr/bin/sh", dir: "/srv/c", count: 1, learned: true }
    ] }).tuples, [])
    compare(scattered[0].scope, "running from 3 places")
  }

  function test_a_row_states_at_most_three_permissions() {
    // Past three it is a list, and a list belongs behind the row rather than
    // inside it: one program with twenty learned tuples was wrapping its row
    // over three lines and pushing the table apart. Five DIFFERENT permissions
    // are five things to know, so they cannot be collapsed the way repeated
    // directories under one verb can.
    var families = ["cred-ssh-private-key-read", "pkg-subtree-interpreter-spawn",
                    "net-egress-new-host", "priv-setuid-exec", "shell-reverse-spawn"]
    var tuples = []
    for (var i = 0; i < families.length; i++) {
      tuples.push({ rule: "moat-" + families[i], exe: "/usr/bin/quickshell",
                    count: 3, learned: true })
    }
    var rows = Model.trustedPrograms(Model.parseBaselineExport({ tuples: tuples }).tuples, [])
    compare(rows.length, 1)
    verify(rows[0].trusted)
    verify(rows[0].scope.indexOf("and 2 more") !== -1, rows[0].scope)
    compare(rows[0].scope.indexOf("\n"), -1)
  }

  function test_a_baseline_export_from_an_older_daemon_is_an_empty_table() {
    compare(Model.parseBaselineExport("").tuples.length, 0)
    compare(Model.parseBaselineExport("not json").ok, false)
    compare(Model.parseBaselineExport(null).tuples.length, 0)
    compare(Model.trustedPrograms(null, null).length, 0)
  }

  // --- 2b / 3a, the sequence ------------------------------------------------
  //
  // Built from the real record on this machine (fixtures/chain.jsonl), because
  // the reason the panel showed one lonely row for a correlated chain was that
  // every part of this was checked against a shape nobody had ever seen come
  // out of moatd.

  /// A synthetic chain object in the daemon's exact shape, for the cases the
  /// live record cannot produce (an escalation, a context step, a truncation).
  function fakeChain(over) {
    var base = {
      v: 1, id: "01CH", ancestor: { pid: 41201, exe: "/usr/bin/npm" },
      families: ["cred", "net"], severity: "critical", severity_base: "high",
      severity_reason: "high -> critical: a credential was read and the same process tree then connected out",
      first_ts: "2026-09-04T09:16:00Z", last_ts: "2026-09-04T09:17:00Z", span_secs: 60,
      steps: [
        { alert: "01S1", ts: "2026-09-04T09:16:00Z", family: "cred",
          rule: "moat-cred-ssh-private-key-read", severity: "high",
          title: "Private SSH key read", pid: 41233, exe: "/usr/bin/node", role: "trigger" },
        { alert: "01S2", ts: "2026-09-04T09:17:00Z", family: "net",
          rule: "moat-x-pkg-egress", severity: "medium",
          title: "A package install talked to an unexpected host", pid: 41233,
          exe: "/usr/bin/node", role: "trigger" }
      ],
      steps_total: 2, truncated: false,
      summary: "2 things happened in 60 seconds under npm (pid 41201), crossing cred and net."
    }
    for (var k in over) base[k] = over[k]
    return base
  }

  function test_a_chain_update_reaches_the_panel_at_all() {
    // moatd writes the chain back onto every member as an `update` line,
    // because correlation needs the second alert and by then the first is
    // already on disk. `UPDATABLE` did not list `chain`, so every one of those
    // lines was read, recognised and thrown away -- which is the whole of why
    // a correctly correlated chain drew one row.
    var alerts = suite.chainAlerts()
    compare(alerts.length, 2, "the two members of the real chain")
    for (var i = 0; i < alerts.length; i++) {
      verify(!!alerts[i].chain, alerts[i].id + " lost the chain moatd wrote onto it")
      compare(alerts[i].chain.id, "01M1Q4KAVQNH96MAW2ASV2QMCD")
      compare(alerts[i].chain.steps_total, 2)
      compare(alerts[i].chain.steps.length, 2)
    }
    // CONTRACT 4: every member carries the WHOLE chain, so either one can draw
    // 2b without joining anything.
    compare(alerts[0].chain.steps[0].alert, alerts[1].chain.steps[0].alert)
  }

  function test_a_triage_verdict_reaches_the_panel_at_all() {
    // The same fault as `chain`, one field over. A verdict is ALWAYS an update
    // -- the pass runs on a timer, long after the alert was written -- and
    // `UPDATABLE` did not list `triage`, so every verdict moatd appended was
    // read and dropped. The panel showed no AI analysis anywhere while
    // `moatctl explain` on the same id printed it, because the socket carried
    // the field and the log reader threw it away.
    var alerts = suite.chainAlerts()
    var withVerdict = null
    for (var i = 0; i < alerts.length; i++) {
      if (alerts[i].id === "01M1Q4KAVQNH96MAW2ASV2QMCD") withVerdict = alerts[i]
    }
    verify(!!withVerdict, "the alert the real triage line names is in the fixture")
    verify(!!withVerdict.triage, "the verdict moatd appended was dropped by the reader")
    compare(withVerdict.triage.verdict, "benign")
    compare(withVerdict.triage.confidence, "high")
    verify(withVerdict.triage.summary.length > 0, "a verdict with no summary shows nothing")
  }

  function test_a_sequence_says_which_day_it_happened_on() {
    // "20:06:10" is unreadable a day later. Steps keep clock times -- a chain
    // spans seconds, so a date per row is one string repeated -- and the day
    // is stated once for the whole sequence, in full, year included.
    var day = Model.chainDay(fakeChain())
    compare(day, "Fri 4 Sep 2026")
    // Taken from the chain's own first_ts, not from the reader's clock.
    compare(Model.chainDay(fakeChain({ first_ts: "2026-01-02T08:00:00Z" })).slice(-4), "2026")
    // Nothing to say beats saying something wrong.
    compare(Model.chainDay(null), "")
    compare(Model.chainDay({ first_ts: "not a date" }), "")
  }

  function test_a_kill_is_never_reported_as_a_quiet_day() {
    // Two contradictions on one screen, both from reading system-wide state to
    // describe one event: the headline said "Nothing needs you" and the
    // sub-line said "Nothing has been blocked, because you are still in monitor
    // mode" -- while an armed rule had just SIGKILLed a process in the user's
    // terminal. A rule armed on its own enforces whatever the daemon-wide mode
    // says, which is the whole point of arming one.
    var killed = incAlert({
      id: "01K", rule: "moat-cred-etc-shadow-read", severity: "high",
      surface: "alerts", mode: "enforce", action_taken: "killed" })
    var incidents = Model.buildIncidents(Model.foldText(JSON.stringify(killed) + "\n"), {})
    compare(Model.stoppedIncidents(incidents).length, 1)

    var v = Model.verdict(incidents, { ok: true, sensorUnhealthy: false, sensorsLoaded: 43 })
    compare(v.state, "stopped")
    compare(v.line, "Moat stopped one thing.")
    // Not the alarm colour: it is over, and shouting about something already
    // handled is how people learn to ignore the shouting.
    compare(v.tone, "accent")

    // Once acknowledged it stops being news.
    killed.acked = true
    var closed = Model.buildIncidents(Model.foldText(JSON.stringify(killed) + "\n"), {})
    compare(Model.stoppedIncidents(closed).length, 0)
    compare(Model.verdict(closed, { ok: true, sensorUnhealthy: false, sensorsLoaded: 43 }).state,
            "quiet")
  }

  function test_a_contained_alert_reaches_now_in_monitor_mode() {
    // Containment is moatd acting on its own -- a narrow network cut -- and it
    // happens in MONITOR mode, not enforce. A contained alert is "contained"
    // by alertState (so not needsYou) and must still be "stopped" (so it
    // reaches the Now blocked card). It used to be neither, so a critical
    // contained chain showed in History and nowhere in Now. 2026-09-06.
    var contained = incAlert({
      id: "01C", rule: "moat-cred-cloud-credentials-read", severity: "medium",
      surface: "alerts", mode: "monitor", action_taken: "contained" })
    var incidents = Model.buildIncidents(Model.foldText(JSON.stringify(contained) + "\n"), {})
    compare(Model.stoppedIncidents(incidents).length, 1, "a contained alert is stopped even in monitor")
    compare(Model.blockedIncidents(incidents).length, 1, "and reaches the Now blocked card")
    var v = Model.verdict(incidents, { ok: true, sensorUnhealthy: false, sensorsLoaded: 43 })
    compare(v.state, "stopped")

    // Acknowledged, it stops being news, like every other stopped thing.
    contained.acked = true
    var done = Model.buildIncidents(Model.foldText(JSON.stringify(contained) + "\n"), {})
    compare(Model.stoppedIncidents(done).length, 0)
  }

  function test_the_apology_card_and_the_headline_never_disagree() {
    // They were two functions answering "is this still outstanding" and only
    // one of them looked at `acked`: after allowing a killed program the
    // headline read "Nothing needs you" while the card apologising for that
    // exact program sat directly underneath it.
    var killed = incAlert({
      id: "01K", rule: "moat-cred-etc-shadow-read", severity: "high",
      surface: "alerts", mode: "enforce", action_taken: "killed" })
    var open = Model.buildIncidents(Model.foldText(JSON.stringify(killed) + "\n"), {})
    compare(Model.blockedIncidents(open).length, 1)
    compare(Model.stoppedIncidents(open).length, 1)

    killed.acked = true
    var done = Model.buildIncidents(Model.foldText(JSON.stringify(killed) + "\n"), {})
    compare(Model.stoppedIncidents(done).length, 0)
    compare(Model.blockedIncidents(done).length, 0,
            "the card goes when the headline does, or the page contradicts itself")

    // A kill the USER asked for is not an apology moat owes: `mode` is the mode
    // the rule was raised under, and `moatctl kill` is not enforcement.
    var byHand = incAlert({
      id: "01H", rule: "moat-cred-etc-shadow-read", severity: "high",
      surface: "alerts", mode: "monitor", action_taken: "killed" })
    var manual = Model.buildIncidents(Model.foldText(JSON.stringify(byHand) + "\n"), {})
    compare(Model.blockedIncidents(manual).length, 0)
  }

  function test_an_exclusion_is_visible_and_undoable() {
    // An excluded binary is a hole in an armed rule, and it lives inside a
    // rendered policy under /run/moat that nobody will ever open. If it does
    // not reach the panel the machine is quietly less protected than the Rules
    // screen says -- and `normalizeStatus` is a whitelist, so a field nobody
    // lists is dropped in silence. That has happened four times.
    var st = Model.normalizeStatus(JSON.stringify({
      ok: true,
      kernel_exclusions: {
        "moat-cred-etc-shadow-read": ["/usr/bin/cat"],
        "moat-rootkit-ldso-preload-write": ["/usr/bin/tee", "/usr/bin/dd"],
        "moat-broken": "not-a-list",
        "": ["/usr/bin/x"]
      }
    }))
    compare(st.exclusions.length, 3)
    var seen = st.exclusions.map(function (e) { return e.rule + ":" + e.exe }).sort()
    compare(seen[0], "moat-cred-etc-shadow-read:/usr/bin/cat")

    // A daemon too old to report it leaves an empty list, not undefined: the
    // section binds `visible` to its length.
    compare(Model.normalizeStatus(JSON.stringify({ ok: true })).exclusions.length, 0)
  }

  function test_a_containment_is_visible_and_undoable() {
    // The switch and the list both cross normalizeStatus, so both have to be
    // whitelisted there or the screen renders empty and looks like a layout
    // bug -- which is exactly how `enforceable` failed.
    var st = Model.normalizeStatus(JSON.stringify({
      ok: true,
      contain_enabled: true,
      contain: [
        { chain: "01CH", exe: "/tmp/lab/browser-helper",
          dests: ["192.168.44.122"], since: 10, expires: 610 },
        // Dropped: nothing to name, nothing to release.
        { chain: "", dests: ["1.2.3.4"] },
        { chain: "01NO", dests: [] },
        null
      ]
    }))
    compare(st.containEnabled, true)
    compare(st.contained.length, 1)
    compare(st.contained[0].chain, "01CH")
    compare(st.contained[0].dests[0], "192.168.44.122")

    // Off is the default, and an old daemon that reports neither is off with
    // nothing live rather than undefined.
    var bare = Model.normalizeStatus(JSON.stringify({ ok: true }))
    compare(bare.containEnabled, false)
    compare(bare.contained.length, 0)
  }

  function test_the_armable_rules_survive_normalisation() {
    // The fourth time a field was dropped by a whitelist and the screen that
    // read it just rendered empty: `chain`, `triage` and `surface` in
    // UPDATABLE, and now `enforceable` in normalizeStatus. It looked like a
    // layout bug -- the section was there, deployed, above "Yours", and had
    // nothing to draw.
    var st = Model.normalizeStatus(JSON.stringify({
      ok: true,
      enforceable: [
        { rule: "moat-net-tmpfs-binary-egress", enforce: "deny",
          title: "Binary from /tmp connected out", severity: "critical", armed: false },
        { rule: "moat-cred-etc-shadow-read", enforce: "kill",
          title: "Password database read", severity: "critical", armed: true },
        // Dropped: the panel could not say what arming it would do.
        { rule: "moat-x-mystery", enforce: "maybe", title: "?" },
        { enforce: "kill" },
        null
      ]
    }))
    compare(st.enforceable.length, 2)
    compare(st.enforceable[0].enforce, "deny")
    compare(st.enforceable[1].armed, true)
    // A daemon too old to report the field leaves an empty list, not undefined:
    // the section binds `visible` to its length.
    compare(Model.normalizeStatus(JSON.stringify({ ok: true })).enforceable.length, 0)
  }

  function test_a_chain_can_raise_a_member_onto_the_badge() {
    // The third field the log reader silently dropped, after `chain` and
    // `triage`. moatd restamps `surface` when correlation concludes a sequence
    // is worth interrupting for -- a per-alert rule only ever saw one event.
    // On 2026-09-04 a live AUR attack was fully detected and fully correlated,
    // and the user saw nothing, because every member sat on the timeline.
    var a = Model.foldText(JSON.stringify(incAlert({
      id: "01S1", severity: "medium", surface: "timeline" })) + "\n")[0]
    compare(a.surface, "timeline")
    Model.applyUpdate(a, { surface: "alerts" })
    compare(a.surface, "alerts", "a high chain has to be able to reach the badge")

    // An unrecognised value is not a licence to invent a third state.
    Model.applyUpdate(a, { surface: "whatever" })
    compare(a.surface, "alerts")
  }

  function test_a_later_update_never_blanks_a_verdict_already_recorded() {
    // A re-triage that produced nothing is not an instruction to forget the
    // verdict we have -- the same rule `incident` and `chain` follow.
    var alerts = suite.chainAlerts()
    var a = null
    for (var i = 0; i < alerts.length; i++) {
      if (alerts[i].id === "01M1Q4KAVQNH96MAW2ASV2QMCD") a = alerts[i]
    }
    var kept = a.triage.summary
    Model.applyUpdate(a, { triage: null })
    Model.applyUpdate(a, { triage: { verdict: "" } })
    verify(!!a.triage, "a malformed verdict blanked one that was already recorded")
    compare(a.triage.summary, kept)
  }

  function test_a_chain_is_one_incident_and_not_two_rows() {
    // 3a's entire premise. The two alerts have different rules and would have
    // been two incidents under the (rule, program) key.
    var alerts = suite.chainAlerts()
    compare(Model.buildIncidents(alerts, {}).length, 1,
            "two alerts moatd put in one chain are one incident")
    var g = suite.chainIncident()
    compare(g.count, 2)
    compare(g.alerts.length, 2)
    // The subject is the process tree's root, not whichever member sorted
    // first: the story is about what ran under node.
    compare(g.program, "node")
    compare(g.story.length, 2)
    // And it still needs the user, because one member does.
    compare(g.state, "needsYou")
  }

  function test_the_verdict_line_reaches_its_chain_state() {
    // This state was unreachable: `buildIncidents` never set `chain`, and the
    // condition read `chain.length > 1` against a field that is an OBJECT with
    // a `steps` array. Both halves are fixed and this is the proof.
    var inc = Model.buildIncidents(suite.chainAlerts(), {})
    var healthy = { tetragon: "running", policies: 1, sensorsLoaded: 1, sensorUnhealthy: false }
    compare(Model.verdictState(inc, healthy), Copy.VERDICT_CHAIN)
    var v = Model.verdict(inc, healthy)
    compare(v.line, "This one needs you now.")
    compare(v.tone, "alarm")
    verify(!!v.chain, "the view needs the chain to write 3a's sub-line")
    compare(v.chain.steps_total, 2)
    // The old shape would have found nothing to read.
    compare(inc[0].chain.length, undefined,
            "a chain is an object, not an array -- if this ever becomes a number, fix verdictState")
  }

  function test_a_chain_severity_never_prints_without_its_reason() {
    // CONTRACT 4's obligation, and the reason it exists: moatd's escalation is
    // written down or it does not happen, and the panel must not be the place
    // it becomes a bare number.
    var g = suite.chainIncident()
    var line = Model.chainSeverityLine(g.chain)
    verify(line.indexOf("high") === 0, "it leads with the severity: " + line)
    verify(line.indexOf("stays high: persist and cred in one process tree") !== -1,
           "and it carries moatd's own reason verbatim: " + line)

    // No reason, no number. Not "high" on its own.
    compare(Model.chainSeverityLine(Model.normalizeChain(
      suite.fakeChain({ severity_reason: "" }))), "")
    compare(Model.chainSeverityLine(null), "")
  }

  function test_a_chain_shows_the_daemons_severity_not_the_loudest_member() {
    // "A reader that shows a chain must show `chain.severity`, not the maximum
    // of its members" -- a sequence means more than its steps, and the members
    // are deliberately not rewritten.
    var text = JSON.stringify({
      v: 1, id: "01S1", severity: "high", rule: "moat-cred-ssh-private-key-read",
      family: "cred", title: "t", ts: "2026-09-04T09:16:00Z", surface: "alerts",
      process: { exe: "/usr/bin/node" }, chain: suite.fakeChain({})
    }) + "\n" + JSON.stringify({
      v: 1, id: "01S2", severity: "medium", rule: "moat-x-pkg-egress",
      family: "net", title: "t", ts: "2026-09-04T09:17:00Z", surface: "timeline",
      process: { exe: "/usr/bin/node" }, chain: suite.fakeChain({})
    }) + "\n"
    var inc = Model.buildIncidents(Model.foldText(text), {})
    compare(inc.length, 1)
    compare(inc[0].severity, "critical", "the chain's severity, not its loudest member's")
    // The members keep their own. The chain record IS the escalation.
    compare(inc[0].alerts[0].severity, "medium")
    compare(inc[0].alerts[1].severity, "high")
    verify(Model.chainSeverityLine(inc[0].chain).indexOf("high -> critical") !== -1)
  }

  function test_the_panel_never_invents_an_escalation() {
    // The rule the whole feature rests on: the daemon decides, the panel
    // renders. A chain with no severity of its own does not get one made up
    // for it -- the incident falls back to what its members already said.
    var text = JSON.stringify({
      v: 1, id: "01S1", severity: "high", rule: "r1", family: "cred", title: "t",
      ts: "2026-09-04T09:16:00Z", surface: "alerts", process: { exe: "/usr/bin/node" },
      chain: suite.fakeChain({ severity: "", severity_base: "" })
    }) + "\n" + JSON.stringify({
      v: 1, id: "01S2", severity: "medium", rule: "r2", family: "net", title: "t",
      ts: "2026-09-04T09:17:00Z", surface: "timeline", process: { exe: "/usr/bin/node" },
      chain: suite.fakeChain({ severity: "", severity_base: "" })
    }) + "\n"
    var inc = Model.buildIncidents(Model.foldText(text), {})
    compare(inc[0].severity, "high", "the members' own maximum, unchanged")
    // An unrecognized severity is not rendered raw either.
    compare(Model.normalizeChain(suite.fakeChain({ severity: "catastrophic" })).severity, "")
  }

  function test_a_malformed_chain_never_blanks_one_already_recorded() {
    // "A chain only ever grows, so a malformed one must be ignored rather than
    // allowed to blank a sequence already recorded."
    var good = suite.fakeChain({})
    var text = JSON.stringify({
      v: 1, id: "01S1", severity: "high", rule: "r1", family: "cred", title: "t",
      ts: "2026-09-04T09:16:00Z", surface: "alerts", process: { exe: "/usr/bin/node" }
    }) + "\n"
    text += JSON.stringify({ v: 1, id: "01S1", update: { chain: good } }) + "\n"
    text += JSON.stringify({ v: 1, id: "01S1", update: { chain: null } }) + "\n"
    text += JSON.stringify({ v: 1, id: "01S1", update: { chain: "nonsense" } }) + "\n"
    text += JSON.stringify({ v: 1, id: "01S1", update: { chain: { id: "01CH" } } }) + "\n"
    text += JSON.stringify({ v: 1, id: "01S1", update: { chain:
      suite.fakeChain({ steps: [good.steps[0]], steps_total: 1 }) } }) + "\n"
    var a = Model.foldText(text)[0]
    verify(!!a.chain, "four bad updates in a row did not erase the sequence")
    compare(a.chain.steps.length, 2, "and none of them shrank it")

    // One step is not a sequence, and drawing 2b's rail for it would show a
    // story that never happened.
    compare(Model.normalizeChain(suite.fakeChain({ steps: [good.steps[0]], steps_total: 1 })), null)
    compare(Model.normalizeChain({ steps: good.steps }), null, "no id, no chain")
    compare(Model.normalizeChain(null), null)
    compare(Model.normalizeChain([]), null)
  }

  function test_an_unrecognized_step_role_is_a_trigger_not_a_permission() {
    // `context` is the claim that the user had already allowed this step.
    // Degrading an unknown role towards it would show an accusation as a
    // permission, which is the wrong direction to fail in.
    var chain = Model.normalizeChain(suite.fakeChain({ steps: [
      { alert: "01S1", ts: "2026-09-04T09:16:00Z", family: "cred", rule: "r1",
        severity: "high", title: "t", pid: 1, exe: "/usr/bin/node", role: "allowed" },
      { alert: "01S2", ts: "2026-09-04T09:17:00Z", family: "net", rule: "r2",
        severity: "medium", title: "t", pid: 1, exe: "/usr/bin/node" }
    ] }))
    compare(chain.steps[0].role, "trigger")
    compare(chain.steps[1].role, "trigger")
    // A step with no alert id is not joinable, ackable or openable, so it is
    // dropped rather than rendered as a row that does nothing.
    compare(Model.normalizeChain(suite.fakeChain({ steps: [
      { ts: "x", family: "cred" },
      { alert: "01S2", family: "net", title: "t" }] })), null)
  }

  function test_a_context_step_is_shown_but_not_as_an_accusation() {
    // CONTRACT 4: a context step is one the user allowlisted or the noise guard
    // demoted. It is in the story because that is what makes 2b readable, and
    // showing it as a charge reverses a decision the user made.
    var chain = Model.normalizeChain(suite.fakeChain({ steps: [
      { alert: "01S1", ts: "2026-09-04T09:16:00Z", family: "cred", rule: "r1",
        severity: "high", title: "Private SSH key read", pid: 1,
        exe: "/usr/bin/node", role: "context" },
      { alert: "01S2", ts: "2026-09-04T09:17:00Z", family: "net", rule: "r2",
        severity: "medium", title: "Talked to an unexpected host", pid: 1,
        exe: "/usr/bin/node", role: "trigger" }
    ] }))
    var story = Model.chainStory(chain, {})
    compare(story.length, 2)
    verify(story[0].isContext)
    compare(story[0].status.label, "you had allowed this")
    compare(story[0].status.tone, "calm")
    verify(!story[1].isContext)
    compare(story[1].status.label, "happened")

    // What has already been done to a step outranks everything: a stopped step
    // says so whatever its role.
    var acted = Model.chainStory(chain, { alerts: [
      { id: "01S2", action_taken: "killed" }, { id: "01S1", acked: true }] })
    compare(acted[1].status.label, "Moat stopped it")
    compare(acted[1].status.tone, "accent")
    compare(acted[0].status.label, "you had allowed this",
            "an allowed step is still an allowed step once it is acked")

    // The concrete detail: the program and the file it read or the host it
    // reached, from the member alert. "python3 read ~/.aws/credentials", not
    // just "a credential file was read".
    var detailed = Model.chainStory(chain, { alerts: [
      { id: "01S1", file: { path: "/home/dan/.aws/credentials" } },
      { id: "01S2", net: { dst_ip: "192.168.44.122", dst_port: 4873 } }
    ] })
    // The program comes from the step's own exe (node here); the concrete
    // object comes from the member alert -- the file read, the host reached.
    verify(detailed[0].detail.indexOf("node") >= 0)
    verify(detailed[0].detail.indexOf(".aws/credentials") >= 0)
    verify(detailed[1].detail.indexOf("192.168.44.122:4873") >= 0)
  }

  function test_a_member_alert_says_it_is_part_of_a_sequence() {
    // The user lands on the `.git/config` row. Without this they never learn
    // that the same process read a credential a second later.
    var alerts = suite.chainAlerts()
    var git = suite.findAlert(alerts, "01M1Q4KAVQNH96MAW2ASV2QMCD")
    var cred = suite.findAlert(alerts, "01M1Q4KAWNGBG1AHZ9DSBDBP4J")
    compare(Model.chainPosition(git), 1)
    compare(Model.chainPosition(cred), 2)
    compare(Model.chainMarker(git), "Part of a sequence — step 1 of 2")
    compare(Model.chainMarker(cred), "Part of a sequence — step 2 of 2")
    // An alert in no chain says nothing, and the callers bind on "".
    compare(Model.chainMarker(Model.foldText(JSON.stringify(suite.incAlert({})))[0]), "")
    compare(Model.chainMarker(null), "")
    compare(Model.chainPosition(null), 0)
  }

  function test_a_truncated_chain_says_so_rather_than_shrinking_the_story() {
    // The correlator keeps a bounded number of steps. A member whose id is not
    // among the ones kept still knows it is in a sequence.
    var chain = Model.normalizeChain(suite.fakeChain({ steps_total: 7 }))
    compare(chain.steps.length, 2)
    compare(chain.steps_total, 7)
    verify(chain.truncated, "more steps than were sent is a truncation whatever the flag says")
    compare(Model.chainMarker({ id: "01S9", chain: chain }), "Part of a sequence of 7")
  }

  function test_the_story_reads_in_time_order_with_clock_times() {
    // 2b is ancestry as a story WITH TIMES, and 3a's rows lead with one. A
    // relative age would read the same on every step of a chain that spans a
    // second, which is exactly when the sequence matters most.
    var g = suite.chainIncident()
    compare(g.story[0].alert, "01M1Q4KAVQNH96MAW2ASV2QMCD")
    compare(g.story[1].alert, "01M1Q4KAWNGBG1AHZ9DSBDBP4J")
    compare(g.story[0].family, "persist")
    compare(g.story[1].family, "cred")
    compare(g.story[0].position, 1)
    verify(/^[0-9][0-9]:[0-9][0-9]:[0-9][0-9]$/.test(g.story[0].time),
           "a clock time, not an age: " + g.story[0].time)
    // The panel's own words for each step, and what it costs the user under it.
    compare(g.story[0].title, "Something changed where one of your repositories pushes to")
    compare(g.story[1].title, "Something read a secret stored inside your project")
    verify(g.story[0].note.length > 0, "each step says what it costs")
    // An unparseable stamp is left blank rather than turned into a fake time.
    compare(Model.clockTime("not a date"), "")
    compare(Model.clockTime(""), "")
  }

  function test_a_step_renders_even_when_its_alert_has_not_been_folded() {
    // The chain is the authority on what happened. Waiting for the log to
    // catch up would draw a shorter story than moatd has.
    var story = Model.chainStory(Model.normalizeChain(suite.fakeChain({})), { alerts: [] })
    compare(story.length, 2)
    compare(story[0].status.label, "happened")
    verify(story[0].title.length > 0)
  }

  function test_advanced_gives_the_sequence_the_daemons_own_words() {
    // Advanced is raw rule ids and severities; the default voice is neither.
    var plain = suite.chainIncident()
    var raw = suite.chainIncident({ rawDetail: true })
    compare(plain.title, "One program set something to run again and read a credential")
    compare(raw.title,
            "2 things happened in 1 second under node (pid 1903747), crossing persist and cred.")
    compare(raw.story[0].title, "A repository's .git/config written by something other than git")
    compare(raw.story[0].note, "moat-persist-git-config-write  ·  high")
    verify(plain.story[0].note.indexOf("moat-") === -1,
           "the default voice never prints a rule id in a step")
    // rawDetail reaches the wording and nothing else: same incident, same
    // members, same state.
    compare(raw.state, plain.state)
    compare(raw.severity, plain.severity)
    compare(raw.story.length, plain.story.length)
  }

  function test_a_chain_row_in_history_says_it_is_a_sequence() {
    // 1d's rows are one line each, so the note beside the title is the only
    // place a History row can say "this is several things, not one".
    var g = suite.chainIncident()
    verify(Model.historyNote(g).indexOf("a sequence of 2") !== -1, Model.historyNote(g))
    // And it never reads "2 times", which would say two of the same thing.
    compare(Model.historyNote(g).indexOf("times"), -1)
  }

  function test_the_chain_copy_stays_in_the_default_voice() {
    // 3g's banned list applies to everything the panel says in its own voice,
    // and a chain is where the daemon's vocabulary (families, pids, severity)
    // is most tempting to pass straight through.
    var chain = Model.normalizeChain(suite.fakeChain({}))
    var lines = [
      Copy.chainTitle(chain, false), Copy.chainStake(chain, false),
      Copy.chainSummaryLine(chain, false), Copy.chainClosingLine(chain),
      Copy.chainRuleNote(chain), Model.chainMarker({ id: "01S1", chain: chain })
    ]
    for (var f in Copy.FAMILY_DID) lines.push(Copy.FAMILY_DID[f])
    for (var i = 0; i < lines.length; i++) {
      var bad = Copy.bannedWordsIn(lines[i])
      compare(bad.length, 0, "\"" + lines[i] + "\" says: " + bad.join(", "))
    }
    // And the sub-line is 3a's sentence about the sequence, not a count of
    // things waiting.
    compare(Copy.chainSummaryLine(chain, false),
            "Two things happened in 1 minute and they all came out of the same program.")
    compare(Copy.spanPhrase(0), "in the same second")
    compare(Copy.spanPhrase(9), "in 9 seconds")
    compare(Copy.spanPhrase(540), "in 9 minutes")
    compare(Copy.spanPhrase(-1), "")
  }

  // --- 2b, what led here ----------------------------------------------------

  function test_the_chain_is_oldest_first_and_invents_no_timestamps() {
    var alerts = Model.foldText(JSON.stringify(incAlert({
      id: "01A", ts: "2026-09-04T11:22:00Z",
      process: { exe: "/usr/bin/flea", args: "--daemon",
                 cwd: "/home/dan/proj", start_ts: "2026-09-04T11:21:00Z",
                 ancestry: [{ pid: 3, exe: "/usr/bin/bash" },
                            { pid: 2, exe: "/usr/lib/systemd/systemd" }] }
    })) + "\n")
    var steps = Model.chainSteps(alerts[0])
    compare(steps.length, 3)
    compare(steps[0].name, "systemd")
    compare(steps[1].name, "bash")
    compare(steps[2].name, "flea")
    verify(steps[2].isAlert)
    // moatd records {pid, exe} per ancestor and no stamp, so the steps above
    // the alert carry no time and this does not make one up.
    compare(steps[0].ts, "")
    compare(steps[1].ts, "")
    compare(steps[2].ts, "2026-09-04T11:22:00Z")
    compare(steps[2].cwd, "~/proj")
    compare(Model.chainSteps(null).length, 0)
  }

  // --- 3e, the bar glyph ----------------------------------------------------

  function test_the_bar_has_exactly_three_states_and_they_are_the_verdicts() {
    var quiet = Model.barState(Copy.VERDICT_QUIET, 0)
    compare(quiet.state, "quiet")
    compare(quiet.label, "", "the quiet glyph carries no text at all")

    var needs = Model.barState(Copy.VERDICT_NEEDS, 3)
    compare(needs.state, "needsYou")
    compare(needs.tone, "alarm")
    compare(needs.label, "3")

    // A live chain is still "needs you" on the bar: the bar has three states,
    // and a fourth would be a state the verdict line cannot say.
    compare(Model.barState(Copy.VERDICT_CHAIN, 1).state, "needsYou")

    var gap = Model.barState(Copy.VERDICT_GAP, 0)
    compare(gap.state, "gap")
    compare(gap.tone, "accent")
    compare(gap.label, "gap")
  }

  function test_the_bar_tooltip_exists_only_for_the_two_loud_states() {
    var inc = incidentsOf([incAlert({ id: "01A", rule: "moat-persist-hypr-config-write" })])
    compare(Model.barTooltip(Copy.VERDICT_QUIET, inc, Date.now()), "",
            "a tooltip on the quiet shield is one nobody ever needed")
    var loud = Model.barTooltip(Copy.VERDICT_NEEDS, inc, Date.parse("2026-09-04T11:00:00Z"))
    verify(loud.indexOf("Something added itself to your login") === 0,
           "the tooltip leads with the consequence, not the detection")
    verify(Model.barTooltip(Copy.VERDICT_GAP, [], Date.now()).length > 0)
  }

  // --- 2h, the three notification shapes -----------------------------------

  function test_only_a_needs_you_incident_may_interrupt() {
    // An alert an unattended pass read and the daemon ACTED on -- `outcome:
    // "demoted"` -- is `explained`: Moat decided, the user may look.
    // Interrupting for a decision that has already been made is how someone
    // learns to dismiss the toast that matters.
    var decided = incAlert({ id: "01A", severity: "critical",
      triage: { verdict: "benign", confidence: "high", summary: "s", reasoning: "r",
                outcome: "demoted" } })
    var folded = Model.foldText(JSON.stringify(decided) + "\n")
    verify(!Model.shouldNotify(folded[0], "high", false, {}))

    var open = Model.foldText(JSON.stringify(incAlert({ id: "01B", severity: "high" })) + "\n")
    verify(Model.shouldNotify(open[0], "high", false, {}))
  }

  function test_a_verdict_the_ceiling_withheld_still_asks_for_the_user() {
    // The distinction the panel used to lose. `verdict: "benign"` alone was
    // enough to mark an alert `explained`, which handed back exactly what the
    // triage ceiling had just refused: on 2026-09-04 the ceiling withheld a
    // demotion on the real C2 chain ("first time this pattern has been seen
    // here") and the panel called it explained anyway and dropped it out of Now.
    //
    // The agent explains, and at most demotes. When the daemon declines to act,
    // the verdict is still SHOWN -- being read is not being dismissed.
    var withheld = incAlert({ id: "01C", severity: "critical",
      triage: { verdict: "benign", confidence: "high", summary: "s", reasoning: "r",
                outcome: "withheld: first time this pattern has been seen here" } })
    var folded = Model.foldText(JSON.stringify(withheld) + "\n")
    compare(Model.alertState(folded[0], {}), "needsYou",
            "a benign verdict the daemon refused to act on must not silence the alert")
    verify(!!folded[0].triage, "and the analysis is still there to read")
    compare(folded[0].triage.withheld, "first time this pattern has been seen here")
    verify(Model.shouldNotify(folded[0], "high", false, {}))
  }

  function test_never_means_never_including_the_noise_guards_exception() {
    // 1f's third answer. It is checked before every exception below it,
    // including the noise guard's own one-shot: a "never" with exceptions is
    // not never.
    var guard = Model.foldText(JSON.stringify(incAlert({
      id: "01A", rule: "moat-x-noisy-rule", severity: "medium" })) + "\n")
    verify(Model.shouldNotify(guard[0], "high", false, {}),
           "the noise guard normally goes through at medium")
    verify(!Model.shouldNotify(guard[0], "high", false, { notifyMuted: true }))
    var critical = Model.foldText(JSON.stringify(incAlert({
      id: "01B", severity: "critical", rarity: "first_seen" })) + "\n")
    verify(!Model.shouldNotify(critical[0], "high", false, { notifyMuted: true }))
  }

  function test_a_burst_summary_names_the_program_not_the_rule() {
    // 2h shape 3. "Claude tripped the same detection 40 more times", never
    // "40 more from moat-ai-cli-in-pkg-subtree".
    var store = Model.createStore()
    var alert = Model.foldText(JSON.stringify(incAlert({
      id: "01A", rule: "moat-ai-cli-in-pkg-subtree", severity: "high",
      process: { exe: "/usr/bin/claude" } })) + "\n")[0]
    var opts = { minNotifySeverity: "high", notifyCooldownMinutes: 10 }
    compare(Model.notifyDecision(store, alert, 0, opts).toast, true)
    Model.notifyDecision(store, alert, 1000, opts)
    Model.notifyDecision(store, alert, 2000, opts)
    var due = Model.flushCollapsed(store, 11 * 60000)
    compare(due.length, 1)
    compare(due[0].program, "claude")
    compare(Copy.burstTitle(due[0].program, due[0].count),
            "claude tripped the same detection 2 more times")
  }

  // --- 1g, the first week ---------------------------------------------------

  function test_the_learning_card_is_a_progress_bar_with_both_ends() {
    var now = Date.parse("2026-09-04T12:00:00Z")
    var card = Model.learningCard(Model.normalizeStatus({
      ok: true, installed_at: "2026-09-03T12:00:00Z",
      baseline: { learning: true, learning_ends: "2026-09-12T12:00:00Z", learned: 412 }
    }), now)
    compare(card.dayTotal, 9)
    compare(card.dayIndex, 2)
    compare(card.daysLeft, 8)
    compare(card.learned, 412)
    verify(card.fraction > 0 && card.fraction < 1)

    // Not learning: no card at all, rather than a bar stuck at 100%.
    compare(Model.learningCard(Model.normalizeStatus({ ok: true,
      baseline: { learning: false } }), now), null)
  }

  function test_the_enforce_question_is_asked_once_and_only_after_learning() {
    var ended = "2026-09-04T09:00:00Z"
    var status = Model.normalizeStatus({ ok: true, mode: "monitor",
      baseline: { learning: false, learning_ends: ended, learned: 14 },
      demoted_rules: ["moat-x"] })
    var soon = Model.learningDoneCard(status, Date.parse("2026-09-04T12:00:00Z"))
    compare(soon.learned, 14)
    compare(soon.demoted, 1)
    verify(!soon.enforcing)
    // A week later it is not news any more. It is the one moment the enforce
    // question can be asked honestly, not a permanent banner.
    compare(Model.learningDoneCard(status, Date.parse("2026-09-11T12:00:00Z")), null)
    // And never while the window is still open.
    compare(Model.learningDoneCard(Model.normalizeStatus({ ok: true,
      baseline: { learning: true, learning_ends: ended } }), Date.parse(ended)), null)
  }

  // --- 3d, after Moat blocked something ------------------------------------

  function test_only_a_kernel_block_gets_the_apology() {
    var blocked = incidentsOf([incAlert({ id: "01A", action_taken: "killed", mode: "enforce" })])
    compare(Model.blockedIncidents(blocked).length, 1)
    // The user pressing Stop it is not something to apologise for: they know
    // what they did, and they were asked first.
    var byHand = incidentsOf([incAlert({ id: "01B", action_taken: "killed", mode: "monitor" })])
    compare(Model.blockedIncidents(byHand).length, 0)
    compare(Model.blockedIncidents(incidentsOf([incAlert({ id: "01C" })])).length, 0)

    var transcript = Model.blockTranscript({
      process: { exe: "/home/dan/proj/deploy.sh", args: "./scripts/deploy.sh",
                 cwd: "/home/dan/proj" } })
    compare(transcript.command, "$ ./scripts/deploy.sh")
    compare(transcript.killed, "Killed")
    compare(transcript.cwd, "~/proj")
  }

  // --- one line means one line -------------------------------------------

  function test_a_row_string_is_one_bounded_line() {
    // Found live: moat's own triage pass invokes an agent CLI with a
    // multi-kilobyte prompt as a single argument, moatd records that invocation
    // as an install receipt like any other, and History rendered the whole
    // prompt -- forty lines of it -- as one row. Text.PlainText stops such a
    // string being read as MARKUP; it does nothing about it being read as
    // LAYOUT, because an elided Text still honours an embedded newline.
    var nasty = "line one\nline two\n\nline three   with   gaps"
    compare(Copy.oneLine(nasty), "line one line two line three with gaps")
    compare(Copy.oneLine("x".repeat(500), 20).length, 20)
    verify(Copy.oneLine("x".repeat(500), 20).indexOf("\u2026") !== -1)
    compare(Copy.oneLine(null), "")
    compare(Copy.oneLine(undefined), "")

    // Every row string that can carry process output goes through it.
    var receipt = Model.normalizeReceipt({ receipt: {
      root_exe: "/usr/bin/claude",
      root_args: "-p " + "argument text\n".repeat(200),
      cwd: "/home/dan/proj", duration_s: 3
    } }, 0)
    var summary = Model.receiptSummary(receipt)
    compare(summary.indexOf("\n"), -1, "a receipt row must never carry a newline")
    verify(summary.length < 220, "a receipt row is bounded, got " + summary.length)

    // A detection with no copy falls back to the daemon's string, and the
    // daemon's string is the one that has been near a process.
    var title = Copy.titleFor({ rule: "moat-not-written-yet",
                                title: "weird\ntitle\n" + "x".repeat(400) })
    compare(title.indexOf("\n"), -1)
    verify(title.length <= 120)
  }

  // --- the key is what a view is allowed to hold on to ---------------------

  function test_an_incidents_key_is_stable_across_rebuilds() {
    // Found live: IncidentCard reset its open drawers in onIncidentChanged, and
    // `incident` is bound through buildIncidents -- which allocates brand-new
    // objects on every rebuild, and rebuilds on the 10-second status poll and
    // on every append to alerts.jsonl. So "Show evidence" collapsed itself a
    // few seconds after every open. A view has to key on identity, and this is
    // the guarantee that lets it.
    var records = [
      incAlert({ id: "01A", ts: "2026-09-04T10:00:00Z" }),
      incAlert({ id: "01B", ts: "2026-09-04T10:05:00Z" })
    ]
    var first = incidentsOf(records)
    var second = incidentsOf(records)
    compare(first.length, 1)
    compare(first[0].key, second[0].key)
    verify(first[0] !== second[0], "a rebuild really does allocate a new object")

    // And it survives a repeat joining the incident -- which is exactly when
    // somebody is most likely to be mid-read. `id` does NOT: it follows the
    // newest member, which is why a view must not key on it.
    var later = incidentsOf(records.concat([
      incAlert({ id: "01C", ts: "2026-09-04T10:09:00Z" })
    ]))
    compare(later[0].key, first[0].key)
    verify(later[0].id !== first[0].id, "the id moves to the newest member")
    compare(later[0].count, 3)
  }

  // =========================================================================
  //  One question, one answer -- agreement tests
  //
  //  Every test here asserts that TWO consumers of one decision agree, in the
  //  manner of test_every_surface_consumer_agrees_with_alertSurface. Each was
  //  written after finding a pair that did not.
  // =========================================================================

  function test_the_bar_tone_is_the_headline_tone_for_every_verdict() {
    // The verdict line grew a fifth form (`stopped`) and barState never learned
    // it: the case fell to `default`, so the bar drew the calm shield while the
    // headline under it said "Moat stopped one thing" in accent. The bar's
    // tone must be the headline's for every state the headline can take.
    var states = [Copy.VERDICT_QUIET, Copy.VERDICT_NEEDS, Copy.VERDICT_CHAIN,
                  Copy.VERDICT_GAP, Copy.VERDICT_STOPPED]
    for (var i = 0; i < states.length; i++) {
      var bar = Model.barState(states[i], 1)
      var headline = Copy.verdictTone(states[i])
      // The bar spells "calm" as "quiet"; every other tone is the same word.
      var expected = headline === "calm" ? "quiet" : headline
      compare(bar.tone, expected, states[i] + ": bar tone vs headline tone")
    }

    // And end to end: a killed, unacked, enforce-mode alert makes the headline
    // say "stopped", and the bar must not be the quiet shield over it.
    var inc = incidentsOf([incAlert({ id: "01K", mode: "enforce", action_taken: "killed" })])
    var v = Model.verdict(inc, healthy())
    compare(v.state, Copy.VERDICT_STOPPED)
    var bar = Model.barState(v.state, Model.needsYouIncidents(inc).length)
    verify(bar.state !== "quiet", "the bar must not read quiet while the headline says stopped")
    compare(bar.tone, v.tone)
  }

  function test_the_day_header_buckets_states_the_way_the_rows_word_them() {
    // The header's catch-all `else` counted every `closed` incident -- acked,
    // never read by anything -- as "explained", so it said "3 explained" over
    // three rows whose state word was "closed". Header and row read the same
    // `state`; they must bucket it the same.
    var now = Date.parse("2026-09-04T12:00:00Z")
    var inc = incidentsOf([
      incAlert({ id: "01A", rule: "r1", ts: "2026-09-04T10:00:00Z", acked: true }),
      incAlert({ id: "01B", rule: "r2", ts: "2026-09-04T10:01:00Z", acked: true }),
      incAlert({ id: "01C", rule: "r3", ts: "2026-09-04T10:02:00Z",
                 triage: { verdict: "benign", confidence: "high", demoted: true,
                           outcome: "demoted", summary: "s" } })
    ])
    compare(inc.length, 3)
    var days = Model.historyDays(inc, now)
    compare(days.length, 1)
    var d = days[0]
    // Count the rows the way HistoryRow words them, then compare to the header.
    var byWord = {}
    for (var i = 0; i < d.incidents.length; i++) {
      var w = Copy.stateWord(d.incidents[i].state)
      byWord[w] = (byWord[w] || 0) + 1
    }
    compare(d.explained, byWord["explained"] || 0, "header 'explained' vs rows worded 'explained'")
    compare(d.closed, byWord["closed"] || 0, "header 'closed' vs rows worded 'closed'")
    compare(d.explained, 1)
    compare(d.closed, 2)
    compare(d.summary.indexOf("3 explained"), -1, "two acked rows are not 'explained'")
    verify(d.summary.indexOf("2 closed") >= 0, d.summary)
  }

  function test_stopped_reads_every_member_the_state_does() {
    // `buildIncidents` derives `state` from EVERY member ("an incident needs
    // you if ANY member does"), but stoppedIncidents read only the head. A
    // chain whose first step was killed under an armed rule and whose newest
    // step was acked by hand was "contained" in History and invisible to the
    // headline and the apology card at the same time.
    var chain = { id: "01K1", severity: "high", severity_reason: "r", steps_total: 2,
                  ancestor: { exe: "/usr/bin/bash", pid: 1 }, families: ["cred", "net"],
                  steps: [{ alert: "01K1", rule: "moat-cred-etc-shadow-read", role: "trigger" },
                          { alert: "01K2", rule: "moat-net-first-contact", role: "trigger" }] }
    var inc = incidentsOf([
      incAlert({ id: "01K1", rule: "moat-cred-etc-shadow-read", ts: "2026-09-04T10:00:00Z",
                 mode: "enforce", action_taken: "killed", chain: chain }),
      incAlert({ id: "01K2", rule: "moat-net-first-contact", ts: "2026-09-04T10:00:05Z",
                 mode: "monitor", acked: true, chain: chain })
    ])
    compare(inc.length, 1, "one chain, one incident")
    compare(inc[0].head.id, "01K2", "the acked step is the head")
    compare(inc[0].state, "contained", "the row says you stopped it")
    compare(Model.stoppedIncidents(inc).length, 1,
            "so the headline and the apology card must say so too")
    compare(Model.blockedIncidents(inc).length, 1)
    compare(Model.verdict(inc, healthy()).state, Copy.VERDICT_STOPPED)

    // The two agree in the other direction as well: an incident stoppedIncidents
    // returns is always one the state calls contained (or louder).
    var stopped = Model.stoppedIncidents(inc)
    for (var i = 0; i < stopped.length; i++) {
      verify(stopped[i].state === "contained" || stopped[i].state === "needsYou",
             "a stopped incident is never quiet on its row: " + stopped[i].state)
    }
  }

  function test_today_on_the_now_page_is_the_today_in_history() {
    // "Moat looked at N things today" summed every incident in the log. The
    // number must be the count of exactly the rows History files under its
    // "Today" header, computed by the same day key.
    var now = Date.parse("2026-09-04T12:00:00Z")
    var inc = incidentsOf([
      incAlert({ id: "01A", rule: "r1", ts: "2026-09-04T10:00:00Z", count: 5 }),
      incAlert({ id: "01B", rule: "r2", ts: "2026-09-03T10:00:00Z", count: 40 }),
      incAlert({ id: "01C", rule: "r3", ts: "2026-08-20T10:00:00Z", count: 400 })
    ])
    var days = Model.historyDays(inc, now)
    var todayRows = 0
    for (var i = 0; i < days.length; i++) {
      if (days[i].label !== "Today") continue
      for (var j = 0; j < days[i].incidents.length; j++) todayRows += days[i].incidents[j].count
    }
    compare(todayRows, 5)
    compare(Model.seenToday(inc, now), todayRows, "Now's 'today' vs History's 'Today'")
    // Not the whole log.
    verify(Model.seenToday(inc, now) !== 445)
    // And the next day (local time, like the day header), yesterday's are
    // yesterday's.
    compare(Model.seenToday(inc, Date.parse("2026-09-05T20:00:00Z")), 0)
  }

  function test_every_consumer_honours_a_surface_the_daemon_stamped_over_the_demoted_list() {
    // The live case from 2026-09-05: a chain of 64 steps under makepkg reached
    // `high`, and the daemon restamped its trigger steps `surface: "alerts"`
    // -- with full knowledge that their rules were demoted, because a chain
    // that reaches high has to be able to reach the badge. The panel then
    // read `status.demoted_rules`, found those rules, and called every one of
    // them "expected": the shield stayed quiet, no toast, no card, and
    // `moatctl chain` was the only place the sequence existed.
    //
    // So: a stamped `alerts` under a listed rule is waiting on the user for
    // EVERY consumer, and a stamped `timeline` is quiet for every consumer,
    // and the list changes neither.
    var chain = { id: "01C1", severity: "high", severity_reason: "r", steps_total: 2,
                  ancestor: { exe: "/usr/bin/makepkg", pid: 1 }, families: ["exec", "pkg"],
                  steps: [{ alert: "01C1", rule: "moat-exec-untrusted-tmpfs", role: "trigger" },
                          { alert: "01C2", rule: "moat-exec-untrusted-home", role: "trigger" }] }
    var text = JSON.stringify(incAlert({ id: "01C1", rule: "moat-exec-untrusted-tmpfs",
      severity: "high", surface: "alerts", chain: chain, ts: "2026-09-05T14:26:04Z",
      process: { exe: "/usr/bin/bash" } })) + "\n"
    text += JSON.stringify(incAlert({ id: "01C2", rule: "moat-exec-untrusted-home",
      severity: "medium", surface: "alerts", chain: chain, ts: "2026-09-05T14:26:05Z",
      process: { exe: "/usr/bin/python3" } })) + "\n"
    // And one the daemon really did put on the timeline, same rule.
    text += JSON.stringify(incAlert({ id: "01Q", rule: "moat-exec-untrusted-tmpfs",
      severity: "high", surface: "timeline", ts: "2026-09-05T14:00:00Z",
      process: { exe: "/usr/bin/cargo" } })) + "\n"
    var alerts = Model.foldText(text)
    var listed = { demotedRules: ["moat-exec-untrusted-tmpfs", "moat-exec-untrusted-home"] }
    var unlisted = {}

    var opts = [listed, unlisted]
    for (var o = 0; o < opts.length; o++) {
      var tab = Model.surfaceAlerts(alerts, "alerts", opts[o])
      compare(tab.length, 2, "the tab shows exactly what the daemon surfaced")
      compare(Model.unackedCounts(alerts, opts[o]).badge, 2, "the badge counts the same two")
      var inc = Model.buildIncidents(alerts, opts[o])
      var needs = Model.needsYouIncidents(inc)
      compare(needs.length, 1, "one chain incident is waiting")
      compare(needs[0].chain.id, "01C1")
      var v = Model.verdict(inc, healthy())
      compare(v.state, Copy.VERDICT_CHAIN, "the headline is the chain form")
      compare(Model.barState(v.state, needs.length).tone, "alarm", "and the bar is alarm")
      var a1 = null, aq = null
      for (var k = 0; k < alerts.length; k++) {
        if (alerts[k].id === "01C1") a1 = alerts[k]
        if (alerts[k].id === "01Q") aq = alerts[k]
      }
      verify(Model.shouldNotify(a1, "high", false, opts[o]), "a surfaced chain step notifies")
      verify(!Model.shouldNotify(aq, "low", false, opts[o]), "a timelined one never does")
      compare(Model.alertState(a1, opts[o].demotedRules), "needsYou")
      compare(Model.alertState(aq, opts[o].demotedRules), "expected")
    }
    // And a needs-you row is never captioned "Moat stopped asking".
    var rows = Model.buildIncidents(alerts, listed)
    for (var r = 0; r < rows.length; r++) {
      if (rows[r].state === "needsYou") compare(rows[r].coveredBy, "")
    }
  }

  function test_the_panel_folds_both_halves_of_the_log_the_way_the_daemon_does() {
    // moatd reads alerts.1.jsonl and then alerts.jsonl (`AlertStore::load`),
    // and every daemon count -- status.unacked, the watchdog, triage_pending
    // -- comes from that. The panel read one file. After a rotation the two
    // disagreed about what was outstanding: on 2026-09-05 five unacked
    // critical alerts lived only in the rotated half.
    var rotated = JSON.stringify(incAlert({ id: "01R1", rule: "moat-rootkit-evidence-tamper",
      severity: "critical", surface: "alerts", ts: "2026-09-05T12:40:56Z" })) + "\n"
    rotated += JSON.stringify(incAlert({ id: "01R2", rule: "r2", severity: "high",
      surface: "alerts", ts: "2026-09-05T12:41:00Z" }))   // no trailing newline
    var current = JSON.stringify({ v: 1, id: "01R2", update: { acked: true } }) + "\n"
    current += JSON.stringify(incAlert({ id: "01C1", rule: "r3", severity: "high",
      surface: "alerts", ts: "2026-09-05T13:30:00Z" })) + "\n"

    var store = Model.createStore()
    var result = Model.ingestText(store, Model.logBody(rotated, current), {})
    compare(result.alerts.length, 3, "both halves fold")
    compare(result.initialLoad, true)
    compare(result.newIds.length, 0, "the priming load never toasts, whichever half an id came from")
    var byId = {}
    for (var i = 0; i < result.alerts.length; i++) byId[result.alerts[i].id] = result.alerts[i]
    compare(byId["01R2"].acked, true, "an ack in the live file lands on a rotated-out record")
    compare(byId["01R1"].acked, false)
    // What the daemon's unacked() counts -- unacked, unsuppressed, on the
    // badge -- is what the panel counts.
    var daemonStyle = 0
    for (var j = 0; j < result.alerts.length; j++) {
      var a = result.alerts[j]
      if (!a.acked && !a.suppressed_by && a.surface === "alerts") daemonStyle++
    }
    compare(result.unacked.badge, daemonStyle)
    compare(result.unacked.badge, 2)
    compare(result.unacked.critical, 1, "the rotated-out critical is still waiting")

    // An append to the live file is still an append to the whole body, so the
    // incremental fold keeps working across the seam.
    current += JSON.stringify(incAlert({ id: "01C2", rule: "r4", severity: "high",
      surface: "alerts", ts: "2026-09-05T13:31:00Z" })) + "\n"
    var again = Model.ingestText(store, Model.logBody(rotated, current), {})
    compare(again.alerts.length, 4)
    compare(again.newIds.length, 1)
    compare(again.newIds[0], "01C2")
    compare(again.reloaded, false)
  }

  function test_the_rotated_half_is_handed_over_once_and_never_concatenated() {
    // The same fold as above, the way Service.qml now does it: the rotated
    // text goes into the store once (setLogPrefix) and every ingest takes the
    // live file alone. Concatenating 20 MB in front of ~100 appended bytes on
    // every reload was the panel's largest allocation, twice a second.
    var rotated = JSON.stringify(incAlert({ id: "01R1", rule: "moat-rootkit-evidence-tamper",
      severity: "critical", surface: "alerts", ts: "2026-09-05T12:40:56Z" })) + "\n"
    rotated += JSON.stringify(incAlert({ id: "01R2", rule: "r2", severity: "high",
      surface: "alerts", ts: "2026-09-05T12:41:00Z" }))   // no trailing newline
    var current = JSON.stringify({ v: 1, id: "01R2", update: { acked: true } }) + "\n"
    current += JSON.stringify(incAlert({ id: "01C1", rule: "r3", severity: "high",
      surface: "alerts", ts: "2026-09-05T13:30:00Z" })) + "\n"

    var store = Model.createStore()
    verify(Model.setLogPrefix(store, rotated), "a new prefix is a change")
    verify(!Model.setLogPrefix(store, rotated), "the same prefix again is not")
    var result = Model.ingestText(store, current, {})
    compare(result.alerts.length, 3, "both halves fold")
    compare(result.newIds.length, 0)
    compare(result.byId["01R2"].acked, true, "an ack in the live file lands on a rotated-out record")
    compare(result.byId["01R1"].acked, false)
    compare(result.unacked.critical, 1, "the rotated-out critical is still waiting")
    var fold = store.fold

    // A live-file append is incremental across the seam: same fold object,
    // one new id, nothing re-folded.
    current += JSON.stringify(incAlert({ id: "01C2", rule: "r4", severity: "high",
      surface: "alerts", ts: "2026-09-05T13:31:00Z" })) + "\n"
    var again = Model.ingestText(store, current, {})
    verify(store.fold === fold, "an append keeps the running fold")
    compare(again.alerts.length, 4)
    compare(again.newIds.length, 1)
    compare(again.newIds[0], "01C2")
    compare(again.reloaded, false)

    // A half-written last line waits for its newline, across the seam too.
    var partial = Model.ingestText(store, current + "{\"v\":1,\"id\":\"01C3\"", {})
    compare(partial.alerts.length, 4)
    var whole = Model.ingestText(store, current + JSON.stringify(incAlert({ id: "01C3", rule: "r5",
      severity: "high", surface: "alerts", ts: "2026-09-05T13:32:00Z" })) + "\n", {})
    compare(whole.alerts.length, 5)

    // Rotation: the live file becomes the rotated one and a fresh live file
    // starts. The prefix changes, so the fold is rebuilt over the new body;
    // the body is shorter, so `reloaded` says so; and nothing that was seen
    // comes back as new.
    var rotatedNow = current
    verify(Model.setLogPrefix(store, rotatedNow))
    var afterRotation = Model.ingestText(store, "", {})
    compare(afterRotation.reloaded, true)
    // `rotatedNow` holds 01C1 and 01C2 plus the ack of 01R2, whose record
    // went with the old rotated half: two alerts, one parked update.
    compare(afterRotation.alerts.length, 2, "the old rotated half is gone; the old live half stays")
    compare(afterRotation.newIds.length, 0)
    verify(store.fold !== fold, "a new prefix is a new fold")
    // ...and the empty live file still ends on a whole line: the fold consumed
    // exactly the prefix.
    compare(store.fold.consumed, rotatedNow.length)

    // The live file alone, with no prefix, folds exactly as before.
    var bare = Model.createStore()
    var bareResult = Model.ingestText(bare, current, {})
    compare(bareResult.alerts.length, 2)
  }
  // The panel is a popup: a click-drag across it is as likely to dismiss it as
  // to select anything, so the record has to leave by a button. What it copies
  // is the WHOLE alert, shaped like `moatctl explain`, because an alert you
  // cannot quote is one you can only obey.
  function test_alertAsText_carries_the_whole_record() {
    var a = {
      id: "01ALERT", rule: "moat-cred-ssh-private-key-read", severity: "critical",
      ts: "2026-09-07T13:00:00.000Z", title: "A program read your SSH key",
      mode: "enforce", action_taken: "blocked",
      process: { exe: "/usr/bin/curl", pid: 42, uid: 1000, args: "-fsSL http://x",
                 cwd: "/home/u", ancestry: [{ exe: "/usr/bin/bash" }] },
      explain: {
        what: "curl read a private key.",
        why: "Nothing but ssh should read that file.",
        evidence: ["hook: file_post_open", "actor: unknown"],
        if_expected: "Rarely."
      },
      suppressed_by: "user.toml#3", acked: true
    }
    var text = Model.alertAsText(a)

    // The identity, so a reader can go and look it up.
    verify(text.indexOf("01ALERT") >= 0, "the id travels with it")
    verify(text.indexOf("moat-cred-ssh-private-key-read") >= 0)
    verify(text.indexOf("critical") >= 0)

    // The story.
    verify(text.indexOf("curl read a private key.") >= 0)
    verify(text.indexOf("/usr/bin/curl") >= 0)
    verify(text.indexOf("pid 42") >= 0)
    verify(text.indexOf("/usr/bin/bash") >= 0, "ancestry is rendered, not dropped")

    // The evidence lines are the point: they are what make an alert arguable.
    verify(text.indexOf("hook: file_post_open") >= 0)
    verify(text.indexOf("actor: unknown") >= 0)

    // And the two facts a half-told alert leaves out.
    verify(text.indexOf("blocked") >= 0, "what moat DID is part of the record")
    verify(text.indexOf("user.toml#3") >= 0, "so is the rule that silenced it")

    // Nothing to copy is not a crash.
    compare(Model.alertAsText(null), "")
    compare(Model.alertAsText({}), "")
  }

  // The first alert ever copied out of the panel printed "[object Object]":
  // `if_expected` is {hint, options:[{scope, cmd, line}]}, not prose. The
  // commands in it are the most useful lines on the clipboard, because they are
  // what you go and run.
  function test_alertAsText_renders_the_ignore_commands() {
    var a = {
      id: "01ALERT", rule: "moat-exec-untrusted-home", severity: "medium",
      explain: {
        what: "something ran.",
        expected: "A build you started yourself.",
        if_expected: {
          hint: "exe",
          options: [{ scope: "exe", cmd: "moatctl ignore 01ALERT --scope exe",
                      line: "[[rule]]\nname = \"moat-exec-untrusted-home\"\nexe = \"/x\"\n" }]
        }
      }
    }
    var text = Model.alertAsText(a)
    verify(text.indexOf("[object Object]") < 0, "never stringify the options object")
    verify(text.indexOf("A build you started yourself.") >= 0, "the prose comes from `expected`")
    verify(text.indexOf("moatctl ignore 01ALERT --scope exe") >= 0, "the command you would run")
    verify(text.indexOf("name = \"moat-exec-untrusted-home\"") >= 0, "and the TOML it writes")
    verify(text.indexOf("recommended scope: exe") >= 0)
  }

}
