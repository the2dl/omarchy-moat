// The Now tab (docs/design/README.md 1a, 1b, 3c).
// One idea runs through all of it: **answer first, evidence on request.** The
// top of the panel is a sentence, not a console; the incident is the page
// rather than half of a list/detail split; the four prose sections collapse to
// one verdict paragraph; five equal buttons become one primary and one
// secondary. Everything that used to lead -- severity pills, the daemon status
// strip, the unacked counter -- either moved into evidence or was deleted for
// being a to-do list the user never asked for.

import "MoatCopy.js" as Copy
import "MoatModel.js" as Model
import QtQuick
import qs.Commons
import qs.Ui

// Which of the four states this shows is DERIVED (Model.verdict), never chosen.
Item {
    // Which of the queue the card is showing. 1b says the incident IS the page,
    // which is right for one thing needing a decision -- but with eight of them
    // the page was pinned to queue[0] and there was no way to reach the other
    // seven. The rows below listed them and clicking one did nothing visible.
    // ------------------------------------------------------- the footer strip

    id: root

    property var service: null
    property var tokens: null
    /// Incidents from Model.buildIncidents, newest first.
    property var incidents: []
    property var status: null
    /// The card the keyboard acts on: the one incident that is the page.
    property alias card: incidentCard
    /// Advanced (`rawDetail`): read off the service, like every other component
    /// that renders an alert.
    readonly property bool raw: !!root.service && root.service.rawDetail === true
    readonly property var verdict: Model.verdict(root.incidents, root.status)
    readonly property var queue: Model.needsYouIncidents(root.incidents)
    // Held as a KEY, not an index: the queue re-sorts as verdicts land and
    // repeats arrive, and an index would silently slide the user onto a
    // different incident mid-read.
    property string cursorKey: ""
    readonly property int cursorIndex: {
        if (root.queue.length === 0)
            return -1;

        for (var i = 0; i < root.queue.length; i++) {
            if (root.queue[i].key === root.cursorKey)
                return i;

        }
        return 0;
    }
    readonly property var current: root.cursorIndex >= 0 ? root.queue[root.cursorIndex] : null
    readonly property var t: root.tokens
    readonly property color toneColor: {
        if (!root.t)
            return "transparent";

        switch (root.verdict.tone) {
        case "alarm":
            return root.t.alarm;
        case "accent":
            return root.t.accent;
        default:
            return root.t.calm;
        }
    }
    // The categories on a quiet day (1a). Grouped by family rather than by rule,
    // because "package installs" is a thing the user recognises and
    // "moat-pkg-subtree-downloader" is not.
    readonly property var categories: {
        var out = [];
        var byFamily = {
        };
        for (var i = 0; i < root.incidents.length; i++) {
            var inc = root.incidents[i];
            if (inc.state === "needsYou")
                continue;

            var fam = String(inc.family || "other");
            if (!byFamily[fam])
                byFamily[fam] = {
                "family": fam,
                "count": 0,
                "state": inc.state,
                "programs": {
                }
            };

            byFamily[fam].count += inc.count;
            byFamily[fam].programs[inc.program] = true;
            // "explained" is louder than "expected": it means Moat made a call.
            if (inc.state === "explained")
                byFamily[fam].state = "explained";

        }
        var labels = {
            "pkg": "Package installs",
            "persist": "Writes to your config",
            "cred": "Reads of your keys",
            "exec": "Programs that ran",
            "net": "Network connections",
            "priv": "Requests for more access",
            "rootkit": "Kernel-level changes",
            "ransom": "Files or snapshots destroyed",
            "shell": "Shells that opened",
            "x": "Moat itself",
            "other": "Other"
        };
        for (var k in byFamily) {
            var g = byFamily[k];
            var names = Object.keys(g.programs);
            out.push({
                "label": labels[g.family] || labels.other,
                "detail": g.count + (g.count === 1 ? " run, by " : " runs, by ") + Model.listOrNone(names.slice(0, 3)),
                "state": g.state
            });
        }
        out.sort(function(a, b) {
            return a.label < b.label ? -1 : 1;
        });
        return out;
    }

    signal openIncident(string id)
    signal requestWasMe(string id, string scope)
    signal requestClose(string id)
    signal requestStop(string id)
    signal requestAsk(string id)
    signal requestCopyBundle(string id)
    signal requestSaveBundle(string id)
    signal requestCopyBundleText(string id)
    /// 2b: one decision closes every step of a sequence.
    signal requestAllowChain(string id)
    signal requestEnforce()
    signal requestMonitor(string rule)
    signal openRules()

    function step(delta) {
        if (root.queue.length === 0)
            return ;

        var i = root.cursorIndex + delta;
        if (i < 0)
            i = root.queue.length - 1;

        if (i >= root.queue.length)
            i = 0;

        root.cursorKey = root.queue[i].key;
    }

    function showIncident(key) {
        root.cursorKey = String(key);
    }

    /// The left of the footer: only things that change what Moat does.
    function footerFacts() {
        if (!root.status)
            return "";

        // Model.footerFacts owns the two facts about what Moat will DO, so
        // they can be tested; the learning line is presentation and stays here.
        var bits = Model.footerFacts(root.status);
        if (root.service && root.service.learningSummary)
            bits.splice(1, 0, String(root.service.learningSummary));

        return bits.join("   ·   ");
    }

    /// The right of the footer: machine counters, dimmest colour, last.
    function footerCounters() {
        if (!root.status)
            return "";

        var loaded = Number(root.status.sensors_loaded);
        var total = Number(root.status.policies);
        var sensors = isFinite(loaded) && isFinite(total) && loaded !== total ? loaded + " of " + total + " detections" : total + " detections";
        return sensors + "  ·  tetragon " + String(root.status.tetragon || "?");
    }

    /// The sub-line under the verdict. Sentences, not counters.
    function summaryLine() {
        // What Moat has actually DONE, counted -- not inferred from the daemon-wide
        // mode.

        if (!root.status)
            return "";

        var bits = [];
        // The same "today" History's day header uses, or the sentence says
        // "today" over a number that is the whole log.
        var seen = Model.seenToday(root.incidents, root.service ? root.service.nowMs : Date.now());
        // 3a's sub-line: "Four things happened in nine minutes and they were all
        // the same program." A chain is the one state where the sentence under the
        // verdict is about the incident rather than about the day, because the
        // sequence IS the thing that needs reading.
        if (root.verdict.state === Copy.VERDICT_CHAIN && root.verdict.chain) {
            var chainLine = Copy.chainSummaryLine(root.verdict.chain, root.raw);
            if (chainLine)
                return chainLine;

        }
        if (root.verdict.state === Copy.VERDICT_GAP) {
            bits.push("Moat is running, but it cannot prove it was watching the whole time.");
            bits.push("Until that is fixed it will not tell you the machine is quiet.");
            return bits.join(" ");
        }
        var explained = 0;
        for (var j = 0; j < root.incidents.length; j++) {
            if (root.incidents[j].state === "explained")
                explained++;

        }
        if (seen > 0)
            bits.push("Moat looked at " + seen + (seen === 1 ? " thing" : " things") + " today.");

        if (explained > 0)
            bits.push(explained === 1 ? "One was worth a second look; it read it and closed it." : explained + " were worth a second look; it read them and closed them.");

        // This used to read the mode alone and announce "Nothing has been blocked,
        // because you are still in monitor mode." A rule armed on its own enforces
        // regardless of that mode, which is the entire point of `set mode enforce
        // --rule`: on 2026-09-05 a `cat /etc/shadow` was SIGKILLed by an armed rule
        // while this line insisted nothing had been blocked. Claiming something
        // about one event from a system-wide setting is the mistake this codebase
        // keeps making, and it is worst here, where the claim is "nothing
        // happened".
        var stopped = Model.stoppedIncidents(root.incidents).length;
        var armed = root.status && Array.isArray(root.status.enforceable) ? root.status.enforceable.filter(function(r) {
            return r.armed;
        }).length : 0;
        if (stopped > 0)
            bits.push(stopped === 1 ? "One thing was stopped." : stopped + " things were stopped.");
        else if (armed > 0)
            bits.push("Nothing has been stopped. " + armed + (armed === 1 ? " rule is armed" : " rules are armed") + "; everything else is watched only.");
        else if (root.status.mode !== "enforce")
            bits.push("Nothing has been blocked, because nothing is armed to block.");
        return bits.join(" ");
    }

    // 1a's key rule: the two facts that change what Moat DOES are sentences on
    // the left; the machine counters sit far right in the dimmest colour there
    // is. This is where the old status strip's content went, demoted from the
    // top of the panel to the bottom of it.
    Rectangle {
        id: footer

        anchors.left: parent.left
        anchors.right: parent.right
        anchors.bottom: parent.bottom
        height: root.t ? root.t.s(44) : 40
        color: root.t ? root.t.sunken : "transparent"

        Rectangle {
            anchors.top: parent.top
            width: parent.width
            height: 1
            color: root.t ? root.t.hairlineChrome : "transparent"
        }

        Text {
            anchors.left: parent.left
            anchors.leftMargin: root.t ? root.t.bodyPadX : 12
            anchors.verticalCenter: parent.verticalCenter
            width: parent.width * 0.62
            text: root.footerFacts()
            color: root.t ? root.t.faint : "grey"
            font.family: root.t ? root.t.family : "monospace"
            font.pixelSize: root.t ? root.t.fMeta : 11
            elide: Text.ElideRight
            textFormat: Text.PlainText
        }

        Text {
            anchors.right: parent.right
            anchors.rightMargin: root.t ? root.t.bodyPadX : 12
            anchors.verticalCenter: parent.verticalCenter
            text: root.footerCounters()
            color: root.t ? root.t.ghost : "grey"
            font.family: root.t ? root.t.family : "monospace"
            font.pixelSize: root.t ? root.t.fMeta : 11
            textFormat: Text.PlainText
        }

    }

    MoatScroll {
        id: scroller

        anchors.left: parent.left
        anchors.right: parent.right
        anchors.top: parent.top
        anchors.bottom: footer.top
        contentHeight: body.implicitHeight

        Column {
            // ------------------------------------------------------- the verdict
            // --------------------------------------------- the one that needs you
            // 3d. Enforce mode's real UI is the apology, and it belongs at the top of
            // Now rather than behind a tab: the user is looking at this panel because
            // something died in their terminal a minute ago.
            // ------------------------------------------------- the rest of the queue
            // 1g. The learning window, while it is open, and the one honest moment
            // the enforce question can be asked, just after it closes. Hides itself
            // the rest of the time.

            id: body

            x: root.t ? root.t.bodyPadX : 0
            width: parent.width - (root.t ? root.t.bodyPadX * 2 : 0)
            topPadding: root.t ? root.t.bodyPadTop : 0
            bottomPadding: root.t ? root.t.bodyPadBottom : 0
            spacing: root.t ? root.t.v(40) : 0

            // Exactly four forms (3g), and never a count of events: 68 repeats of one
            // thing is "One thing needs you."
            Row {
                width: parent.width
                spacing: root.t ? root.t.s(12) : 0

                Rectangle {
                    width: root.t ? root.t.dotSize : 0
                    height: width
                    radius: width / 2
                    color: root.toneColor
                    y: root.t ? Math.round(root.t.fVerdict * 0.45) : 0
                }

                Column {
                    width: parent.width - (root.t ? root.t.dotSize + root.t.s(12) : 0)
                    spacing: root.t ? root.t.s(13) : 0

                    Text {
                        width: parent.width
                        text: root.verdict.line
                        color: root.t ? root.t.primary : "white"
                        font.family: root.t ? root.t.family : "monospace"
                        font.pixelSize: root.t ? root.t.fVerdict : 26
                        font.weight: Font.Medium
                        font.letterSpacing: root.t ? root.t.lsVerdict : 0
                        wrapMode: Text.WordWrap
                        textFormat: Text.PlainText
                    }

                    // The sub-line says what Moat DID, in sentences. The two facts that
                    // change what it does -- not blocking, still learning -- belong here;
                    // machine counters live in the footer in the dimmest colour.
                    Text {
                        width: parent.width
                        visible: text !== ""
                        text: root.summaryLine()
                        color: root.t ? root.t.muted : "grey"
                        font.family: root.t ? root.t.family : "monospace"
                        font.pixelSize: root.t ? root.t.fBody : 13
                        lineHeight: root.t ? root.t.lhBody : 1.7
                        wrapMode: Text.WordWrap
                        textFormat: Text.PlainText
                    }

                }

            }

            // 1b: when something needs a decision, the incident IS the page. No
            // list/detail split, because the split is what made the old panel need a
            // severity pill on every row to tell you where to look.
            // Where you are in the queue, and how to move. Only when there is more
            // than one thing waiting -- a single incident needs no pager.
            Row {
                width: parent.width
                visible: root.queue.length > 1
                spacing: root.t ? root.t.s(12) : 8

                Text {
                    anchors.verticalCenter: parent.verticalCenter
                    text: (root.cursorIndex + 1) + " of " + root.queue.length
                    color: root.t ? root.t.fainter : "grey"
                    font.family: root.t ? root.t.family : "monospace"
                    font.pixelSize: root.t ? root.t.fMeta : 11
                    textFormat: Text.PlainText
                }

                Button {
                    anchors.verticalCenter: parent.verticalCenter
                    text: "Previous"
                    iconText: ""
                    foreground: root.t ? root.t.dimmer : "grey"
                    fontSize: root.t ? root.t.fSecondary : 12
                    onClicked: root.step(-1)
                }

                Button {
                    anchors.verticalCenter: parent.verticalCenter
                    text: "Next"
                    iconText: ""
                    foreground: root.t ? root.t.dimmer : "grey"
                    fontSize: root.t ? root.t.fSecondary : 12
                    onClicked: root.step(1)
                }

                Text {
                    anchors.verticalCenter: parent.verticalCenter
                    text: "or j / k"
                    color: root.t ? root.t.ghost : "grey"
                    font.family: root.t ? root.t.family : "monospace"
                    font.pixelSize: root.t ? root.t.fMeta : 11
                    textFormat: Text.PlainText
                }

            }

            // It sat BELOW the focused incident card until 2026-09-05, and that card
            // can be taller than the screen -- so the one thing on this page with a
            // deadline was the one thing you had to scroll to find. The comment above
            // was right and the layout did not match it.
            Repeater {
                model: Model.blockedIncidents(root.incidents).slice(0, 1)

                delegate: BlockedCard {
                    required property var modelData

                    width: body.width
                    tokens: root.t
                    service: root.service
                    incident: modelData
                    // Do what the button says. It used to navigate to the History tab,
                    // so a button labelled "Allow cat" -- under a line promising it adds
                    // a rule -- moved the user to another screen and allowed nothing.
                    // Allowing needs root, so the confirmation is the polkit prompt.
                    onAllowRequested: function(id, scope) {
                        root.requestWasMe(id, scope);
                    }
                    onMonitorRequested: function(rule) {
                        root.requestMonitor(rule);
                    }
                    onCloseIt: function(id) {
                        root.requestClose(id);
                    }
                }

            }

            IncidentCard {
                id: incidentCard

                width: parent.width
                visible: root.queue.length > 0
                tokens: root.t
                service: root.service
                incident: root.current
                onWasMe: function(id, scope) {
                    root.requestWasMe(id, scope);
                }
                onCloseIt: function(id) {
                    root.requestClose(id);
                }
                onStopIt: function(id) {
                    root.requestStop(id);
                }
                onAskMoat: function(id) {
                    root.requestAsk(id);
                }
                onCopyBundle: function(id) {
                    root.requestCopyBundle(id);
                }
                onSaveBundle: function(id) {
                    root.requestSaveBundle(id);
                }
                onCopyBundleText: function(id) {
                    root.requestCopyBundleText(id);
                }
                onAllowChain: function(id) {
                    root.requestAllowChain(id);
                }
            }

            // 3c: ordered by what Moat is least sure about, not by severity.
            Column {
                width: parent.width
                visible: root.queue.length > 1
                spacing: root.t ? root.t.s(10) : 0

                PanelSectionHeader {
                    text: root.queue.length === 2 ? "THE OTHER ONE" : "THE OTHER " + (root.queue.length - 1)
                    foreground: root.t ? root.t.fainter : "grey"
                }

                Repeater {
                    // Advanced: severity beside the state word. Empty in the default
                    // voice, where 1a's whole point is that a row says what is wanted
                    // from you rather than how alarming a detection thought it was.

                    // Everything except the one on screen, so the list is always "what
                    // else", never a row duplicating the card above it.
                    model: root.queue.filter(function(q) {
                        return q.key !== root.cursorKey;
                    })

                    delegate: SummaryRow {
                        required property var modelData

                        width: parent.width
                        tokens: root.t
                        label: modelData.title
                        detail: modelData.stake
                        state: modelData.state
                        // And empty on a chain in EVERY mode. A chain's severity is the
                        // daemon's statement about a sequence and CONTRACT 4 forbids
                        // showing it without `severity_reason`; a 130px column cannot
                        // carry the reason, so the number stays on the card, where it
                        // prints with it. The row says "a sequence of N" instead.
                        severity: root.raw && !modelData.chain ? String(modelData.severity || "") : ""
                        count: modelData.count
                        // Clicking a row brings it into the card. Previously this raised
                        // openIncident, which selected an alert nothing on this tab was
                        // showing -- so the click appeared to do nothing at all.
                        onActivated: root.showIncident(modelData.key)
                    }

                }

            }

            // BELOW the queue, not above it. This is reassurance -- "the job has an
            // end and here is how far through it is" -- and it was sitting between
            // the incident that needs a decision and the list of the others, cutting
            // the one flow on this page in half: read the incident, press j, read the
            // next. In a window shorter than the design's page it also pushed that
            // list off the bottom. Down here it costs the queue nothing, and on a
            // quiet day -- no queue, no card, nothing between it and the verdict --
            // it lands exactly where it used to, which is where it belongs when it is
            // the most interesting thing on the screen.
            LearningCard {
                width: parent.width
                tokens: root.t
                service: root.service
                status: root.status
                onEnforceRequested: root.requestEnforce()
                onReviewRulesRequested: root.openRules()
            }

            // --------------------------------------------- what it watched today
            Column {
                width: parent.width
                visible: root.categories.length > 0
                spacing: 0

                PanelSectionHeader {
                    text: root.queue.length > 0 ? "ALSO TODAY" : "WHAT IT WATCHED TODAY"
                    foreground: root.t ? root.t.fainter : "grey"
                    bottomPadding: root.t ? root.t.s(10) : 0
                }

                Repeater {
                    model: root.categories

                    delegate: SummaryRow {
                        required property var modelData

                        width: parent.width
                        tokens: root.t
                        label: modelData.label
                        detail: modelData.detail
                        state: modelData.state
                        showChevron: false
                    }

                }

            }

        }

    }

}
