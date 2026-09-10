// The incident that needs you (docs/design/README.md 1b), and the same card
// with a repeat count and a silence choice (1c).
// What changed from the old AlertDetail: the four headed prose sections (what
// happened / why flagged / evidence / what to do) collapse into ONE verdict
// paragraph, because AI analysis now runs on arrival and its verdict *is* the
// summary. Evidence is collapsed behind a disclosure rather than being a third
// of the page. Five equally-weighted buttons become one primary and one
// secondary, with scope as a follow-up choice rather than four more buttons.

import "MoatCopy.js" as Copy
import "MoatModel.js" as Model
import QtQuick
import qs.Commons
import qs.Ui

// Severity appears exactly once, inside evidence, as a fact with its reason --
// never as a badge. A badge answers "how bad is this?", which is the question
// the user cannot act on; the state word answers "what do you want from me?".
Rectangle {
    // A different incident means a fresh set of drawers: leaving the scope chips
    // open across a change of incident would offer to write a rule about one
    // thing while the card describes another.
    // Keyed on the incident's IDENTITY, not on the object. `incident` is bound
    // through `Model.buildIncidents`, which allocates new JS objects on every
    // rebuild -- and it rebuilds on the status poll (10 s by default) and on
    // every append to alerts.jsonl. Resetting on the object changing therefore
    // closed the evidence drawer under the user a few seconds after they opened
    // it, on every refresh, forever.
    // Closed, in both modes.

    id: root

    property var tokens: null
    property var service: null
    property var incident: null
    property bool evidenceOpen: false
    /// Whether the agent's full reasoning is expanded. Collapsed by default:
    /// see the note on `reasoningText`.
    property bool reasoningOpen: false
    /// 1c: "This was me" asks how wide before it writes anything.
    property bool scopeOpen: false
    /// 2i: the third answer, opened from "I don't know".
    property bool bundleOpen: false
    readonly property var t: root.tokens
    readonly property var head: root.incident ? root.incident.head : null
    // `key` and not `id`: the id is the newest member's alert id and moves when a
    // repeat joins a still-open incident, which is exactly the incident somebody
    // is most likely to be reading the evidence of.
    property string _openFor: ""
    /// The Advanced setting. Read straight off the service: every component that
    /// renders an alert already has one, so there is nothing to thread through.
    readonly property bool raw: !!root.service && root.service.rawDetail === true
    readonly property var verdict: root.incident ? root.incident.verdict : null
    readonly property bool needsYou: !!root.incident && root.incident.state === "needsYou"
    /// 3a. A correlated sequence is the one thing in this product allowed to be
    /// alarming: the border, the verdict rule and the verdict label all move from
    /// accent to alarm, and the card grows the chain between the paragraph and
    /// the actions. `buildIncidents` set this from the daemon's `alert.chain`;
    /// nothing here decides that a sequence exists.
    readonly property var chain: root.incident && root.incident.chain ? root.incident.chain : null
    readonly property var rotateItems: root.service && root.head ? root.service.rotateItems(root.head) : []
    /// The recorded fields, label/value flattened. Empty unless Advanced is on,
    /// so the default card allocates nothing for it.
    readonly property var rawFacts: root.raw && root.service && root.head ? root.service.rawFacts(root.head) : []
    /// True while auto-triage has not yet reached this incident. The design wants
    /// the incident listed with its title and facts while the paragraph resolves,
    /// not held back until it does.
    /// Nothing has been read yet: show "reading the evidence" in place of the
    /// paragraph. Distinct from `stillReading` below, which is a note beside a
    /// verdict that already exists.
    readonly property bool pendingVerdict: !root.verdict && !!root.head && !!root.service && root.service.autoTriageOn === true
    /// A verdict is shown, but a newer occurrence has not been looked at yet.
    readonly property bool stillReading: !!root.verdict && !!root.incident && root.incident.awaitingVerdict === true && !!root.service && root.service.autoTriageOn === true

    signal wasMe(string id, string scope)
    /// "I have read this; stop asking." Acks the alert and writes no rule.
    signal closeIt(string id)
    signal stopIt(string id)
    signal askMoat(string id)
    signal copyBundle(string id)
    signal saveBundle(string id)
    signal copyBundleText(string id)
    /// 2b: "same chain, same decision" -- one ack for every step of a sequence.
    signal allowChain(string id)

    function openScope() {
        root.bundleOpen = false;
        root.scopeOpen = true;
    }

    /// 2g: `a` opens the scopes, then 1-4 picks one.
    function chooseScope(n) {
        if (root.scopeOpen)
            scopeChoice.chooseIndex(n);

    }

    function toggleEvidence() {
        root.evidenceOpen = !root.evidenceOpen;
    }

    function factTarget() {
        if (!root.head)
            return "";

        if (root.head.file && root.head.file.path)
            return String(root.head.file.path);

        if (root.head.net && root.head.net.dst_ip)
            return String(root.head.net.dst_ip) + ":" + String(root.head.net.dst_port || "");

        return String(root.head.process ? root.head.process.exe || "" : "");
    }

    // The feed sends `explain` as `{why}` alone; the rest of the block is
    // fetched when a card shows the alert. Every poll rebuilds the incident,
    // so this also re-asks after a fold moved the count -- and it is a no-op
    // once the block is held (Service caches it by id and count).
    onHeadChanged: {
        if (root.service && root.head && typeof root.service.loadExplain === "function")
            root.service.loadExplain(root.head.id);

    }

    onIncidentChanged: {
        var key = root.incident ? String(root.incident.key) : "";
        if (key === root._openFor)
            return ;

        root._openFor = key;
        root.scopeOpen = false;
        root.bundleOpen = false;
        // Advanced used to force this open on every card, and the raw block is a
        // dozen key/value rows -- so with Advanced on, one incident filled the
        // viewport and the queue behind it, the blocked card and the day's summary
        // were all below the fold. Advanced means the raw values are AVAILABLE and
        // the copy is blunt; it does not mean every card should be its longest
        // possible self. One click still opens it, and the button says so.
        root.evidenceOpen = false;
    }
    implicitHeight: card.implicitHeight
    color: root.t ? root.t.card : "transparent"
    radius: root.t ? root.t.rIncident : 0
    border.width: root.needsYou || !!root.chain ? 1 : 0
    // 3a's card border is the same colour a stronger step further up: 0.22 for
    // 1b's one thing, 0.3 for a sequence.
    border.color: root.t ? root.t.alarmTint(root.chain ? 0.3 : 0.22) : "transparent"

    Column {
        // ------------------------------------------------------------- title
        // ----------------------------------------------------- the verdict
        // The answer, first. One paragraph in Moat's own voice, marked by an accent
        // rule down the left so it is visibly Moat talking rather than evidence.
        // ------------------------------------------------------ the sequence
        // ------------------------------------------------------- two facts
        // ------------------------------------------------- what was reachable
        // CONTRACT 4's `rotate[]`. The point it exists to make is that no decision
        // on this page un-reads a secret: allowing the alert does not, and killing
        // the process does not. It sits above the actions for that reason.
        // --------------------------------------------------------- actions
        // Two, not five. `This was me` is the answer nine times out of ten and gets
        // the only filled button; scope is a follow-up choice (1c), not four more
        // buttons. `Ack` is gone -- reading a resolved incident acknowledges it.
        // 2i. The bundle preview and the two things that can be done with it.

        id: card

        x: root.t ? root.t.cardPadX : 0
        width: parent.width - (root.t ? root.t.cardPadX * 2 : 0)
        topPadding: root.t ? root.t.cardPadTop : 0
        bottomPadding: root.t ? root.t.cardPadBottom : 0
        spacing: root.t ? root.t.v(22) : 12

        // The consequence in the user's terms (3g), never the detection's name.
        // The rule id is available, at the bottom, in the dimmest colour there is.
        // The title, and beside it the way to get this record OUT of the panel.
        // The panel is a popup: a click-drag across it is as likely to dismiss
        // it as to select anything, so without a button the text is trapped
        // here. It sits in the header because that is where a person looks when
        // they have decided they want to keep or send an alert -- not at the
        // bottom, after the evidence they have already finished reading.
        Item {
            width: parent.width
            implicitHeight: Math.max(titleText.implicitHeight, copyAlert.implicitHeight)

            Text {
                id: titleText

                anchors.left: parent.left
                anchors.right: copyAlert.left
                anchors.rightMargin: root.t ? root.t.s(10) : 6
                anchors.verticalCenter: parent.verticalCenter
                text: root.incident ? root.incident.title : ""
                color: root.t ? root.t.primary : "white"
                font.family: root.t ? root.t.family : "monospace"
                font.pixelSize: root.t ? root.t.fHeading : 19
                font.weight: Font.Medium
                lineHeight: 1.4
                wrapMode: Text.WordWrap
                textFormat: Text.PlainText
            }

            Button {
                id: copyAlert

                anchors.right: parent.right
                anchors.top: parent.top
                text: "copy"
                foreground: root.t ? root.t.fainter : "grey"
                fontSize: root.t ? root.t.fMeta : 11
                onClicked: {
                    if (root.service && root.head)
                        root.service.copyText(Model.alertAsText(root.head), "alert");
                }
            }

        }

        // 1e/3g put the rule id last and dimmest; Advanced puts it first and bright,
        // beside the severity, because that pair is the whole reason someone turned
        // this on. The state word underneath still says what is wanted from them --
        // severity is added here, it does not replace it.
        Row {
            width: parent.width
            visible: root.raw && !!root.incident
            spacing: root.t ? root.t.s(14) : 8

            Text {
                text: root.chain ? Copy.chainRuleNote(root.chain) : (root.incident ? root.incident.rule : "")
                color: root.t ? root.t.accent : "orange"
                font.family: root.t ? root.t.family : "monospace"
                font.pixelSize: root.t ? root.t.fSecondary : 12
                textFormat: Text.PlainText
            }

            // On a chain this is the HEAD's own severity, which is still the truth
            // about that one event; the sequence's severity is a different number and
            // it only ever appears with its reason, in ChainBlock.
            Text {
                text: root.head && root.service ? root.service.rawSeverityLine(root.head) : ""
                color: root.t ? root.t.secondary : "white"
                font.family: root.t ? root.t.family : "monospace"
                font.pixelSize: root.t ? root.t.fSecondary : 12
                textFormat: Text.PlainText
            }

            Text {
                text: root.incident ? Copy.stateWord(String(root.incident.state)) : ""
                color: root.t ? root.t.fainter : "grey"
                font.family: root.t ? root.t.family : "monospace"
                font.pixelSize: root.t ? root.t.fSecondary : 12
                textFormat: Text.PlainText
            }

        }

        // Meta row: dot-separated facts, program name brightest.
        Text {
            width: parent.width
            text: {
                if (!root.incident)
                    return "";

                var bits = [root.incident.program];
                if (root.service) {
                    var age = root.service.relativeTime(root.incident.lastSeen);
                    if (age)
                        bits.push(age);

                }
                // A chain's members are DIFFERENT things, so "2 times" would be a lie
                // in the one place the user most needs the truth. It says how many
                // steps and how long they took instead.
                if (root.chain) {
                    bits.push(root.chain.steps_total + " steps");
                    var span = Copy.spanPhrase(root.chain.span_secs);
                    if (span)
                        bits.push(span);

                } else {
                    var repeat = Copy.repeatPhrase(root.incident.family, root.incident.count);
                    if (repeat)
                        bits.push(repeat);

                }
                if (root.head && root.head.rarity === "first_seen")
                    bits.push("first time on this machine");

                if (root.head && root.head.action_taken === "none")
                    bits.push("nothing has been stopped");

                return bits.join("  ·  ");
            }
            color: root.t ? root.t.faint : "grey"
            font.family: root.t ? root.t.family : "monospace"
            font.pixelSize: root.t ? root.t.fSecondary : 12
            wrapMode: Text.WordWrap
            textFormat: Text.PlainText
        }

        // 3a's standalone line: the one sentence that says why these are one
        // thing. It sits above the model's paragraph rather than inside it,
        // because it is true whether or not auto-triage ever ran -- moatd
        // correlated the sequence, and that is a fact about the machine, not an
        // opinion about it.
        Text {
            width: parent.width
            visible: !!root.chain && text !== ""
            text: root.incident ? String(root.incident.stake || "") : ""
            color: root.t ? root.t.bright : "white"
            font.family: root.t ? root.t.family : "monospace"
            font.pixelSize: root.t ? root.t.fBody : 13
            lineHeight: root.t ? root.t.lhBody : 1.7
            wrapMode: Text.WordWrap
            textFormat: Text.PlainText
        }

        // Every string in here was written by a language model that had just read
        // attacker-controlled input, so all of it renders as PlainText.
        Item {
            width: parent.width
            visible: !!root.verdict || root.pendingVerdict
            implicitHeight: verdictCol.implicitHeight

            // 3a: the only place the accent verdict rule turns red.
            Rectangle {
                width: 2
                height: parent.height
                color: root.t ? (root.chain ? root.t.alarmTint(0.5) : root.t.accentTint(0.4)) : "transparent"
            }

            Column {
                id: verdictCol

                x: root.t ? root.t.s(16) : 8
                width: parent.width - x
                spacing: root.t ? root.t.s(9) : 6

                Text {
                    text: "MOAT READ IT THIS WAY"
                    // 3a: "the only place the orange verdict label turns red".
                    color: root.t ? (root.chain ? root.t.alarm : root.t.accent) : "orange"
                    font.family: root.t ? root.t.family : "monospace"
                    font.pixelSize: root.t ? root.t.fMeta : 11
                    font.letterSpacing: root.t ? root.t.lsVerdictLabel : 0
                }

                // While the pass is still running the incident is listed with its title
                // and facts and this line stands in for the paragraph -- the design's
                // pending state, rather than an empty block that looks like a bug.
                // A verdict that predates the newest occurrence says so, rather than
                // silently describing an older event.
                Text {
                    width: parent.width
                    visible: root.stillReading
                    text: "Still reading the most recent one."
                    color: root.t ? root.t.faint : "grey"
                    font.family: root.t ? root.t.family : "monospace"
                    font.pixelSize: root.t ? root.t.fMeta : 11
                    font.italic: true
                    textFormat: Text.PlainText
                }

                Text {
                    width: parent.width
                    visible: root.pendingVerdict
                    text: "Reading the evidence…"
                    color: root.t ? root.t.dimmer : "grey"
                    font.family: root.t ? root.t.family : "monospace"
                    font.pixelSize: root.t ? root.t.fTitle : 14
                    font.italic: true
                    textFormat: Text.PlainText
                }

                Text {
                    width: parent.width
                    visible: !!root.verdict
                    text: root.verdict ? root.verdict.summary : ""
                    color: root.t ? root.t.body : "white"
                    font.family: root.t ? root.t.family : "monospace"
                    font.pixelSize: root.t ? root.t.fTitle : 14
                    lineHeight: root.t ? root.t.lhVerdictBody : 1.75
                    wrapMode: Text.WordWrap
                    textFormat: Text.PlainText
                }

                // Clamped, because this is the one field on the card with no upper
                // bound: an agent writes as much as it wants to. On 2026-09-05 one
                // verdict ran to roughly eight hundred words and filled the whole of
                // Now by itself -- the blocked-process card, the rest of the queue and
                // the day's summary were all still there, just below the fold, and the
                // page read as though they were missing. The reasoning is worth having;
                // it is not worth more room than everything else put together.
                Text {
                    id: reasoningText

                    width: parent.width
                    visible: !!root.verdict && root.verdict.reasoning !== ""
                    text: root.verdict ? root.verdict.reasoning : ""
                    color: root.t ? root.t.dimmer : "grey"
                    font.family: root.t ? root.t.family : "monospace"
                    font.pixelSize: root.t ? root.t.fSecondary : 12
                    lineHeight: root.t ? root.t.lhBody : 1.7
                    wrapMode: Text.WordWrap
                    maximumLineCount: root.reasoningOpen ? 10000 : 6
                    elide: Text.ElideRight
                    textFormat: Text.PlainText
                }

                // Only offered when there is more to see: a control that expands
                // nothing is worse than no control.
                Button {
                    visible: reasoningText.visible && (reasoningText.truncated || root.reasoningOpen)
                    text: root.reasoningOpen ? "Show less" : "Show the whole reasoning"
                    foreground: root.t ? root.t.dimmer : "grey"
                    fontSize: root.t ? root.t.fSecondary : 12
                    onClicked: root.reasoningOpen = !root.reasoningOpen
                }

                // What the verdict was allowed to do. A benign call the ceiling refused
                // to act on says so, or it reads as the panel ignoring the agent.
                Text {
                    width: parent.width
                    visible: !!root.verdict && root.verdict.withheld !== ""
                    text: root.verdict ? "Left waiting on you: " + root.verdict.withheld + "." : ""
                    color: root.t ? root.t.faint : "grey"
                    font.family: root.t ? root.t.family : "monospace"
                    font.pixelSize: root.t ? root.t.fMeta : 11
                    wrapMode: Text.WordWrap
                    textFormat: Text.PlainText
                }

            }

        }

        // 3a. Between the paragraph and the actions, because the sequence is the
        // reasoning: the fourth event is what changes the meaning of the first, and
        // it has to be read before a decision is made about any of them.
        ChainBlock {
            width: parent.width
            tokens: root.t
            service: root.service
            incident: root.incident
            onAllowChain: function(id) {
                root.allowChain(id);
            }
        }

        // Only the two that answer "what, and by what". Everything else is evidence.
        // Advanced: the record itself, in the card, without opening anything. The
        // two facts below are a strict subset of these, so they step aside rather
        // than print the same exe twice under a friendlier label.
        Grid {
            width: parent.width
            visible: root.raw && root.rawFacts.length > 0
            columns: 2
            columnSpacing: root.t ? root.t.s(16) : 8
            rowSpacing: root.t ? root.t.s(6) : 4

            Repeater {
                model: root.rawFacts

                delegate: Text {
                    required property var modelData
                    required property int index

                    width: index % 2 === 0 ? (root.t ? root.t.s(120) : 90) : card.width - (root.t ? root.t.s(136) : 98)
                    text: modelData
                    color: index % 2 === 0 ? (root.t ? root.t.fainter : "grey") : (root.t ? root.t.secondary : "white")
                    font.family: root.t ? root.t.family : "monospace"
                    font.pixelSize: root.t ? root.t.fSecondary : 12
                    // Values here are argv, paths and a multi-line parent chain out of a
                    // process nobody vouched for. WrapAnywhere so a 3 kB argument wraps
                    // instead of stretching the card, and a ceiling so it cannot own the
                    // page -- Advanced is more detail, not unbounded detail.
                    wrapMode: Text.WrapAnywhere
                    maximumLineCount: 10
                    elide: Text.ElideRight
                    textFormat: Text.PlainText
                }

            }

        }

        Grid {
            width: parent.width
            visible: !root.raw
            columns: 2
            columnSpacing: root.t ? root.t.s(16) : 8
            rowSpacing: root.t ? root.t.s(7) : 4
            verticalItemAlignment: Grid.AlignVCenter

            Text {
                width: root.t ? root.t.s(120) : 90
                text: root.head && root.head.file ? "The file" : "The target"
                color: root.t ? root.t.fainter : "grey"
                font.family: root.t ? root.t.family : "monospace"
                font.pixelSize: root.t ? root.t.fSecondary : 12
            }

            Text {
                width: parent.width - (root.t ? root.t.s(120) + root.t.s(16) : 98)
                text: root.factTarget()
                color: root.t ? root.t.secondary : "white"
                font.family: root.t ? root.t.family : "monospace"
                font.pixelSize: root.t ? root.t.fSecondary : 12
                elide: Text.ElideMiddle
                textFormat: Text.PlainText
            }

            Text {
                width: root.t ? root.t.s(120) : 90
                text: "The program"
                color: root.t ? root.t.fainter : "grey"
                font.family: root.t ? root.t.family : "monospace"
                font.pixelSize: root.t ? root.t.fSecondary : 12
            }

            Text {
                width: parent.width - (root.t ? root.t.s(120) + root.t.s(16) : 98)
                text: root.head && root.head.process ? String(root.head.process.exe || "") : ""
                color: root.t ? root.t.secondary : "white"
                font.family: root.t ? root.t.family : "monospace"
                font.pixelSize: root.t ? root.t.fSecondary : 12
                elide: Text.ElideMiddle
                textFormat: Text.PlainText
            }

        }

        // It used to make that point by shouting "CHANGE THESE, WHATEVER YOU
        // DECIDE HERE" over a list, unconditionally -- including on the alerts
        // most likely to be nothing. Telling somebody to reset every password in
        // their browser profile because a helper process touched a cookie DB is an
        // instruction nobody follows, and an instruction nobody follows teaches
        // them to skip the panel. The exposure is a FACT and is stated as one; the
        // rotation is a CONSEQUENCE of a judgement the user has not made yet, and
        // is phrased against that judgement.
        Column {
            width: parent.width
            visible: root.rotateItems.length > 0
            spacing: root.t ? root.t.s(7) : 4

            Text {
                text: "WHAT THAT PROGRAM COULD READ"
                color: root.t ? root.t.faint : "grey"
                font.family: root.t ? root.t.family : "monospace"
                font.pixelSize: root.t ? root.t.fMeta : 11
                font.letterSpacing: root.t ? root.t.lsLabel : 0
            }

            // The one sentence that used to be a shout. Said once, in ordinary
            // weight, and conditioned on the decision the user is about to make.
            Text {
                width: parent.width
                text: "If that was not something you ran, replacing these is the only thing that " + "undoes it \u2014 nothing on this page does."
                color: root.t ? root.t.dimmer : "grey"
                font.family: root.t ? root.t.family : "monospace"
                font.pixelSize: root.t ? root.t.fSecondary : 12
                lineHeight: root.t ? root.t.lhBody : 1.7
                wrapMode: Text.WordWrap
                textFormat: Text.PlainText
            }

            Repeater {
                model: root.rotateItems

                delegate: Text {
                    required property var modelData

                    width: card.width
                    text: modelData.kind + " — " + modelData.guidance
                    color: root.t ? root.t.secondary : "white"
                    font.family: root.t ? root.t.family : "monospace"
                    font.pixelSize: root.t ? root.t.fSecondary : 12
                    lineHeight: root.t ? root.t.lhBody : 1.7
                    wrapMode: Text.WordWrap
                    textFormat: Text.PlainText
                }

            }

        }

        // `I don't know` (2i) is a text link rather than a third button because it
        // is not a third opinion of equal weight -- but it exists, because an
        // honest non-answer with nowhere to go becomes a permanent red dot, and a
        // permanent red dot is what makes people click allow on things they do not
        // understand.
        Flow {
            // Every alert needs a way out that is not "allow this forever".
            // NOT 2a. The design's "Ask Moat" is a thread inside the panel and the
            // daemon has no endpoint for one, so this is the thing that does exist:
            // `moatctl analyze` writes the evidence bundle and hands it to
            // `omarchy-agent`, which opens a TERMINAL. The label says so, and the
            // panel gets out of the way when it is pressed -- a button that silently
            // spawns a window behind an overlay is a button that appears to do
            // nothing.

            width: parent.width
            visible: !root.scopeOpen && !root.bundleOpen
            spacing: root.t ? root.t.s(12) : 8

            Button {
                text: "This was me"
                iconText: "" // nerd-font check; this shell has no Material Symbols
                background: root.t ? root.t.accent : "orange"
                foreground: root.t ? root.t.accentLabel : "black"
                fontSize: root.t ? root.t.fBody : 13
                // Gated on the daemon offering `ignore`, exactly as "Stop it" is
                // gated on `kill`. Some alerts report on Moat itself being weakened,
                // stopped or blinded, and they carry no ignore action: allowlisting
                // one would not quieten a noisy detection, it would make every future
                // weakening silent. Offering a button the daemon then refuses is
                // worse than not offering it.
                visible: !!root.head && root.head.actions && root.head.actions.indexOf("ignore") !== -1
                onClicked: root.openScope()
            }

            // What to say when there is nothing to decide. Without this the card
            // shows an alert, no primary action and no reason why, which reads as a
            // broken screen rather than a deliberate one.
            Text {
                visible: !!root.head && root.head.actions && root.head.actions.indexOf("ignore") === -1 && root.head.actions.indexOf("kill") === -1
                width: parent.width
                text: "Nothing to allow here \u2014 this is Moat reporting on itself. Read it and close it."
                color: root.t ? root.t.dimmer : "grey"
                font.family: root.t ? root.t.family : "monospace"
                font.pixelSize: root.t ? root.t.fSecondary : 12
                wrapMode: Text.WordWrap
                textFormat: Text.PlainText
            }

            Button {
                text: "Stop it"
                iconText: "" // nerd-font ban
                bordered: true
                background: root.t ? root.t.alarmTint(0.13) : "transparent"
                foreground: root.t ? root.t.alarm : "red"
                accent: root.t ? root.t.alarm : "red"
                fontSize: root.t ? root.t.fBody : 13
                visible: !!root.head && root.head.actions && root.head.actions.indexOf("kill") !== -1
                onClicked: root.stopIt(root.incident ? root.incident.id : "")
            }

            Button {
                text: "I don't know"
                foreground: root.t ? root.t.dimmer : "grey"
                fontSize: root.t ? root.t.fSecondary : 12
                onClicked: {
                    root.scopeOpen = false;
                    root.bundleOpen = true;
                }
            }

            // `Ack` was removed from this card on the reasoning that reading a
            // RESOLVED incident acknowledges it -- true for one Moat already dealt
            // with, and not true for one that is asking. The alerts about Moat's own
            // integrity make that plain: they deliberately carry no `ignore`, so
            // until this existed there was no way to clear one at all, and the badge
            // kept a permanent count nobody could answer. A permanent red dot is
            // what teaches people to allow things they do not understand.
            Button {
                text: "Close it"
                foreground: root.t ? root.t.dimmer : "grey"
                fontSize: root.t ? root.t.fSecondary : 12
                onClicked: root.closeIt(root.incident ? root.incident.id : "")
            }

            Button {
                text: root.evidenceOpen ? "Hide evidence" : "Show evidence"
                foreground: root.t ? root.t.dimmer : "grey"
                fontSize: root.t ? root.t.fSecondary : 12
                onClicked: root.evidenceOpen = !root.evidenceOpen
            }

            // The label never names the agent. `omarchy default agent` may be any of
            // them, and Moat does not put one vendor's name on its own button; which
            // one it is lives in the tooltip.
            Button {
                visible: !!root.service && root.service.agentButtonLabel !== ""
                text: root.service ? root.service.agentButtonLabel : ""
                tooltipText: root.service ? root.service.agentTooltip : ""
                foreground: root.t ? root.t.dimmer : "grey"
                fontSize: root.t ? root.t.fSecondary : 12
                onClicked: root.askMoat(root.incident ? root.incident.id : "")
            }

            // No default agent set: the exact command, rather than a dead control.
            Text {
                visible: !!root.service && root.service.agentButtonLabel === ""
                anchors.verticalCenter: parent.verticalCenter
                text: root.service ? root.service.agentHint : ""
                color: root.t ? root.t.ghost : "grey"
                font.family: root.t ? root.t.family : "monospace"
                font.pixelSize: root.t ? root.t.fMeta : 11
                textFormat: Text.PlainText
            }

        }

        // 1c. It replaces the action row rather than sitting under it: the question
        // "how wide?" has one answer, and leaving the buttons that asked it on
        // screen invites a second one.
        ScopeChoice {
            id: scopeChoice

            width: parent.width
            visible: root.scopeOpen
            tokens: root.t
            service: root.service
            incident: root.incident
            onConfirmed: function(id, scope) {
                root.scopeOpen = false;
                root.wasMe(id, scope);
            }
            onCancelled: root.scopeOpen = false
        }

        // NOT DONE, and deliberately: 2i also mutes the incident until something
        // new happens. There is no daemon verb for that state -- `ack` closes an
        // alert, which is a different promise -- so this offers the file and says
        // nothing about muting.
        Rectangle {
            width: parent.width
            visible: root.bundleOpen
            implicitHeight: bundle.implicitHeight + (root.t ? root.t.smallCardPadY * 2 : 16)
            radius: root.t ? root.t.rCard : 0
            color: root.t ? root.t.chip : "transparent"

            Column {
                id: bundle

                x: root.t ? root.t.smallCardPadX : 8
                y: root.t ? root.t.smallCardPadY : 8
                width: parent.width - (root.t ? root.t.smallCardPadX * 2 : 16)
                spacing: root.t ? root.t.s(9) : 6

                Text {
                    width: parent.width
                    text: "Leaves this open, and packages what Moat recorded as one file you can hand to someone who does know."
                    color: root.t ? root.t.body : "white"
                    font.family: root.t ? root.t.family : "monospace"
                    font.pixelSize: root.t ? root.t.fSecondary : 12
                    lineHeight: root.t ? root.t.lhBody : 1.7
                    wrapMode: Text.WordWrap
                    textFormat: Text.PlainText
                }

                Rectangle {
                    width: parent.width
                    implicitHeight: bundleName.implicitHeight + (root.t ? root.t.s(20) : 12)
                    radius: root.t ? root.t.rChip : 0
                    color: root.t ? root.t.sunken : "transparent"

                    Column {
                        id: bundleName

                        x: root.t ? root.t.s(12) : 8
                        y: root.t ? root.t.s(10) : 6
                        width: parent.width - (root.t ? root.t.s(24) : 16)
                        spacing: root.t ? root.t.s(4) : 2

                        Text {
                            width: parent.width
                            text: "moat-incident-" + (root.incident ? root.incident.id : "") + ".md"
                            color: root.t ? root.t.dim : "grey"
                            font.family: root.t ? root.t.family : "monospace"
                            font.pixelSize: root.t ? root.t.fMeta : 11
                            elide: Text.ElideMiddle
                            textFormat: Text.PlainText
                        }

                        Text {
                            width: parent.width
                            text: "plain text  ·  what the kernel recorded, fenced so it cannot be read as instructions  ·  nothing is sent anywhere"
                            color: root.t ? root.t.fainter : "grey"
                            font.family: root.t ? root.t.family : "monospace"
                            font.pixelSize: root.t ? root.t.fMeta : 11
                            wrapMode: Text.WordWrap
                            textFormat: Text.PlainText
                        }

                    }

                }

                Row {
                    spacing: root.t ? root.t.s(10) : 6

                    Button {
                        text: "Save the bundle"
                        background: root.t ? root.t.accent : "orange"
                        foreground: root.t ? root.t.accentLabel : "black"
                        fontSize: root.t ? root.t.fBody : 13
                        onClicked: root.saveBundle(root.incident ? root.incident.id : "")
                    }

                    Button {
                        text: "Copy as text"
                        foreground: root.t ? root.t.dimmer : "grey"
                        fontSize: root.t ? root.t.fSecondary : 12
                        onClicked: root.copyBundleText(root.incident ? root.incident.id : "")
                    }

                    Button {
                        text: "Back"
                        foreground: root.t ? root.t.ghost : "grey"
                        fontSize: root.t ? root.t.fSecondary : 12
                        onClicked: root.bundleOpen = false
                    }

                }

            }

        }

        // The evidence drawer. Collapsed by default, opened in place, never in the
        // reading path (1b). This is where severity finally appears, once, as a
        // fact with its reason.
        EvidenceBlock {
            width: parent.width
            visible: root.evidenceOpen
            tokens: root.t
            service: root.service
            alert: root.head
            onCopyBundleRequested: function(id) {
                root.copyBundle(id);
            }
        }

        // The transient result of whatever one of those buttons last ran. It sits
        // with the incident rather than in the panel notice, because it is about
        // this one incident and not about the daemon.
        Text {
            width: parent.width
            visible: text !== ""
            text: {
                if (!root.service)
                    return "";

                if (root.service.copyMessage)
                    return String(root.service.copyMessage);

                if (root.service.analyzeMessage)
                    return String(root.service.analyzeMessage);

                return "";
            }
            color: root.t ? root.t.faint : "grey"
            font.family: root.t ? root.t.family : "monospace"
            font.pixelSize: root.t ? root.t.fMeta : 11
            wrapMode: Text.WrapAnywhere
            maximumLineCount: 3
            elide: Text.ElideRight
            textFormat: Text.PlainText
        }

        // The rule id, present and last and dimmest. It is the thing a person
        // greps for once a year and never the thing they read first. Advanced has
        // already printed it at the top in the accent colour, so it is not repeated.
        Text {
            width: parent.width
            visible: !root.raw
            horizontalAlignment: Text.AlignRight
            // A chain is not one detection, so a single rule id here would name one
            // step and hide the rest. 3a puts "4 detections · one process tree" in
            // this slot instead; the individual rule ids are on the steps in Advanced.
            text: root.chain ? Copy.chainRuleNote(root.chain) : (root.incident ? root.incident.rule : "")
            color: root.t ? root.t.ghost : "grey"
            font.family: root.t ? root.t.family : "monospace"
            font.pixelSize: root.t ? root.t.fMeta : 11
            textFormat: Text.PlainText
        }

    }

}
