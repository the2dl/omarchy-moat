// The evidence drawer (docs/design/README.md 1b), with 2b's chain inside it.
// Collapsed by default and never in the reading path. Everything the old panel
// led with lives here: process, args, cwd, what led here, what was written, the
// hook, and severity -- which appears HERE, once, as a fact with its reason, and
// never as a badge. A badge answers "how bad is this?", which is the question
// the user cannot act on; the state word answers "what do you want from me?".

import "MoatCopy.js" as Copy
import "MoatModel.js" as Model
import QtQuick
import qs.Commons
import qs.Ui

// Every value in here is process-derived, so every value in here is PlainText.
Rectangle {
    id: root

    property var tokens: null
    property var service: null
    property var alert: null
    readonly property var t: root.tokens
    readonly property var steps: Model.chainSteps(root.alert)
    /// Advanced (`rawDetail`). IncidentCard already prints the whole record above
    /// this block in that mode, so the friendlier `facts()` grid here would be
    /// the same exe and the same args a second time under softer labels. What
    /// stays is what Advanced cannot get anywhere else: the chain, and the
    /// daemon's own evidence lines -- which is where the hook that fired and the
    /// policy name actually live.
    readonly property bool raw: !!root.service && root.service.rawDetail === true

    signal copyBundleRequested(string id)

    /// The label/value pairs, flattened so one Repeater fills a two-column Grid.
    function facts() {
        function add(label, value) {
            var text = String(value === undefined || value === null ? "" : value);
            if (text) {
                out.push(label);
                out.push(text);
            }
        }

        var a = root.alert;
        if (!a)
            return [];

        var out = [];
        add("process", a.process ? a.process.exe : "");
        add("args", a.process ? a.process.args : "");
        add("working dir", a.process ? Model.shortenHome(a.process.cwd) : "");
        if (a.file)
            add("wrote", Model.shortenHome(String(a.file.path || "")));

        if (a.net)
            add("connected to", String(a.net.dst_ip || "") + (a.net.dst_port ? ":" + a.net.dst_port : ""));

        add("first seen here", a.rarity_text);
        add("context", root.service ? root.service.actorLine(a) : "");
        // 3a's marker on a single alert. Every member of a chain carries the whole
        // chain, so an alert opened on its own still says it is one step of
        // something and which step -- otherwise the reader who lands on the
        // `.git/config` write never learns that the same process read a credential
        // a second later.
        add("part of", Model.chainMarker(a));
        // Severity, once, here, as a fact with its reason. Never a badge.
        var change = root.service ? root.service.severityChangeLine(a) : "";
        add("severity", change ? change : a.severity);
        // And the SEQUENCE's severity, which is a different number about a
        // different thing and may be higher than this alert's own. It only ever
        // prints with the daemon's reason attached (CONTRACT 4), which is what
        // `chainSeverityLine` guarantees by returning "" when there is none.
        add("as a sequence", Model.chainSeverityLine(a.chain));
        add("covered by", root.service ? root.service.suppressedLine(a) : "");
        add("detection", a.rule);
        if (a.incident && a.incident.dir)
            add("kept at", a.incident.dir);

        return out;
    }

    implicitHeight: column.implicitHeight
    color: root.t ? root.t.evidence : "transparent"
    radius: root.t ? root.t.rInner : 0

    Column {
        // ------------------------------------------------------- what led here

        id: column

        x: root.t ? root.t.cardPadX : 12
        width: parent.width - (root.t ? root.t.cardPadX * 2 : 24)
        topPadding: root.t ? root.t.s(20) : 12
        bottomPadding: root.t ? root.t.cardPadBottom : 14
        spacing: root.t ? root.t.s(16) : 10

        Item {
            width: parent.width
            implicitHeight: evidenceLabel.implicitHeight

            Text {
                id: evidenceLabel

                anchors.left: parent.left
                text: "EVIDENCE"
                color: root.t ? root.t.fainter : "grey"
                font.family: root.t ? root.t.family : "monospace"
                font.pixelSize: root.t ? root.t.fMeta : 11
                font.letterSpacing: root.t ? root.t.lsLabel : 0
            }

            Row {
                anchors.right: parent.right
                anchors.verticalCenter: evidenceLabel.verticalCenter
                spacing: root.t ? root.t.s(10) : 6

                // LEARNING 2c. An unattended agent pass wrote the verdict at the top of
                // this card, and a verdict the user cannot reverse from the panel is a
                // verdict they have to trust. Reversing it puts the incident back in
                // front of them, which is the cautious direction, so unlike stopping
                // and holding it goes straight through with no confirm.
                Button {
                    visible: !!root.alert && !!root.alert.triage
                    text: "Undo Moat's call"
                    foreground: root.t ? root.t.dimmer : "grey"
                    fontSize: root.t ? root.t.fMeta : 11
                    onClicked: {
                        if (root.service) {
                            root.service.undoTriage(root.alert.id);
                        }
                    }
                }

                Button {
                    text: "Copy bundle"
                    foreground: root.t ? root.t.dimmer : "grey"
                    fontSize: root.t ? root.t.fMeta : 11
                    onClicked: root.copyBundleRequested(root.alert ? root.alert.id : "")
                }

            }

        }

        // The facts, as a label/value grid. Two columns, and the label column is
        // the dimmest thing in the block: a person reads down the values.
        Grid {
            width: parent.width
            visible: !root.raw
            columns: 2
            columnSpacing: root.t ? root.t.s(16) : 10
            rowSpacing: root.t ? root.t.s(7) : 4

            Repeater {
                model: root.raw ? [] : root.facts()

                delegate: Text {
                    required property var modelData
                    required property int index

                    width: index % 2 === 0 ? (root.t ? root.t.s(110) : 90) : column.width - (root.t ? root.t.s(126) : 100)
                    text: modelData
                    color: index % 2 === 0 ? (root.t ? root.t.fainter : "grey") : (root.t ? root.t.secondary : "white")
                    font.family: root.t ? root.t.family : "monospace"
                    font.pixelSize: root.t ? root.t.fSecondary : 12
                    wrapMode: Text.WrapAnywhere
                    // args and paths out of a hostile process. Evidence is where the long
                    // version belongs, but "long" still has a ceiling.
                    maximumLineCount: 8
                    elide: Text.ElideRight
                    textFormat: Text.PlainText
                }

            }

        }

        // 2b. The old panel had this as one line with arrows in it and no times,
        // which answers a question nobody asks. As a chain, what started what is
        // legible -- and where Moat has no time for a step, it says nothing rather
        // than inventing one. moatd records {pid, exe} per ancestor and no stamp.
        Column {
            width: parent.width
            visible: root.steps.length > 1
            spacing: root.t ? root.t.s(9) : 6

            Text {
                text: "WHAT LED HERE"
                color: root.t ? root.t.fainter : "grey"
                font.family: root.t ? root.t.family : "monospace"
                font.pixelSize: root.t ? root.t.fMeta : 11
                font.letterSpacing: root.t ? root.t.lsLabel : 0
                topPadding: root.t ? root.t.s(5) : 3
            }

            Repeater {
                model: root.steps

                delegate: Item {
                    required property var modelData
                    required property int index

                    width: column.width
                    implicitHeight: stepText.implicitHeight + (root.t ? root.t.s(12) : 8)

                    // The rail: a dot per step over a connector down to the next. The
                    // alert's own step is the only one with any colour in it.
                    Rectangle {
                        id: connector

                        x: root.t ? root.t.s(58) : 44
                        y: 0
                        width: 1
                        height: parent.height
                        visible: index < root.steps.length - 1
                        color: root.t ? root.t.hair(0.08) : "transparent"
                    }

                    Rectangle {
                        x: (root.t ? root.t.s(58) : 44) - (root.t ? root.t.s(4) : 3)
                        y: root.t ? root.t.s(5) : 3
                        width: root.t ? root.t.s(9) : 7
                        height: width
                        radius: width / 2
                        color: modelData.isAlert ? (root.t ? root.t.alarm : "red") : (root.t ? root.t.ghost : "grey")
                    }

                    Text {
                        x: 0
                        y: root.t ? root.t.s(3) : 2
                        width: root.t ? root.t.s(48) : 38
                        horizontalAlignment: Text.AlignRight
                        text: modelData.ts && root.service ? root.service.relativeTime(modelData.ts) : ""
                        color: root.t ? root.t.fainter : "grey"
                        font.family: root.t ? root.t.family : "monospace"
                        font.pixelSize: root.t ? root.t.fMeta : 11
                        textFormat: Text.PlainText
                    }

                    Column {
                        id: stepText

                        x: root.t ? root.t.s(78) : 58
                        width: parent.width - x
                        spacing: root.t ? root.t.s(2) : 1

                        Text {
                            width: parent.width
                            text: modelData.path || modelData.name
                            color: modelData.isAlert ? (root.t ? root.t.primary : "white") : (root.t ? root.t.secondary : "white")
                            font.family: root.t ? root.t.family : "monospace"
                            font.pixelSize: root.t ? root.t.fSecondary : 12
                            elide: Text.ElideMiddle
                            textFormat: Text.PlainText
                        }

                        Text {
                            width: parent.width
                            visible: text !== ""
                            text: modelData.note
                            color: root.t ? root.t.faint : "grey"
                            font.family: root.t ? root.t.family : "monospace"
                            font.pixelSize: root.t ? root.t.fMeta : 11
                            elide: Text.ElideRight
                            maximumLineCount: 2
                            wrapMode: Text.WrapAnywhere
                            textFormat: Text.PlainText
                        }

                    }

                }

            }

        }

        // What the daemon itself wrote about this alert, verbatim. It is the
        // sentence a person quotes into a search engine, and it belongs with the
        // rest of the machine's own words rather than above them.
        Repeater {
            model: root.alert && root.alert.explain ? root.alert.explain.evidence : []

            delegate: Text {
                required property string modelData

                width: column.width
                text: modelData
                color: root.t ? root.t.dimmer : "grey"
                font.family: root.t ? root.t.family : "monospace"
                font.pixelSize: root.t ? root.t.fCode : 12
                lineHeight: root.t ? root.t.lhMeta : 1.6
                wrapMode: Text.WrapAnywhere
                maximumLineCount: 12
                elide: Text.ElideRight
                textFormat: Text.PlainText
            }

        }

    }

}
