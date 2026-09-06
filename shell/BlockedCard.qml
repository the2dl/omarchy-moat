// After Moat blocked something (docs/design/README.md 3d).
// **Enforce mode's real UI is the apology, not the switch.** A kernel-level
// block shows up in the user's terminal as a program dying for no reason -- no
// message, no exit code they can read, nothing to search for. If the product is
// willing to kill things, the recovery path is part of the product: show what
// they saw, own it, offer the narrow rule, and offer the retreat.

import "MoatCopy.js" as Copy
import "MoatModel.js" as Model
import QtQuick
import qs.Commons
import qs.Ui

// The old Settings copy warned that "a false positive stops a real program
// mid-write" and then left the user alone with the consequence.
Rectangle {
    id: root

    property var tokens: null
    property var service: null
    property var incident: null
    readonly property var t: root.tokens
    readonly property var head: root.incident ? root.incident.head : null
    readonly property var transcript: Model.blockTranscript(root.head)
    readonly property var verdict: root.head && root.head.triage ? root.head.triage : null
    readonly property bool pendingVerdict: !root.verdict && !!root.head && !!root.service && root.service.autoTriageOn === true

    /// Allow exactly what was stopped, at the narrow scope this card promises.
    signal allowRequested(string id, string scope)
    /// Stop enforcing THE RULE THAT DID THIS -- not everything.
    signal monitorRequested(string rule)
    /// "I have read this." Acks the incident; writes nothing.
    signal closeIt(string id)

    /// Why it was stopped, in the daemon's own words where it has them. Ends by
    /// naming the cost of the rule being wrong, because that is the sentence the
    /// user is owed and the one they will not write for themselves.
    function explanation() {
        var a = root.head;
        if (!a)
            return "";

        var bits = [];
        if (a.explain && a.explain.why)
            bits.push(String(a.explain.why));
        else if (a.summary)
            bits.push(String(a.summary));
        bits.push("That is the pattern Moat is set to stop. It can also be exactly what a build or a deploy script does, in which case Moat was wrong.");
        return bits.join(" ");
    }

    implicitHeight: column.implicitHeight
    color: root.t ? root.t.card : "transparent"
    radius: root.t ? root.t.rIncident : 0
    border.width: 1
    border.color: root.t ? root.t.alarmTint(0.22) : "transparent"

    Column {
        // ----------------------------------------------------- what you saw
        // What led here, when the thing Moat stopped was a SEQUENCE.

        id: column

        x: root.t ? root.t.cardPadX : 12
        width: parent.width - (root.t ? root.t.cardPadX * 2 : 24)
        topPadding: root.t ? root.t.cardPadTop : 14
        bottomPadding: root.t ? root.t.cardPadBottom : 14
        spacing: root.t ? root.t.s(18) : 10

        Text {
            width: parent.width
            text: "Moat stopped something while you were working"
            color: root.t ? root.t.primary : "white"
            font.family: root.t ? root.t.family : "monospace"
            font.pixelSize: root.t ? root.t.fHeading : 19
            font.weight: Font.Medium
            wrapMode: Text.WordWrap
            textFormat: Text.PlainText
        }

        Text {
            width: parent.width
            text: "Your terminal will have shown this as a program dying for no reason. That is what a kernel-level block looks like from the outside, so this exists to explain it after the fact."
            color: root.t ? root.t.muted : "grey"
            font.family: root.t ? root.t.family : "monospace"
            font.pixelSize: root.t ? root.t.fBody : 13
            lineHeight: root.t ? root.t.lhBody : 1.7
            wrapMode: Text.WordWrap
            textFormat: Text.PlainText
        }

        // Reconstructed from the command line moatd recorded, and from nothing
        // else: Moat does not capture terminal output, so the only two lines here
        // it can be sure of are the command and the word the shell printed.
        Column {
            width: parent.width
            spacing: root.t ? root.t.s(7) : 4

            Text {
                text: "WHAT YOU SAW"
                color: root.t ? root.t.fainter : "grey"
                font.family: root.t ? root.t.family : "monospace"
                font.pixelSize: root.t ? root.t.fMeta : 11
                font.letterSpacing: root.t ? root.t.lsLabel : 0
            }

            Rectangle {
                width: parent.width
                implicitHeight: term.implicitHeight + (root.t ? root.t.s(24) : 14)
                radius: root.t ? root.t.rChip : 0
                color: root.t ? root.t.sunken : "transparent"

                Column {
                    id: term

                    x: root.t ? root.t.s(14) : 8
                    y: root.t ? root.t.s(12) : 7
                    width: parent.width - (root.t ? root.t.s(28) : 16)
                    spacing: 0

                    Text {
                        width: parent.width
                        text: root.transcript.command
                        color: root.t ? root.t.dim : "grey"
                        font.family: root.t ? root.t.family : "monospace"
                        font.pixelSize: root.t ? root.t.fCode : 12
                        lineHeight: root.t ? root.t.lhCode : 2
                        elide: Text.ElideRight
                        textFormat: Text.PlainText
                    }

                    Text {
                        width: parent.width
                        text: root.transcript.killed
                        color: root.t ? root.t.alarm : "red"
                        font.family: root.t ? root.t.family : "monospace"
                        font.pixelSize: root.t ? root.t.fCode : 12
                        lineHeight: root.t ? root.t.lhCode : 2
                        textFormat: Text.PlainText
                    }

                    Text {
                        width: parent.width
                        text: "$"
                        color: root.t ? root.t.fainter : "grey"
                        font.family: root.t ? root.t.family : "monospace"
                        font.pixelSize: root.t ? root.t.fCode : 12
                        lineHeight: root.t ? root.t.lhCode : 2
                    }

                }

            }

        }

        // ---------------------------------------------------- what happened
        Column {
            width: parent.width
            spacing: root.t ? root.t.s(7) : 4

            Text {
                text: "WHAT HAPPENED"
                color: root.t ? root.t.fainter : "grey"
                font.family: root.t ? root.t.family : "monospace"
                font.pixelSize: root.t ? root.t.fMeta : 11
                font.letterSpacing: root.t ? root.t.lsLabel : 0
            }

            Text {
                width: parent.width
                text: root.explanation()
                color: root.t ? root.t.secondary : "white"
                font.family: root.t ? root.t.family : "monospace"
                font.pixelSize: root.t ? root.t.fSecondary : 12
                lineHeight: root.t ? root.t.lhVerdictBody : 1.75
                wrapMode: Text.WordWrap
                textFormat: Text.PlainText
            }

        }

        // A containment fires on a correlated chain -- a credential harvest
        // then an outbound connection -- and the sequence IS the reason it was
        // stopped. Showing only the terminal transcript ("connect: Permission
        // denied") told the user what they saw, never what happened: the four
        // steps that led to the block were in the record and nowhere on the
        // card. ChainBlock self-hides when there is no chain, so a single-event
        // block (a lone reverse shell) is unchanged.
        ChainBlock {
            width: parent.width
            tokens: root.t
            service: root.service
            incident: root.incident
            onAllowChain: function(id) {
                root.allowRequested(id, "chain");
            }
        }

        // What Moat's own agent made of it, when it has looked -- a contained
        // chain is the case auto-triage matters most for.
        Column {
            width: parent.width
            spacing: root.t ? root.t.s(6) : 4
            visible: !!root.verdict || root.pendingVerdict

            Text {
                text: "MOAT'S READ"
                color: root.t ? root.t.fainter : "grey"
                font.family: root.t ? root.t.family : "monospace"
                font.pixelSize: root.t ? root.t.fMeta : 11
                font.letterSpacing: root.t ? root.t.lsLabel : 0
            }

            Text {
                width: parent.width
                visible: root.pendingVerdict
                text: "Moat is still reviewing this; its read will appear here."
                color: root.t ? root.t.dimmer : "grey"
                font.family: root.t ? root.t.family : "monospace"
                font.pixelSize: root.t ? root.t.fSecondary : 12
                wrapMode: Text.WordWrap
                textFormat: Text.PlainText
            }

            Text {
                width: parent.width
                visible: !!root.verdict
                text: (root.verdict ? Model.triageChip(root.verdict) : "") + "  " + (root.verdict ? String(root.verdict.summary || "") : "")
                color: root.t ? root.t.secondary : "white"
                font.family: root.t ? root.t.family : "monospace"
                font.pixelSize: root.t ? root.t.fSecondary : 12
                lineHeight: root.t ? root.t.lhVerdictBody : 1.75
                wrapMode: Text.WordWrap
                textFormat: Text.PlainText
            }

        }

        // ------------------------------------------------------- the recovery
        Rectangle {
            width: parent.width
            implicitHeight: recovery.implicitHeight + (root.t ? root.t.smallCardPadY * 2 : 16)
            radius: root.t ? root.t.rCard : 0
            color: root.t ? root.t.chip : "transparent"
            border.width: 1
            border.color: root.t ? root.t.accentTint(0.24) : "transparent"

            Column {
                id: recovery

                x: root.t ? root.t.smallCardPadX : 8
                y: root.t ? root.t.smallCardPadY : 8
                width: parent.width - (root.t ? root.t.smallCardPadX * 2 : 16)
                spacing: root.t ? root.t.s(9) : 6

                Text {
                    width: parent.width
                    text: "Let it run and do not stop it again"
                    color: root.t ? root.t.primary : "white"
                    font.family: root.t ? root.t.family : "monospace"
                    font.pixelSize: root.t ? root.t.fBody : 13
                    wrapMode: Text.WordWrap
                    textFormat: Text.PlainText
                }

                Text {
                    width: parent.width
                    text: "Adds it to your rules for the one thing it was stopped for, and nothing else. Then re-run it yourself — Moat will not restart something for you."
                    color: root.t ? root.t.dimmer : "grey"
                    font.family: root.t ? root.t.family : "monospace"
                    font.pixelSize: root.t ? root.t.fSecondary : 12
                    lineHeight: root.t ? root.t.lhBody : 1.7
                    wrapMode: Text.WordWrap
                    textFormat: Text.PlainText
                }

                Item {
                    width: parent.width
                    implicitHeight: recoveryActions.implicitHeight

                    Row {
                        id: recoveryActions

                        anchors.left: parent.left
                        spacing: root.t ? root.t.s(10) : 6

                        Button {
                            text: "Allow " + (root.incident ? root.incident.program : "it")
                            background: root.t ? root.t.accent : "orange"
                            foreground: root.t ? root.t.accentLabel : "black"
                            fontSize: root.t ? root.t.fBody : 13
                            // The narrowest scope the alert supports, because the line above
                            // this button promises "the one thing it was stopped for, and
                            // nothing else". `exe+file` names both; `exe` is the fallback for
                            // an alert with no file (a connection, say).
                            onClicked: {
                                var scope = (root.head && root.head.file && root.head.file.path) ? "exe+file" : "exe";
                                root.allowRequested(root.incident ? root.incident.id : "", scope);
                            }
                        }

                        Button {
                            text: "Close it"
                            foreground: root.t ? root.t.dimmer : "grey"
                            fontSize: root.t ? root.t.fSecondary : 12
                            onClicked: root.closeIt(root.incident ? root.incident.id : "")
                        }

                        Button {
                            text: "Copy the command to re-run"
                            foreground: root.t ? root.t.dimmer : "grey"
                            fontSize: root.t ? root.t.fSecondary : 12
                            onClicked: {
                                if (root.service && root.head && root.head.process)
                                    root.service.copyText(String(root.head.process.args || root.head.process.exe || ""), "command");

                            }
                        }

                    }

                    Button {
                        // Names the rule, and disarms only that rule.

                        anchors.right: parent.right
                        anchors.verticalCenter: recoveryActions.verticalCenter
                        // This said "Go back to just telling me" and called `set mode
                        // monitor` with no rule -- daemon-wide. A grey text link on an
                        // apology card would have disarmed every armed rule on the machine,
                        // and neither the label nor the position suggested anything of the
                        // kind. The scope a button acts on has to be the scope its label
                        // describes.
                        text: "Only warn me about " + (root.head ? Model.shortRule(root.head.rule) : "this")
                        foreground: root.t ? root.t.dimmer : "grey"
                        fontSize: root.t ? root.t.fSecondary : 12
                        onClicked: root.monitorRequested(root.head ? root.head.rule : "")
                    }

                }

            }

        }

    }

}
