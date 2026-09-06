// First run (docs/design/README.md 3f).
// What is shown before Moat has anything to say: what it watches, what it does
// NOT do, and what the next nine days will look like. The two sentences that
// matter most are the ones about what it never does -- it never reads the
// contents of your files, and it never sends anything anywhere -- because a
// program that watches everything you run has to answer that first.

import "MoatCopy.js" as Copy
import "MoatModel.js" as Model
import QtQuick
import qs.Commons
import qs.Ui

// Shown when the daemon is reachable and has nothing recorded yet. It is not a
// wizard: nothing here has to be answered, so it has no "next".
Item {
    id: root

    property var tokens: null
    property var service: null
    property var status: null
    readonly property var t: root.tokens

    signal dismissed()

    /// How long learning runs, said in days rather than as a setting. Comes from
    /// the daemon's own window, so a machine configured for a different length
    /// does not get told the wrong number.
    function learningLine() {
        var card = Model.learningCard(root.status, root.service ? root.service.nowMs : Date.now());
        if (!card)
            return "First it spends its learning window working out what is normal here.";

        return "First it spends " + card.dayTotal + " days learning what is normal here.";
    }

    MoatScroll {
        anchors.fill: parent
        contentHeight: body.implicitHeight

        Column {
            id: body

            x: root.t ? root.t.bodyPadX : 0
            width: parent.width - (root.t ? root.t.bodyPadX * 2 : 0)
            topPadding: root.t ? root.t.s(46) : 0
            bottomPadding: root.t ? root.t.bodyPadBottom : 0
            spacing: root.t ? root.t.v(26) : 14

            Column {
                width: parent.width
                spacing: root.t ? root.t.s(12) : 8

                Text {
                    width: parent.width
                    text: "Moat watches four things"
                    color: root.t ? root.t.primary : "white"
                    font.family: root.t ? root.t.family : "monospace"
                    font.pixelSize: root.t ? root.t.fHeading : 19
                    font.weight: Font.Medium
                    wrapMode: Text.WordWrap
                    textFormat: Text.PlainText
                }

                Text {
                    width: parent.width
                    text: "It reads what programs do, in the kernel. It never reads the contents of your files, and it never sends anything anywhere."
                    color: root.t ? root.t.muted : "grey"
                    font.family: root.t ? root.t.family : "monospace"
                    font.pixelSize: root.t ? root.t.fBody : 13
                    lineHeight: root.t ? root.t.lhBody : 1.7
                    wrapMode: Text.WordWrap
                    textFormat: Text.PlainText
                }

            }

            Column {
                width: parent.width
                spacing: 0

                Repeater {
                    model: Copy.WATCHES

                    delegate: Item {
                        required property var modelData

                        width: body.width
                        implicitHeight: watchText.implicitHeight + (root.t ? root.t.rowPadY * 2 : 12)

                        Rectangle {
                            anchors.top: parent.top
                            width: parent.width
                            height: 1
                            color: root.t ? root.t.hairlineRow : "transparent"
                        }

                        Column {
                            id: watchText

                            anchors.verticalCenter: parent.verticalCenter
                            width: parent.width
                            spacing: root.t ? root.t.s(4) : 2

                            Text {
                                width: parent.width
                                text: modelData.what
                                color: root.t ? root.t.body : "white"
                                font.family: root.t ? root.t.family : "monospace"
                                font.pixelSize: root.t ? root.t.fBody : 13
                                wrapMode: Text.WordWrap
                                textFormat: Text.PlainText
                            }

                            Text {
                                width: parent.width
                                text: modelData.like
                                color: root.t ? root.t.faint : "grey"
                                font.family: root.t ? root.t.family : "monospace"
                                font.pixelSize: root.t ? root.t.fMeta : 11
                                wrapMode: Text.WordWrap
                                textFormat: Text.PlainText
                            }

                        }

                    }

                }

            }

            Rectangle {
                width: parent.width
                implicitHeight: expect.implicitHeight + (root.t ? root.t.smallCardPadY * 2 : 16)
                radius: root.t ? root.t.rCard : 0
                color: root.t ? root.t.card : "transparent"

                Column {
                    id: expect

                    x: root.t ? root.t.smallCardPadX : 8
                    y: root.t ? root.t.smallCardPadY : 8
                    width: parent.width - (root.t ? root.t.smallCardPadX * 2 : 16)
                    spacing: root.t ? root.t.s(7) : 4

                    Text {
                        width: parent.width
                        text: root.learningLine()
                        color: root.t ? root.t.body : "white"
                        font.family: root.t ? root.t.family : "monospace"
                        font.pixelSize: root.t ? root.t.fBody : 13
                        wrapMode: Text.WordWrap
                        textFormat: Text.PlainText
                    }

                    Text {
                        width: parent.width
                        text: "During that time it will not stop anything, and it will only interrupt you for something serious. Expect it to be quiet."
                        color: root.t ? root.t.dimmer : "grey"
                        font.family: root.t ? root.t.family : "monospace"
                        font.pixelSize: root.t ? root.t.fSecondary : 12
                        lineHeight: root.t ? root.t.lhBody : 1.7
                        wrapMode: Text.WordWrap
                        textFormat: Text.PlainText
                    }

                }

            }

            Row {
                spacing: root.t ? root.t.s(10) : 6

                Button {
                    text: "Start watching"
                    background: root.t ? root.t.accent : "orange"
                    foreground: root.t ? root.t.accentLabel : "black"
                    fontSize: root.t ? root.t.fBody : 13
                    onClicked: root.dismissed()
                }

                Text {
                    anchors.verticalCenter: parent.verticalCenter
                    text: root.status && root.status.policies > 0 ? root.status.policies + " detections are already loaded" : ""
                    color: root.t ? root.t.ghost : "grey"
                    font.family: root.t ? root.t.family : "monospace"
                    font.pixelSize: root.t ? root.t.fMeta : 11
                    textFormat: Text.PlainText
                }

            }

        }

    }

}
