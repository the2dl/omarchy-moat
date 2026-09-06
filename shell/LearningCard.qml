// The first week (docs/design/README.md 1g).
// Two cards, and only ever one of them at a time: **learning**, while the
// window is open, and **done learning**, for the two days after it closes.
// Learning is a finite job with an end and this is what says so. Nine silent
// days are indistinguishable from nine broken ones, and a monitor nobody can
// tell is running is a monitor people turn off.

import "MoatCopy.js" as Copy
import "MoatModel.js" as Model
import QtQuick
import qs.Commons
import qs.Ui

// The done card is the ONLY place the enforce question is asked, because the end
// of learning is the only moment it can be asked honestly: before then Moat has
// not seen enough of the machine to guess well, and a wrong guess in enforce
// mode kills a real program mid-write.
Rectangle {
    id: root

    property var tokens: null
    property var service: null
    property var status: null
    readonly property var t: root.tokens
    readonly property var learning: Model.learningCard(root.status, root.service ? root.service.nowMs : Date.now())
    readonly property var done: Model.learningDoneCard(root.status, root.service ? root.service.nowMs : Date.now())

    signal enforceRequested()
    signal reviewRulesRequested()

    visible: !!root.learning || (!!root.done && !root.done.enforcing)
    implicitHeight: visible ? content.implicitHeight : 0
    color: root.t ? root.t.card : "transparent"
    radius: root.t ? root.t.rCard : 0

    Column {
        id: content

        x: root.t ? root.t.smallCardPadX : 8
        width: parent.width - (root.t ? root.t.smallCardPadX * 2 : 16)
        topPadding: root.t ? root.t.smallCardPadY : 10
        bottomPadding: root.t ? root.t.smallCardPadY : 10
        spacing: root.t ? root.t.s(14) : 8

        // ------------------------------------------------------------ learning
        Text {
            width: parent.width
            visible: !!root.learning
            text: "Moat is learning your machine"
            color: root.t ? root.t.primary : "white"
            font.family: root.t ? root.t.family : "monospace"
            font.pixelSize: root.t ? root.t.fHeading : 19
            font.weight: Font.Medium
            wrapMode: Text.WordWrap
            textFormat: Text.PlainText
        }

        Text {
            width: parent.width
            visible: !!root.learning
            text: "For the rest of this window it watches without judging much. Anything that looks like your normal work gets written down as normal, so you see fewer and better alerts at the end of it."
            color: root.t ? root.t.muted : "grey"
            font.family: root.t ? root.t.family : "monospace"
            font.pixelSize: root.t ? root.t.fBody : 13
            lineHeight: root.t ? root.t.lhBody : 1.7
            wrapMode: Text.WordWrap
            textFormat: Text.PlainText
        }

        // The progress bar. 5px, because it is a fact rather than a control.
        Rectangle {
            width: parent.width
            visible: !!root.learning
            height: root.t ? root.t.s(5) : 4
            radius: height / 2
            color: root.t ? root.t.chip : "transparent"

            Rectangle {
                width: parent.width * (root.learning ? root.learning.fraction : 0)
                height: parent.height
                radius: parent.radius
                color: root.t ? root.t.accent : "orange"
            }

        }

        Item {
            width: parent.width
            visible: !!root.learning
            implicitHeight: dayCount.implicitHeight

            Text {
                id: dayCount

                anchors.left: parent.left
                text: root.learning ? "day " + root.learning.dayIndex + " of " + root.learning.dayTotal : ""
                color: root.t ? root.t.fainter : "grey"
                font.family: root.t ? root.t.family : "monospace"
                font.pixelSize: root.t ? root.t.fMeta : 11
                textFormat: Text.PlainText
            }

            Text {
                anchors.right: parent.right
                text: root.learning ? root.learning.learned + (root.learning.learned === 1 ? " thing learned" : " things learned") : ""
                color: root.t ? root.t.fainter : "grey"
                font.family: root.t ? root.t.family : "monospace"
                font.pixelSize: root.t ? root.t.fMeta : 11
                textFormat: Text.PlainText
            }

        }

        // The reassurance that makes the whole window acceptable: learning is not
        // a hole. A write to a loader path or a key read by something unknown does
        // not wait for it to finish.
        Text {
            width: parent.width
            visible: !!root.learning
            text: "Serious things still reach you today — a write to a loader path, or your keys read by something Moat has never seen, does not wait for learning to finish."
            color: root.t ? root.t.dimmer : "grey"
            font.family: root.t ? root.t.family : "monospace"
            font.pixelSize: root.t ? root.t.fSecondary : 12
            lineHeight: root.t ? root.t.lhBody : 1.7
            wrapMode: Text.WordWrap
            textFormat: Text.PlainText
        }

        // ------------------------------------------------------ done learning
        Text {
            width: parent.width
            visible: !!root.done && !root.learning
            text: "Done learning. Here is what changed."
            color: root.t ? root.t.primary : "white"
            font.family: root.t ? root.t.family : "monospace"
            font.pixelSize: root.t ? root.t.fHeading : 19
            font.weight: Font.Medium
            wrapMode: Text.WordWrap
            textFormat: Text.PlainText
        }

        Column {
            width: parent.width
            visible: !!root.done && !root.learning
            spacing: root.t ? root.t.s(7) : 4

            Repeater {
                model: root.done ? [{
                    "label": "Written down as normal",
                    "value": String(root.done.learned)
                }, {
                    "label": "Detections gone quiet",
                    "value": String(root.done.demoted)
                }, {
                    "label": "Waiting for you to say yes",
                    "value": String(root.done.proposals)
                }] : []

                delegate: Item {
                    required property var modelData

                    width: content.width
                    implicitHeight: statLabel.implicitHeight

                    Text {
                        id: statLabel

                        anchors.left: parent.left
                        text: modelData.label
                        color: root.t ? root.t.dimmer : "grey"
                        font.family: root.t ? root.t.family : "monospace"
                        font.pixelSize: root.t ? root.t.fSecondary : 12
                        textFormat: Text.PlainText
                    }

                    Text {
                        anchors.right: parent.right
                        text: modelData.value
                        color: root.t ? root.t.body : "white"
                        font.family: root.t ? root.t.family : "monospace"
                        font.pixelSize: root.t ? root.t.fSecondary : 12
                        textFormat: Text.PlainText
                    }

                }

            }

        }

        Text {
            width: parent.width
            visible: !!root.done && !root.learning
            text: "Alerts from here will be about things Moat has not seen before. This is the one moment the next question can be asked honestly, so it is asked here and nowhere else."
            color: root.t ? root.t.muted : "grey"
            font.family: root.t ? root.t.family : "monospace"
            font.pixelSize: root.t ? root.t.fSecondary : 12
            lineHeight: root.t ? root.t.lhBody : 1.7
            wrapMode: Text.WordWrap
            textFormat: Text.PlainText
        }

        Row {
            visible: !!root.done && !root.learning
            spacing: root.t ? root.t.s(10) : 6

            Button {
                text: "Let Moat stop things now"
                background: root.t ? root.t.accent : "orange"
                foreground: root.t ? root.t.accentLabel : "black"
                fontSize: root.t ? root.t.fBody : 13
                onClicked: root.enforceRequested()
            }

            Button {
                text: "Keep just telling me"
                foreground: root.t ? root.t.dimmer : "grey"
                fontSize: root.t ? root.t.fSecondary : 12
                onClicked: root.reviewRulesRequested()
            }

        }

    }

}
