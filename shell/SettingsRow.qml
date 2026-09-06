// One Settings row (docs/design/README.md 1f): a question on the left with one
// line of consequence under it, and its answer right-aligned on the right.

import QtQuick
import qs.Commons
import qs.Ui

// The control is `default property` content, so a row is written as the
// question plus whatever answers it -- chips, a switch, a list -- and every row
// on the screen lines up without any of them knowing the grid.
Item {
    // The question column is what is left. Computed from the control's own width
    // rather than from a constant, so a wide answer takes room from the sentence
    // instead of landing on top of it.

    id: root

    property var tokens: null
    property string question: ""
    property string help: ""
    /// The one row whose consequence is worth saying in alarm rather than grey:
    /// enforce mode, when it is on.
    property bool helpLoud: false
    default property alias content: controlHolder.data
    readonly property var t: root.tokens
    readonly property int gap: root.t ? root.t.s(40) : 24
    // 1f pins the control column at 320px. A row whose answer does not fit -- the
    // three-chip "when should Moat interrupt you?" is the one -- widens instead of
    // overlapping the question, because the alternative is a control drawn on top
    // of the sentence explaining it.
    readonly property int minControlWidth: root.t ? root.t.s(320) : 240
    readonly property int controlWidth: Math.max(root.minControlWidth, controlHolder.children.length > 0 ? controlHolder.children[0].implicitWidth : 0)

    implicitHeight: Math.max(text.implicitHeight, controlHolder.childrenRect.height) + (root.t ? root.t.s(24) * 2 : 24)

    Rectangle {
        anchors.top: parent.top
        width: parent.width
        height: 1
        color: root.t ? root.t.hairlineRow : "transparent"
    }

    Column {
        id: text

        anchors.left: parent.left
        anchors.verticalCenter: parent.verticalCenter
        width: parent.width - root.controlWidth - root.gap
        spacing: root.t ? root.t.s(7) : 4

        Text {
            width: parent.width
            text: root.question
            color: root.t ? root.t.body : "white"
            font.family: root.t ? root.t.family : "monospace"
            font.pixelSize: root.t ? root.t.fBody : 13
            wrapMode: Text.WordWrap
            textFormat: Text.PlainText
        }

        Text {
            width: parent.width
            visible: text !== ""
            text: root.help
            color: root.helpLoud ? (root.t ? root.t.alarm : "red") : (root.t ? root.t.dimmer : "grey")
            font.family: root.t ? root.t.family : "monospace"
            font.pixelSize: root.t ? root.t.fSecondary : 12
            lineHeight: root.t ? root.t.lhBody : 1.7
            wrapMode: Text.WordWrap
            textFormat: Text.PlainText
        }

    }

    // Right-aligned, the way 1f pins every control: the questions read as a
    // column of sentences and the answers as a column of controls.
    Item {
        id: controlHolder

        anchors.right: parent.right
        anchors.verticalCenter: parent.verticalCenter
        width: root.controlWidth
        height: childrenRect.height
    }

}
