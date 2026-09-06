// One line in "What it watched today" (1a) or "Also today" (1b).

import "MoatCopy.js" as Copy
import QtQuick
import qs.Commons
import qs.Ui

// Four columns: what it was, what actually happened in plain words, the state
// word, and a chevron. No severity pill anywhere -- the redesign's whole point
// is that a row says what is wanted from you, not how alarming a detection
// thought it was. On a quiet day every row here reads `expected` and the page
// carries no colour at all.
Item {
    id: root

    property var tokens: null
    property string label: ""
    property string detail: ""
    /// needsYou | explained | expected | contained | closed
    property string state: "expected"
    property int count: 0
    /// Advanced (`rawDetail`) only, and empty otherwise: the severity printed
    /// BESIDE the state word, never instead of it. The state word is what says
    /// what is wanted from the user and what the shield agrees with; severity is
    /// the extra fact Advanced puts back.
    property string severity: ""
    property bool showChevron: true
    property bool lastRow: false
    readonly property var t: root.tokens
    // The state word carries the only colour in the row, and only when it is
    // asking for something. `expected` is the quietest thing on the page: it is
    // reassurance, and reassurance that shouts is noise.
    readonly property color stateColor: {
        if (!root.t)
            return "transparent";

        switch (root.state) {
        case "needsYou":
            return root.t.alarm;
        case "contained":
            return root.t.calm;
        case "explained":
            return root.t.muted;
        default:
            return root.t.faint;
        }
    }

    signal activated()

    implicitHeight: content.implicitHeight + (root.t ? root.t.rowPadY * 2 : 0)

    Rectangle {
        anchors.top: parent.top
        width: parent.width
        height: 1
        color: root.t ? root.t.hairlineRow : "transparent"
    }

    Rectangle {
        anchors.bottom: parent.bottom
        width: parent.width
        height: 1
        visible: root.lastRow
        color: root.t ? root.t.hairlineRow : "transparent"
    }

    Rectangle {
        anchors.fill: parent
        color: mouse.containsMouse && root.showChevron ? (root.t ? root.t.hair(0.03) : "transparent") : "transparent"
        radius: root.t ? root.t.rChipSmall : 0
    }

    Row {
        id: content

        anchors.verticalCenter: parent.verticalCenter
        width: parent.width
        spacing: root.t ? root.t.s(16) : 8

        Text {
            id: labelText

            width: Math.round(parent.width * 0.34)
            anchors.verticalCenter: parent.verticalCenter
            text: root.label
            color: root.t ? root.t.body : "white"
            font.family: root.t ? root.t.family : "monospace"
            font.pixelSize: root.t ? root.t.fBody : 13
            elide: Text.ElideRight
            maximumLineCount: 2
            wrapMode: Text.WordWrap
            textFormat: Text.PlainText
        }

        Text {
            id: detailText

            anchors.verticalCenter: parent.verticalCenter
            width: parent.width - labelText.width - stateText.width - chevron.width - (root.t ? root.t.s(16) * 3 : 24)
            text: root.detail
            color: root.t ? root.t.dimmer : "grey"
            font.family: root.t ? root.t.family : "monospace"
            font.pixelSize: root.t ? root.t.fSecondary : 12
            elide: Text.ElideRight
            maximumLineCount: 1
            textFormat: Text.PlainText
        }

        Text {
            id: stateText

            anchors.verticalCenter: parent.verticalCenter
            width: root.t ? root.t.s(root.severity ? 190 : 130) : 100
            horizontalAlignment: Text.AlignRight
            text: {
                var word = Copy.stateWord(root.state);
                if (root.severity)
                    word = root.severity + " · " + word;

                if (root.count > 1)
                    return root.count + "x  " + word;

                return word;
            }
            color: root.stateColor
            font.family: root.t ? root.t.family : "monospace"
            font.pixelSize: root.t ? root.t.fMeta : 11
            elide: Text.ElideRight
            textFormat: Text.PlainText
        }

        Text {
            id: chevron

            anchors.verticalCenter: parent.verticalCenter
            width: root.t ? root.t.s(22) : 16
            horizontalAlignment: Text.AlignRight
            visible: root.showChevron
            text: "›"
            color: root.t ? root.t.ghost : "grey"
            font.family: root.t ? root.t.family : "monospace"
            font.pixelSize: root.t ? root.t.fBody : 13
        }

    }

    MouseArea {
        id: mouse

        anchors.fill: parent
        enabled: root.showChevron
        hoverEnabled: true
        cursorShape: Qt.PointingHandCursor
        onClicked: root.activated()
    }

}
