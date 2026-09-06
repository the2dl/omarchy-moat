// One row of History (docs/design/README.md 1d).
// Four columns: a 3px tick, the title, the relative time, and the status word.
// The tick and the title's BRIGHTNESS carry what a severity pill used to shout,
// which is why a page of these has at most one alarm-coloured mark on it.

import "MoatCopy.js" as Copy
import "MoatModel.js" as Model
import QtQuick
import qs.Commons
import qs.Ui

// The repeat count and whose rule covered it are appended to the title in a
// dimmer colour rather than given columns of their own: they are qualifications
// of the sentence, not facts to line up and compare.
Item {
    id: root

    property var tokens: null
    property var service: null
    property var incident: null
    property bool selected: false
    readonly property var t: root.tokens
    readonly property string state: root.incident ? String(root.incident.state) : "closed"
    /// Advanced (`rawDetail`). The tick and the title colour still carry the
    /// state -- what is added is the rule id and the severity, which 1d
    /// deliberately keeps off a History row and which is exactly what the reader
    /// who turned this on came for.
    readonly property bool raw: !!root.service && root.service.rawDetail === true
    readonly property var head: root.incident ? root.incident.head : null
    // The tick. Three steps, and only the first has any colour in it.
    readonly property color tickColor: {
        if (!root.t)
            return "transparent";

        switch (root.state) {
        case "needsYou":
            return root.t.alarm;
        case "contained":
            return root.t.calm;
        case "expected":
            return root.t.deepest;
        default:
            return root.t.ghost;
        }
    }
    // The same signal again, in text weight. Brightness is doing the work a pill
    // used to do, and it costs the page no colour at all.
    readonly property color titleColor: {
        if (!root.t)
            return "white";

        switch (root.state) {
        case "needsYou":
            return root.t.primary;
        case "expected":
            return root.t.faint;
        default:
            return root.t.secondary;
        }
    }
    readonly property color stateColor: {
        if (!root.t)
            return "grey";

        switch (root.state) {
        case "needsYou":
            return root.t.alarm;
        case "contained":
            return root.t.calm;
        case "expected":
            return root.t.ghost;
        default:
            return root.t.faint;
        }
    }

    signal activated()

    implicitHeight: content.implicitHeight + (root.t ? root.t.rowPadY * 2 : 12)

    Rectangle {
        anchors.top: parent.top
        width: parent.width
        height: 1
        color: root.t ? root.t.hairlineRow : "transparent"
    }

    Rectangle {
        anchors.fill: parent
        color: root.selected ? (root.t ? root.t.hair(0.05) : "transparent") : (mouse.containsMouse ? (root.t ? root.t.hair(0.03) : "transparent") : "transparent")
        radius: root.t ? root.t.rChipSmall : 0
    }

    Item {
        id: content

        anchors.verticalCenter: parent.verticalCenter
        width: parent.width
        implicitHeight: Math.max(title.implicitHeight, root.t ? root.t.tickHeight : 20)

        Rectangle {
            id: tick

            anchors.verticalCenter: parent.verticalCenter
            x: 0
            width: root.t ? root.t.tickWidth : 3
            height: root.t ? root.t.tickHeight : 20
            radius: root.t ? Math.round(root.t.tickWidth / 1.5) : 2
            color: root.tickColor
        }

        Text {
            id: title

            anchors.verticalCenter: parent.verticalCenter
            x: root.t ? root.t.s(23) : 20
            // Shrink-to-fit within what is left, so the note beside it gets the
            // remainder. Taking the whole column pushed the note off the row.
            width: Math.min(implicitWidth, parent.width - x - age.width - stateWord.width - (root.t ? root.t.s(56) : 40))
            text: root.incident ? root.incident.title : ""
            color: root.titleColor
            font.family: root.t ? root.t.family : "monospace"
            font.pixelSize: root.t ? root.t.fBody : 13
            elide: Text.ElideRight
            maximumLineCount: 1
            // The title is written from the copy table for a known detection and
            // falls back to the daemon's own string for one nobody has written copy
            // for yet -- and that string carries process-derived text.
            textFormat: Text.PlainText
        }

        Text {
            id: note

            anchors.left: title.right
            anchors.leftMargin: root.t ? root.t.s(9) : 6
            anchors.right: age.left
            anchors.rightMargin: root.t ? root.t.s(14) : 8
            anchors.verticalCenter: parent.verticalCenter
            text: {
                if (!root.incident)
                    return "";

                var note = Model.historyNote(root.incident);
                if (!root.raw)
                    return note;

                // The rule id, in the place the count and the covering rule already
                // occupy. Not a new column: 1d's four columns are what makes a page of
                // these scannable, and Advanced is allowed to be denser, not wider.
                var rule = String(root.incident.rule || "");
                return note ? note + "  ·  " + rule : (rule ? "·  " + rule : "");
            }
            color: root.t ? root.t.ghost : "grey"
            font.family: root.t ? root.t.family : "monospace"
            font.pixelSize: root.t ? root.t.fMeta : 11
            elide: Text.ElideRight
            maximumLineCount: 1
            textFormat: Text.PlainText
        }

        Text {
            id: age

            anchors.right: stateWord.left
            anchors.rightMargin: root.t ? root.t.s(20) : 12
            anchors.verticalCenter: parent.verticalCenter
            width: root.t ? root.t.s(90) : 70
            horizontalAlignment: Text.AlignRight
            text: root.incident && root.service ? root.service.relativeTime(root.incident.lastSeen) : ""
            color: root.t ? root.t.fainter : "grey"
            font.family: root.t ? root.t.family : "monospace"
            font.pixelSize: root.t ? root.t.fMeta : 11
            textFormat: Text.PlainText
        }

        Text {
            id: stateWord

            anchors.right: parent.right
            anchors.verticalCenter: parent.verticalCenter
            width: root.t ? root.t.s(root.raw ? 190 : 120) : 90
            horizontalAlignment: Text.AlignRight
            text: {
                var word = root.state === "expected" ? "covered" : Copy.stateWord(root.state);
                if (!root.raw)
                    return word;

                // Severity AS severity, and the state word kept beside it: the state
                // word is still what decides the surface, and dropping it here would
                // make Advanced disagree with the shield about what is waiting.
                var severity = root.head ? String(root.head.severity || "") : "";
                return severity ? severity + " · " + word : word;
            }
            color: root.stateColor
            font.family: root.t ? root.t.family : "monospace"
            font.pixelSize: root.t ? root.t.fMeta : 11
            textFormat: Text.PlainText
        }

    }

    MouseArea {
        id: mouse

        anchors.fill: parent
        hoverEnabled: true
        cursorShape: Qt.PointingHandCursor
        onClicked: root.activated()
    }

}
