// The chip. One shape for every "pick one of these" in the redesign: 1c's
// silence scopes, 1d's history filters, 1f's segmented answers.

import QtQuick
import qs.Commons
import qs.Ui

// Three states rather than two, and the third is the point. `dim` is the
// deliberately duller chip 1c gives to the broadest option ("this detection,
// everywhere") -- the one whose consequences the user cannot see from the
// screen they are on. A chooser whose most dangerous option looks exactly like
// the others is a chooser that recommends it by accident.
Rectangle {
    id: root

    property var tokens: null
    property string text: ""
    property bool selected: false
    /// Drawn duller than an unselected chip. For an option that is available but
    /// should never look like the easy one.
    property bool dim: false
    property bool enabled: true
    readonly property var t: root.tokens

    signal clicked()

    implicitWidth: label.implicitWidth + (root.t ? root.t.s(32) : 24)
    implicitHeight: label.implicitHeight + (root.t ? root.t.s(18) : 14)
    radius: root.t ? root.t.rChip : 0
    color: {
        if (!root.t)
            return "transparent";

        if (root.selected)
            return root.t.accent;

        if (root.dim)
            return root.t.chipDim;

        return mouse.containsMouse ? root.t.track : root.t.chip;
    }

    Text {
        id: label

        anchors.centerIn: parent
        text: root.text
        color: {
            if (!root.t)
                return "white";

            if (root.selected)
                return root.t.accentLabel;

            if (root.dim)
                return root.t.dimmer;

            return root.t.secondary;
        }
        font.family: root.t ? root.t.family : "monospace"
        font.pixelSize: root.t ? root.t.fBody : 13
        // Chip labels name programs and parents taken from process output, so they
        // are never markup.
        textFormat: Text.PlainText
    }

    MouseArea {
        id: mouse

        anchors.fill: parent
        enabled: root.enabled
        hoverEnabled: true
        cursorShape: Qt.PointingHandCursor
        onClicked: root.clicked()
    }

}
