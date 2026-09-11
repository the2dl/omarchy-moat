// One line of the process tree: an ancestor on the path, or one of the other
// children an ancestor started.
//
// The two are drawn differently on purpose. A solid connector means lineage --
// this process started the next one, and that is how the alert got here. A
// dashed one at 70% opacity means context: that shell also did this, and it is
// not on the path. Reading a tree where both look alike is how a person
// convinces themselves an ordinary build step is part of an intrusion.
import QtQuick

Item {
    id: row

    property var tokens: null
    property var node: null
    property int depth: 0
    property bool isFlagged: false
    property bool isSelected: false
    property bool isSibling: false
    /// Shown after the command on a sibling row: `exited`, `killed by SIGKILL`.
    property string note: ""
    /// How many other children this ancestor has; 0 hides the toggle.
    property int otherCount: 0
    property bool othersOpen: false

    signal picked
    signal toggled

    readonly property var t: row.tokens
    readonly property int indent: (row.t ? row.t.s(18) : 12) * row.depth

    function base(path) {
        var s = String(path || "");
        var i = s.lastIndexOf("/");
        return i >= 0 ? s.slice(i + 1) : s;
    }

    height: row.isSibling ? (row.t ? row.t.s(26) : 20) : (row.t ? row.t.s(32) : 24)
    opacity: row.isSibling ? 0.7 : 1

    Rectangle {
        anchors.fill: parent
        radius: row.t ? row.t.s(8) : 6
        // Selection is a wash, not a border: a border on one row in a tree
        // reads as a box around a group.
        color: row.isSelected ? Qt.rgba(1, 1, 1, 0.045)
             : (hover.hovered && !row.isSibling ? Qt.rgba(1, 1, 1, 0.03) : "transparent")
    }

    HoverHandler {
        id: hover
        enabled: !row.isSibling
    }

    MouseArea {
        anchors.fill: parent
        enabled: !row.isSibling
        cursorShape: Qt.PointingHandCursor
        onClicked: row.picked()
    }

    Row {
        anchors.left: parent.left
        anchors.leftMargin: row.indent
        anchors.verticalCenter: parent.verticalCenter
        spacing: row.t ? row.t.s(10) : 7

        Text {
            anchors.verticalCenter: parent.verticalCenter
            // Box characters rather than drawn rectangles: this is a monospace
            // panel and the glyphs line up with the text grid for free.
            text: row.depth === 0 ? "" : (row.isSibling ? "╌─" : "└─")
            color: row.t ? row.t.fainter : "grey"
            font.family: row.t ? row.t.family : "monospace"
            font.pixelSize: row.t ? row.t.fMeta : 11
        }

        ProcessTreeMark {
            anchors.verticalCenter: parent.verticalCenter
            height: row.t ? row.t.s(9) : 7
            kind: row.isFlagged ? "flagged" : "lineage"
            // Siblings are context, not lineage: no mark, so the column of
            // marks reads as the path and nothing else.
            visible: !row.isSibling
            tone: row.isFlagged ? (row.t ? row.t.alarm : "red")
                : row.isSelected ? (row.t ? row.t.faint : "grey")
                : (row.t ? row.t.fainter : "grey")
        }

        Text {
            anchors.verticalCenter: parent.verticalCenter
            width: row.t ? row.t.s(58) : 43
            horizontalAlignment: Text.AlignRight
            text: {
                var p = row.node ? row.node.pid : undefined;
                return p === undefined || p === null ? "?" : String(p);
            }
            color: row.isFlagged ? (row.t ? row.t.alarm : "red")
                 : (row.isSibling ? (row.t ? row.t.ramp(0.78) : "grey")
                                  : (row.t ? row.t.fainter : "grey"))
            font.family: row.t ? row.t.family : "monospace"
            font.pixelSize: row.t ? row.t.fMeta : 11
        }

        Text {
            anchors.verticalCenter: parent.verticalCenter
            text: row.base(row.node ? row.node.exe : "") || "?"
            color: row.isFlagged ? (row.t ? row.t.alarm : "red")
                 : row.isSelected ? (row.t ? row.t.primary : "white")
                 : (row.t ? row.t.secondary : "grey")
            font.family: row.t ? row.t.family : "monospace"
            // fSecondary, not fBody. The rest of the card is fSecondary and
            // fMeta almost everywhere -- 14 uses to 1 -- so a tree at fBody
            // read as a larger, separate thing bolted onto the card.
            font.pixelSize: row.isSibling ? (row.t ? row.t.fMeta : 11) : (row.t ? row.t.fSecondary : 12)
            font.weight: row.isSibling ? Font.Normal : Font.Medium
        }

        Text {
            anchors.verticalCenter: parent.verticalCenter
            // The command, and on a sibling the state after it. Elided: a
            // `cargo test` line is longer than any panel and the first words
            // are the ones that identify it.
            width: Math.max(0, row.width - row.indent - (row.t ? row.t.s(190) : 140))
            text: {
                var args = String((row.node && row.node.args) || "");
                if (row.note)
                    return args ? args + "  ·  " + row.note : row.note;
                return args;
            }
            color: row.t ? row.t.fainter : "grey"
            font.family: row.t ? row.t.family : "monospace"
            font.pixelSize: row.t ? row.t.fMeta : 11
            elide: Text.ElideRight
            maximumLineCount: 1
        }
    }

    // The "N other children" chip. Only where there are any, and clicking it
    // must not also select the row -- the two are different questions.
    Rectangle {
        id: chip

        anchors.right: parent.right
        anchors.verticalCenter: parent.verticalCenter
        visible: !row.isSibling && row.otherCount > 0
        width: chipText.implicitWidth + (row.t ? row.t.s(16) : 12)
        height: row.t ? row.t.s(20) : 15
        radius: row.t ? row.t.s(6) : 4
        color: chipHover.hovered ? Qt.rgba(1, 1, 1, 0.06) : "transparent"

        HoverHandler {
            id: chipHover
        }

        Text {
            id: chipText

            anchors.centerIn: parent
            text: (row.othersOpen ? "▾  " : "▸  ") + row.otherCount
                + (row.otherCount === 1 ? " other child" : " other children")
            color: chipHover.hovered ? (row.t ? row.t.dimmer : "grey") : (row.t ? row.t.faint : "grey")
            font.family: row.t ? row.t.family : "monospace"
            font.pixelSize: row.t ? row.t.fMeta : 11
        }

        MouseArea {
            anchors.fill: parent
            cursorShape: Qt.PointingHandCursor
            onClicked: row.toggled()
        }
    }
}
