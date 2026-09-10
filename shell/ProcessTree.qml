// The chain of processes that led to the alert, as a tree you can open.
//
// The record carries `process.ancestry` as `[{pid, exe}, ...]`, nearest parent
// first, and the card printed it as a block of "pid  path" lines under
// Advanced. That is the whole story of an alert -- who started what -- rendered
// as the least readable thing on the card, and the shape it actually has is a
// tree, so this draws one.
//
// Collapsed by default, and the collapsed line is the answer most of the time:
// `systemd -> containerd-shim -> sh -> pg_isready` fits on one row and says
// where a process came from. Opening it adds the pid and the full path, which
// is what you want only once the summary has told you something is wrong.
//
// Collapsed is also what keeps it cheap. Every incident card carries one of
// these, and the History view builds many cards at once -- measured on
// 2026-09-10, delegate churn there was 206 ms of a 413 ms poll. The rows are
// behind a Loader so a closed tree costs a single Text and nothing else.
import QtQuick

Column {
    id: root

    property var tokens: null
    /// `[{pid, exe}, ...]`, nearest parent first, straight off the record.
    property var ancestry: []
    /// The process the alert is about -- the deepest node, which the record
    /// keeps beside the ancestry rather than inside it.
    property var process: null
    property bool open: false

    readonly property var t: root.tokens
    /// Oldest first, with the alerting process last: the order a person reads a
    /// causal chain in. The record stores it the other way round because that
    /// is the order the kernel walks it.
    readonly property var nodes: {
        var out = [];
        // Duck-typed, not `Array.isArray`. A JS array assigned to a `var`
        // property from QML comes back as a QVariantList, which has a length
        // and indexes fine and which `Array.isArray` rejects -- so the strict
        // check silently produced a one-node tree for every caller that was not
        // handing over a freshly JSON.parsed record.
        var src = root.ancestry;
        var list = src && typeof src.length === "number" ? src : [];
        for (var i = list.length - 1; i >= 0; i--) {
            out.push(list[i] || {});
        }
        if (root.process && (root.process.exe || root.process.pid))
            out.push(root.process);
        return out;
    }

    function base(path) {
        var s = String(path || "");
        var i = s.lastIndexOf("/");
        return i >= 0 ? s.slice(i + 1) : s;
    }

    /// `systemd -> sh -> pg_isready`, basenames only.
    readonly property string summary: {
        var parts = [];
        for (var i = 0; i < root.nodes.length; i++) {
            parts.push(root.base(root.nodes[i].exe) || "?");
        }
        return parts.join("  →  ");
    }

    spacing: root.t ? root.t.s(4) : 3
    visible: root.nodes.length > 0

    Text {
        width: parent.width
        text: (root.open ? "▾  " : "▸  ") + root.summary
        color: root.t ? root.t.secondary : "white"
        font.family: root.t ? root.t.family : "monospace"
        font.pixelSize: root.t ? root.t.fSecondary : 12
        elide: Text.ElideRight
        // One line, always. The summary is meant to be scanned; a chain deep
        // enough to wrap is a chain to open rather than to read across.
        maximumLineCount: 1

        MouseArea {
            anchors.fill: parent
            cursorShape: Qt.PointingHandCursor
            onClicked: root.open = !root.open
        }
    }

    Loader {
        width: parent.width
        // Nothing is built until it is opened -- see the note at the top about
        // what delegate churn costs in History.
        active: root.open
        visible: root.open
        sourceComponent: Column {
            spacing: root.t ? root.t.s(2) : 2

            Repeater {
                model: root.nodes

                delegate: Row {
                    required property var modelData
                    required property int index

                    spacing: root.t ? root.t.s(8) : 6

                    Text {
                        // Two spaces per level, and a corner on every row but
                        // the first. Indentation alone stops reading as a tree
                        // once the paths are long enough to wrap the eye.
                        text: index === 0 ? "" : "  ".repeat(index) + "└─"
                        color: root.t ? root.t.fainter : "grey"
                        font.family: root.t ? root.t.family : "monospace"
                        font.pixelSize: root.t ? root.t.fSecondary : 12
                    }

                    Text {
                        text: String(modelData.pid === undefined || modelData.pid === null ? "?" : modelData.pid)
                        color: root.t ? root.t.fainter : "grey"
                        font.family: root.t ? root.t.family : "monospace"
                        font.pixelSize: root.t ? root.t.fSecondary : 12
                    }

                    Text {
                        text: String(modelData.exe || "?")
                        // The last node is the process the alert is about, and
                        // it is the one a reader is looking for in here.
                        color: index === root.nodes.length - 1
                             ? (root.t ? root.t.primary : "white")
                             : (root.t ? root.t.dimmer : "grey")
                        font.family: root.t ? root.t.family : "monospace"
                        font.pixelSize: root.t ? root.t.fSecondary : 12
                    }
                }
            }
        }
    }
}
