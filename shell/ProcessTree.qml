// "What started it" — the chain of processes that led to the alert.
//
// The record carries `process.ancestry` as `[{pid, exe, args, cwd, start_time,
// uid, others[]}]`, nearest parent first. The first version of this drew the
// names and the pids and stopped there; this one is the 4a handoff: the chain
// stays as the collapsed summary, and open turns it into something walkable.
//
// Three things the flat list could not say, and this can:
//
//   * **which process the alert is about.** It is the leaf, it is red end to
//     end, and it is selected when the card opens. Previously you counted rows.
//   * **what else that shell was doing.** `others` is every process an ancestor
//     started that is NOT on the path here, which is how a person tells a build
//     from an intrusion without leaving the card. Dashed connector for context,
//     solid for lineage.
//   * **what any one of them actually did.** Selecting a row fills the panel
//     with its facts and the events moat recorded for that pid.
//
// Degrades on purpose. Records written before the daemon carried the detail
// have pid and exe only; every field below is optional and the panel says
// "not recorded" rather than drawing an empty row. An empty `others` means
// none were RECORDED -- the process table is an LRU -- never that the shell
// did nothing else, and the copy says so.
import QtQuick

Column {
    id: root

    property var tokens: null
    /// `[{pid, exe, args, cwd, start_time, uid, others}]`, nearest parent first.
    property var ancestry: []
    /// The process the alert is about: the leaf, kept beside the ancestry.
    property var process: null
    /// `{ "<pid>": [{time, text, alert}] }` — what moat recorded for each pid.
    /// The card builds this from the incident's own members.
    property var events: ({})
    /// Timestamp of the alert, for the header's duration.
    property string alertTs: ""
    property bool open: root.nodes.length > 0 && root.nodes.length <= autoOpenMax

    /// Chains up to this deep open themselves. Five covers the ordinary shapes;
    /// a container or package-manager chain, which is where these get long,
    /// stays folded until someone wants it.
    readonly property int autoOpenMax: 5
    /// Below this the detail panel stacks under the tree instead of beside it.
    /// The handoff specifies a 420px column; moat's card is not always that
    /// wide plus a readable tree.
    readonly property int twoColumnMin: 660

    readonly property var t: root.tokens
    readonly property color flagged: root.t ? root.t.alarm : "#e0523f"
    readonly property color faintest: root.t ? root.t.ramp(0.78) : "#3d3a37"

    /// Oldest first, with the alerting process last: the order a person reads a
    /// causal chain in. The record stores it the other way round because that
    /// is the order the kernel walks it.
    readonly property var nodes: {
        var out = [];
        // Duck-typed, not `Array.isArray`: a JS array assigned to a `var`
        // property from QML comes back as a QVariantList, which has a length,
        // indexes fine, and which `Array.isArray` rejects.
        var src = root.ancestry;
        var list = src && typeof src.length === "number" ? src : [];
        for (var i = list.length - 1; i >= 0; i--) {
            out.push(list[i] || {});
        }
        if (root.process && (root.process.exe || root.process.pid))
            out.push(root.process);
        return out;
    }

    property int selected: root.nodes.length - 1
    /// Which ancestors have their other children showing, by node index.
    property var revealed: ({})

    function base(path) {
        var s = String(path || "");
        var i = s.lastIndexOf("/");
        return i >= 0 ? s.slice(i + 1) : s;
    }

    function othersOf(node) {
        var o = node && node.others;
        return o && typeof o.length === "number" ? o : [];
    }

    function eventsFor(pid) {
        var e = root.events ? root.events[String(pid)] : null;
        return e && typeof e.length === "number" ? e : [];
    }

    /// `systemd → sh → pg_isready`, basenames only.
    readonly property string summary: {
        var parts = [];
        for (var i = 0; i < root.nodes.length; i++) {
            parts.push(root.base(root.nodes[i].exe) || "?");
        }
        return parts.join("  →  ");
    }

    /// "7 processes · 1m 46s from the first to the read". Omits the duration
    /// rather than inventing one when the record has no start time -- older
    /// records do not, and a made-up number here reads as evidence.
    readonly property string headline: {
        var n = root.nodes.length;
        var word = n + (n === 1 ? " process" : " processes");
        var first = root.nodes.length ? root.nodes[0].start_time : "";
        if (!first || !root.alertTs)
            return word;
        var a = Date.parse(String(first));
        var b = Date.parse(String(root.alertTs));
        if (!isFinite(a) || !isFinite(b) || b < a)
            return word;
        var secs = Math.round((b - a) / 1000);
        var span = secs < 60 ? secs + "s" : Math.floor(secs / 60) + "m " + (secs % 60) + "s";
        return word + "  ·  " + span + " from the first to the read";
    }

    spacing: root.t ? root.t.s(8) : 6
    visible: root.nodes.length > 0

    // ----------------------------------------------------------- header

    Row {
        width: parent.width
        spacing: root.t ? root.t.s(8) : 6

        Text {
            text: root.open ? "▾" : "▸"
            color: root.t ? root.t.fainter : "grey"
            font.family: root.t ? root.t.family : "monospace"
            font.pixelSize: root.t ? root.t.fMeta : 11
        }

        Text {
            text: "WHAT STARTED IT"
            color: root.t ? root.t.fainter : "grey"
            font.family: root.t ? root.t.family : "monospace"
            font.pixelSize: root.t ? root.t.fMeta : 11
            font.letterSpacing: root.t ? root.t.lsLabel : 0
        }

        Text {
            text: root.headline
            color: root.faintest
            font.family: root.t ? root.t.family : "monospace"
            font.pixelSize: root.t ? root.t.fMeta : 11
        }
    }

    MouseArea {
        // The whole header row toggles, not just the glyph.
        width: parent.width
        height: 1
        visible: false
    }

    // ----------------------------------------------- chain (always visible)

    Text {
        width: parent.width
        text: root.summary
        color: root.t ? root.t.primary : "white"
        font.family: root.t ? root.t.family : "monospace"
        // fSecondary like the rest of the card; this was the one line at
        // fBody and it made the whole block look oversized.
        font.pixelSize: root.t ? root.t.fSecondary : 12
        elide: Text.ElideRight
        // One line, always. The summary is meant to be scanned; a chain deep
        // enough to wrap is a chain to open rather than to read across.
        maximumLineCount: 1
        leftPadding: root.t ? root.t.s(20) : 14

        MouseArea {
            anchors.fill: parent
            cursorShape: Qt.PointingHandCursor
            onClicked: root.open = !root.open
        }
    }

    // --------------------------------------------------------- the tree

    Loader {
        width: parent.width
        // Nothing is built until it is opened. Every incident card carries one
        // of these and History builds many at once -- delegate churn there was
        // 206 ms of a 413 ms poll, measured 2026-09-10.
        active: root.open
        visible: root.open
        sourceComponent: treeAndDetail
    }

    Component {
        id: treeAndDetail

        Grid {
            width: parent.width
            columns: root.width >= root.twoColumnMin ? 2 : 1
            columnSpacing: root.t ? root.t.s(20) : 14
            rowSpacing: root.t ? root.t.s(14) : 10

            Column {
                id: rows
                width: root.width >= root.twoColumnMin
                     ? root.width - (root.t ? root.t.s(20) : 14) - detail.width
                     : root.width
                spacing: 0

                Repeater {
                    model: root.nodes

                    delegate: Column {
                        required property var modelData
                        required property int index

                        width: rows.width
                        spacing: 0

                        ProcessTreeRow {
                            width: parent.width
                            tokens: root.t
                            depth: index
                            node: modelData
                            isFlagged: index === root.nodes.length - 1
                            isSelected: index === root.selected
                            otherCount: root.othersOf(modelData).length
                            othersOpen: root.revealed[index] === true
                            onPicked: root.selected = index
                            onToggled: {
                                var m = {};
                                for (var k in root.revealed)
                                    m[k] = root.revealed[k];
                                m[index] = !(m[index] === true);
                                root.revealed = m;
                            }
                        }

                        // Other children of this ancestor, under it, before the
                        // next one. Dashed connector and dimmed: context, not
                        // lineage.
                        Repeater {
                            model: root.revealed[index] === true ? root.othersOf(modelData) : []

                            delegate: ProcessTreeRow {
                                required property var modelData

                                width: rows.width
                                tokens: root.t
                                depth: index + 1
                                node: modelData
                                isSibling: true
                                note: modelData.state || ""
                            }
                        }
                    }
                }
            }

            ProcessTreeDetail {
                id: detail
                tokens: root.t
                width: root.width >= root.twoColumnMin
                     ? Math.min(420, Math.round(root.width * 0.42))
                     : root.width
                node: root.nodes[root.selected] || null
                distance: root.nodes.length - 1 - root.selected
                events: root.eventsFor((root.nodes[root.selected] || {}).pid)
            }
        }
    }
}
