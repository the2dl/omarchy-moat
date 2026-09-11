// The right-hand column of the process tree: everything moat recorded about
// the process currently selected.
//
// The tree answers "what led here". This answers "what was that thing", which
// is the question a person asks next and previously had to leave the card to
// answer -- `moatctl explain`, or `ps`, on a process that exited minutes ago.
//
// Records written before the daemon carried this detail have a pid and a path
// and nothing else. Every field says "not recorded" in that case rather than
// rendering blank: an empty value beside a label reads as "this process had no
// arguments", which is a different and wrong claim.
import QtQuick

Rectangle {
    id: detail

    property var tokens: null
    property var node: null
    /// How far the selected process is from the flagged one. 0 is the flagged
    /// process itself.
    property int distance: 0
    /// `[{time, text, alert}]` for this pid, newest first.
    property var events: []

    readonly property var t: detail.tokens

    function base(path) {
        var s = String(path || "");
        var i = s.lastIndexOf("/");
        return i >= 0 ? s.slice(i + 1) : s;
    }

    function shown(v) {
        var s = String(v === undefined || v === null ? "" : v);
        return s.length > 0 ? s : "";
    }

    implicitHeight: body.implicitHeight + (t ? t.s(32) : 24)
    radius: t ? t.s(12) : 8
    // One step under the card, the way the footer strip and code insets are.
    color: t ? t.under(1) : "#121316"
    visible: detail.node !== null

    Column {
        id: body

        anchors.left: parent.left
        anchors.right: parent.right
        anchors.top: parent.top
        anchors.margins: detail.t ? detail.t.s(16) : 12
        spacing: detail.t ? detail.t.s(10) : 7

        Text {
            width: parent.width
            text: detail.distance === 0
                ? "THE PROCESS THAT TRIPPED THE RULE"
                : "ANCESTOR  ·  " + detail.distance + " above"
            color: detail.distance === 0 ? (detail.t ? detail.t.alarm : "red")
                                         : (detail.t ? detail.t.fainter : "grey")
            font.family: detail.t ? detail.t.family : "monospace"
            font.pixelSize: detail.t ? detail.t.fMeta : 11
            font.letterSpacing: detail.t ? detail.t.lsLabel : 0
        }

        Text {
            width: parent.width
            text: detail.base(detail.node ? detail.node.exe : "") || "?"
            color: detail.t ? detail.t.primary : "white"
            font.family: detail.t ? detail.t.family : "monospace"
            font.pixelSize: detail.t ? detail.t.fSecondary : 12
            font.weight: Font.Medium
            wrapMode: Text.WrapAnywhere
        }

        Grid {
            width: parent.width
            columns: 2
            columnSpacing: detail.t ? detail.t.s(12) : 9
            rowSpacing: detail.t ? detail.t.s(5) : 4

            Repeater {
                model: {
                    var n = detail.node || {};
                    var out = [];
                    function add(k, v) {
                        out.push(k);
                        // The distinction that matters: nothing recorded is not
                        // the same claim as an empty value.
                        out.push(detail.shown(v) || "not recorded");
                    }
                    add("pid", n.pid);
                    add("exe", n.exe);
                    add("cmd", n.args);
                    add("cwd", n.cwd);
                    add("started", n.start_time);
                    add("uid", n.uid === undefined || n.uid === null ? "" : n.uid);
                    return out;
                }

                delegate: Text {
                    required property var modelData
                    required property int index

                    width: index % 2 === 0
                         ? (detail.t ? detail.t.s(46) : 34)
                         : body.width - (detail.t ? detail.t.s(58) : 43)
                    text: modelData
                    color: index % 2 === 0 ? (detail.t ? detail.t.fainter : "grey")
                         : (String(modelData) === "not recorded"
                            ? (detail.t ? detail.t.ramp(0.78) : "grey")
                            : (detail.t ? detail.t.secondary : "white"))
                    font.family: detail.t ? detail.t.family : "monospace"
                    font.pixelSize: detail.t ? detail.t.fMeta : 11
                    wrapMode: index % 2 === 0 ? Text.NoWrap : Text.WrapAnywhere
                }
            }
        }

        Rectangle {
            width: parent.width
            height: 1
            color: Qt.rgba(1, 1, 1, 0.06)
        }

        Text {
            text: "WHAT IT DID"
            color: detail.t ? detail.t.fainter : "grey"
            font.family: detail.t ? detail.t.family : "monospace"
            font.pixelSize: detail.t ? detail.t.fMeta : 11
            font.letterSpacing: detail.t ? detail.t.lsLabel : 0
        }

        Text {
            width: parent.width
            visible: !detail.events || detail.events.length === 0
            // Said plainly. Most ancestors are a login shell that did nothing
            // moat has a rule about, and blank space there reads as a panel
            // that failed to load.
            text: "nothing recorded for this process"
            color: detail.t ? detail.t.ramp(0.78) : "grey"
            font.family: detail.t ? detail.t.family : "monospace"
            font.pixelSize: detail.t ? detail.t.fSecondary : 12
        }

        Repeater {
            model: detail.events

            delegate: Row {
                required property var modelData

                width: body.width
                spacing: detail.t ? detail.t.s(10) : 7

                Text {
                    width: detail.t ? detail.t.s(60) : 45
                    text: String(modelData.time || "")
                    color: detail.t ? detail.t.fainter : "grey"
                    font.family: detail.t ? detail.t.family : "monospace"
                    font.pixelSize: detail.t ? detail.t.fSecondary : 12
                }

                Text {
                    width: body.width - (detail.t ? detail.t.s(70) : 52)
                    text: String(modelData.text || "")
                        + (modelData.alert === true ? "  ·  this alert" : "")
                    color: modelData.alert === true ? (detail.t ? detail.t.alarm : "red")
                                                    : (detail.t ? detail.t.secondary : "white")
                    font.family: detail.t ? detail.t.family : "monospace"
                    font.pixelSize: detail.t ? detail.t.fSecondary : 12
                    wrapMode: Text.WordWrap
                }
            }
        }
    }
}
