// History (docs/design/README.md 1d).
// **Severity is a 3px tick and the brightness of the text.** That is the whole
// screen. The old Timeline gave every row a coloured severity pill, so a week of
// normal activity rendered as a page of red and the one thing that actually
// needed a decision had nothing left to distinguish it. Here at most one mark on
// the page is alarm-coloured, and a rule-covered row recedes into the
// background without disappearing -- the user asked for those to be silent, not
// invisible.

import "MoatCopy.js" as Copy
import "MoatModel.js" as Model
import QtQuick
import qs.Commons
import qs.Ui

// The day header carries the counts, because "how many needed me on Tuesday" is
// the question a person actually scans a log for.
Item {
    id: root

    property var service: null
    property var tokens: null
    /// Incidents from Model.buildIncidents, newest activity first.
    property var incidents: []
    /// The same list with nothing hidden. The "Silenced by a rule" chip reads
    /// from this one, so that filter can still answer even when the Advanced
    /// setting keeps rule-covered rows off the other two.
    property var coveredIncidents: []
    property string selectedId: ""
    property string filter: "everything"
    /// LEARNING 3. An install receipt is not an alert and never counts as one --
    /// it is the record of a package install Moat watched all the way through.
    /// It belongs on this screen because the point of a history is chronology,
    /// and filing the install away from the one alert it raised breaks both.
    property string openReceipt: ""
    readonly property int receiptLimit: 6
    readonly property var receipts: root.service ? root.service.receipts : []
    readonly property var t: root.tokens
    readonly property var shown: Model.filterHistory(root.filter === "covered" ? root.coveredIncidents : root.incidents, root.filter)
    readonly property var days: Model.historyDays(root.shown, root.service ? root.service.nowMs : Date.now())

    signal openIncident(string id)

    /// "last 7 days" -- or the truth, when the record does not go back that far.
    function rangeLine() {
        if (root.shown.length === 0)
            return "";

        var oldest = root.shown[root.shown.length - 1];
        var age = root.service ? root.service.relativeTime(oldest.firstSeen) : "";
        return age ? "back to " + age : "";
    }

    // ------------------------------------------------------------ filter row
    Item {
        id: filterRow

        anchors.top: parent.top
        anchors.left: parent.left
        anchors.right: parent.right
        height: (root.t ? root.t.s(16) * 2 : 24) + chips.implicitHeight

        Row {
            id: chips

            anchors.left: parent.left
            anchors.leftMargin: root.t ? root.t.bodyPadX : 12
            anchors.verticalCenter: parent.verticalCenter
            spacing: root.t ? root.t.s(9) : 6

            Repeater {
                model: Model.HISTORY_FILTERS

                delegate: MoatChip {
                    required property string modelData

                    tokens: root.t
                    text: Model.historyFilterLabel(modelData)
                    selected: root.filter === modelData
                    onClicked: root.filter = modelData
                }

            }

        }

        Text {
            anchors.right: parent.right
            anchors.rightMargin: root.t ? root.t.bodyPadX : 12
            anchors.verticalCenter: parent.verticalCenter
            text: root.rangeLine()
            color: root.t ? root.t.fainter : "grey"
            font.family: root.t ? root.t.family : "monospace"
            font.pixelSize: root.t ? root.t.fSecondary : 12
            textFormat: Text.PlainText
        }

        Rectangle {
            anchors.bottom: parent.bottom
            width: parent.width
            height: 1
            color: root.t ? root.t.hairlineRow : "transparent"
        }

    }

    // ---------------------------------------------------------- the day groups
    Text {
        anchors.centerIn: parent
        width: parent.width * 0.6
        visible: root.days.length === 0
        text: {
            if (root.service && !root.service.logReadable)
                return "Moat cannot read its own record of what happened.";

            if (root.filter === "needsYou")
                return "Nothing has needed a decision.";

            if (root.filter === "covered")
                return "No rule has silenced anything yet.";

            return "Nothing has happened yet. Moat is watching.";
        }
        color: root.t ? root.t.faint : "grey"
        font.family: root.t ? root.t.family : "monospace"
        font.pixelSize: root.t ? root.t.fBody : 13
        horizontalAlignment: Text.AlignHCenter
        wrapMode: Text.WordWrap
        textFormat: Text.PlainText
    }

    MoatScroll {
        anchors.top: filterRow.bottom
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.bottom: parent.bottom
        contentHeight: body.implicitHeight

        Column {
            id: body

            x: root.t ? root.t.bodyPadX : 0
            width: parent.width - (root.t ? root.t.bodyPadX * 2 : 0)
            topPadding: root.t ? root.t.v(26) : 0
            bottomPadding: root.t ? root.t.bodyPadBottom : 0
            spacing: root.t ? root.t.v(30) : 12

            // Day groups, then rows, each kept by KEY across polls. A Repeater
            // over a JS array destroys and recreates every delegate when the
            // array changes, and the array changes on every poll -- 58 rows
            // rebuilt about once a second, measured at 206 ms of the desktop's
            // thread each time, for one changed line. MoatKeyed keeps the item
            // for a key and hands it the new value only when the value is a
            // different object; an incident nothing happened to is the same
            // object (Model.reuseIncidents), so its row does nothing at all.
            MoatKeyed {
                width: body.width
                spacing: root.t ? root.t.v(30) : 12
                items: root.days

                delegate: Column {
                    property var value: null

                    width: body.width
                    spacing: root.t ? root.t.s(4) : 2

                    // Day header: the name of the day, then the counts. The counts are
                    // incidents, never events -- a number in this panel is a number of
                    // decisions.
                    Row {
                        width: parent.width
                        spacing: root.t ? root.t.s(14) : 8

                        // Both rows are given the same explicit height and centred in it
                        // rather than baseline-anchored: a Positioner ignores anchors on
                        // its children, so anchors.baseline inside a Row silently does
                        // nothing and the smaller text top-aligns.
                        Text {
                            height: root.t ? root.t.s(20) : 16
                            verticalAlignment: Text.AlignVCenter
                            text: value ? value.label : ""
                            color: root.t ? root.t.primary : "white"
                            font.family: root.t ? root.t.family : "monospace"
                            font.pixelSize: root.t ? root.t.fBody : 13
                            textFormat: Text.PlainText
                        }

                        Text {
                            height: root.t ? root.t.s(20) : 16
                            verticalAlignment: Text.AlignVCenter
                            text: value ? value.summary : ""
                            color: root.t ? root.t.fainter : "grey"
                            font.family: root.t ? root.t.family : "monospace"
                            font.pixelSize: root.t ? root.t.fMeta : 11
                            textFormat: Text.PlainText
                        }

                    }

                    MoatKeyed {
                        width: body.width
                        items: value ? value.incidents : []

                        delegate: HistoryRow {
                            property var value: null

                            width: body.width
                            tokens: root.t
                            service: root.service
                            incident: value
                            selected: !!value && value.id === root.selectedId
                            onActivated: root.openIncident(value ? value.id : "")
                        }

                    }

                }

            }

            // Installs Moat watched all the way through. Shown only under
            // "Everything": the other two filters are about decisions, and an
            // install that raised no alert asked nothing of anybody.
            Column {
                width: parent.width
                visible: root.filter === "everything" && root.receipts.length > 0
                spacing: root.t ? root.t.s(4) : 2

                Text {
                    height: root.t ? root.t.s(20) : 16
                    verticalAlignment: Text.AlignVCenter
                    text: "Installs Moat watched  ·  " + root.receipts.length
                    color: root.t ? root.t.primary : "white"
                    font.family: root.t ? root.t.family : "monospace"
                    font.pixelSize: root.t ? root.t.fBody : 13
                    textFormat: Text.PlainText
                }

                Repeater {
                    // The most recent handful. This is History, and History is about
                    // decisions -- a hundred clean installs pushing the one thing that
                    // needed you off the bottom of the screen is the wall of rows this
                    // redesign exists to remove.
                    model: root.receipts.slice(0, root.receiptLimit)

                    delegate: Column {
                        required property var modelData

                        width: body.width
                        spacing: 0

                        Item {
                            width: parent.width
                            implicitHeight: receiptRow.implicitHeight + (root.t ? root.t.rowPadY * 2 : 12)

                            Rectangle {
                                anchors.top: parent.top
                                width: parent.width
                                height: 1
                                color: root.t ? root.t.hairlineRow : "transparent"
                            }

                            Rectangle {
                                anchors.fill: parent
                                color: receiptMouse.containsMouse ? (root.t ? root.t.hair(0.03) : "transparent") : "transparent"
                                radius: root.t ? root.t.rChipSmall : 0
                            }

                            Item {
                                id: receiptRow

                                anchors.verticalCenter: parent.verticalCenter
                                width: parent.width
                                implicitHeight: receiptText.implicitHeight

                                Text {
                                    id: receiptText

                                    anchors.left: parent.left
                                    x: root.t ? root.t.s(23) : 20
                                    width: parent.width - x - (root.t ? root.t.s(160) : 120)
                                    text: root.service ? root.service.receiptSummary(modelData) : ""
                                    color: root.t ? root.t.secondary : "white"
                                    font.family: root.t ? root.t.family : "monospace"
                                    font.pixelSize: root.t ? root.t.fBody : 13
                                    elide: Text.ElideRight
                                    maximumLineCount: 1
                                    textFormat: Text.PlainText
                                }

                                Text {
                                    anchors.right: chevron.left
                                    anchors.rightMargin: root.t ? root.t.s(8) : 6
                                    anchors.verticalCenter: parent.verticalCenter
                                    width: root.t ? root.t.s(140) : 100
                                    horizontalAlignment: Text.AlignRight
                                    text: root.service ? root.service.relativeTime(modelData.started) : ""
                                    color: root.t ? root.t.fainter : "grey"
                                    font.family: root.t ? root.t.family : "monospace"
                                    font.pixelSize: root.t ? root.t.fMeta : 11
                                    textFormat: Text.PlainText
                                }

                                // The row toggles on click, and always did -- but with nothing
                                // marking it as expandable there was no way to know that, and
                                // no way to guess that clicking again closes it. A disclosure
                                // chevron that turns when open is the whole affordance.
                                Text {
                                    id: chevron

                                    anchors.right: parent.right
                                    anchors.verticalCenter: parent.verticalCenter
                                    width: root.t ? root.t.s(18) : 14
                                    horizontalAlignment: Text.AlignRight
                                    text: root.openReceipt === String(modelData.key) ? "\u2304" : "\u203a"
                                    color: root.t ? root.t.ghost : "grey"
                                    font.family: root.t ? root.t.family : "monospace"
                                    font.pixelSize: root.t ? root.t.fBody : 13
                                    textFormat: Text.PlainText
                                }

                            }

                            MouseArea {
                                id: receiptMouse

                                anchors.fill: parent
                                hoverEnabled: true
                                cursorShape: Qt.PointingHandCursor
                                onClicked: root.openReceipt = root.openReceipt === String(modelData.key) ? "" : String(modelData.key)
                            }

                        }

                        // LEARNING 3's six-line block. `receiptBlock` returns
                        // { headline, lines } -- an OBJECT, so that the headline can be
                        // rendered at body weight and the rest as detail under it.
                        // Assigning it straight to `text` binds a QJSValue to a QString,
                        // which Qt refuses at every repaint: a log full of "Unable to
                        // assign QJSValue to QString" and an expansion that renders as
                        // nothing.
                        Column {
                            readonly property var block: root.service ? root.service.receiptBlock(modelData) : ({
                                "headline": "",
                                "lines": []
                            })

                            width: parent.width
                            visible: root.openReceipt === String(modelData.key)
                            leftPadding: root.t ? root.t.s(23) : 20
                            // Room to breathe under an expansion, so the next row reads as a
                            // separate thing rather than as more of this one.
                            bottomPadding: root.t ? root.t.s(16) : 10
                            spacing: root.t ? root.t.s(2) : 1

                            Text {
                                width: body.width - (root.t ? root.t.s(23) : 20)
                                text: parent.block.headline
                                color: root.t ? root.t.secondary : "white"
                                font.family: root.t ? root.t.family : "monospace"
                                font.pixelSize: root.t ? root.t.fCode : 12
                                lineHeight: root.t ? root.t.lhMeta : 1.6
                                wrapMode: Text.WrapAnywhere
                                maximumLineCount: 3
                                elide: Text.ElideRight
                                textFormat: Text.PlainText
                            }

                            Repeater {
                                model: parent.block.lines

                                delegate: Text {
                                    required property string modelData

                                    width: body.width - (root.t ? root.t.s(23) : 20)
                                    text: modelData
                                    color: root.t ? root.t.dimmer : "grey"
                                    font.family: root.t ? root.t.family : "monospace"
                                    font.pixelSize: root.t ? root.t.fCode : 12
                                    lineHeight: root.t ? root.t.lhMeta : 1.6
                                    wrapMode: Text.WrapAnywhere
                                    // An expansion is allowed to be long. It is not allowed to be
                                    // unbounded: every one of these lines is a path, a host or an
                                    // argument out of a package build.
                                    maximumLineCount: 6
                                    elide: Text.ElideRight
                                    textFormat: Text.PlainText
                                }

                            }

                        }

                    }

                }

                Text {
                    visible: root.receipts.length > root.receiptLimit
                    topPadding: root.t ? root.t.s(10) : 6
                    text: (root.receipts.length - root.receiptLimit) + " older installs, all watched through"
                    color: root.t ? root.t.ghost : "grey"
                    font.family: root.t ? root.t.family : "monospace"
                    font.pixelSize: root.t ? root.t.fMeta : 11
                    textFormat: Text.PlainText
                }

            }

        }

    }

}
