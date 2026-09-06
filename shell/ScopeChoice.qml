// The silence choice (docs/design/README.md 1c).
// "This was me" does not write anything. It asks one more question -- how wide?
// -- and this is that question. What it replaces: four headings, four
// paragraphs about file paths, and four "Show TOML" links, all live at once.
// **Only the chosen scope is explained.** That is the screen's whole rule. The
// consequence card has two halves and always both: what stops asking, and what
// still gets through. A silence explained only by what it silences is how
// somebody agrees to a rule they would not have written.

import "MoatCopy.js" as Copy
import "MoatModel.js" as Model
import QtQuick
import qs.Commons
import qs.Ui

// The scopes are the DAEMON'S. `explain.if_expected.options[]` is the list moatd
// is prepared to write for this alert, each with the exact TOML it would append,
// and the action names an alert id plus one of those scope words. The panel
// never composes a rule out of a string, which is the difference between an
// action surface four verbs wide and one that grows a fifth.
Rectangle {
    id: root

    property var tokens: null
    property var service: null
    property var incident: null
    readonly property var t: root.tokens
    readonly property var head: root.incident ? root.incident.head : null
    readonly property var scopes: root.head ? Model.silenceScopes(root.head, root.incident.count) : []
    /// Which chip is chosen. Starts on the recommendation, and the recommendation
    /// can never be the machine-wide one (Model.silenceScopes enforces that).
    property string chosen: ""
    property bool tomlOpen: false
    readonly property var chosenScope: {
        for (var i = 0; i < root.scopes.length; i++) {
            if (root.scopes[i].scope === root.chosen)
                return root.scopes[i];

        }
        return root.scopes.length > 0 ? root.scopes[0] : null;
    }

    signal confirmed(string id, string scope)
    signal cancelled()

    /// Pick by number, for 2g's `a` then 1-4.
    function chooseIndex(n) {
        var i = Number(n) - 1;
        if (i >= 0 && i < root.scopes.length)
            root.chosen = root.scopes[i].scope;

    }

    function confirm() {
        if (!root.incident || !root.chosenScope)
            return ;

        root.confirmed(root.incident.id, root.chosenScope.scope);
    }

    onScopesChanged: {
        if (root.scopes.length === 0) {
            root.chosen = "";
            return ;
        }
        for (var i = 0; i < root.scopes.length; i++) {
            if (root.scopes[i].scope === root.chosen)
                return ;

        }
        root.chosen = root.scopes[0].scope;
    }
    implicitHeight: column.implicitHeight
    color: root.t ? root.t.card : "transparent"
    radius: root.t ? root.t.rCard : 0
    border.width: 1
    border.color: root.t ? root.t.accentTint(0.24) : "transparent"

    Column {
        id: column

        x: root.t ? root.t.smallCardPadX : 8
        width: parent.width - (root.t ? root.t.smallCardPadX * 2 : 16)
        topPadding: root.t ? root.t.smallCardPadY : 8
        bottomPadding: root.t ? root.t.smallCardPadY : 8
        spacing: root.t ? root.t.s(14) : 8

        Text {
            width: parent.width
            text: root.incident && root.incident.count > 1 ? "This keeps firing. Stop asking about it?" : "Say this was you. How wide should that be?"
            color: root.t ? root.t.body : "white"
            font.family: root.t ? root.t.family : "monospace"
            font.pixelSize: root.t ? root.t.fBody : 13
            wrapMode: Text.WordWrap
            textFormat: Text.PlainText
        }

        // The daemon offered nothing. Say so, rather than showing an empty row of
        // chips and a button that would send a scope nobody was offered.
        Text {
            width: parent.width
            visible: root.scopes.length === 0
            text: "Moat has not worked out a rule it could write for this one. Open its evidence, or stop it."
            color: root.t ? root.t.dimmer : "grey"
            font.family: root.t ? root.t.family : "monospace"
            font.pixelSize: root.t ? root.t.fSecondary : 12
            wrapMode: Text.WordWrap
            textFormat: Text.PlainText
        }

        Flow {
            width: parent.width
            visible: root.scopes.length > 0
            spacing: root.t ? root.t.s(9) : 6

            Repeater {
                model: root.scopes

                delegate: MoatChip {
                    required property var modelData

                    tokens: root.t
                    text: modelData.label
                    selected: root.chosen === modelData.scope
                    // The broadest option stays reachable and stays duller, selected or
                    // not. It is the one choice whose consequences cannot be seen from
                    // this screen.
                    dim: modelData.broadest && root.chosen !== modelData.scope
                    onClicked: root.chosen = modelData.scope
                }

            }

        }

        // ----------------------------------------- the consequence, for ONE chip
        Rectangle {
            width: parent.width
            visible: !!root.chosenScope
            implicitHeight: consequence.implicitHeight + (root.t ? root.t.s(28) : 16)
            radius: root.t ? root.t.rInner : 0
            color: root.t ? root.t.chip : "transparent"

            Text {
                id: check

                x: root.t ? root.t.s(14) : 8
                y: root.t ? root.t.s(14) : 8
                text: "" // nerd-font check; the same one the primary button uses
                color: root.t ? root.t.calm : "green"
                font.family: root.t ? root.t.family : "monospace"
                font.pixelSize: root.t ? root.t.fBody : 13
            }

            Column {
                id: consequence

                x: root.t ? root.t.s(36) : 24
                y: root.t ? root.t.s(14) : 8
                width: parent.width - x - (root.t ? root.t.s(14) : 8)
                spacing: root.t ? root.t.s(7) : 4

                Text {
                    width: parent.width
                    text: root.chosenScope ? root.chosenScope.consequence.silences : ""
                    color: root.t ? root.t.body : "white"
                    font.family: root.t ? root.t.family : "monospace"
                    font.pixelSize: root.t ? root.t.fSecondary : 12
                    lineHeight: root.t ? root.t.lhBody : 1.7
                    wrapMode: Text.WordWrap
                    textFormat: Text.PlainText
                }

                Text {
                    width: parent.width
                    text: root.chosenScope ? root.chosenScope.consequence.through : ""
                    color: root.t ? root.t.dimmer : "grey"
                    font.family: root.t ? root.t.family : "monospace"
                    font.pixelSize: root.t ? root.t.fMeta : 11
                    lineHeight: root.t ? root.t.lhBody : 1.7
                    wrapMode: Text.WordWrap
                    textFormat: Text.PlainText
                }

            }

        }

        // The exact bytes, one click away. Never model-authored: this string came
        // out of the daemon's own `explain` block and is what it will append.
        Rectangle {
            width: parent.width
            visible: root.tomlOpen && !!root.chosenScope && root.chosenScope.line !== ""
            implicitHeight: tomlText.implicitHeight + (root.t ? root.t.s(24) : 14)
            radius: root.t ? root.t.rChip : 0
            color: root.t ? root.t.sunken : "transparent"

            Text {
                id: tomlText

                x: root.t ? root.t.s(12) : 8
                y: root.t ? root.t.s(12) : 7
                width: parent.width - (root.t ? root.t.s(24) : 16)
                text: root.chosenScope ? root.chosenScope.line : ""
                color: root.t ? root.t.dimmer : "grey"
                font.family: root.t ? root.t.family : "monospace"
                font.pixelSize: root.t ? root.t.fCode : 12
                lineHeight: root.t ? root.t.lhMeta : 1.6
                wrapMode: Text.WrapAnywhere
                textFormat: Text.PlainText
            }

        }

        Item {
            width: parent.width
            implicitHeight: actions.implicitHeight

            Row {
                id: actions

                anchors.left: parent.left
                spacing: root.t ? root.t.s(10) : 6

                Button {
                    text: "Stop asking"
                    iconText: ""
                    background: root.t ? root.t.accent : "orange"
                    foreground: root.t ? root.t.accentLabel : "black"
                    fontSize: root.t ? root.t.fBody : 13
                    enabled: !!root.chosenScope
                    opacity: enabled ? 1 : 0.4
                    onClicked: root.confirm()
                }

                Button {
                    text: "Keep asking"
                    foreground: root.t ? root.t.dimmer : "grey"
                    fontSize: root.t ? root.t.fSecondary : 12
                    onClicked: root.cancelled()
                }

            }

            Button {
                anchors.right: parent.right
                anchors.verticalCenter: actions.verticalCenter
                visible: !!root.chosenScope && root.chosenScope.line !== ""
                text: root.tomlOpen ? "Hide the rule it writes" : "Show the rule it writes"
                foreground: root.t ? root.t.ghost : "grey"
                fontSize: root.t ? root.t.fMeta : 11
                onClicked: root.tomlOpen = !root.tomlOpen
            }

        }

    }

}
