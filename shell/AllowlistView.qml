import QtQuick
import qs.Commons
import qs.Ui

// The Allowlist tab: every [[rule]] block the user has added to
// /etc/moat/allowlist.d/user.toml through the "if this is expected" flow,
// with the comment moatd stamped on it and a Remove button.
//
// The index is the handle CONTRACT 5's `unignore` takes, so it is displayed and
// passed through exactly as the daemon reported it. Renumbering client-side
// would remove the wrong block.
Item {
  id: root

  property var service: null
  property color foreground: Color.popups.text

  readonly property color mutedForeground: Qt.darker(foreground, 1.5)
  readonly property color codeBackground: Util.alpha(foreground, 0.06)
  readonly property var rules: service ? service.allowlistRules : []

  signal removeRequested(int index)

  Flickable {
    anchors.fill: parent
    contentWidth: width
    contentHeight: column.implicitHeight
    clip: true
    boundsBehavior: Flickable.StopAtBounds

    Column {
      id: column
      width: parent.width
      spacing: Style.spacing.md

      Row {
        width: parent.width
        spacing: Style.spacing.md

        Text {
          anchors.verticalCenter: parent.verticalCenter
          text: root.service ? root.service.allowlistFile : ""
          color: root.mutedForeground
          font.family: Style.font.family
          font.pixelSize: Style.font.caption
          elide: Text.ElideMiddle
          width: parent.width - reloadButton.width - parent.spacing
        }

        Button {
          id: reloadButton
          text: root.service && root.service.allowlistLoading ? "Loading…" : "Reload"
          foreground: root.mutedForeground
          fontSize: Style.font.caption
          onClicked: if (root.service) root.service.loadAllowlist()
        }
      }

      Text {
        width: parent.width
        visible: text !== ""
        text: root.service ? root.service.allowlistError : ""
        color: Color.urgent
        font.family: Style.font.family
        font.pixelSize: Style.font.bodySmall
        wrapMode: Text.WordWrap
      }

      Text {
        width: parent.width
        visible: root.rules.length === 0 && (!root.service || root.service.allowlistError === "")
        text: "No user allowlist rules. Rules you add from an alert's \"if this is expected\" block appear here."
        color: root.mutedForeground
        font.family: Style.font.family
        font.pixelSize: Style.font.body
        wrapMode: Text.WordWrap
      }

      Repeater {
        model: root.rules

        delegate: Rectangle {
          required property var modelData
          width: column.width
          height: ruleColumn.implicitHeight + Style.spacing.xl
          color: root.codeBackground
          radius: Style.cornerRadius

          Column {
            id: ruleColumn
            x: Style.spacing.rowPaddingX
            y: Style.spacing.md
            width: parent.width - Style.spacing.rowPaddingX * 2
            spacing: Style.spacing.xs

            Row {
              width: parent.width
              spacing: Style.spacing.md

              Column {
                width: parent.width - removeButton.width - parent.spacing
                spacing: Style.spacing.xxs

                Text {
                  width: parent.width
                  // Rules merged from another allowlist.d fragment carry no
                  // index: `unignore` only edits user.toml, so there is no
                  // number to show and no button to press.
                  text: (modelData.removable ? "#" + modelData.index + "  " : "")
                    + (modelData.name || "(unnamed rule)")
                    + (modelData.scope ? "  ·  " + root.scopeLabel(modelData.scope) : "")
                  color: root.foreground
                  font.family: Style.font.family
                  font.pixelSize: Style.font.subtitle
                  font.bold: true
                  elide: Text.ElideRight
                }

                Text {
                  width: parent.width
                  visible: text !== ""
                  text: modelData.comment
                  color: root.mutedForeground
                  font.family: Style.font.family
                  font.pixelSize: Style.font.caption
                  wrapMode: Text.WordWrap
                }

                Text {
                  width: parent.width
                  visible: text !== ""
                  text: modelData.detail || modelData.line
                  color: root.foreground
                  font.family: Style.font.family
                  font.pixelSize: Style.font.bodySmall
                  wrapMode: Text.WrapAnywhere
                  textFormat: Text.PlainText
                }

                Text {
                  width: parent.width
                  visible: text !== ""
                  text: modelData.removable || !modelData.sourceFile
                    ? ""
                    : "from " + modelData.sourceFile + " — edit that file to remove it"
                  color: root.mutedForeground
                  font.family: Style.font.family
                  font.pixelSize: Style.font.caption
                  wrapMode: Text.WrapAnywhere
                  textFormat: Text.PlainText
                }
              }

              Button {
                id: removeButton
                anchors.verticalCenter: parent.verticalCenter
                text: "Remove"
                visible: modelData.removable
                bordered: true
                foreground: Color.urgent
                accent: Color.urgent
                fontSize: Style.font.caption
                onClicked: root.removeRequested(modelData.index)
              }
            }
          }
        }
      }
    }
  }

  function scopeLabel(scope) {
    return root.service ? root.service.ignoreScopeLabel(scope) : String(scope || "")
  }
}
