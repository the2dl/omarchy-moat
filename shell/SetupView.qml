import QtQuick
import qs.Commons
import qs.Ui

// Shown instead of the alert list whenever the plugin cannot see the truth:
// the package is not installed, or this session is not in the `moat` group
// (CONTRACT 2). Both cases would otherwise render as an empty alert list, which
// reads as "all clear" — the one thing a security panel must never say when it
// is blind.
//
// Every step is the exact command, copyable, in the order the .install file
// prints them.
Item {
  id: root

  property var service: null
  property color foreground: Color.popups.text
  property bool needsPackage: true
  property bool needsGroup: true

  readonly property color mutedForeground: Qt.darker(foreground, 1.5)
  readonly property color codeBackground: Util.alpha(foreground, 0.06)
  readonly property var steps: service ? service.setupSteps() : []

  signal recheckRequested()

  MoatScroll {
    anchors.fill: parent
    contentHeight: column.implicitHeight

    Column {
      id: column
      width: parent.width
      spacing: Style.spacing.panelGap

      Text {
        width: parent.width
        text: root.needsPackage ? "Moat is not installed" : "You are not in the moat group"
        color: root.foreground
        font.family: Style.font.family
        font.pixelSize: Style.font.heading
        font.bold: true
        wrapMode: Text.WordWrap
      }

      Text {
        width: parent.width
        text: root.needsPackage
          ? "The omarchy-moat package provides Tetragon, the policies, and the moatd daemon. Until it is installed and its services are running there is nothing to monitor."
          : "The control socket (/run/moat/control.sock) and the alert log (/var/lib/moat/alerts.jsonl) are both group-readable by `moat` only. Without that membership this panel cannot read alerts or act on them."
        color: root.mutedForeground
        font.family: Style.font.family
        font.pixelSize: Style.font.body
        wrapMode: Text.WordWrap
      }

      PanelSeparator { width: parent.width; foreground: root.foreground }

      Repeater {
        model: root.steps

        delegate: Column {
          required property var modelData
          required property int index
          width: column.width
          spacing: Style.spacing.xs

          Text {
            text: (index + 1) + ". " + modelData.label
            color: root.foreground
            font.family: Style.font.family
            font.pixelSize: Style.font.subtitle
            font.bold: true
          }

          Rectangle {
            width: parent.width
            height: commandText.implicitHeight + Style.spacing.xl
            color: root.codeBackground
            radius: Style.cornerRadius

            Text {
              id: commandText
              x: Style.spacing.rowPaddingX
              y: Style.spacing.md
              width: parent.width - Style.spacing.rowPaddingX * 2
              text: modelData.command
              color: root.foreground
              font.family: Style.font.family
              font.pixelSize: Style.font.bodySmall
              wrapMode: Text.WrapAnywhere
              textFormat: Text.PlainText
            }
          }
        }
      }

      PanelSeparator { width: parent.width; foreground: root.foreground }

      Row {
        spacing: Style.spacing.controlGap

        Button {
          text: "Re-check"
          bordered: true
          foreground: root.foreground
          onClicked: root.recheckRequested()
        }
      }

      Text {
        width: parent.width
        visible: root.needsGroup
        text: "Group membership only takes effect in a new session, so the re-check keeps failing until you log out and back in."
        color: root.mutedForeground
        font.family: Style.font.family
        font.pixelSize: Style.font.caption
        wrapMode: Text.WordWrap
      }
    }
  }
}
