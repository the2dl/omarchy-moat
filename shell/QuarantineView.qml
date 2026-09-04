import QtQuick
import qs.Commons
import qs.Ui

// The Quarantine tab: what moat is holding.
//
// Quarantine moves a file aside and chmods it 000. It never deletes, and this
// tab is the reason that matters — after something is caught, the question a
// user actually has is "what got me", and a store you cannot look into does not
// answer it. So every held file is listed with where it came from, which rule
// took it, when, and its size, plus the path it is being held at so it can be
// inspected with any tool.
//
// Restore puts it back byte for byte. The daemon refuses if the original path
// is occupied again or if the held bytes no longer hash to what was recorded
// when it was taken, so this button cannot silently overwrite anything or hand
// back a file that changed while it was held.
Item {
  id: root

  property var service: null
  property color foreground: Color.popups.text

  readonly property color mutedForeground: Qt.darker(foreground, 1.5)
  readonly property color codeBackground: Util.alpha(foreground, 0.06)
  readonly property var items: service ? service.quarantineItems : []

  signal restoreRequested(string id)

  function humanBytes(n) {
    if (n < 0) return "missing"
    if (n < 1024) return n + " B"
    if (n < 1024 * 1024) return (n / 1024).toFixed(1) + " KiB"
    return (n / (1024 * 1024)).toFixed(1) + " MiB"
  }

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
          width: parent.width - refreshButton.width - parent.spacing
          text: root.items.length === 0
                ? "Nothing is being held."
                : root.items.length + " file" + (root.items.length === 1 ? "" : "s")
                  + " held. Moved aside and made unreadable — never deleted."
          color: root.mutedForeground
          font.family: Style.font.family
          font.pixelSize: Style.font.caption
          wrapMode: Text.WordWrap
        }

        Button {
          id: refreshButton
          text: "Refresh"
          foreground: root.mutedForeground
          fontSize: Style.font.caption
          onClicked: if (root.service) root.service.loadQuarantine()
        }
      }

      PanelSectionHeader {
        visible: root.items.length > 0
        text: "HELD · " + root.items.length
        foreground: root.foreground
      }

      Repeater {
        model: root.items

        Column {
          width: column.width
          spacing: Style.spacing.xs

          Text {
            width: parent.width
            text: modelData.originalPath
            color: root.foreground
            font.family: Style.font.family
            font.pixelSize: Style.font.body
            elide: Text.ElideMiddle
          }

          Text {
            width: parent.width
            text: modelData.rule + " · " + root.humanBytes(modelData.bytes)
                  + " · taken " + modelData.when
            color: root.mutedForeground
            font.family: Style.font.family
            font.pixelSize: Style.font.caption
            wrapMode: Text.WordWrap
          }

          // Where it is now, so it can be examined with any tool the user
          // trusts rather than only through this panel.
          Rectangle {
            width: parent.width
            height: heldPath.implicitHeight + Style.spacing.sm * 2
            color: root.codeBackground
            radius: Style.radius.sm

            Text {
              id: heldPath
              anchors.fill: parent
              anchors.margins: Style.spacing.sm
              text: modelData.heldAt
              color: root.mutedForeground
              font.family: Style.font.mono
              font.pixelSize: Style.font.caption
              wrapMode: Text.WrapAnywhere
            }
          }

          // A held file that is no longer on disk means something removed it
          // out from under moat. Worth saying loudly rather than hiding.
          Text {
            width: parent.width
            visible: !modelData.present
            text: "The held file is gone from disk. Something removed it after moat took it."
            color: Color.urgent
            font.family: Style.font.family
            font.pixelSize: Style.font.caption
            wrapMode: Text.WordWrap
          }

          Row {
            spacing: Style.spacing.sm

            Button {
              text: "Restore"
              enabled: modelData.present
              foreground: root.mutedForeground
              fontSize: Style.font.caption
              onClicked: root.restoreRequested(modelData.id)
            }
          }
        }
      }
    }
  }
}
