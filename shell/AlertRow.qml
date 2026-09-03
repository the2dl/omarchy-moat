import QtQuick
import qs.Commons
import qs.Ui

// One row in the alert list: severity pill, title, exe basename, relative time,
// ack state. Everything the list needs to be triaged without opening anything.
BorderSurface {
  id: root

  property var service: null
  property var alert: null
  property bool selected: false
  property color foreground: Color.popups.text

  signal clicked()

  readonly property color mutedForeground: Qt.darker(foreground, 1.5)
  readonly property string severity: alert ? String(alert.severity) : "low"
  readonly property color severityColor: {
    switch (root.severity) {
    case "critical":
    case "high":
      return Color.urgent
    case "medium":
      return "#d9a13b"
    default:
      return Util.alpha(root.foreground, 0.45)
    }
  }

  implicitHeight: content.implicitHeight + Style.spacing.xl
  radius: Style.cornerRadius
  color: root.selected ? Style.selectedFillFor(foreground, Color.accent)
    : (mouse.containsMouse ? Style.hoverFillFor(foreground, Color.accent) : "transparent")
  borderSpec: root.selected
    ? Border.controlSpec("selected", foreground, Color.accent)
    : Border.none()

  Behavior on color { ColorAnimation { duration: 100 } }

  // An unacked alert carries a severity-colored spine down its left edge, so a
  // list scanned at a glance shows what still needs a decision without the row
  // having to spell it out.
  Rectangle {
    anchors.left: parent.left
    anchors.top: parent.top
    anchors.bottom: parent.bottom
    anchors.margins: Style.spacing.xxs
    width: Math.max(2, Style.space(3))
    radius: width / 2
    visible: !!root.alert && !root.alert.acked
    color: root.severityColor
  }

  Column {
    id: content
    anchors.left: parent.left
    anchors.right: parent.right
    anchors.verticalCenter: parent.verticalCenter
    anchors.leftMargin: Style.spacing.rowPaddingX
    anchors.rightMargin: Style.spacing.md
    spacing: Style.spacing.xxs

    Row {
      width: parent.width
      spacing: Style.spacing.sm

      Rectangle {
        id: pill
        anchors.verticalCenter: parent.verticalCenter
        width: pillText.implicitWidth + Style.space(8)
        height: Math.round(Style.font.caption * 1.55)
        radius: Style.cornerRadius > 0 ? height / 2 : 0
        color: root.severityColor

        Text {
          id: pillText
          anchors.centerIn: parent
          text: root.severity.slice(0, 4).toUpperCase()
          color: Color.background
          font.family: Style.font.family
          font.pixelSize: Style.font.caption
          font.bold: true
        }
      }

      Text {
        anchors.verticalCenter: parent.verticalCenter
        width: parent.width - pill.width - parent.spacing
        text: root.alert ? root.alert.title : ""
        color: root.foreground
        font.family: Style.font.family
        font.pixelSize: Style.font.bodySmall
        font.bold: !!root.alert && !root.alert.acked
        elide: Text.ElideRight
        maximumLineCount: 2
        wrapMode: Text.WordWrap
      }
    }

    Text {
      width: parent.width
      text: {
        if (!root.alert) return ""
        var bits = []
        var exe = root.service ? root.service.basename(root.alert.process.exe) : ""
        if (exe) bits.push(exe)
        if (root.service) {
          var age = root.service.relativeTime(root.alert.ts)
          if (age) bits.push(age)
        }
        if (root.alert.count > 1) bits.push("×" + root.alert.count)
        if (root.alert.action_taken !== "none") bits.push(root.alert.action_taken)
        bits.push(root.alert.acked ? "acked" : "unacked")
        return bits.join("  ·  ")
      }
      color: root.mutedForeground
      font.family: Style.font.family
      font.pixelSize: Style.font.caption
      elide: Text.ElideRight
    }
  }

  MouseArea {
    id: mouse
    anchors.fill: parent
    hoverEnabled: true
    cursorShape: Qt.PointingHandCursor
    onClicked: root.clicked()
  }
}
