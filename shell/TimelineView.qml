import QtQuick
import qs.Commons
import qs.Ui

// The Timeline tab: everything BASELINE 5 says is worth recording but not worth
// interrupting anyone for — medium, low, the alerts of a rule the noise guard
// demoted, and (only when "show suppressed" is on) the ones a learned or user
// allowlist entry already covers — interleaved with LEARNING 3's install
// receipts.
//
// Alerts are grouped by (rule, actor exe) because that is the difference
// between a timeline and a firehose: BASELINE 5's own words are "a thousand
// identical events read as one row with a count". A row expands into the
// individual alerts, and selecting one shows the same detail pane the Alerts
// tab uses — a demoted alert is not a lesser alert, it is the same record filed
// quietly.
//
// A receipt row is the other half of the same idea and the reason the two kinds
// share one list: after `npm install`, "41 s, 3 postinstall scripts, 3 hosts,
// no credential reads" is the answer the developer wanted, and filing it in a
// separate panel from the one alert that install did raise would break the
// chronology that makes either of them legible. Receipts never notify and never
// count toward the badge; they are not folded into `alerts` at all.
Item {
  id: root

  property var service: null
  property color foreground: Color.popups.text
  property string selectedId: ""

  signal alertSelected(string id)

  readonly property color mutedForeground: Qt.darker(foreground, 1.5)
  readonly property var rows: service ? service.timelineRows : []

  // Expansion state, keyed by the row key rather than by index: the list
  // re-sorts whenever an alert or a receipt arrives, and an index-keyed map
  // would silently expand a different row.
  property var expanded: ({})

  function isExpanded(key) { return root.expanded[key] === true }

  function toggle(key) {
    var next = ({})
    for (var k in root.expanded) next[k] = root.expanded[k]
    next[key] = !next[key]
    root.expanded = next
  }

  // The alerts currently on screen, in screen order, so the panel's j/k can
  // walk them. Collapsed groups contribute nothing — moving the selection onto
  // a row nobody can see would be a cursor that vanishes. Receipts contribute
  // nothing either: there is no alert behind one, so there is nothing for the
  // detail pane to show and nothing to act on.
  readonly property var flatAlerts: {
    var out = []
    for (var i = 0; i < root.rows.length; i++) {
      var row = root.rows[i]
      if (row.kind !== "group") continue
      if (!root.isExpanded(row.group.key)) continue
      for (var j = 0; j < row.group.alerts.length; j++) out.push(row.group.alerts[j])
    }
    return out
  }

  function severityColor(severity) {
    switch (String(severity)) {
    case "critical":
    case "high":
      return Color.urgent
    case "medium":
      return "#d9a13b"
    default:
      return Util.alpha(root.foreground, 0.45)
    }
  }

  Text {
    anchors.centerIn: parent
    width: parent.width
    visible: root.rows.length === 0
    text: root.service && root.service.showSuppressed
      ? "Nothing in the timeline."
      : "Nothing in the timeline. Suppressed alerts are hidden — turn on \"show suppressed\" in Settings to include them."
    color: root.mutedForeground
    font.family: Style.font.family
    font.pixelSize: Style.font.bodySmall
    wrapMode: Text.WordWrap
    horizontalAlignment: Text.AlignHCenter
  }

  Flickable {
    anchors.fill: parent
    contentWidth: width
    contentHeight: column.implicitHeight
    clip: true
    visible: root.rows.length > 0
    boundsBehavior: Flickable.StopAtBounds

    Column {
      id: column
      width: parent.width
      spacing: Style.spacing.xs

      Repeater {
        model: root.rows

        delegate: Column {
          id: rowItem
          required property var modelData
          width: column.width
          spacing: Style.spacing.xxs

          readonly property var groupData: modelData.group
          readonly property var receiptData: modelData.receipt
          readonly property string rowKey: modelData.key

          // ------------------------------------------------- alert group row
          Column {
            id: groupBlock
            width: parent.width
            spacing: Style.spacing.xxs
            visible: rowItem.modelData.kind === "group"

            // A group every member of which is suppressed is only on screen
            // because the user asked for it; grey it back so it never competes
            // with something that was actually surfaced.
            opacity: rowItem.groupData && rowItem.groupData.suppressed ? 0.55 : 1

            BorderSurface {
              id: header
              width: parent.width
              implicitHeight: headerContent.implicitHeight + Style.spacing.xl
              radius: Style.cornerRadius
              color: headerMouse.containsMouse
                ? Style.hoverFillFor(root.foreground, Color.accent) : "transparent"
              borderSpec: Border.none()

              Rectangle {
                anchors.left: parent.left
                anchors.top: parent.top
                anchors.bottom: parent.bottom
                anchors.margins: Style.spacing.xxs
                width: Math.max(2, Style.space(3))
                radius: width / 2
                color: root.severityColor(rowItem.groupData ? rowItem.groupData.severity : "")
              }

              Column {
                id: headerContent
                anchors.left: parent.left
                anchors.right: parent.right
                anchors.verticalCenter: parent.verticalCenter
                anchors.leftMargin: Style.spacing.rowPaddingX
                anchors.rightMargin: Style.spacing.md
                spacing: Style.spacing.xxs

                Row {
                  width: parent.width
                  spacing: Style.spacing.sm

                  Text {
                    id: chevron
                    anchors.verticalCenter: parent.verticalCenter
                    text: root.isExpanded(rowItem.rowKey) ? "󰅀" : "󰅂"
                    color: root.mutedForeground
                    font.family: Style.font.family
                    font.pixelSize: Style.font.caption
                  }

                  Rectangle {
                    id: pill
                    anchors.verticalCenter: parent.verticalCenter
                    width: pillText.implicitWidth + Style.space(8)
                    height: Math.round(Style.font.caption * 1.55)
                    radius: Style.cornerRadius > 0 ? height / 2 : 0
                    color: root.severityColor(rowItem.groupData ? rowItem.groupData.severity : "")

                    Text {
                      id: pillText
                      anchors.centerIn: parent
                      text: rowItem.groupData
                        ? String(rowItem.groupData.severity).slice(0, 4).toUpperCase() : ""
                      color: Color.background
                      font.family: Style.font.family
                      font.pixelSize: Style.font.caption
                      font.bold: true
                    }
                  }

                  Text {
                    anchors.verticalCenter: parent.verticalCenter
                    width: parent.width - chevron.width - pill.width - countPill.width - parent.spacing * 3
                    text: rowItem.groupData ? rowItem.groupData.title : ""
                    color: root.foreground
                    font.family: Style.font.family
                    font.pixelSize: Style.font.bodySmall
                    elide: Text.ElideRight
                  }

                  // The count is the whole point of grouping, so it is a pill of
                  // its own rather than a suffix that elides away with the title.
                  Rectangle {
                    id: countPill
                    anchors.verticalCenter: parent.verticalCenter
                    width: countText.implicitWidth + Style.space(8)
                    height: Math.round(Style.font.caption * 1.55)
                    radius: Style.cornerRadius > 0 ? height / 2 : 0
                    color: Util.alpha(root.foreground, 0.12)

                    Text {
                      id: countText
                      anchors.centerIn: parent
                      text: "×" + (rowItem.groupData ? rowItem.groupData.count : 0)
                      color: root.foreground
                      font.family: Style.font.family
                      font.pixelSize: Style.font.caption
                      font.bold: true
                    }
                  }
                }

                Text {
                  width: parent.width
                  text: {
                    var group = rowItem.groupData
                    if (!group) return ""
                    var bits = []
                    if (group.exeName) bits.push(group.exeName)
                    if (root.service) {
                      var age = root.service.relativeTime(group.latestTs)
                      if (age) bits.push("latest " + age)
                    }
                    if (group.demoted) bits.push("demoted rule")
                    if (group.suppressed) bits.push("suppressed")
                    bits.push(group.rule)
                    return bits.join("  ·  ")
                  }
                  color: root.mutedForeground
                  font.family: Style.font.family
                  font.pixelSize: Style.font.caption
                  elide: Text.ElideRight
                }
              }

              MouseArea {
                id: headerMouse
                anchors.fill: parent
                hoverEnabled: true
                cursorShape: Qt.PointingHandCursor
                onClicked: {
                  root.toggle(rowItem.rowKey)
                  // Expanding a group selects its newest alert, so the detail
                  // pane is never blank next to an open row.
                  if (root.isExpanded(rowItem.rowKey) && rowItem.groupData
                      && rowItem.groupData.alerts.length > 0)
                    root.alertSelected(rowItem.groupData.alerts[0].id)
                }
              }
            }

            Repeater {
              model: root.isExpanded(rowItem.rowKey) && rowItem.groupData
                ? rowItem.groupData.alerts : []

              delegate: AlertRow {
                required property var modelData
                width: rowItem.width - Style.spacing.xl
                x: Style.spacing.xl
                alert: modelData
                service: root.service
                selected: modelData.id === root.selectedId
                foreground: root.foreground
                onClicked: root.alertSelected(modelData.id)
              }
            }
          }

          // ---------------------------------------------------- receipt row
          //
          // LEARNING 3's one-liner, expanding into the six-line block the
          // document prints verbatim. There is no severity accent and no
          // action: a receipt is a record of an install that finished, not
          // something asking for a decision.
          Column {
            id: receiptBlock
            width: parent.width
            spacing: Style.spacing.xxs
            visible: rowItem.modelData.kind === "receipt"

            readonly property var detail: rowItem.receiptData && root.service
              ? root.service.receiptBlock(rowItem.receiptData) : null

            BorderSurface {
              width: parent.width
              implicitHeight: receiptHeader.implicitHeight + Style.spacing.xl
              radius: Style.cornerRadius
              color: receiptMouse.containsMouse
                ? Style.hoverFillFor(root.foreground, Color.accent) : "transparent"
              borderSpec: Border.none()

              Rectangle {
                anchors.left: parent.left
                anchors.top: parent.top
                anchors.bottom: parent.bottom
                anchors.margins: Style.spacing.xxs
                width: Math.max(2, Style.space(3))
                radius: width / 2
                color: Util.alpha(root.foreground, 0.25)
              }

              Column {
                id: receiptHeader
                anchors.left: parent.left
                anchors.right: parent.right
                anchors.verticalCenter: parent.verticalCenter
                anchors.leftMargin: Style.spacing.rowPaddingX
                anchors.rightMargin: Style.spacing.md
                spacing: Style.spacing.xxs

                Row {
                  width: parent.width
                  spacing: Style.spacing.sm

                  Text {
                    id: receiptChevron
                    anchors.verticalCenter: parent.verticalCenter
                    text: root.isExpanded(rowItem.rowKey) ? "󰅀" : "󰅂"
                    color: root.mutedForeground
                    font.family: Style.font.family
                    font.pixelSize: Style.font.caption
                  }

                  Rectangle {
                    id: receiptPill
                    anchors.verticalCenter: parent.verticalCenter
                    width: receiptPillText.implicitWidth + Style.space(8)
                    height: Math.round(Style.font.caption * 1.55)
                    radius: Style.cornerRadius > 0 ? height / 2 : 0
                    color: Util.alpha(root.foreground, 0.12)

                    Text {
                      id: receiptPillText
                      anchors.centerIn: parent
                      text: "INSTALL"
                      color: root.foreground
                      font.family: Style.font.family
                      font.pixelSize: Style.font.caption
                      font.bold: true
                    }
                  }

                  Text {
                    anchors.verticalCenter: parent.verticalCenter
                    width: parent.width - receiptChevron.width - receiptPill.width - parent.spacing * 2
                    text: rowItem.receiptData && root.service
                      ? root.service.receiptSummary(rowItem.receiptData) : ""
                    color: root.foreground
                    font.family: Style.font.family
                    font.pixelSize: Style.font.bodySmall
                    elide: Text.ElideRight
                  }
                }

                Text {
                  width: parent.width
                  text: {
                    if (!rowItem.receiptData) return ""
                    var bits = []
                    if (root.service) {
                      var age = root.service.relativeTime(rowItem.receiptData.ts)
                      if (age) bits.push(age)
                    }
                    bits.push("install receipt")
                    return bits.join("  ·  ")
                  }
                  color: root.mutedForeground
                  font.family: Style.font.family
                  font.pixelSize: Style.font.caption
                  elide: Text.ElideRight
                }
              }

              MouseArea {
                id: receiptMouse
                anchors.fill: parent
                hoverEnabled: true
                cursorShape: Qt.PointingHandCursor
                onClicked: root.toggle(rowItem.rowKey)
              }
            }

            Rectangle {
              width: parent.width - Style.spacing.xl
              x: Style.spacing.xl
              visible: root.isExpanded(rowItem.rowKey)
              height: visible ? receiptLines.implicitHeight + Style.spacing.xl : 0
              color: Util.alpha(root.foreground, 0.06)
              radius: Style.cornerRadius

              Column {
                id: receiptLines
                x: Style.spacing.rowPaddingX
                y: Style.spacing.md
                width: parent.width - Style.spacing.rowPaddingX * 2
                spacing: Style.spacing.xxs

                Text {
                  width: parent.width
                  text: receiptBlock.detail ? receiptBlock.detail.headline : ""
                  color: root.foreground
                  font.family: Style.font.family
                  font.pixelSize: Style.font.bodySmall
                  font.bold: true
                  wrapMode: Text.WrapAnywhere
                }

                Repeater {
                  model: receiptBlock.detail ? receiptBlock.detail.lines : []

                  delegate: Text {
                    required property string modelData
                    width: receiptLines.width
                    text: modelData
                    color: root.foreground
                    font.family: Style.font.family
                    font.pixelSize: Style.font.bodySmall
                    wrapMode: Text.WrapAnywhere
                  }
                }
              }
            }
          }
        }
      }
    }
  }
}
