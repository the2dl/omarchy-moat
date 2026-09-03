import QtQuick
import qs.Commons
import qs.Ui

// Moat's bar slot: a shield glyph whose color is the whole security posture
// at a glance, plus a count badge for the alerts that need a decision.
//
// The clickable thing MUST be a WidgetButton. The bar overlays its own
// MouseArea per slot and forwards presses only to items registered as click
// targets — which WidgetButton does in its Component.onCompleted — so a bare
// Item with a MouseArea or TapHandler never sees the press at all.
BarWidget {
  id: root
  moduleName: "io.github.the2dl.moat"

  readonly property var service: root.bar && root.bar.shell
    && typeof root.bar.shell.serviceFor === "function"
    ? root.bar.shell.serviceFor(root.moduleName) : null

  readonly property string shieldState: service ? service.widgetState : "grey"
  readonly property int badge: service ? service.badgeCount : 0
  readonly property bool showBadge: setting("showCountBadge", true) === true && badge > 0

  // CONTRACT 7 colors. Red tracks the theme's urgent so it matches every other
  // alarm in the bar; green and amber are fixed semantic colors because the
  // theme has no token for "healthy" or "warning".
  property color greyColor: Qt.darker(root.bar ? root.bar.barForeground : Color.foreground, 1.9)
  property color greenColor: "#7fb069"
  property color amberColor: "#d9a13b"
  property color redColor: root.bar ? root.bar.urgent : Color.urgent

  readonly property color stateColor: root.shieldState === "red" ? redColor
    : root.shieldState === "amber" ? amberColor
    : root.shieldState === "green" ? greenColor
    : greyColor

  readonly property string tooltip: {
    if (!service) return "Moat"
    if (!service.available) return "Moat: not installed — click for setup steps"
    if (!service.groupOk) return "Moat: not in the moat group — click for setup steps"
    return service.statusSummary
  }

  implicitWidth: button.implicitWidth
  implicitHeight: button.implicitHeight

  // The bar owns the settings the manifest declares (they live on this widget's
  // shell.json layout entry), and the service owns the behavior they change.
  // Push them across on every change rather than have the service read config.
  function _syncSettings() {
    if (!service) return
    service.minNotifySeverity = setting("minNotifySeverity", "high")
    service.pollSeconds = Number(setting("pollSeconds", 10))
    service.showCountBadge = setting("showCountBadge", true) === true
  }

  onSettingsChanged: _syncSettings()
  onServiceChanged: _syncSettings()
  Component.onCompleted: _syncSettings()

  function togglePanel() {
    if (root.bar && root.bar.shell && typeof root.bar.shell.toggle === "function")
      root.bar.shell.toggle(root.moduleName, "{}")
  }

  WidgetButton {
    id: button
    anchors.fill: parent
    bar: root.bar

    // The label is our own composed content, not WidgetButton's centered Text.
    labelVisible: false
    hasVisualContent: true
    fontSize: Style.bar.iconFont
    fixedWidth: root.vertical ? -1 : Style.bar.iconSlot + (root.showBadge ? Style.space(9) : 0)
    fixedHeight: root.vertical ? Style.bar.iconSlot + (root.showBadge ? Style.space(6) : 0) : -1
    tooltipText: root.tooltip
    active: root.shieldState === "red"
    useActiveColor: false

    onPressed: function(mouseButton) {
      if (mouseButton === Qt.LeftButton) root.togglePanel()
      else if (mouseButton === Qt.RightButton && root.service) root.service.refresh()
    }

    // Scroll is a no-op on purpose: every setting behind this glyph changes
    // enforcement or notification behavior, and none of them should be
    // reachable by a stray touchpad flick.

    Item {
      id: content
      anchors.centerIn: parent
      width: shield.implicitWidth + (root.showBadge ? badgePill.width + Style.space(2) : 0)
      height: parent.height

      Text {
        id: shield
        anchors.verticalCenter: parent.verticalCenter
        anchors.left: parent.left
        text: root.service ? root.service.widgetGlyph(root.shieldState) : "󰦝"
        color: root.stateColor
        font.family: root.bar ? root.bar.fontFamily : Style.font.family
        font.pixelSize: Style.bar.iconFont
        renderType: Text.NativeRendering

        Behavior on color {
          enabled: !root.bar || root.bar.foregroundAnimationEnabled
          ColorAnimation { duration: 160 }
        }
      }

      // Count of unacked high + critical: the alerts CONTRACT 7 says the shield
      // must carry a number for. Medium and low are amber-without-a-number so
      // the badge always means "this many decisions are waiting".
      Rectangle {
        id: badgePill
        visible: root.showBadge
        anchors.verticalCenter: parent.verticalCenter
        anchors.left: shield.right
        anchors.leftMargin: Style.space(2)
        width: Math.max(height, badgeLabel.implicitWidth + Style.space(4))
        height: Math.round(Style.font.caption * 1.45)
        radius: Style.cornerRadius > 0 ? height / 2 : 0
        color: root.stateColor

        Text {
          id: badgeLabel
          anchors.centerIn: parent
          text: root.badge > 99 ? "99+" : String(root.badge)
          color: Color.background
          font.family: root.bar ? root.bar.fontFamily : Style.font.family
          font.pixelSize: Style.font.caption
          font.bold: true
          renderType: Text.NativeRendering
        }
      }
    }
  }
}
