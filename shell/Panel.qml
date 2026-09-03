import QtQuick
import Quickshell
import Quickshell.Io
import Quickshell.Wayland
import qs.Commons
import qs.Ui

// Sentinel's panel. Declared as kind "panel" with keepLoaded, so the shell
// mounts it once at startup and drives it through the standard verbs:
//
//   omarchy-shell shell toggle io.github.the2dl.sentinel '{}'
//   omarchy-shell shell summon io.github.the2dl.sentinel '{"alert":"<id>"}'
//
// The shell's panel loader injects `shell`, `manifest` and `service` (the
// matching service singleton) and calls open(payloadJson) / close(); `opened`
// is what it reads back to decide whether a toggle should summon or hide. The
// bar widget click and the notification click both arrive through those verbs,
// which is why nothing here reaches for the bar widget instance.
Item {
  id: root

  // Injected by shell.qml's panel loader.
  property var shell: null
  property var manifest: null
  property var service: null

  property bool opened: false
  property string selectedId: ""
  property string tab: "alerts"          // "alerts" | "allowlist"
  property string notice: ""             // transient result line under the header

  readonly property string pluginId: "io.github.the2dl.sentinel"
  readonly property var alerts: service ? service.alerts : []
  readonly property bool ready: !!service && service.available && service.groupOk
  readonly property var selected: {
    if (!service || !root.selectedId) return null
    return service.alertById(root.selectedId)
  }

  // ---------------------------------------------------------------- lifecycle

  // The shell hands open() the raw payload string. `{"alert":"<id>"}` selects
  // an alert — this is how a notification click lands on the right one.
  // `{"tab":"allowlist"}` opens straight to the allowlist.
  function open(payloadJson) {
    var payload = {}
    try { payload = JSON.parse(String(payloadJson || "") || "{}") } catch (e) { payload = {} }
    if (payload && payload.alert) {
      root.tab = "alerts"
      root.selectAlert(String(payload.alert))
    }
    if (payload && payload.tab === "allowlist") root.tab = "allowlist"
    root.notice = ""
    root.opened = true
    if (service) service.refresh()
  }

  function close() {
    confirm.opened = false
    root._pendingCommand = ""
    root.opened = false
  }

  function toggle() { root.opened ? root.close() : root.open("{}") }

  function selectAlert(id) {
    root.selectedId = String(id || "")
    // Repair path for an alert whose line predates the explain block.
    if (service && root.selectedId) service.loadExplain(root.selectedId)
  }

  onOpenedChanged: {
    if (!opened) return
    if (!root.selectedId && root.alerts.length > 0) root.selectAlert(root.alerts[0].id)
  }

  Connections {
    target: root.service
    enabled: !!root.service

    function onActionFinished(command, ok, message) {
      if (!ok) {
        root.notice = "Failed: " + command + (message ? " — " + message : "")
      } else if (command === "ignore") {
        var block = root.service.lastIgnoreBlock
        root.notice = block
          ? "Allowlist rule written:\n" + block
          : "Allowlist rule written to " + root.service.allowlistFile
      } else if (command === "unignore") {
        root.notice = "Allowlist rule removed."
      } else {
        root.notice = command.charAt(0).toUpperCase() + command.slice(1) + " done."
      }
      noticeTimer.restart()
    }
  }

  Timer {
    id: noticeTimer
    interval: 12000
    onTriggered: root.notice = ""
  }

  // ------------------------------------------------------------- act + confirm
  //
  // Kill and Quarantine are irreversible from the panel's side — one ends a
  // process tree, the other chmod 000s a file into
  // /var/lib/sentinel/quarantine — so both go through a confirm, and so does
  // removing an allowlist rule (it silently re-arms a detection). Ack and the
  // allowlist writes do not: ack is a label, and an added rule is listed with a
  // Remove button one tab away.
  property string _pendingCommand: ""
  property string _pendingArg: ""

  function requestKill(id) {
    root._confirm("kill", id, "Kill the process tree recorded in this alert?")
  }

  function requestQuarantine(id) {
    root._confirm("quarantine", id,
      "Move this file into quarantine (chmod 000, under /var/lib/sentinel/quarantine)? Anything still using it will break.")
  }

  function requestUnignore(index) {
    root._confirm("unignore", String(index),
      "Remove allowlist rule #" + index + "? Its detection starts firing again.")
  }

  function requestAck(id) { if (service) service.ack(id) }
  function requestIgnore(id, scope) { if (service) service.ignore(id, scope) }

  function _confirm(command, arg, message) {
    root._pendingCommand = command
    root._pendingArg = String(arg)
    confirm.message = message
    confirm.confirmText = command.charAt(0).toUpperCase() + command.slice(1)
    confirm.selectedIndex = 0     // a destructive prompt defaults to Cancel
    confirm.opened = true
  }

  function _runPending() {
    var command = root._pendingCommand
    var arg = root._pendingArg
    confirm.opened = false
    root._pendingCommand = ""
    if (!service) return
    if (command === "kill") service.kill(arg)
    else if (command === "quarantine") service.quarantine(arg)
    else if (command === "unignore") service.unignore(Number(arg))
  }

  // ------------------------------------------------------------- keyboard nav
  //
  // PanelKeyCatcher already owns the raw Keys handler, so the panel wires its
  // semantic signals rather than declaring a second Keys.onPressed (which would
  // shadow the component's own and kill every binding it provides). While the
  // confirm is up, the same signals drive the dialog instead of the list.

  function moveSelection(delta) {
    if (confirm.opened) {
      confirm.selectedIndex = confirm.selectedIndex === 0 ? 1 : 0
      return
    }
    if (root.tab !== "alerts" || root.alerts.length === 0) return
    var index = 0
    for (var i = 0; i < root.alerts.length; i++) {
      if (root.alerts[i].id === root.selectedId) { index = i; break }
    }
    index = Math.max(0, Math.min(root.alerts.length - 1, index + delta))
    root.selectAlert(root.alerts[index].id)
  }

  function activate() {
    if (!confirm.opened) return
    if (confirm.selectedIndex === 0) {
      confirm.opened = false
      root._pendingCommand = ""
    } else {
      root._runPending()
    }
  }

  function dismiss() {
    if (confirm.opened) {
      confirm.opened = false
      root._pendingCommand = ""
      return
    }
    root.close()
  }

  function handleTextKey(text) {
    if (confirm.opened) return
    switch (text) {
    case "a": if (root.selected) root.requestAck(root.selected.id); break
    case "r": if (service) service.refresh(); break
    case "t": root.tab = root.tab === "alerts" ? "allowlist" : "alerts"; break
    }
  }

  // Persisting min-notify-severity means writing the bar widget's shell.json
  // entry, because that is where the manifest's barWidget.defaults live. When
  // the widget is not on the bar there is no entry to write, so the change
  // applies for this session and the notice says so rather than lying.
  function setMinNotifySeverity(value) {
    if (!service) return
    service.minNotifySeverity = value
    var error = service.persistSetting("minNotifySeverity", value)
    root.notice = error
      ? "Notify threshold set to " + value + " for this session (not saved: " + error + ")"
      : "Notify threshold saved: " + value
    noticeTimer.restart()
  }

  // ------------------------------------------------------------------ geometry

  readonly property var barItem: shell && shell.bar ? shell.bar : null
  readonly property string barPosition: barItem && barItem.position ? String(barItem.position) : "top"
  readonly property int barClearance: barItem && barItem.barSize ? Number(barItem.barSize) : Style.bar.sizeHorizontal
  readonly property int gap: Style.gapsOut

  IpcHandler {
    target: "sentinel"

    function open(payloadJson: string): string { root.open(payloadJson); return "ok" }
    function close(): string { root.close(); return "ok" }
    function toggle(): string { root.toggle(); return "ok" }
    function state(): string { return root.opened ? "open" : "closed" }
    function refresh(): string { if (root.service) root.service.refresh(); return "ok" }
    function ping(): string { return "ok" }
  }

  PanelWindow {
    id: window

    // Mapped only while the panel is logically open. Nothing animates on close,
    // so there is no fade to keep the surface alive for.
    visible: root.opened
    color: "transparent"
    exclusionMode: ExclusionMode.Ignore

    WlrLayershell.namespace: "omarchy-sentinel-panel"
    WlrLayershell.layer: WlrLayer.Overlay
    // Exclusive on map, then OnDemand. Hyprland focuses an OnDemand surface
    // when it first maps but not when a mapped one changes back to it, and the
    // panel can be summoned with no pointer involved at all (a notification
    // click). Without the brief Exclusive prime, Escape would not reach us.
    // Settling on OnDemand releases compositor-wide pointer capture so clicks
    // still land on other outputs.
    WlrLayershell.keyboardFocus: root.opened
      ? (focusPrimed ? WlrKeyboardFocus.OnDemand : WlrKeyboardFocus.Exclusive)
      : WlrKeyboardFocus.None

    property bool focusPrimed: false

    // Full-screen surface with the card placed inside, so a click anywhere
    // outside the card dismisses.
    anchors { top: true; bottom: true; left: true; right: true }

    readonly property real screenW: screen ? screen.width : 0
    readonly property real screenH: screen ? screen.height : 0
    readonly property int cardWidth: Math.round(Math.min(Style.space(900),
      Math.max(Style.space(420), screenW - root.gap * 2)))
    readonly property int cardHeight: Math.round(Math.min(Style.space(640),
      Math.max(Style.space(320), screenH - root.barClearance - root.gap * 3)))

    // Under the bar, on the side the widget defaults to (right). Clamped so a
    // small screen or a vertical bar still lands the card fully on screen.
    readonly property point cardOrigin: {
      var x = 0, y = 0
      var vertical = root.barPosition === "left" || root.barPosition === "right"
      if (vertical) {
        x = root.barPosition === "left"
          ? root.barClearance + root.gap
          : screenW - root.barClearance - cardWidth - root.gap
        y = root.gap
      } else {
        x = screenW - cardWidth - root.gap
        y = root.barPosition === "bottom"
          ? screenH - root.barClearance - cardHeight - root.gap
          : root.barClearance + root.gap
      }
      x = Math.max(root.gap, Math.min(x, screenW - cardWidth - root.gap))
      y = Math.max(root.gap, Math.min(y, screenH - cardHeight - root.gap))
      return Qt.point(Math.round(x), Math.round(y))
    }

    onVisibleChanged: {
      focusPrimed = false
      if (visible) focusPrimeTimer.restart()
      else focusPrimeTimer.stop()
    }

    Timer {
      id: focusPrimeTimer
      interval: 75
      onTriggered: if (window.visible) window.focusPrimed = true
    }

    // Click-outside dismissal.
    MouseArea {
      anchors.fill: parent
      acceptedButtons: Qt.AllButtons
      onClicked: root.close()
    }

    BorderSurface {
      id: card
      x: window.cardOrigin.x
      y: window.cardOrigin.y
      width: window.cardWidth
      height: window.cardHeight
      color: Color.popups.background
      borderSpec: Border.surfaceSpec("popups", "border", Color.popups.border, Math.max(1, Style.space(2)))
      padding: Style.spacing.popupPadding
      radius: Style.cornerRadius

      readonly property color fg: Color.popups.text
      readonly property color mutedFg: Qt.darker(Color.popups.text, 1.4)

      // Swallow clicks so they do not reach the dismissal area behind.
      MouseArea {
        anchors.fill: parent
        acceptedButtons: Qt.AllButtons
      }

      PanelKeyCatcher {
        id: keys
        anchors.fill: parent
        anchors.topMargin: card.contentTopInset
        anchors.rightMargin: card.contentRightInset
        anchors.bottomMargin: card.contentBottomInset
        anchors.leftMargin: card.contentLeftInset

        onCloseRequested: root.dismiss()
        onMoveRequested: function(dx, dy) { if (dy !== 0) root.moveSelection(dy) }
        onActivateRequested: root.activate()
        onTextKey: function(text) { root.handleTextKey(text) }

        // Header, body and footer are anchored rather than stacked in a Column
        // so the body takes exactly the leftover height. A Column would need
        // the body to subtract every sibling's height by hand, which silently
        // goes wrong the moment a row wraps.

        // ------------------------------------------------------------ header
        Column {
          id: headerBlock
          anchors.top: parent.top
          anchors.left: parent.left
          anchors.right: parent.right
          spacing: Style.spacing.md

          Item {
            width: parent.width
            height: Math.max(titleRow.implicitHeight, tabRow.implicitHeight)

            Row {
              id: titleRow
              anchors.left: parent.left
              anchors.verticalCenter: parent.verticalCenter
              spacing: Style.spacing.md

              Text {
                anchors.verticalCenter: parent.verticalCenter
                text: root.service ? root.service.widgetGlyph(root.service.widgetState) : "󰦝"
                color: card.fg
                font.family: Style.font.family
                font.pixelSize: Style.font.iconLarge
              }

              Text {
                anchors.verticalCenter: parent.verticalCenter
                text: "Sentinel"
                color: card.fg
                font.family: Style.font.family
                font.pixelSize: Style.font.title
                font.bold: true
              }
            }

            Row {
              id: tabRow
              anchors.right: parent.right
              anchors.verticalCenter: parent.verticalCenter
              spacing: Style.spacing.sm

              Button {
                anchors.verticalCenter: parent.verticalCenter
                text: "Alerts"
                selected: root.tab === "alerts"
                foreground: card.fg
                fontSize: Style.font.bodySmall
                onClicked: root.tab = "alerts"
              }

              Button {
                anchors.verticalCenter: parent.verticalCenter
                text: "Allowlist"
                selected: root.tab === "allowlist"
                foreground: card.fg
                fontSize: Style.font.bodySmall
                onClicked: {
                  root.tab = "allowlist"
                  if (root.service) root.service.loadAllowlist()
                }
              }

              PanelActionButton {
                anchors.verticalCenter: parent.verticalCenter
                iconText: "󰑐"
                tooltipText: "Refresh (r)"
                foreground: card.fg
                onClicked: if (root.service) root.service.refresh()
              }

              PanelActionButton {
                anchors.verticalCenter: parent.verticalCenter
                iconText: "󰅖"
                tooltipText: "Close (Esc)"
                foreground: card.fg
                onClicked: root.close()
              }
            }
          }

          // -------------------------------------------------- status strip
          Flow {
            width: parent.width
            spacing: Style.spacing.xl

            Repeater {
              model: {
                if (!root.service) return []
                var s = root.service.status
                return [
                  { label: "mode", value: s.mode, warn: s.mode === "enforce" },
                  { label: "tetragon", value: s.tetragon, warn: s.tetragon !== "running" },
                  { label: "policies", value: String(s.policies)
                      + (s.policies_failed.length ? " (" + s.policies_failed.length + " failed)" : ""),
                    warn: s.policies_failed.length > 0 || s.policies === 0 },
                  { label: "feeds", value: root.service.feedsAge() || "never", warn: !s.feeds.updated },
                  { label: "sandbox", value: s.sandbox ? "on" : "off", warn: false },
                  { label: "unacked", value: String(root.service.unacked.total),
                    warn: root.service.unacked.total > 0 }
                ]
              }

              delegate: Text {
                required property var modelData
                text: modelData.label + " " + modelData.value
                color: modelData.warn ? Color.urgent : card.mutedFg
                font.family: Style.font.family
                font.pixelSize: Style.font.caption
              }
            }
          }

          Text {
            width: parent.width
            visible: text !== ""
            text: root.notice
            color: root.notice.indexOf("Failed") === 0 ? Color.urgent : card.mutedFg
            font.family: Style.font.family
            font.pixelSize: Style.font.caption
            wrapMode: Text.WrapAnywhere
            maximumLineCount: 5
            elide: Text.ElideRight
          }

          PanelSeparator { width: parent.width; foreground: card.fg }
        }

        // ------------------------------------------------------------ footer
        Column {
          id: footerBlock
          anchors.bottom: parent.bottom
          anchors.left: parent.left
          anchors.right: parent.right
          spacing: Style.spacing.md

          PanelSeparator { width: parent.width; foreground: card.fg }

          Flow {
            width: parent.width
            spacing: Style.spacing.xl

            Row {
              spacing: Style.spacing.controlGap

              Text {
                anchors.verticalCenter: parent.verticalCenter
                text: "Mode"
                color: card.mutedFg
                font.family: Style.font.family
                font.pixelSize: Style.font.caption
                font.bold: true
              }

              Button {
                text: "Monitor"
                selected: !!root.service && root.service.status.mode === "monitor"
                bordered: true
                foreground: card.fg
                fontSize: Style.font.bodySmall
                onClicked: if (root.service) root.service.setMode("monitor")
              }

              Button {
                text: "Enforce"
                selected: !!root.service && root.service.status.mode === "enforce"
                bordered: true
                foreground: Color.urgent
                accent: Color.urgent
                fontSize: Style.font.bodySmall
                onClicked: if (root.service) root.service.setMode("enforce")
              }
            }

            Row {
              spacing: Style.spacing.controlGap

              Text {
                anchors.verticalCenter: parent.verticalCenter
                text: "Sandbox shims"
                color: card.mutedFg
                font.family: Style.font.family
                font.pixelSize: Style.font.caption
                font.bold: true
              }

              ToggleSwitch {
                anchors.verticalCenter: parent.verticalCenter
                checked: !!root.service && root.service.status.sandbox
                busy: !!root.service && root.service.busy
                foreground: card.fg
                trackHeight: Style.space(18)
                onToggled: if (root.service) root.service.setSandbox(!root.service.status.sandbox)
              }
            }

            Row {
              spacing: Style.spacing.sm

              Text {
                anchors.verticalCenter: parent.verticalCenter
                text: "Notify at"
                color: card.mutedFg
                font.family: Style.font.family
                font.pixelSize: Style.font.caption
                font.bold: true
              }

              Repeater {
                model: ["low", "medium", "high", "critical"]

                delegate: Button {
                  required property string modelData
                  anchors.verticalCenter: parent.verticalCenter
                  text: modelData
                  selected: !!root.service && root.service.minNotifySeverity === modelData
                  foreground: card.fg
                  fontSize: Style.font.caption
                  onClicked: root.setMinNotifySeverity(modelData)
                }
              }
            }
          }

          Text {
            width: parent.width
            visible: !!root.service && root.service.status.mode === "enforce"
            text: "Enforce mode lets Tetragon SIGKILL a matching process in the kernel, before this panel ever sees it. A false positive stops a real program mid-write. Stay in monitor until the allowlist is quiet."
            color: Color.urgent
            font.family: Style.font.family
            font.pixelSize: Style.font.caption
            wrapMode: Text.WordWrap
          }
        }

        // -------------------------------------------------------------- body
        Item {
          id: bodyArea
          anchors.top: headerBlock.bottom
          anchors.bottom: footerBlock.top
          anchors.left: parent.left
          anchors.right: parent.right
          anchors.topMargin: Style.spacing.md
          anchors.bottomMargin: Style.spacing.md

          // The setup screen wins over everything: an empty alert list with no
          // group membership would read as "all clear", which is the one thing
          // a security panel must never say while it is blind.
          SetupView {
            anchors.fill: parent
            visible: !!root.service && !root.ready
            service: root.service
            foreground: card.fg
            needsPackage: !!root.service && !root.service.available
            needsGroup: !!root.service && !root.service.groupOk
            onRecheckRequested: if (root.service) root.service.probe()
          }

          AllowlistView {
            anchors.fill: parent
            visible: root.ready && root.tab === "allowlist"
            service: root.service
            foreground: card.fg
            onRemoveRequested: function(index) { root.requestUnignore(index) }
          }

          Row {
            anchors.fill: parent
            visible: root.ready && root.tab === "alerts"
            spacing: Style.spacing.panelGap

            Item {
              id: listPane
              width: Math.round(Math.min(Style.space(300), parent.width * 0.4))
              height: parent.height

              Text {
                anchors.centerIn: parent
                width: parent.width
                visible: root.alerts.length === 0
                text: root.service && root.service.logReadable
                  ? "No alerts. Sentinel is watching."
                  : "The alert log is not readable."
                color: card.mutedFg
                font.family: Style.font.family
                font.pixelSize: Style.font.bodySmall
                wrapMode: Text.WordWrap
                horizontalAlignment: Text.AlignHCenter
              }

              ListView {
                id: alertList
                anchors.fill: parent
                visible: root.alerts.length > 0
                clip: true
                model: root.alerts
                spacing: Style.spacing.xxs
                boundsBehavior: Flickable.StopAtBounds
                currentIndex: {
                  for (var i = 0; i < root.alerts.length; i++)
                    if (root.alerts[i].id === root.selectedId) return i
                  return -1
                }
                onCurrentIndexChanged: if (currentIndex >= 0) positionViewAtIndex(currentIndex, ListView.Contain)

                delegate: AlertRow {
                  required property var modelData
                  width: alertList.width
                  alert: modelData
                  service: root.service
                  selected: modelData.id === root.selectedId
                  foreground: card.fg
                  onClicked: root.selectAlert(modelData.id)
                }
              }
            }

            Item {
              id: detailPane
              width: parent.width - listPane.width - parent.spacing
              height: parent.height

              Text {
                anchors.centerIn: parent
                visible: !root.selected
                text: "Select an alert."
                color: card.mutedFg
                font.family: Style.font.family
                font.pixelSize: Style.font.bodySmall
              }

              // The action row CONTRACT 7 asks for by name is pinned to the
              // bottom of the pane so the decision is never more than a glance
              // from the evidence for it, however far the detail has scrolled.
              Flow {
                id: actionRow
                anchors.bottom: parent.bottom
                anchors.left: parent.left
                anchors.right: parent.right
                visible: !!root.selected
                spacing: Style.spacing.controlGap

                Button {
                  text: "Kill"
                  bordered: true
                  enabled: !!root.selected && root.selected.actions.indexOf("kill") !== -1
                  opacity: enabled ? 1 : 0.4
                  foreground: Color.urgent
                  accent: Color.urgent
                  fontSize: Style.font.bodySmall
                  onClicked: if (root.selected) root.requestKill(root.selected.id)
                }

                Button {
                  text: "Quarantine"
                  bordered: true
                  enabled: !!root.selected && root.selected.actions.indexOf("quarantine") !== -1
                  opacity: enabled ? 1 : 0.4
                  foreground: Color.urgent
                  accent: Color.urgent
                  fontSize: Style.font.bodySmall
                  onClicked: if (root.selected) root.requestQuarantine(root.selected.id)
                }

                Button {
                  text: root.selected && root.selected.acked ? "Acked" : "Ack"
                  bordered: true
                  enabled: !!root.selected && !root.selected.acked
                  opacity: enabled ? 1 : 0.4
                  foreground: card.fg
                  fontSize: Style.font.bodySmall
                  onClicked: if (root.selected) root.requestAck(root.selected.id)
                }

                Button {
                  text: "Ignore (exe)"
                  bordered: true
                  foreground: card.fg
                  fontSize: Style.font.bodySmall
                  onClicked: if (root.selected) root.requestIgnore(root.selected.id, "exe")
                }

                Button {
                  text: "Ignore (rule)"
                  bordered: true
                  foreground: card.fg
                  fontSize: Style.font.bodySmall
                  onClicked: if (root.selected) root.requestIgnore(root.selected.id, "rule")
                }
              }

              AlertDetail {
                anchors.top: parent.top
                anchors.left: parent.left
                anchors.right: parent.right
                anchors.bottom: actionRow.top
                anchors.bottomMargin: Style.spacing.md
                visible: !!root.selected
                service: root.service
                alert: root.selected
                foreground: card.fg
                onRequestKill: function(id) { root.requestKill(id) }
                onRequestQuarantine: function(id) { root.requestQuarantine(id) }
                onRequestAck: function(id) { root.requestAck(id) }
                onRequestIgnore: function(id, scope) { root.requestIgnore(id, scope) }
              }
            }
          }
        }
      }

      // Sits above the content, inside the card. PanelKeyCatcher's signals are
      // routed to it by root.dismiss()/root.activate()/root.moveSelection while
      // it is open, so it never needs a second raw key handler.
      ConfirmDialog {
        id: confirm
        anchors.fill: parent
        background: Color.popups.background
        foreground: Color.popups.text
        cancelText: "Cancel"
        onCanceled: {
          confirm.opened = false
          root._pendingCommand = ""
        }
        onConfirmed: root._runPending()
      }
    }
  }
}
