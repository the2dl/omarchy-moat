import QtQuick
import Quickshell
import Quickshell.Io
import Quickshell.Wayland
import qs.Commons
import qs.Ui

// Moat's panel. Declared as kind "panel" with keepLoaded, so the shell
// mounts it once at startup and drives it through the standard verbs:
//
//   omarchy-shell shell toggle io.github.the2dl.moat '{}'
//   omarchy-shell shell summon io.github.the2dl.moat '{"alert":"<id>"}'
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
  // BASELINE 5 splits the alert list in two: Alerts is high + critical, the
  // things asking for a decision; Timeline is medium, low, demoted and (when
  // asked for) suppressed, grouped. Allowlist and Settings are the other two.
  property string tab: "alerts"          // "alerts" | "timeline" | "allowlist" | "settings"
  property string notice: ""             // transient result line under the header

  readonly property var tabNames: ["alerts", "timeline", "allowlist", "settings"]

  readonly property string pluginId: "io.github.the2dl.moat"
  // The Alerts tab's list: high + critical, not demoted, not suppressed,
  // unacked first (BASELINE 5).
  readonly property var alertsList: service ? service.alertsSurface : []
  readonly property bool ready: !!service && service.available && service.groupOk
  readonly property bool listTab: root.tab === "alerts" || root.tab === "timeline"
  readonly property bool enforcing: !!service && service.status.mode === "enforce"
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
      root.selectAlert(String(payload.alert))
      // Land on the tab that actually holds it. The one alert that can arrive
      // here from a toast while living on the timeline is moat-x-noisy-rule,
      // which notifies at medium on purpose (BASELINE 4); opening the Alerts
      // tab on it would show an empty list.
      var target = service ? service.alertById(String(payload.alert)) : null
      root.tab = target && target.surface === "timeline" ? "timeline" : "alerts"
    }
    if (payload && payload.tab && root.tabNames.indexOf(String(payload.tab)) !== -1)
      root.tab = String(payload.tab)
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
    if (!root.selectedId && root.alertsList.length > 0) root.selectAlert(root.alertsList[0].id)
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
      } else if (command === "baseline-accept") {
        root.notice = "Proposal accepted — written to /etc/moat/allowlist.d/baseline.toml."
      } else if (command === "baseline-dismiss") {
        root.notice = "Proposal dismissed. Its alerts keep coming."
      } else if (command === "baseline-relearn") {
        root.notice = "Learning window restarted."
      } else if (command === "digest") {
        // setWeeklyDigest already wrote the notice, and it says more than this
        // would (whether the setting was persisted). Leave it alone.
        return
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
  // /var/lib/moat/quarantine — so both go through a confirm, and so does
  // removing an allowlist rule (it silently re-arms a detection). Ack and the
  // allowlist writes do not: ack is a label, and an added rule is listed with a
  // Remove button one tab away.
  property string _pendingCommand: ""
  property string _pendingArg: ""
  property string _pendingArg2: ""

  function requestKill(id) {
    root._confirm("kill", id, "Kill the process tree recorded in this alert?")
  }

  function requestQuarantine(id) {
    root._confirm("quarantine", id,
      "Move this file into quarantine (chmod 000, under /var/lib/moat/quarantine)? Anything still using it will break.")
  }

  function requestUnignore(index, file) {
    root._pendingArg2 = String(file || "")
    root._confirm("unignore", String(index),
      "Remove allowlist rule #" + index + (file ? " from " + file : "")
      + "? Its detection starts firing again.")
  }

  // BASELINE 3: relearning re-opens the window in which recurring medium/low
  // alerts are silently written to baseline.toml instead of shown. That is a
  // week of deliberately reduced visibility, so it asks first.
  function requestRelearn() {
    root._confirm("baseline-relearn", "",
      "Restart the baseline learning window? For the next learning period, recurring medium and low alerts from official binaries are written to baseline.toml instead of being shown.")
  }

  function requestAck(id) { if (service) service.ack(id) }
  function requestIgnore(id, scope) { if (service) service.ignore(id, scope) }
  // Accept and dismiss are both reversible — an accepted entry is listed with a
  // Remove button in the same tab, and a dismissed pattern proposes itself
  // again if it keeps recurring — so neither goes through the confirm.
  function requestAcceptProposal(id) { if (service) service.acceptProposal(id) }
  function requestDismissProposal(id) { if (service) service.dismissProposal(id) }

  function _confirm(command, arg, message) {
    root._pendingCommand = command
    root._pendingArg = String(arg)
    if (command !== "unignore") root._pendingArg2 = ""
    confirm.message = message
    confirm.confirmText = command === "baseline-relearn"
      ? "Relearn"
      : command.charAt(0).toUpperCase() + command.slice(1)
    confirm.selectedIndex = 0     // a destructive prompt defaults to Cancel
    confirm.opened = true
  }

  function _runPending() {
    var command = root._pendingCommand
    var arg = root._pendingArg
    var arg2 = root._pendingArg2
    confirm.opened = false
    root._pendingCommand = ""
    root._pendingArg2 = ""
    if (!service) return
    if (command === "kill") service.kill(arg)
    else if (command === "quarantine") service.quarantine(arg)
    else if (command === "unignore") service.unignore(Number(arg), arg2)
    else if (command === "baseline-relearn") service.relearnBaseline()
  }

  // ------------------------------------------------------------- keyboard nav
  //
  // PanelKeyCatcher already owns the raw Keys handler, so the panel wires its
  // semantic signals rather than declaring a second Keys.onPressed (which would
  // shadow the component's own and kill every binding it provides). While the
  // confirm is up, the same signals drive the dialog instead of the list.

  // The list j/k walks: the Alerts tab's own list, or on the Timeline the rows
  // that are actually on screen (an expanded group's alerts). Moving the
  // selection into a collapsed group would be a cursor nobody can see.
  function navigableAlerts() {
    if (root.tab === "alerts") return root.alertsList
    if (root.tab === "timeline") return timelineView.flatAlerts
    return []
  }

  function moveSelection(delta) {
    if (confirm.opened) {
      confirm.selectedIndex = confirm.selectedIndex === 0 ? 1 : 0
      return
    }
    var list = root.navigableAlerts()
    if (list.length === 0) return
    var index = 0
    for (var i = 0; i < list.length; i++) {
      if (list[i].id === root.selectedId) { index = i; break }
    }
    index = Math.max(0, Math.min(list.length - 1, index + delta))
    root.selectAlert(list[index].id)
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
    case "t": root.cycleTab(1); break
    }
  }

  // `t` cycles the four tabs in order rather than toggling two, so the key
  // still reaches every surface now that there are four of them.
  function cycleTab(delta) {
    var index = root.tabNames.indexOf(root.tab)
    if (index < 0) index = 0
    root.selectTab(root.tabNames[(index + delta + root.tabNames.length) % root.tabNames.length])
  }

  function selectTab(name) {
    root.tab = String(name)
    if (root.tab === "allowlist" && service) service.loadAllowlist()
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

  function setNotifyCooldown(minutes) {
    if (!service) return
    var value = Number(minutes)
    service.notifyCooldownMinutes = value
    var error = service.persistSetting("notifyCooldownMinutes", value)
    root.notice = error
      ? "Notification cooldown " + value + " min for this session (not saved: " + error + ")"
      : "Notification cooldown saved: " + value + " min per rule"
    noticeTimer.restart()
  }

  function setShowSuppressed(value) {
    if (!service) return
    service.showSuppressed = value === true
    var error = service.persistSetting("showSuppressed", value === true)
    var label = value === true ? "shown" : "hidden"
    root.notice = error
      ? "Suppressed alerts " + label + " for this session (not saved: " + error + ")"
      : "Suppressed alerts " + label + "."
    noticeTimer.restart()
  }

  // LEARNING 5. The digest is the daemon's to send; this switch is the user's
  // to turn off. Two writes, because they answer different questions: the bar
  // widget entry is what the panel reads back, and `moatctl set digest` is what
  // actually stops the notification being scheduled.
  function setWeeklyDigest(value) {
    if (!service) return
    var on = value === true
    service.weeklyDigest = on
    service.setDigest(on)
    var error = service.persistSetting("weeklyDigest", on)
    root.notice = error
      ? "Weekly digest " + (on ? "on" : "off") + " for this session (not saved: " + error + ")"
      : "Weekly digest " + (on ? "on" : "off") + "."
    noticeTimer.restart()
  }

  // ------------------------------------------------------------------ geometry

  readonly property var barItem: shell && shell.bar ? shell.bar : null
  readonly property string barPosition: barItem && barItem.position ? String(barItem.position) : "top"
  readonly property int barClearance: barItem && barItem.barSize ? Number(barItem.barSize) : Style.bar.sizeHorizontal
  readonly property int gap: Style.gapsOut

  IpcHandler {
    target: "moat"

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

    WlrLayershell.namespace: "omarchy-moat-panel"
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
                text: "Moat"
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

              Repeater {
                model: [
                  { tab: "alerts", label: "Alerts" },
                  { tab: "timeline", label: "Timeline" },
                  { tab: "allowlist", label: "Allowlist" },
                  { tab: "settings", label: "Settings" }
                ]

                delegate: Button {
                  required property var modelData
                  anchors.verticalCenter: parent.verticalCenter
                  // The Alerts tab carries the badge count and the Allowlist
                  // tab the number of proposals waiting: the two places where
                  // something is asking the user for a decision.
                  text: {
                    if (modelData.tab === "alerts" && root.service && root.service.badgeCount > 0)
                      return "Alerts " + root.service.badgeCount
                    if (modelData.tab === "allowlist" && root.service
                        && root.service.proposals.length > 0)
                      return "Allowlist " + root.service.proposals.length
                    return modelData.label
                  }
                  selected: root.tab === modelData.tab
                  foreground: card.fg
                  fontSize: Style.font.bodySmall
                  onClicked: root.selectTab(modelData.tab)
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
                  // BASELINE 3: where the machine is in its learning window,
                  // and how many patterns are waiting to be reviewed. It is a
                  // status cell rather than a banner because it is the normal
                  // state of the system, not an incident.
                  // learningSummary already reads as a phrase ("learning, 5
                  // days left" / "baseline active · 3 proposals"), so this cell
                  // carries no label of its own.
                  { label: "", value: root.service.learningSummary,
                    warn: s.baseline.proposals > 0 },
                  { label: "unacked", value: String(root.service.unacked.total),
                    warn: root.service.unacked.total > 0 }
                ]
              }

              delegate: Text {
                required property var modelData
                text: modelData.label ? modelData.label + " " + modelData.value : modelData.value
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
        //
        // The settings row CONTRACT 7 asks for moved into its own tab when
        // baselining added a fifth and sixth control to it (show suppressed,
        // relearn); a Flow of six controls under every tab was more chrome than
        // list. What stays pinned here is the one thing that is true no matter
        // which tab you are on: the sensor is armed to kill.
        Column {
          id: footerBlock
          anchors.bottom: parent.bottom
          anchors.left: parent.left
          anchors.right: parent.right
          spacing: Style.spacing.md
          visible: root.enforcing

          PanelSeparator { width: parent.width; foreground: card.fg; visible: root.enforcing }

          Text {
            width: parent.width
            visible: root.enforcing
            text: "Enforce mode: Tetragon can SIGKILL a matching process in the kernel before this panel sees it. A false positive stops a real program mid-write."
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
            onRemoveRequested: function(index, file) { root.requestUnignore(index, file) }
            onAcceptRequested: function(id) { root.requestAcceptProposal(id) }
            onDismissRequested: function(id) { root.requestDismissProposal(id) }
          }

          SettingsView {
            anchors.fill: parent
            visible: root.ready && root.tab === "settings"
            service: root.service
            foreground: card.fg
            onMinNotifySeverityRequested: function(value) { root.setMinNotifySeverity(value) }
            onNotifyCooldownRequested: function(minutes) { root.setNotifyCooldown(minutes) }
            onShowSuppressedRequested: function(value) { root.setShowSuppressed(value) }
            onWeeklyDigestRequested: function(value) { root.setWeeklyDigest(value) }
            onRelearnRequested: root.requestRelearn()
          }

          // Alerts and Timeline are the same two-pane layout with a different
          // left half: one detail pane serves both, because a demoted or
          // downgraded alert deserves the same five blocks as a critical one.
          Row {
            anchors.fill: parent
            visible: root.ready && root.listTab
            spacing: Style.spacing.panelGap

            Item {
              id: listPane
              width: Math.round(Math.min(Style.space(340), parent.width * 0.42))
              height: parent.height

              Text {
                anchors.centerIn: parent
                width: parent.width
                visible: root.tab === "alerts" && root.alertsList.length === 0
                text: {
                  if (root.service && !root.service.logReadable) return "The alert log is not readable."
                  if (root.service && root.service.timelineRows.length > 0)
                    return "Nothing needs a decision. Lower-severity activity and install receipts are in the Timeline."
                  return "No alerts. Moat is watching."
                }
                color: card.mutedFg
                font.family: Style.font.family
                font.pixelSize: Style.font.bodySmall
                wrapMode: Text.WordWrap
                horizontalAlignment: Text.AlignHCenter
              }

              ListView {
                id: alertList
                anchors.fill: parent
                visible: root.tab === "alerts" && root.alertsList.length > 0
                clip: true
                model: root.alertsList
                spacing: Style.spacing.xxs
                boundsBehavior: Flickable.StopAtBounds
                currentIndex: {
                  for (var i = 0; i < root.alertsList.length; i++)
                    if (root.alertsList[i].id === root.selectedId) return i
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

              TimelineView {
                id: timelineView
                anchors.fill: parent
                visible: root.tab === "timeline"
                service: root.service
                foreground: card.fg
                selectedId: root.selectedId
                onAlertSelected: function(id) { root.selectAlert(id) }
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
                // LEARNING 2 and 4. All three go straight to the service: none
                // of them changes anything on this machine, so none needs the
                // confirm that Kill and Quarantine go through. Their results
                // land next to the buttons rather than in the panel notice,
                // because they are about one alert, not about the daemon.
                onRequestAnalyze: function(id) { if (root.service) root.service.analyze(id) }
                onRequestCopyBundle: function(id) { if (root.service) root.service.copyBundlePath(id) }
                onRequestCopyPath: function(path) { if (root.service) root.service.copyText(path, "incident path") }
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
