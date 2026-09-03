import QtQuick
import qs.Commons
import qs.Ui

// The Settings tab: the three controls CONTRACT 7 asks for (mode, sandbox
// shims, minimum notify severity), plus the two knobs baselining adds —
// "show suppressed" (BASELINE 8) and "Relearn baseline" (BASELINE 3).
//
// Every control here changes what the sensor does or what the user is told, so
// each one says what it costs underneath. Nothing is a bare switch.
Item {
  id: root

  property var service: null
  property color foreground: Color.popups.text

  readonly property color mutedForeground: Qt.darker(foreground, 1.5)
  readonly property var status: service ? service.status : null
  readonly property var baselineState: service ? service.baselineState : null

  signal minNotifySeverityRequested(string value)
  signal notifyCooldownRequested(int minutes)
  signal showSuppressedRequested(bool value)
  signal weeklyDigestRequested(bool value)
  signal relearnRequested()

  Flickable {
    anchors.fill: parent
    contentWidth: width
    contentHeight: column.implicitHeight
    clip: true
    boundsBehavior: Flickable.StopAtBounds

    Column {
      id: column
      width: parent.width
      spacing: Style.spacing.panelGap

      // ------------------------------------------------------------- mode
      Column {
        width: parent.width
        spacing: Style.spacing.sm

        PanelSectionHeader { text: "MODE"; foreground: root.foreground }

        Row {
          spacing: Style.spacing.controlGap

          Button {
            text: "Monitor"
            selected: !!root.status && root.status.mode === "monitor"
            bordered: true
            foreground: root.foreground
            fontSize: Style.font.bodySmall
            onClicked: if (root.service) root.service.setMode("monitor")
          }

          Button {
            text: "Enforce"
            selected: !!root.status && root.status.mode === "enforce"
            bordered: true
            foreground: Color.urgent
            accent: Color.urgent
            fontSize: Style.font.bodySmall
            onClicked: if (root.service) root.service.setMode("enforce")
          }
        }

        Text {
          width: parent.width
          text: "Enforce mode lets Tetragon SIGKILL a matching process in the kernel, before this panel ever sees it. A false positive stops a real program mid-write. Stay in monitor until the allowlist is quiet."
          color: !!root.status && root.status.mode === "enforce" ? Color.urgent : root.mutedForeground
          font.family: Style.font.family
          font.pixelSize: Style.font.caption
          wrapMode: Text.WordWrap
        }
      }

      // ---------------------------------------------------------- sandbox
      Column {
        width: parent.width
        spacing: Style.spacing.sm

        PanelSectionHeader { text: "SANDBOX SHIMS"; foreground: root.foreground }

        Row {
          spacing: Style.spacing.controlGap

          ToggleSwitch {
            anchors.verticalCenter: parent.verticalCenter
            checked: !!root.status && root.status.sandbox
            busy: !!root.service && root.service.busy
            foreground: root.foreground
            trackHeight: Style.space(18)
            onToggled: if (root.service) root.service.setSandbox(!root.service.status.sandbox)
          }

          Text {
            anchors.verticalCenter: parent.verticalCenter
            text: !!root.status && root.status.sandbox ? "on" : "off"
            color: root.mutedForeground
            font.family: Style.font.family
            font.pixelSize: Style.font.bodySmall
          }
        }

        Text {
          width: parent.width
          text: "Runs npm, pip, cargo, makepkg and friends under bubblewrap with your credential directories hidden. Takes effect in new shells."
          color: root.mutedForeground
          font.family: Style.font.family
          font.pixelSize: Style.font.caption
          wrapMode: Text.WordWrap
        }
      }

      // --------------------------------------------------------- notifying
      Column {
        width: parent.width
        spacing: Style.spacing.sm

        PanelSectionHeader { text: "NOTIFY AT"; foreground: root.foreground }

        Row {
          spacing: Style.spacing.sm

          Repeater {
            model: ["low", "medium", "high", "critical"]

            delegate: Button {
              required property string modelData
              anchors.verticalCenter: parent.verticalCenter
              text: modelData
              selected: !!root.service && root.service.minNotifySeverity === modelData
              bordered: true
              foreground: root.foreground
              fontSize: Style.font.bodySmall
              onClicked: root.minNotifySeverityRequested(modelData)
            }
          }
        }

        Text {
          width: parent.width
          text: "Alerts below this never raise a toast. They still appear in the panel. The noise guard's own alert (moat-x-noisy-rule) notifies once regardless, because it is the one that tells you a detection just went quiet."
          color: root.mutedForeground
          font.family: Style.font.family
          font.pixelSize: Style.font.caption
          wrapMode: Text.WordWrap
        }
      }

      // ---------------------------------------------------- notify cooldown
      //
      // BASELINE 5. The first live run turned one broken rule into 173 popups
      // in 15 minutes; this is the cap that makes that two.
      Column {
        width: parent.width
        spacing: Style.spacing.sm

        PanelSectionHeader { text: "NOTIFY COOLDOWN"; foreground: root.foreground }

        Row {
          spacing: Style.spacing.sm

          Repeater {
            model: [1, 5, 10, 30, 60]

            delegate: Button {
              required property int modelData
              anchors.verticalCenter: parent.verticalCenter
              text: modelData + " min"
              selected: !!root.service && root.service.notifyCooldownMinutes === modelData
              bordered: true
              foreground: root.foreground
              fontSize: Style.font.bodySmall
              onClicked: root.notifyCooldownRequested(modelData)
            }
          }
        }

        Text {
          width: parent.width
          text: "One notification per rule per window. The rest of a burst is counted and arrives as a single \"N more from ...\" notification when the window ends, so a rule that floods costs two toasts instead of hundreds. Nothing is dropped — every alert is still in the panel. A critical alert whose tuple has never been seen on this machine goes through immediately."
          color: root.mutedForeground
          font.family: Style.font.family
          font.pixelSize: Style.font.caption
          wrapMode: Text.WordWrap
        }
      }

      // ------------------------------------------------------- suppressed
      Column {
        width: parent.width
        spacing: Style.spacing.sm

        PanelSectionHeader { text: "SHOW SUPPRESSED"; foreground: root.foreground }

        Row {
          spacing: Style.spacing.controlGap

          ToggleSwitch {
            anchors.verticalCenter: parent.verticalCenter
            checked: !!root.service && root.service.showSuppressed
            foreground: root.foreground
            trackHeight: Style.space(18)
            // Routed through the panel so the change is persisted to the bar
            // widget's settings entry, the same way the notify threshold is.
            onToggled: if (root.service) root.showSuppressedRequested(!root.service.showSuppressed)
          }

          Text {
            anchors.verticalCenter: parent.verticalCenter
            text: !!root.service && root.service.showSuppressed ? "shown" : "hidden"
            color: root.mutedForeground
            font.family: Style.font.family
            font.pixelSize: Style.font.bodySmall
          }
        }

        Text {
          width: parent.width
          text: "moatd still writes an alert an allowlist entry covers, so it can be shown greyed out in the timeline with the entry that hid it. Off by default; either way it never notifies and never counts toward the badge."
          color: root.mutedForeground
          font.family: Style.font.family
          font.pixelSize: Style.font.caption
          wrapMode: Text.WordWrap
        }
      }

      // ------------------------------------------------------ weekly digest
      //
      // LEARNING 5. One normal-urgency notification a week — "moat: 0
      // incidents, 18 installs watched, 3 baseline proposals to review" — and
      // it is the ONLY thing moat ever puts on a schedule. Its job is to remind
      // the user the monitor is on and working without being noise, which is
      // also why the off switch is here and not buried.
      //
      // The daemon owns the schedule and sends it; this toggle is a
      // `moatctl set digest on|off` and nothing more.
      Column {
        width: parent.width
        spacing: Style.spacing.sm

        PanelSectionHeader { text: "WEEKLY DIGEST"; foreground: root.foreground }

        Row {
          spacing: Style.spacing.controlGap

          ToggleSwitch {
            anchors.verticalCenter: parent.verticalCenter
            checked: !!root.service && root.service.weeklyDigest
            busy: !!root.service && root.service.busy
            foreground: root.foreground
            trackHeight: Style.space(18)
            onToggled: if (root.service) root.weeklyDigestRequested(!root.service.weeklyDigest)
          }

          Text {
            anchors.verticalCenter: parent.verticalCenter
            text: !!root.service && root.service.weeklyDigest ? "on" : "off"
            color: root.mutedForeground
            font.family: Style.font.family
            font.pixelSize: Style.font.bodySmall
          }
        }

        Text {
          width: parent.width
          text: "One notification a week: incidents, installs watched, and proposals waiting for review. It is the only scheduled notification moat sends — everything else is a reaction to something that happened."
          color: root.mutedForeground
          font.family: Style.font.family
          font.pixelSize: Style.font.caption
          wrapMode: Text.WordWrap
        }
      }

      // ---------------------------------------------------------- baseline
      Column {
        width: parent.width
        spacing: Style.spacing.sm

        PanelSectionHeader { text: "BASELINE"; foreground: root.foreground }

        Text {
          width: parent.width
          text: {
            if (!root.service || !root.baselineState) return ""
            var bits = [root.service.learningSummary]
            bits.push(root.baselineState.learned + " learned")
            if (root.baselineState.demoted.length > 0)
              bits.push(root.baselineState.demoted.length + " demoted rule"
                        + (root.baselineState.demoted.length === 1 ? "" : "s"))
            return bits.join("  ·  ")
          }
          color: root.foreground
          font.family: Style.font.family
          font.pixelSize: Style.font.bodySmall
          wrapMode: Text.WordWrap
        }

        Text {
          width: parent.width
          visible: !!root.baselineState && root.baselineState.demoted.length > 0
          text: root.baselineState ? "demoted: " + root.baselineState.demoted.join(", ") : ""
          color: root.mutedForeground
          font.family: Style.font.family
          font.pixelSize: Style.font.caption
          wrapMode: Text.WrapAnywhere
        }

        Row {
          spacing: Style.spacing.controlGap

          Button {
            text: "Relearn baseline"
            bordered: true
            foreground: Color.urgent
            accent: Color.urgent
            fontSize: Style.font.bodySmall
            onClicked: root.relearnRequested()
          }
        }

        Text {
          width: parent.width
          text: "Restarts the learning window. For a week after that, recurring medium and low alerts from official binaries are written to baseline.toml instead of being shown — which is what you want after a new toolchain or a new job, and not what you want otherwise."
          color: root.mutedForeground
          font.family: Style.font.family
          font.pixelSize: Style.font.caption
          wrapMode: Text.WordWrap
        }
      }

      Item { width: 1; height: Style.spacing.md }
    }
  }
}
