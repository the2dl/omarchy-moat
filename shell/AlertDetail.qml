import QtQuick
import qs.Commons
import qs.Ui

// The detail pane for one alert, laid out as the five headed blocks CONTRACT 7
// pins in order: WHAT HAPPENED, WHY IT WAS FLAGGED, EVIDENCE, IF THIS IS
// EXPECTED, WHAT TO DO. Each block hides itself when the alert carries nothing
// for it, so an alert written before `explain` existed still renders the parts
// it does have instead of five empty headings.
//
// This item only asks; the panel owns confirmation and calls the service.
Item {
  id: root

  property var service: null
  property var alert: null
  property color foreground: Color.popups.text
  property color accent: Color.accent

  // Per-scope disclosure state for the exact TOML each ignore option would
  // write. Keyed by scope because the alert can change under us.
  property var expanded: ({})

  signal requestKill(string id)
  signal requestQuarantine(string id)
  signal requestAck(string id)
  signal requestIgnore(string id, string scope)
  // LEARNING 2 and 4. The panel owns the service call, the same way it does for
  // every other action here.
  signal requestAnalyze(string id)
  signal requestCopyBundle(string id)
  signal requestCopyPath(string path)

  readonly property var explain: alert && alert.explain ? alert.explain : null
  // LEARNING 1: how unusual this exact tuple is on this machine. null when the
  // daemon said nothing, in which case neither the pill nor the line renders.
  readonly property var rarity: alert && service ? service.rarityPill(alert.rarity) : null
  readonly property string rarityText: alert && service ? service.rarityLine(alert) : ""
  // LEARNING 4: what was captured into /var/lib/moat/incidents/<id>/ before
  // anything was killed. null on every alert below the snapshot threshold.
  readonly property var incident: alert && alert.incident ? alert.incident : null
  readonly property var ignoreOptions: alert && service ? service.ignoreOptions(alert) : []
  // BASELINE 4's noise-guard alert offers two options that are not allowlist
  // scopes ("these are expected", "keep watching"). They carry their own
  // command; the panel prints it rather than growing a button for a verb the
  // service does not speak.
  readonly property var otherOptions: alert && service ? service.otherOptions(alert) : []
  readonly property var rotateItems: alert && service ? service.rotateItems(alert) : []
  readonly property bool canKill: alert && alert.actions.indexOf("kill") !== -1
  readonly property bool canQuarantine: alert && alert.actions.indexOf("quarantine") !== -1

  readonly property color mutedForeground: Qt.darker(foreground, 1.5)
  readonly property color codeBackground: Util.alpha(foreground, 0.06)

  // The rarity pill's weight. "first seen" is the one that should catch an eye:
  // it is the tuple nobody on this machine has ever produced before. "common"
  // is deliberately the quietest thing on the pane — it is reassurance, and
  // reassurance that shouts is noise.
  function rarityColor(kind) {
    switch (String(kind || "")) {
    case "strong": return Color.urgent
    case "warn": return "#d9a13b"
    default: return Util.alpha(root.foreground, 0.35)
    }
  }

  function toggleScope(scope) {
    var next = ({})
    for (var k in root.expanded) next[k] = root.expanded[k]
    next[scope] = !next[scope]
    root.expanded = next
  }

  function isExpanded(scope) { return root.expanded[scope] === true }

  // "node (pid 41233, uid 1000)" — the identity line under WHAT HAPPENED.
  function processLine() {
    if (!alert) return ""
    var p = alert.process
    var name = service ? service.basename(p.exe) : p.exe
    var bits = []
    if (p.pid) bits.push("pid " + p.pid)
    if (p.uid >= 0) bits.push("uid " + p.uid)
    return (name || "?") + (bits.length ? " (" + bits.join(", ") + ")" : "")
  }

  function netLine() {
    if (!alert || !alert.net) return ""
    var n = alert.net
    var host = n.domain ? String(n.domain) : String(n.dst_ip || "")
    if (!host) return ""
    return host + (n.dst_port ? ":" + n.dst_port : "")
  }

  function iocLine() {
    if (!alert || !alert.ioc) return ""
    var i = alert.ioc
    return String(i.matched || "") + (i.source ? "  (" + i.source + ")" : "")
  }

  Flickable {
    id: scroller
    anchors.fill: parent
    contentWidth: width
    contentHeight: body.implicitHeight
    clip: true
    boundsBehavior: Flickable.StopAtBounds

    Column {
      id: body
      width: scroller.width
      spacing: Style.spacing.panelGap

      // ------------------------------------------------------- title header
      Column {
        width: parent.width
        spacing: Style.spacing.xs

        Row {
          width: parent.width
          spacing: Style.spacing.md

          Rectangle {
            id: pill
            anchors.verticalCenter: parent.verticalCenter
            width: pillText.implicitWidth + Style.space(10)
            height: Math.round(Style.font.caption * 1.7)
            radius: Style.cornerRadius > 0 ? height / 2 : 0
            color: root.alert ? severityColor(root.alert.severity) : "transparent"

            function severityColor(severity) {
              switch (String(severity)) {
              case "critical": return Color.urgent
              case "high": return Color.urgent
              case "medium": return "#d9a13b"
              default: return Util.alpha(root.foreground, 0.35)
              }
            }

            Text {
              id: pillText
              anchors.centerIn: parent
              text: root.alert ? String(root.alert.severity).toUpperCase() : ""
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
            font.pixelSize: Style.font.title
            font.bold: true
            wrapMode: Text.WordWrap
          }
        }

        Text {
          width: parent.width
          text: {
            if (!root.alert) return ""
            var bits = [root.alert.rule]
            if (root.service) bits.push(root.service.relativeTime(root.alert.ts))
            bits.push("mode " + root.alert.mode)
            if (root.alert.count > 1) bits.push("×" + root.alert.count)
            if (root.alert.action_taken !== "none") bits.push(root.alert.action_taken)
            bits.push(root.alert.acked ? "acked" : "unacked")
            return bits.join("  ·  ")
          }
          color: root.mutedForeground
          font.family: Style.font.family
          font.pixelSize: Style.font.caption
          wrapMode: Text.WordWrap
        }
      }

      PanelSeparator { width: parent.width; foreground: root.foreground }

      // -------------------------------------------------- 1. WHAT HAPPENED
      Column {
        width: parent.width
        spacing: Style.spacing.sm

        PanelSectionHeader { text: "WHAT HAPPENED"; foreground: root.foreground }

        Text {
          width: parent.width
          visible: text !== ""
          text: root.explain && root.explain.what ? root.explain.what
            : (root.alert ? root.alert.summary : "")
          color: root.foreground
          font.family: Style.font.family
          font.pixelSize: Style.font.body
          wrapMode: Text.WordWrap
        }

        // LEARNING 1: rarity. "first time /usr/bin/node has read ~/.aws on this
        // machine" is the single most useful sentence on the pane for deciding
        // whether something is worth caring about, so it sits directly under
        // WHAT HAPPENED with a pill that says which of the three classes it is.
        //
        // It is evidence, never a verdict. A `common` alert is still an alert:
        // rarity does not move a severity here any more than it does in the
        // daemon, and the pill is styled so it cannot read as an all-clear.
        Row {
          width: parent.width
          spacing: Style.spacing.md
          visible: root.rarityText !== "" || !!root.rarity

          Rectangle {
            id: rarityPill
            anchors.verticalCenter: parent.verticalCenter
            visible: !!root.rarity
            width: visible ? rarityPillText.implicitWidth + Style.space(8) : 0
            height: Math.round(Style.font.caption * 1.55)
            radius: Style.cornerRadius > 0 ? height / 2 : 0
            color: root.rarityColor(root.rarity ? root.rarity.kind : "")

            Text {
              id: rarityPillText
              anchors.centerIn: parent
              text: root.rarity ? root.rarity.label : ""
              color: Color.background
              font.family: Style.font.family
              font.pixelSize: Style.font.caption
              font.bold: true
            }
          }

          Text {
            anchors.verticalCenter: parent.verticalCenter
            width: parent.width - rarityPill.width - parent.spacing
            text: root.rarityText
            color: root.foreground
            font.family: Style.font.family
            font.pixelSize: Style.font.bodySmall
            wrapMode: Text.WordWrap
          }
        }

        // BASELINE 1 and 2b: who acted, and what they were doing at the time.
        // "context: interactive · actor: official (package hyprland 0.53-1)".
        // Provenance is evidence, not a verdict, so it reads as a fact line
        // rather than as a reassurance.
        Text {
          width: parent.width
          visible: text !== ""
          text: root.alert && root.service ? root.service.actorLine(root.alert) : ""
          color: root.mutedForeground
          font.family: Style.font.family
          font.pixelSize: Style.font.bodySmall
          wrapMode: Text.WordWrap
        }

        // BASELINE 2: when provenance or context moved the severity, say so and
        // say why. A user who reads "high → medium: interactive session" learns
        // what moat would have done to the same event from an install script.
        Text {
          width: parent.width
          visible: text !== ""
          text: root.alert && root.service ? root.service.severityChangeLine(root.alert) : ""
          color: root.mutedForeground
          font.family: Style.font.family
          font.pixelSize: Style.font.bodySmall
          wrapMode: Text.WordWrap
        }

        // BASELINE 6: every suppression is visible and removable. An alert that
        // only appears because "show suppressed" is on says what hid it.
        Text {
          width: parent.width
          visible: text !== ""
          text: root.alert && root.service ? root.service.suppressedLine(root.alert) : ""
          color: root.mutedForeground
          font.family: Style.font.family
          font.pixelSize: Style.font.bodySmall
          font.italic: true
          wrapMode: Text.WrapAnywhere
        }

        Repeater {
          model: {
            if (!root.alert) return []
            var rows = []
            rows.push({ key: "Process", value: root.processLine() })
            if (root.alert.process.exe) rows.push({ key: "Path", value: root.alert.process.exe })
            if (root.alert.process.args) rows.push({ key: "Args", value: root.alert.process.args })
            if (root.alert.process.cwd) rows.push({ key: "Cwd", value: root.alert.process.cwd })
            var chain = root.service ? root.service.ancestryChain(root.alert) : ""
            if (chain) rows.push({ key: "Ancestry", value: chain })
            if (root.alert.file && root.alert.file.path) rows.push({ key: "File", value: String(root.alert.file.path) })
            if (root.alert.file && root.alert.file.sha256) rows.push({ key: "sha256", value: String(root.alert.file.sha256) })
            var net = root.netLine()
            if (net) rows.push({ key: "Network", value: net })
            var ioc = root.iocLine()
            if (ioc) rows.push({ key: "IOC", value: ioc })
            return rows
          }

          delegate: Row {
            required property var modelData
            width: body.width
            spacing: Style.spacing.md

            Text {
              width: Style.space(74)
              text: modelData.key
              color: root.mutedForeground
              font.family: Style.font.family
              font.pixelSize: Style.font.bodySmall
            }

            Text {
              width: parent.width - Style.space(74) - parent.spacing
              text: modelData.value
              color: root.foreground
              font.family: Style.font.family
              font.pixelSize: Style.font.bodySmall
              wrapMode: Text.WrapAnywhere
            }
          }
        }
      }

      // ------------------------------------------- 2. WHY IT WAS FLAGGED
      Column {
        width: parent.width
        spacing: Style.spacing.sm
        visible: whyText.text !== ""

        PanelSectionHeader { text: "WHY IT WAS FLAGGED"; foreground: root.foreground }

        Text {
          id: whyText
          width: parent.width
          text: root.explain && root.explain.why ? root.explain.why
            : (root.alert && root.alert.family ? "Matched the " + root.alert.family + " family rule " + root.alert.rule + "." : "")
          color: root.foreground
          font.family: Style.font.family
          font.pixelSize: Style.font.body
          wrapMode: Text.WordWrap
        }
      }

      // -------------------------------------------------------- 3. EVIDENCE
      Column {
        width: parent.width
        spacing: Style.spacing.sm
        visible: root.explain && root.explain.evidence.length > 0

        PanelSectionHeader { text: "EVIDENCE"; foreground: root.foreground }

        Rectangle {
          width: parent.width
          height: evidenceColumn.implicitHeight + Style.spacing.xl
          color: root.codeBackground
          radius: Style.cornerRadius

          Column {
            id: evidenceColumn
            x: Style.spacing.rowPaddingX
            y: Style.spacing.md
            width: parent.width - Style.spacing.rowPaddingX * 2
            spacing: Style.spacing.xs

            Repeater {
              model: root.explain ? root.explain.evidence : []

              delegate: Text {
                required property string modelData
                width: evidenceColumn.width
                text: "· " + modelData
                color: root.foreground
                font.family: Style.font.family
                font.pixelSize: Style.font.bodySmall
                wrapMode: Text.WrapAnywhere
              }
            }
          }
        }
      }

      // --------------------------------------------- INCIDENT SNAPSHOT
      //
      // LEARNING 4. On a high or critical alert the daemon copies the process
      // state, the tree, the sockets and the acting binary into
      // /var/lib/moat/incidents/<id>/ immediately, before any kill — because
      // quarantine moves the original and a dead process has no /proc.
      //
      // The panel lists what was captured and hands over the path. It never
      // opens the files: they are a byte-for-byte copy of exactly the untrusted
      // material the alert is about.
      Column {
        width: parent.width
        spacing: Style.spacing.sm
        visible: !!root.incident

        PanelSectionHeader { text: "INCIDENT SNAPSHOT"; foreground: root.foreground }

        Row {
          width: parent.width
          spacing: Style.spacing.md

          Text {
            id: incidentDir
            anchors.verticalCenter: parent.verticalCenter
            width: parent.width - copyIncident.width - parent.spacing
            text: root.incident ? root.incident.dir : ""
            color: root.foreground
            font.family: Style.font.family
            font.pixelSize: Style.font.bodySmall
            wrapMode: Text.WrapAnywhere
          }

          Button {
            id: copyIncident
            anchors.verticalCenter: parent.verticalCenter
            text: "Copy path"
            foreground: root.mutedForeground
            fontSize: Style.font.caption
            onClicked: root.requestCopyPath(root.incident ? root.incident.dir : "")
          }
        }

        Rectangle {
          width: parent.width
          visible: !!root.incident && root.incident.files.length > 0
          height: visible ? incidentFiles.implicitHeight + Style.spacing.xl : 0
          color: root.codeBackground
          radius: Style.cornerRadius

          Column {
            id: incidentFiles
            x: Style.spacing.rowPaddingX
            y: Style.spacing.md
            width: parent.width - Style.spacing.rowPaddingX * 2
            spacing: Style.spacing.xxs

            Repeater {
              model: root.incident ? root.incident.files : []

              delegate: Row {
                required property var modelData
                width: incidentFiles.width
                spacing: Style.spacing.md

                Text {
                  width: parent.width - Style.space(70) - parent.spacing
                  text: modelData.name
                  color: root.foreground
                  font.family: Style.font.family
                  font.pixelSize: Style.font.bodySmall
                  wrapMode: Text.WrapAnywhere
                }

                Text {
                  width: Style.space(70)
                  horizontalAlignment: Text.AlignRight
                  text: root.service ? root.service.formatBytes(modelData.size) : ""
                  color: root.mutedForeground
                  font.family: Style.font.family
                  font.pixelSize: Style.font.bodySmall
                }
              }
            }
          }
        }

        Text {
          width: parent.width
          text: "Captured before any kill or quarantine, and kept for 30 days. The copies are the untrusted files themselves — read them in a viewer, not by executing them."
          color: root.mutedForeground
          font.family: Style.font.family
          font.pixelSize: Style.font.caption
          wrapMode: Text.WordWrap
        }
      }

      // ------------------------------------------- 4. IF THIS IS EXPECTED
      Column {
        width: parent.width
        spacing: Style.spacing.sm
        visible: (root.explain && root.explain.expected !== "") || root.ignoreOptions.length > 0
          || root.otherOptions.length > 0

        PanelSectionHeader { text: "IF THIS IS EXPECTED"; foreground: root.foreground }

        Text {
          width: parent.width
          visible: text !== ""
          text: root.explain ? root.explain.expected : ""
          color: root.foreground
          font.family: Style.font.family
          font.pixelSize: Style.font.body
          wrapMode: Text.WordWrap
        }

        // One button per scope, recommended first. Each opens a collapsible
        // block showing the exact TOML the daemon would append, so the user
        // approves the bytes rather than a description of them.
        Repeater {
          model: root.ignoreOptions

          delegate: Column {
            required property var modelData
            width: body.width
            spacing: Style.spacing.xs

            Row {
              width: parent.width
              spacing: Style.spacing.md

              Button {
                id: scopeButton
                text: modelData.label + (modelData.recommended ? "  ·  recommended" : "")
                bordered: modelData.recommended
                foreground: root.foreground
                accent: root.accent
                onClicked: root.requestIgnore(root.alert ? root.alert.id : "", modelData.scope)
              }

              Button {
                text: root.isExpanded(modelData.scope) ? "Hide TOML" : "Show TOML"
                foreground: root.mutedForeground
                fontSize: Style.font.caption
                onClicked: root.toggleScope(modelData.scope)
              }
            }

            Text {
              width: parent.width
              text: root.service ? root.service.ignoreScopeCaution(modelData.scope) : ""
              color: root.mutedForeground
              font.family: Style.font.family
              font.pixelSize: Style.font.caption
              wrapMode: Text.WordWrap
            }

            Rectangle {
              width: parent.width
              visible: root.isExpanded(modelData.scope)
              height: visible ? tomlColumn.implicitHeight + Style.spacing.xl : 0
              color: root.codeBackground
              radius: Style.cornerRadius

              Column {
                id: tomlColumn
                x: Style.spacing.rowPaddingX
                y: Style.spacing.md
                width: parent.width - Style.spacing.rowPaddingX * 2
                spacing: Style.spacing.sm

                Text {
                  width: parent.width
                  text: modelData.line
                  color: root.foreground
                  font.family: Style.font.family
                  font.pixelSize: Style.font.bodySmall
                  wrapMode: Text.WrapAnywhere
                  textFormat: Text.PlainText
                }

                Text {
                  width: parent.width
                  visible: modelData.cmd !== ""
                  text: "$ " + modelData.cmd
                  color: root.mutedForeground
                  font.family: Style.font.family
                  font.pixelSize: Style.font.caption
                  wrapMode: Text.WrapAnywhere
                }
              }
            }
          }
        }

        Repeater {
          model: root.otherOptions

          delegate: Column {
            required property var modelData
            width: parent.width
            spacing: Style.spacing.xxs

            Text {
              width: parent.width
              text: modelData.label
              color: root.foreground
              font.family: Style.font.family
              font.pixelSize: Style.font.bodySmall
              font.bold: true
              wrapMode: Text.WordWrap
            }

            Text {
              width: parent.width
              text: "$ " + modelData.cmd
              color: root.mutedForeground
              font.family: Style.font.family
              font.pixelSize: Style.font.caption
              wrapMode: Text.WrapAnywhere
              textFormat: Text.PlainText
            }

            Text {
              width: parent.width
              visible: text !== ""
              text: modelData.line
              color: root.mutedForeground
              font.family: Style.font.family
              font.pixelSize: Style.font.caption
              wrapMode: Text.WrapAnywhere
              textFormat: Text.PlainText
            }
          }
        }

        Text {
          width: parent.width
          visible: root.ignoreOptions.length > 0
          text: "Written to " + (root.explain ? root.explain.if_expected.file : "")
            + ". Remove it again from the Allowlist tab."
          color: root.mutedForeground
          font.family: Style.font.family
          font.pixelSize: Style.font.caption
          wrapMode: Text.WordWrap
        }
      }

      // ----------------------------------------------------- 5. WHAT TO DO
      Column {
        width: parent.width
        spacing: Style.spacing.sm
        visible: (root.explain && root.explain.next.length > 0) || root.rotateItems.length > 0

        PanelSectionHeader { text: "WHAT TO DO"; foreground: root.foreground }

        Repeater {
          model: root.explain ? root.explain.next : []

          delegate: Text {
            required property string modelData
            width: body.width
            text: "· " + modelData
            color: root.foreground
            font.family: Style.font.family
            font.pixelSize: Style.font.body
            wrapMode: Text.WordWrap
          }
        }

        // Rotation guidance. `rotate` names the secret kind; the plugin turns
        // it into the concrete thing to go do, because a hint that a key leaked
        // and then stops is worse than no hint.
        Repeater {
          model: root.rotateItems

          delegate: Column {
            required property var modelData
            width: body.width
            spacing: Style.spacing.xxs

            Text {
              text: "Rotate: " + modelData.kind
              color: Color.urgent
              font.family: Style.font.family
              font.pixelSize: Style.font.bodySmall
              font.bold: true
            }

            Text {
              width: parent.width
              text: modelData.guidance
              color: root.foreground
              font.family: Style.font.family
              font.pixelSize: Style.font.bodySmall
              wrapMode: Text.WordWrap
            }
          }
        }
      }

      // -------------------------------------------------------- 6. ANALYSIS
      //
      // LEARNING 2. Sixth block, deliberately after the five CONTRACT 7 pins in
      // order: the user reads what happened and what to do about it before
      // being offered a second opinion, and the five headed blocks stay in the
      // order the contract fixes them in.
      Column {
        width: parent.width
        spacing: Style.spacing.sm
        visible: !!root.alert

        PanelSectionHeader { text: "ANALYSIS"; foreground: root.foreground }

        Row {
          width: parent.width
          spacing: Style.spacing.controlGap
          visible: !!root.service && root.service.agentButtonLabel !== ""

          Button {
            text: root.service ? root.service.agentButtonLabel : ""
            bordered: true
            enabled: !!root.service && root.service.analyzeState !== "running"
            opacity: enabled ? 1 : 0.5
            foreground: root.foreground
            accent: root.accent
            fontSize: Style.font.bodySmall
            onClicked: root.requestAnalyze(root.alert ? root.alert.id : "")
          }

          Button {
            anchors.verticalCenter: parent.verticalCenter
            text: "Copy bundle path"
            foreground: root.mutedForeground
            fontSize: Style.font.caption
            enabled: !!root.service && root.service.copyState !== "running"
            opacity: enabled ? 1 : 0.5
            onClicked: root.requestCopyBundle(root.alert ? root.alert.id : "")
          }
        }

        // No default agent: say the exact command that sets one rather than
        // showing a button that cannot do anything.
        Text {
          width: parent.width
          visible: !!root.service && root.service.agentButtonLabel === ""
          text: root.service ? root.service.agentHint : ""
          color: root.mutedForeground
          font.family: Style.font.family
          font.pixelSize: Style.font.bodySmall
          wrapMode: Text.WordWrap
        }

        // Transient: "opened in claude" after a launch, the daemon's own error
        // when moatctl exited non-zero. Cleared by the service on a timer.
        Text {
          width: parent.width
          visible: text !== ""
          text: {
            if (!root.service) return ""
            if (root.service.analyzeState === "running") return "bundling…"
            return root.service.analyzeMessage
          }
          color: root.service && root.service.analyzeState === "failed"
            ? Color.urgent : root.mutedForeground
          font.family: Style.font.family
          font.pixelSize: Style.font.caption
          wrapMode: Text.WrapAnywhere
        }

        Text {
          width: parent.width
          visible: text !== ""
          text: root.service ? root.service.copyMessage : ""
          color: root.service && root.service.copyState === "failed"
            ? Color.urgent : root.mutedForeground
          font.family: Style.font.family
          font.pixelSize: Style.font.caption
          wrapMode: Text.WrapAnywhere
        }

        Text {
          width: parent.width
          visible: !!root.service && root.service.agentButtonLabel !== ""
          text: "moatctl writes the evidence bundle and launches the agent on it. Everything the bundle quotes from a process is fenced as untrusted data, and the agent is asked to propose moatctl commands rather than run kill, quarantine or ignore itself."
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
