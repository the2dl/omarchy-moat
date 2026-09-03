import QtQuick
import qs.Commons
import qs.Ui

// The Allowlist tab, in three sections:
//
//   PROPOSALS   BASELINE 3's `status.proposals[]`: tuples that kept recurring
//               after the learning window closed. Accept writes the proposed
//               block to baseline.toml, Dismiss drops it. Shown first, because
//               it is the only part of this tab that is asking a question.
//   YOUR RULES  every [[rule]] block the user added to
//               /etc/moat/allowlist.d/user.toml through the "if this is
//               expected" flow, with the comment moatd stamped on it.
//   LEARNED     the entries the learning window wrote to baseline.toml on the
//               user's behalf, tagged "learned". BASELINE 6: a suppression the
//               machine chose for you is the one you most need to be able to
//               see and remove, so they are listed the same way and not in a
//               footnote.
//   SHIPPED     LEARNING 8's reviewed baseline, /etc/moat/allowlist.d/
//               omarchy-default.toml. The daemon reports these
//               `removable: false` and `unignore` refuses them, so they are
//               listed with their reason and no Remove button -- visible,
//               because "not silent" is the promise, and unremovable, because
//               the package owns the file and would put it back on upgrade.
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
  readonly property var sections: service ? service.allowlistSections() : ({ user: [], learned: [], shipped: [] })
  readonly property var proposals: service ? service.proposals : []

  // The fragment travels with the index: BASELINE 8 numbers each allowlist.d
  // file from 1 independently, so an index alone names three different rules.
  signal removeRequested(int index, string file)
  signal acceptRequested(string id)
  signal dismissRequested(string id)

  // Per-proposal disclosure of the exact TOML accepting would write, the same
  // deal the ignore flow offers: the user approves the bytes, not a summary.
  property var expandedProposals: ({})

  function isProposalExpanded(id) { return root.expandedProposals[id] === true }

  function toggleProposal(id) {
    var next = ({})
    for (var k in root.expandedProposals) next[k] = root.expandedProposals[k]
    next[id] = !next[id]
    root.expandedProposals = next
  }

  function scopeLabel(scope) {
    return root.service ? root.service.ignoreScopeLabel(scope) : String(scope || "")
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

      // ----------------------------------------------------------- proposals
      Column {
        width: parent.width
        spacing: Style.spacing.sm
        visible: root.proposals.length > 0

        PanelSectionHeader {
          text: "PROPOSALS · " + root.proposals.length + " recurring pattern"
                + (root.proposals.length === 1 ? "" : "s") + " to review"
          foreground: root.foreground
        }

        Text {
          width: parent.width
          text: "Each of these recurred often enough during normal use that moat would have learned it, had the learning window still been open. Accepting writes the block below to baseline.toml; dismissing leaves the alerts coming."
          color: root.mutedForeground
          font.family: Style.font.family
          font.pixelSize: Style.font.caption
          wrapMode: Text.WordWrap
        }

        Repeater {
          model: root.proposals

          delegate: Rectangle {
            id: proposalItem
            required property var modelData
            width: column.width
            height: proposalColumn.implicitHeight + Style.spacing.xl
            color: root.codeBackground
            radius: Style.cornerRadius

            Column {
              id: proposalColumn
              x: Style.spacing.rowPaddingX
              y: Style.spacing.md
              width: parent.width - Style.spacing.rowPaddingX * 2
              spacing: Style.spacing.xs

              Text {
                width: parent.width
                text: proposalItem.modelData.rule || "(unnamed rule)"
                color: root.foreground
                font.family: Style.font.family
                font.pixelSize: Style.font.subtitle
                font.bold: true
                elide: Text.ElideRight
              }

              Text {
                width: parent.width
                visible: text !== ""
                text: root.service ? root.service.proposalDetail(proposalItem.modelData) : ""
                color: root.mutedForeground
                font.family: Style.font.family
                font.pixelSize: Style.font.caption
                wrapMode: Text.WrapAnywhere
              }

              Row {
                spacing: Style.spacing.controlGap

                Button {
                  text: "Accept"
                  bordered: true
                  enabled: proposalItem.modelData.actionable
                  opacity: enabled ? 1 : 0.4
                  foreground: root.foreground
                  fontSize: Style.font.bodySmall
                  onClicked: root.acceptRequested(proposalItem.modelData.id)
                }

                Button {
                  text: "Dismiss"
                  bordered: true
                  enabled: proposalItem.modelData.actionable
                  opacity: enabled ? 1 : 0.4
                  foreground: root.mutedForeground
                  fontSize: Style.font.bodySmall
                  onClicked: root.dismissRequested(proposalItem.modelData.id)
                }

                Button {
                  visible: proposalItem.modelData.toml !== ""
                  text: root.isProposalExpanded(proposalItem.modelData.id) ? "Hide TOML" : "Show TOML"
                  foreground: root.mutedForeground
                  fontSize: Style.font.caption
                  onClicked: root.toggleProposal(proposalItem.modelData.id)
                }
              }

              Text {
                width: parent.width
                visible: root.isProposalExpanded(proposalItem.modelData.id)
                text: proposalItem.modelData.toml
                color: root.foreground
                font.family: Style.font.family
                font.pixelSize: Style.font.bodySmall
                wrapMode: Text.WrapAnywhere
                textFormat: Text.PlainText
              }

              // A proposal with no id cannot be acted on over the socket. Say
              // that instead of drawing two buttons that would do nothing.
              Text {
                width: parent.width
                visible: !proposalItem.modelData.actionable
                text: "This proposal arrived without an id, so it can only be accepted from the CLI (moatctl baseline list)."
                color: Color.urgent
                font.family: Style.font.family
                font.pixelSize: Style.font.caption
                wrapMode: Text.WordWrap
              }
            }
          }
        }
      }

      // ----------------------------------------------------- the two origins
      Repeater {
        model: [
          { key: "user", title: "YOUR RULES", rules: root.sections.user,
            empty: "No user allowlist rules. Rules you add from an alert's \"if this is expected\" block appear here." },
          { key: "learned", title: "LEARNED", rules: root.sections.learned,
            empty: "" },
          { key: "shipped", title: "SHIPPED WITH THE PACKAGE", rules: root.sections.shipped,
            empty: "" }
        ]

        delegate: Column {
          id: section
          required property var modelData
          width: column.width
          spacing: Style.spacing.sm
          visible: modelData.rules.length > 0 || modelData.empty !== ""

          PanelSectionHeader {
            text: section.modelData.title
                  + (section.modelData.rules.length > 0 ? " · " + section.modelData.rules.length : "")
            foreground: root.foreground
          }

          Text {
            width: parent.width
            visible: section.modelData.rules.length === 0 && text !== ""
              && (!root.service || root.service.allowlistError === "")
            text: section.modelData.empty
            color: root.mutedForeground
            font.family: Style.font.family
            font.pixelSize: Style.font.body
            wrapMode: Text.WordWrap
          }

          Repeater {
            model: section.modelData.rules

            delegate: Rectangle {
              id: ruleItem
              required property var modelData
              width: section.width
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
                      text: (ruleItem.modelData.removable ? "#" + ruleItem.modelData.index + "  " : "")
                        + (ruleItem.modelData.name || "(unnamed rule)")
                        + (ruleItem.modelData.learned ? "  ·  learned" : "")
                        + (ruleItem.modelData.scope ? "  ·  " + root.scopeLabel(ruleItem.modelData.scope) : "")
                      color: root.foreground
                      font.family: Style.font.family
                      font.pixelSize: Style.font.subtitle
                      font.bold: true
                      elide: Text.ElideRight
                    }

                    Text {
                      width: parent.width
                      visible: text !== ""
                      text: ruleItem.modelData.comment
                      color: root.mutedForeground
                      font.family: Style.font.family
                      font.pixelSize: Style.font.caption
                      wrapMode: Text.WordWrap
                    }

                    Text {
                      width: parent.width
                      visible: text !== ""
                      text: ruleItem.modelData.detail || ruleItem.modelData.line
                      color: root.foreground
                      font.family: Style.font.family
                      font.pixelSize: Style.font.bodySmall
                      wrapMode: Text.WrapAnywhere
                      textFormat: Text.PlainText
                    }

                    Text {
                      width: parent.width
                      visible: text !== ""
                      text: ruleItem.modelData.removable || !ruleItem.modelData.sourceFile
                        ? ""
                        : (ruleItem.modelData.shipped
                           ? "shipped in " + ruleItem.modelData.sourceFile
                             + " — the package owns it and replaces it on upgrade; add a narrower rule of your own to override it"
                           : "from " + ruleItem.modelData.sourceFile + " — edit that file to remove it")
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
                    visible: ruleItem.modelData.removable
                    bordered: true
                    foreground: Color.urgent
                    accent: Color.urgent
                    fontSize: Style.font.caption
                    onClicked: root.removeRequested(ruleItem.modelData.index,
                                                    ruleItem.modelData.sourceName)
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
