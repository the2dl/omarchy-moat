import QtQuick
import qs.Commons
import qs.Ui
import "MoatModel.js" as Model
import "MoatCopy.js" as Copy

// Rules (docs/design/README.md 1e, plus 2e and 2c folded in).
//
// Three things live here, in this order, and the order is the argument:
//
//   1. **Yours** -- what your own decisions silenced, with a count of what each
//      one has silenced SINCE. That count is the only way a person can tell
//      whether a rule they wrote was a good idea, so it gets a column.
//   2. **Programs Moat knows** (2e) -- the positive mirror. Rules lists what has
//      been silenced; this lists what is considered normal, which is the thing
//      you want to audit after a month of clicking "this was me".
//   3. **Came with Moat** -- sixteen near-identical shipped entries collapsed
//      into about five grouped lines. Four cards that differ only in a binary
//      path, each repeating the same sentence about upgrades, are a list
//      pretending to be cards. The upgrade caveat is stated ONCE, in the header.
//
// Quarantine was a tab (2c). It folds in here as "things Moat is holding",
// because on almost every machine on almost every day it was an empty tab.
Item {
  id: root

  property var service: null
  property var tokens: null
  property var incidents: []

  signal removeRequested(int index, string file)
  signal restoreRequested(string id)
  signal acceptRequested(string id)
  signal dismissRequested(string id)

  readonly property var t: root.tokens
  readonly property var rules: root.service ? root.service.allowlistRules : []
  readonly property var tuples: root.service ? root.service.baselineTuples : []
  readonly property var yours: Model.userRuleRows(root.rules, root.tuples)
  readonly property var shippedGroups: Model.shippedRuleGroups(root.rules)
  readonly property int shippedCount: {
    var n = 0
    for (var i = 0; i < root.shippedGroups.length; i++) n += root.shippedGroups[i].count
    return n
  }
  readonly property var programs: root.service
    ? Model.trustedPrograms(root.tuples, root.incidents) : []
  readonly property var held: root.service ? root.service.quarantineItems : []
  readonly property var proposals: root.service ? root.service.proposals : []
  // Bound through `status` on purpose: reading it is what makes this
  // re-evaluate when the daemon's answer changes after arming one.
  readonly property var enforceable: root.service && root.service.status
    ? root.service.enforceableRules() : []
  readonly property var contained: root.service && root.service.status
    ? root.service.containments() : []
  readonly property var exclusions: root.service && root.service.status
    ? root.service.exclusions() : []
  readonly property int armedCount: {
    var n = 0
    for (var i = 0; i < root.enforceable.length; i++) if (root.enforceable[i].armed) n++
    return n
  }

  property string openGroup: ""

  MoatScroll {
    anchors.fill: parent
    contentHeight: body.implicitHeight

    Column {
      id: body
      x: root.t ? root.t.bodyPadX : 0
      width: parent.width - (root.t ? root.t.bodyPadX * 2 : 0)
      topPadding: root.t ? root.t.bodyPadTop : 0
      bottomPadding: root.t ? root.t.bodyPadBottom : 0
      spacing: root.t ? root.t.v(34) : 16

      // ------------------------------------------------------------ heading
      Column {
        width: parent.width
        spacing: root.t ? root.t.s(9) : 6

        Text {
          width: parent.width
          text: "What Moat has been told to ignore"
          color: root.t ? root.t.primary : "white"
          font.family: root.t ? root.t.family : "monospace"
          font.pixelSize: root.t ? root.t.fHeading : 19
          font.weight: Font.Medium
          wrapMode: Text.WordWrap
          textFormat: Text.PlainText
        }

        Text {
          width: parent.width
          text: "Every time you say this was me, a line lands here. You can take any of them back."
          color: root.t ? root.t.muted : "grey"
          font.family: root.t ? root.t.family : "monospace"
          font.pixelSize: root.t ? root.t.fBody : 13
          lineHeight: root.t ? root.t.lhBody : 1.7
          wrapMode: Text.WordWrap
          textFormat: Text.PlainText
        }
      }

      // ------------------------------------------ holes the user opened on purpose
      //
      // A binary excluded from an armed rule is a hole in that rule, and it
      // lives inside a rendered policy under /run/moat that nobody will ever
      // open. If the panel does not show it, the only record is a line in
      // state.json -- so the machine would be quietly less protected than the
      // Rules screen claims, which is the exact thing this screen exists to
      // prevent.
      Column {
        width: parent.width
        visible: root.exclusions.length > 0
        spacing: root.t ? root.t.s(10) : 6

        PanelSectionHeader {
          text: "NOT WATCHED, BECAUSE YOU ALLOWED IT  \u00b7  " + root.exclusions.length
          foreground: root.t ? root.t.accent : "orange"
        }

        Repeater {
          model: root.exclusions

          delegate: Item {
            id: exRow
            required property var modelData
            width: parent.width
            implicitHeight: exText.implicitHeight + (root.t ? root.t.s(16) : 10)

            Column {
              id: exText
              anchors.left: parent.left
              anchors.verticalCenter: parent.verticalCenter
              width: parent.width - (root.t ? root.t.s(130) : 100)
              spacing: root.t ? root.t.s(3) : 2

              Text {
                width: parent.width
                text: Model.basename(exRow.modelData.exe) + " is not watched by "
                      + exRow.modelData.rule
                color: root.t ? root.t.body : "white"
                font.family: root.t ? root.t.family : "monospace"
                font.pixelSize: root.t ? root.t.fBody : 13
                elide: Text.ElideRight
                textFormat: Text.PlainText
              }

              Text {
                width: parent.width
                // Said plainly: the kernel can only exclude a program, not one
                // file for one program, so this is wider than the alert that
                // prompted it.
                text: exRow.modelData.exe
                      + " — for every path that rule watches, not just the one you allowed."
                color: root.t ? root.t.faint : "grey"
                font.family: root.t ? root.t.family : "monospace"
                font.pixelSize: root.t ? root.t.fMeta : 11
                wrapMode: Text.WordWrap
                textFormat: Text.PlainText
              }
            }

            Button {
              anchors.right: parent.right
              anchors.verticalCenter: parent.verticalCenter
              text: "Watch it again"
              foreground: root.t ? root.t.dimmer : "grey"
              fontSize: root.t ? root.t.fSecondary : 12
              enabled: !!root.service && !root.service.busy
              onClicked: if (root.service)
                root.service.watchAgain(exRow.modelData.rule, exRow.modelData.exe)
            }
          }
        }
      }

      // ------------------------------------------------- what Moat is refusing
      //
      // A containment is the only thing moat does without being asked rule by
      // rule, so it has to be visible and undoable in the place the user
      // already looks -- not in a log they have to be told to read.
      Column {
        width: parent.width
        visible: root.contained.length > 0
        spacing: root.t ? root.t.s(10) : 6

        PanelSectionHeader {
          text: "MOAT IS REFUSING THESE RIGHT NOW  \u00b7  " + root.contained.length
          foreground: root.t ? root.t.alarm : "red"
        }

        Repeater {
          model: root.contained

          delegate: Item {
            id: cRow
            required property var modelData
            width: parent.width
            implicitHeight: cText.implicitHeight + (root.t ? root.t.s(16) : 10)

            Column {
              id: cText
              anchors.left: parent.left
              anchors.verticalCenter: parent.verticalCenter
              width: parent.width - (root.t ? root.t.s(120) : 90)
              spacing: root.t ? root.t.s(3) : 2

              Text {
                width: parent.width
                text: Model.basename(cRow.modelData.exe) + " may not reach "
                      + cRow.modelData.dests.join(", ")
                color: root.t ? root.t.body : "white"
                font.family: root.t ? root.t.family : "monospace"
                font.pixelSize: root.t ? root.t.fBody : 13
                elide: Text.ElideRight
                textFormat: Text.PlainText
              }

              Text {
                width: parent.width
                text: "its connections fail; it is still running. Ends on its own."
                color: root.t ? root.t.faint : "grey"
                font.family: root.t ? root.t.family : "monospace"
                font.pixelSize: root.t ? root.t.fMeta : 11
                wrapMode: Text.WordWrap
                textFormat: Text.PlainText
              }
            }

            Button {
              anchors.right: parent.right
              anchors.verticalCenter: parent.verticalCenter
              text: "Let it through"
              foreground: root.t ? root.t.dimmer : "grey"
              fontSize: root.t ? root.t.fSecondary : 12
              enabled: !!root.service && !root.service.busy
              onClicked: if (root.service) root.service.releaseContainment(cRow.modelData.chain)
            }
          }
        }
      }

      // ------------------------------------------- what Moat is allowed to stop
      //
      // Arming is per rule and never global. `moatctl set --rule` calls that
      // the safe way to start enforcing -- one rule whose false-positive
      // surface you have already measured -- and a switch that armed
      // everything at once is not something anybody should be handed.
      //
      // Only rules whose policy carries an enforcing action appear here, and
      // the daemon decides which those are: the panel never works out what is
      // enforceable, it asks. Each row says which of the two things arming it
      // does, because "kill the program" and "refuse the call" are different
      // promises and one label for both would be a lie about one of them.
      Column {
        width: parent.width
        visible: root.enforceable.length > 0
        spacing: root.t ? root.t.s(10) : 6

        PanelSectionHeader {
          text: "WHAT MOAT IS ALLOWED TO STOP  \u00b7  " + root.armedCount
                + " of " + root.enforceable.length
        }

        Text {
          width: parent.width
          text: "Everything else is watched and reported only. Arm one at a time, "
                + "and only after you have seen how often it fires here."
          color: root.t ? root.t.dimmer : "grey"
          font.family: root.t ? root.t.family : "monospace"
          font.pixelSize: root.t ? root.t.fSecondary : 12
          lineHeight: root.t ? root.t.lhBody : 1.6
          wrapMode: Text.WordWrap
          textFormat: Text.PlainText
        }

        Repeater {
          model: root.enforceable

          delegate: Item {
            id: armRow
            required property var modelData
            width: parent.width
            implicitHeight: armText.implicitHeight + (root.t ? root.t.s(16) : 10)

            Column {
              id: armText
              anchors.left: parent.left
              anchors.verticalCenter: parent.verticalCenter
              width: parent.width - (root.t ? root.t.s(150) : 110)
              spacing: root.t ? root.t.s(3) : 2

              Text {
                width: parent.width
                text: armRow.modelData.title
                color: root.t ? root.t.body : "white"
                font.family: root.t ? root.t.family : "monospace"
                font.pixelSize: root.t ? root.t.fBody : 13
                elide: Text.ElideRight
                textFormat: Text.PlainText
              }

              Text {
                width: parent.width
                text: Copy.enforceConsequence(armRow.modelData.enforce)
                color: root.t ? root.t.faint : "grey"
                font.family: root.t ? root.t.family : "monospace"
                font.pixelSize: root.t ? root.t.fMeta : 11
                wrapMode: Text.WordWrap
                textFormat: Text.PlainText
              }
            }

            Text {
              anchors.right: armSwitch.left
              anchors.rightMargin: root.t ? root.t.s(10) : 8
              anchors.verticalCenter: parent.verticalCenter
              text: Copy.enforceState(armRow.modelData.armed, armRow.modelData.enforce)
              color: armRow.modelData.armed ? (root.t ? root.t.accent : "orange")
                                            : (root.t ? root.t.faint : "grey")
              font.family: root.t ? root.t.family : "monospace"
              font.pixelSize: root.t ? root.t.fSecondary : 12
              textFormat: Text.PlainText
            }

            ToggleSwitch {
              id: armSwitch
              anchors.right: parent.right
              anchors.verticalCenter: parent.verticalCenter
              checked: armRow.modelData.armed === true
              busy: !!root.service && root.service.busy
              foreground: root.t ? root.t.secondary : "white"
              accent: root.t ? root.t.accent : "orange"
              trackHeight: root.t ? root.t.s(23) : 18
              onToggled: {
                if (!root.service) return
                root.service.setRuleMode(armRow.modelData.rule,
                                         armRow.modelData.armed ? "monitor" : "enforce")
              }
            }
          }
        }
      }

      // ------------------------------------------------------- what is waiting
      //
      // A baseline proposal is the same decision one step earlier: the daemon
      // saw a pattern recur and is asking before it writes anything. It sits
      // above "Yours" because it is the only thing on this screen that is
      // asking for something.
      Column {
        width: parent.width
        visible: root.proposals.length > 0
        spacing: root.t ? root.t.s(10) : 6

        PanelSectionHeader {
          text: "WAITING FOR YOU TO SAY YES  ·  " + root.proposals.length
          foreground: root.t ? root.t.accent : "orange"
        }

        Repeater {
          model: root.proposals

          delegate: Rectangle {
            required property var modelData
            width: body.width
            implicitHeight: proposalCol.implicitHeight + (root.t ? root.t.smallCardPadY * 2 : 16)
            radius: root.t ? root.t.rCard : 0
            color: root.t ? root.t.card : "transparent"
            border.width: 1
            border.color: root.t ? root.t.accentTint(0.24) : "transparent"

            Column {
              id: proposalCol
              x: root.t ? root.t.smallCardPadX : 8
              y: root.t ? root.t.smallCardPadY : 8
              width: parent.width - (root.t ? root.t.smallCardPadX * 2 : 16)
              spacing: root.t ? root.t.s(7) : 4

              Text {
                width: parent.width
                text: Model.basename(modelData.exe) + " keeps doing this — stop asking?"
                color: root.t ? root.t.body : "white"
                font.family: root.t ? root.t.family : "monospace"
                font.pixelSize: root.t ? root.t.fBody : 13
                wrapMode: Text.WordWrap
                textFormat: Text.PlainText
              }

              Text {
                width: parent.width
                text: modelData.count + (modelData.count === 1 ? " time" : " times")
                      + " on " + modelData.days + (modelData.days === 1 ? " day" : " days")
                      + "  ·  " + Model.ruleScopeWords(modelData.rule, modelData.dir)
                color: root.t ? root.t.dimmer : "grey"
                font.family: root.t ? root.t.family : "monospace"
                font.pixelSize: root.t ? root.t.fSecondary : 12
                wrapMode: Text.WordWrap
                textFormat: Text.PlainText
              }

              Row {
                spacing: root.t ? root.t.s(10) : 6

                Button {
                  text: "Stop asking"
                  background: root.t ? root.t.accent : "orange"
                  foreground: root.t ? root.t.accentLabel : "black"
                  fontSize: root.t ? root.t.fBody : 13
                  enabled: modelData.actionable
                  onClicked: root.acceptRequested(modelData.id)
                }

                Button {
                  text: "Keep asking"
                  foreground: root.t ? root.t.dimmer : "grey"
                  fontSize: root.t ? root.t.fSecondary : 12
                  enabled: modelData.actionable
                  onClicked: root.dismissRequested(modelData.id)
                }
              }
            }
          }
        }
      }

      // ------------------------------------------------------------- Yours
      //
      // First, deliberately: these are the only rules on the screen anybody
      // chose, and the only ones that can be taken back from here.
      Column {
        width: parent.width
        spacing: root.t ? root.t.s(10) : 6

        PanelSectionHeader {
          text: "YOURS  ·  " + root.yours.length
          foreground: root.t ? root.t.fainter : "grey"
        }

        Text {
          width: parent.width
          visible: root.yours.length === 0
          text: "Nothing yet. The first time you say this was me, the line it writes lands here."
          color: root.t ? root.t.faint : "grey"
          font.family: root.t ? root.t.family : "monospace"
          font.pixelSize: root.t ? root.t.fSecondary : 12
          wrapMode: Text.WordWrap
          textFormat: Text.PlainText
        }

        Repeater {
          model: root.yours

          delegate: Rectangle {
            required property var modelData
            width: body.width
            implicitHeight: yoursRow.implicitHeight + (root.t ? root.t.smallCardPadY * 2 : 16)
            radius: root.t ? root.t.rCard : 0
            color: root.t ? root.t.card : "transparent"

            Item {
              id: yoursRow
              x: root.t ? root.t.smallCardPadX : 8
              y: root.t ? root.t.smallCardPadY : 8
              width: parent.width - (root.t ? root.t.smallCardPadX * 2 : 16)
              implicitHeight: Math.max(yoursTitle.implicitHeight, undoButton.implicitHeight)

              Column {
                id: yoursTitle
                anchors.left: parent.left
                anchors.verticalCenter: parent.verticalCenter
                width: parent.width - (root.t ? root.t.s(360) : 300)
                spacing: root.t ? root.t.s(4) : 2

                Text {
                  width: parent.width
                  text: modelData.label
                  color: root.t ? root.t.primary : "white"
                  font.family: root.t ? root.t.family : "monospace"
                  font.pixelSize: root.t ? root.t.fBody : 13
                  elide: Text.ElideRight
                  textFormat: Text.PlainText
                }

                Text {
                  width: parent.width
                  visible: text !== ""
                  text: modelData.provenance
                  color: root.t ? root.t.faint : "grey"
                  font.family: root.t ? root.t.family : "monospace"
                  font.pixelSize: root.t ? root.t.fMeta : 11
                  elide: Text.ElideRight
                  textFormat: Text.PlainText
                }
              }

              Text {
                anchors.right: silenced.left
                anchors.rightMargin: root.t ? root.t.s(16) : 10
                anchors.verticalCenter: parent.verticalCenter
                width: root.t ? root.t.s(150) : 120
                text: modelData.binary
                color: root.t ? root.t.fainter : "grey"
                font.family: root.t ? root.t.family : "monospace"
                font.pixelSize: root.t ? root.t.fMeta : 11
                elide: Text.ElideMiddle
                textFormat: Text.PlainText
              }

              // The one column that says whether this rule was a good idea.
              Text {
                id: silenced
                anchors.right: undoButton.left
                anchors.rightMargin: root.t ? root.t.s(16) : 10
                anchors.verticalCenter: parent.verticalCenter
                width: root.t ? root.t.s(130) : 100
                horizontalAlignment: Text.AlignRight
                text: modelData.silenced < 0 ? "not counted"
                  : "silenced " + modelData.silenced + " since"
                color: root.t ? root.t.faint : "grey"
                font.family: root.t ? root.t.family : "monospace"
                font.pixelSize: root.t ? root.t.fMeta : 11
                textFormat: Text.PlainText
              }

              Button {
                id: undoButton
                anchors.right: parent.right
                anchors.verticalCenter: parent.verticalCenter
                text: "Undo"
                foreground: root.t ? root.t.accent : "orange"
                fontSize: root.t ? root.t.fSecondary : 12
                enabled: modelData.removable
                opacity: enabled ? 1 : 0.4
                onClicked: root.removeRequested(modelData.index, modelData.file)
              }
            }
          }
        }
      }

      // ------------------------------------------- programs Moat knows (2e)
      Column {
        width: parent.width
        visible: root.programs.length > 0
        spacing: root.t ? root.t.s(10) : 6

        // The two right-hand columns have no headers of their own, the way a
        // table would give them: the section's own meta line names them once,
        // which is what lets the rows drop the word "alerts" eight times over.
        Item {
          width: parent.width
          implicitHeight: programsHeader.implicitHeight

          PanelSectionHeader {
            id: programsHeader
            anchors.left: parent.left
            text: root.programs.length + " PROGRAMS MOAT TREATS AS YOURS"
            foreground: root.t ? root.t.fainter : "grey"
          }

          Text {
            anchors.right: parent.right
            anchors.verticalCenter: programsHeader.verticalCenter
            text: "last seen  ·  alerts silenced since"
            color: root.t ? root.t.ghost : "grey"
            font.family: root.t ? root.t.family : "monospace"
            font.pixelSize: root.t ? root.t.fMeta : 11
            textFormat: Text.PlainText
          }
        }

        Text {
          width: parent.width
          text: "Learned during the first week, or added when you said this was me. Each one is only trusted for the things next to it."
          color: root.t ? root.t.dimmer : "grey"
          font.family: root.t ? root.t.family : "monospace"
          font.pixelSize: root.t ? root.t.fSecondary : 12
          lineHeight: root.t ? root.t.lhBody : 1.7
          wrapMode: Text.WordWrap
          textFormat: Text.PlainText
          bottomPadding: root.t ? root.t.s(7) : 4
        }

        Repeater {
          model: root.programs

          delegate: Item {
            required property var modelData
            width: body.width
            implicitHeight: (root.t ? root.t.rowPadY * 2 : 12) + programRow.implicitHeight

            Rectangle {
              anchors.top: parent.top
              width: parent.width
              height: 1
              color: root.t ? root.t.hairlineRow : "transparent"
            }

            // A program with an incident waiting on the user is the most useful
            // row on the screen: it is the one that is NOT trusted for anything
            // yet, sitting in the list of things that are.
            Rectangle {
              anchors.fill: parent
              visible: modelData.open
              color: root.t ? root.t.accentTint(0.04) : "transparent"
            }

            Item {
              id: programRow
              anchors.verticalCenter: parent.verticalCenter
              width: parent.width
              implicitHeight: Math.max(programName.implicitHeight, programScope.implicitHeight)

              Text {
                id: programName
                anchors.left: parent.left
                anchors.verticalCenter: parent.verticalCenter
                // Wide enough for the longest thing a program is actually
                // called. At 200 the agent wrappers truncated mid-word
                // ("omarchy-agent-usage-clau…"), which is the one cell on the
                // row where the tail is the part that identifies it.
                width: root.t ? root.t.s(250) : 200
                text: modelData.program
                color: root.t ? root.t.body : "white"
                font.family: root.t ? root.t.family : "monospace"
                font.pixelSize: root.t ? root.t.fBody : 13
                elide: Text.ElideRight
                textFormat: Text.PlainText
              }

              Text {
                id: programScope
                anchors.left: programName.right
                anchors.leftMargin: root.t ? root.t.s(16) : 10
                anchors.right: programSeen.left
                anchors.rightMargin: root.t ? root.t.s(16) : 10
                anchors.verticalCenter: parent.verticalCenter
                text: modelData.scope
                // Accent only when the cell is the "trusted for nothing yet"
                // line. A real permission is a fact, not a warning.
                color: modelData.trusted ? (root.t ? root.t.dimmer : "grey")
                                         : (root.t ? root.t.accent : "orange")
                font.family: root.t ? root.t.family : "monospace"
                font.pixelSize: root.t ? root.t.fSecondary : 12
                elide: Text.ElideRight
                wrapMode: Text.WordWrap
                maximumLineCount: 2
                textFormat: Text.PlainText
              }

              Text {
                id: programSeen
                anchors.right: programSilenced.left
                anchors.rightMargin: root.t ? root.t.s(16) : 10
                anchors.verticalCenter: parent.verticalCenter
                width: root.t ? root.t.s(150) : 110
                horizontalAlignment: Text.AlignRight
                text: root.service ? root.service.relativeTime(modelData.lastSeen) : ""
                color: root.t ? root.t.fainter : "grey"
                font.family: root.t ? root.t.family : "monospace"
                font.pixelSize: root.t ? root.t.fMeta : 11
                textFormat: Text.PlainText
              }

              Text {
                id: programSilenced
                anchors.right: parent.right
                anchors.verticalCenter: parent.verticalCenter
                width: root.t ? root.t.s(110) : 90
                horizontalAlignment: Text.AlignRight
                // The unit is stated once in the section's meta line, so the
                // cell is a number. Repeated down eight rows, "alerts" was the
                // widest thing in the column and the least informative.
                text: modelData.silenced > 0 ? String(modelData.silenced) : "—"
                color: root.t ? root.t.faint : "grey"
                font.family: root.t ? root.t.family : "monospace"
                font.pixelSize: root.t ? root.t.fMeta : 11
                textFormat: Text.PlainText
              }
            }
          }
        }

        // The thing that stops this list becoming a hole.
        Rectangle {
          width: parent.width
          implicitHeight: pinnedText.implicitHeight + (root.t ? root.t.smallCardPadY * 2 : 16)
          radius: root.t ? root.t.rCard : 0
          color: root.t ? root.t.card : "transparent"

          Text {
            id: pinnedText
            x: root.t ? root.t.smallCardPadX : 8
            y: root.t ? root.t.smallCardPadY : 8
            width: parent.width - (root.t ? root.t.smallCardPadX * 2 : 16)
            text: "Trust is pinned to the file itself. If one of these is replaced — by an upgrade or by anything else — it comes back as a new program and you will hear about it once."
            color: root.t ? root.t.dimmer : "grey"
            font.family: root.t ? root.t.family : "monospace"
            font.pixelSize: root.t ? root.t.fSecondary : 12
            lineHeight: root.t ? root.t.lhBody : 1.7
            wrapMode: Text.WordWrap
            textFormat: Text.PlainText
          }
        }
      }

      // ------------------------------------------------ things Moat is holding
      //
      // 2c. This was its own tab, and on almost every machine on almost every
      // day it was an empty one. It belongs beside the rules because both
      // answer "what has Moat done on my behalf, and can I undo it".
      Column {
        width: parent.width
        visible: root.held.length > 0
        spacing: root.t ? root.t.s(10) : 6

        PanelSectionHeader {
          text: "THINGS MOAT IS HOLDING  ·  " + root.held.length
          foreground: root.t ? root.t.fainter : "grey"
        }

        Repeater {
          model: root.held

          delegate: Item {
            required property var modelData
            width: body.width
            implicitHeight: (root.t ? root.t.rowPadY * 2 : 12) + heldRow.implicitHeight

            Rectangle {
              anchors.top: parent.top
              width: parent.width
              height: 1
              color: root.t ? root.t.hairlineRow : "transparent"
            }

            Item {
              id: heldRow
              anchors.verticalCenter: parent.verticalCenter
              width: parent.width
              implicitHeight: heldText.implicitHeight

              Column {
                id: heldText
                anchors.left: parent.left
                anchors.verticalCenter: parent.verticalCenter
                width: parent.width - (root.t ? root.t.s(220) : 180)
                spacing: root.t ? root.t.s(4) : 2

                Text {
                  width: parent.width
                  text: Model.basename(modelData.originalPath)
                  color: root.t ? root.t.body : "white"
                  font.family: root.t ? root.t.family : "monospace"
                  font.pixelSize: root.t ? root.t.fBody : 13
                  elide: Text.ElideMiddle
                  textFormat: Text.PlainText
                }

                Text {
                  width: parent.width
                  text: {
                    var bits = []
                    var dir = String(modelData.originalPath || "")
                    var cut = dir.lastIndexOf("/")
                    if (cut > 0) bits.push("taken from " + Model.shortenHome(dir.slice(0, cut)))
                    var age = root.service ? root.service.relativeTime(modelData.when) : ""
                    if (age) bits.push(age)
                    if (!modelData.present) bits.push("no longer where Moat put it")
                    return bits.join("  ·  ")
                  }
                  color: modelData.present ? (root.t ? root.t.faint : "grey")
                                           : (root.t ? root.t.alarm : "red")
                  font.family: root.t ? root.t.family : "monospace"
                  font.pixelSize: root.t ? root.t.fMeta : 11
                  elide: Text.ElideMiddle
                  textFormat: Text.PlainText
                }
              }

              Text {
                anchors.right: restoreButton.left
                anchors.rightMargin: root.t ? root.t.s(16) : 10
                anchors.verticalCenter: parent.verticalCenter
                width: root.t ? root.t.s(90) : 70
                horizontalAlignment: Text.AlignRight
                text: modelData.bytes >= 0 && root.service
                  ? root.service.formatBytes(modelData.bytes) : ""
                color: root.t ? root.t.fainter : "grey"
                font.family: root.t ? root.t.family : "monospace"
                font.pixelSize: root.t ? root.t.fMeta : 11
                textFormat: Text.PlainText
              }

              Button {
                id: restoreButton
                anchors.right: parent.right
                anchors.verticalCenter: parent.verticalCenter
                text: "Restore"
                foreground: root.t ? root.t.accent : "orange"
                fontSize: root.t ? root.t.fSecondary : 12
                enabled: modelData.present
                opacity: enabled ? 1 : 0.4
                onClicked: root.restoreRequested(modelData.id)
              }
            }
          }
        }

        Rectangle {
          width: parent.width
          implicitHeight: heldNote.implicitHeight + (root.t ? root.t.smallCardPadY * 2 : 16)
          radius: root.t ? root.t.rCard : 0
          color: root.t ? root.t.card : "transparent"

          Text {
            id: heldNote
            x: root.t ? root.t.smallCardPadX : 8
            y: root.t ? root.t.smallCardPadY : 8
            width: parent.width - (root.t ? root.t.smallCardPadX * 2 : 16)
            text: "Held files cannot run from where they are. Nothing is deleted — Restore puts a file back where it came from, and Moat refuses if something else has taken the name or if the bytes changed while it was held."
            color: root.t ? root.t.dimmer : "grey"
            font.family: root.t ? root.t.family : "monospace"
            font.pixelSize: root.t ? root.t.fSecondary : 12
            lineHeight: root.t ? root.t.lhBody : 1.7
            wrapMode: Text.WordWrap
            textFormat: Text.PlainText
          }
        }
      }

      // ------------------------------------------------------ came with Moat
      Column {
        width: parent.width
        visible: root.shippedGroups.length > 0
        spacing: root.t ? root.t.s(10) : 6

        Item {
          width: parent.width
          implicitHeight: shippedHeader.implicitHeight

          PanelSectionHeader {
            id: shippedHeader
            anchors.left: parent.left
            text: "CAME WITH MOAT  ·  " + root.shippedCount
            foreground: root.t ? root.t.fainter : "grey"
          }

          // The caveat, once, where 1e puts it.
          Text {
            anchors.right: parent.right
            anchors.verticalCenter: shippedHeader.verticalCenter
            text: "grouped by what they cover  ·  replaced on upgrade"
            color: root.t ? root.t.ghost : "grey"
            font.family: root.t ? root.t.family : "monospace"
            font.pixelSize: root.t ? root.t.fMeta : 11
            textFormat: Text.PlainText
          }
        }

        Repeater {
          model: root.shippedGroups

          delegate: Column {
            required property var modelData
            width: body.width
            spacing: 0

            Item {
              width: parent.width
              implicitHeight: (root.t ? root.t.rowPadY * 2 : 12) + groupRow.implicitHeight

              Rectangle {
                anchors.top: parent.top
                width: parent.width
                height: 1
                color: root.t ? root.t.hairlineRow : "transparent"
              }

              Rectangle {
                anchors.fill: parent
                color: groupMouse.containsMouse
                  ? (root.t ? root.t.hair(0.03) : "transparent") : "transparent"
                radius: root.t ? root.t.rChipSmall : 0
              }

              Item {
                id: groupRow
                anchors.verticalCenter: parent.verticalCenter
                width: parent.width
                implicitHeight: Math.max(groupLabel.implicitHeight, groupReason.implicitHeight)

                Text {
                  id: groupLabel
                  anchors.left: parent.left
                  anchors.verticalCenter: parent.verticalCenter
                  width: root.t ? root.t.s(260) : 200
                  text: modelData.label
                  color: root.t ? root.t.body : "white"
                  font.family: root.t ? root.t.family : "monospace"
                  font.pixelSize: root.t ? root.t.fBody : 13
                  elide: Text.ElideRight
                  textFormat: Text.PlainText
                }

                Text {
                  id: groupReason
                  anchors.left: groupLabel.right
                  anchors.leftMargin: root.t ? root.t.s(16) : 10
                  anchors.right: groupCount.left
                  anchors.rightMargin: root.t ? root.t.s(16) : 10
                  anchors.verticalCenter: parent.verticalCenter
                  text: modelData.reason
                  color: root.t ? root.t.dimmer : "grey"
                  font.family: root.t ? root.t.family : "monospace"
                  font.pixelSize: root.t ? root.t.fSecondary : 12
                  elide: Text.ElideRight
                  wrapMode: Text.WordWrap
                  maximumLineCount: 2
                  textFormat: Text.PlainText
                }

                Text {
                  id: groupCount
                  anchors.right: groupChevron.left
                  anchors.rightMargin: root.t ? root.t.s(10) : 6
                  anchors.verticalCenter: parent.verticalCenter
                  width: root.t ? root.t.s(90) : 70
                  horizontalAlignment: Text.AlignRight
                  text: modelData.count + (modelData.count === 1 ? " rule" : " rules")
                  color: root.t ? root.t.faint : "grey"
                  font.family: root.t ? root.t.family : "monospace"
                  font.pixelSize: root.t ? root.t.fMeta : 11
                  textFormat: Text.PlainText
                }

                Text {
                  id: groupChevron
                  anchors.right: parent.right
                  anchors.verticalCenter: parent.verticalCenter
                  width: root.t ? root.t.s(22) : 16
                  horizontalAlignment: Text.AlignRight
                  text: root.openGroup === modelData.key ? "⌄" : "›"
                  color: root.t ? root.t.ghost : "grey"
                  font.family: root.t ? root.t.family : "monospace"
                  font.pixelSize: root.t ? root.t.fBody : 13
                }
              }

              MouseArea {
                id: groupMouse
                anchors.fill: parent
                hoverEnabled: true
                cursorShape: Qt.PointingHandCursor
                onClicked: root.openGroup = root.openGroup === modelData.key ? "" : modelData.key
              }
            }

            // Opened, the group is what it always was: the individual entries,
            // with the exact block each one is. Present, one click away, never
            // in the reading path.
            Column {
              width: parent.width
              visible: root.openGroup === modelData.key
              leftPadding: root.t ? root.t.s(20) : 12
              topPadding: root.t ? root.t.s(9) : 6
              bottomPadding: root.t ? root.t.s(9) : 6
              spacing: root.t ? root.t.s(7) : 4

              Repeater {
                model: modelData.rules

                delegate: Text {
                  required property var modelData
                  width: body.width - (root.t ? root.t.s(20) : 12)
                  text: Model.ruleProgram(modelData) + "  ·  "
                        + Model.ruleScopeWords(modelData.name, modelData.path || "")
                        + "\n" + modelData.sourceName + "  ·  " + modelData.name
                  color: root.t ? root.t.faint : "grey"
                  font.family: root.t ? root.t.family : "monospace"
                  font.pixelSize: root.t ? root.t.fMeta : 11
                  lineHeight: root.t ? root.t.lhMeta : 1.6
                  wrapMode: Text.WrapAnywhere
                  textFormat: Text.PlainText
                }
              }
            }
          }
        }
      }

      // The daemon's own complaint, if it had one. Kept last and quiet: it is
      // about the machine, not about a decision.
      Text {
        width: parent.width
        visible: text !== ""
        text: root.service ? String(root.service.allowlistError || "") : ""
        color: root.t ? root.t.alarm : "red"
        font.family: root.t ? root.t.family : "monospace"
        font.pixelSize: root.t ? root.t.fMeta : 11
        wrapMode: Text.WordWrap
        textFormat: Text.PlainText
      }
    }
  }
}
