import QtQuick
import qs.Commons
import qs.Ui
import "MoatModel.js" as Model
import "MoatCopy.js" as Copy

// The sequence (docs/design/README.md 2b "What led here", 3a "a chain, not
// four alerts").
//
// This is the case the product exists for. moatd correlates alerts that share
// a process tree and cross detection families into one chain and writes it onto
// every member as `alert.chain`; `MoatModel.buildIncidents` collapses those
// members into ONE incident, and this is that incident's story.
//
// 2b's rail-and-dot layout: a right-aligned time, a dot over a connector, the
// step and what it costs you, and 3a's fourth column saying what has already
// happened to it. Times are clock times, not "2 minutes ago" -- a chain spans
// seconds, so relative ages would make every step read the same and the
// sequence, which is the whole point of the screen, would be invisible.
//
// Two rules this block exists to keep:
//
//   * The severity is NEVER shown without `severity_reason` (CONTRACT 4). It
//     goes through `Model.chainSeverityLine`, which returns "" rather than a
//     bare number, so the daemon's "it did not escalate, and here is why" can
//     never be dropped on the way to the screen.
//   * A `context` step -- one the user had already allowed, or one the noise
//     guard demoted -- is shown but never as an accusation. It is in the story
//     because that is what makes the story readable, and it did not create the
//     chain.
//
// Everything here is process-derived or daemon-written, so everything here is
// PlainText.
Column {
  id: root

  property var tokens: null
  property var service: null
  /// The incident from Model.buildIncidents. Renders nothing unless it is one.
  property var incident: null

  /// 2b: "same chain, same decision". One ack closes every step.
  signal allowChain(string id)

  readonly property var t: root.tokens
  readonly property var chain: root.incident && root.incident.chain ? root.incident.chain : null
  readonly property var story: root.incident && root.incident.story ? root.incident.story : []
  readonly property bool raw: !!root.service && root.service.rawDetail === true
  /// "" when the daemon sent no reason, and then nothing prints: a chain
  /// severity with no reason beside it is the one shape the contract forbids.
  readonly property string severityLine: Model.chainSeverityLine(root.chain)

  visible: !!root.chain
  spacing: root.t ? root.t.s(12) : 8

  // The date is stated here and nowhere else: every step below prints a clock
  // time, and without this the whole sequence had no day attached to it.
  Text {
    text: {
      var day = Model.chainDay(root.chain)
      return day ? "WHAT HAPPENED, IN ORDER  \u00b7  " + day.toUpperCase()
                 : "WHAT HAPPENED, IN ORDER"
    }
    color: root.t ? root.t.fainter : "grey"
    font.family: root.t ? root.t.family : "monospace"
    font.pixelSize: root.t ? root.t.fMeta : 11
    font.letterSpacing: root.t ? root.t.lsLabel : 0
  }

  // The daemon's own sentence about the severity of the sequence, verbatim.
  // It is the only place a chain's severity appears, and it appears with the
  // reason attached or not at all.
  Text {
    width: parent.width
    visible: root.severityLine !== ""
    text: "As a sequence: " + root.severityLine
    color: root.t ? root.t.dimmer : "grey"
    font.family: root.t ? root.t.family : "monospace"
    font.pixelSize: root.t ? root.t.fMeta : 11
    lineHeight: root.t ? root.t.lhMeta : 1.6
    wrapMode: Text.WordWrap
    textFormat: Text.PlainText
  }

  Repeater {
    model: root.story

    delegate: Item {
      required property var modelData
      required property int index
      width: root.width
      implicitHeight: stepText.implicitHeight + (root.t ? root.t.s(18) : 12)

      readonly property int railX: root.t ? root.t.s(84) : 62

      // The rail: a dot per step over a connector down to the next one.
      Rectangle {
        x: parent.railX
        y: 0
        width: 1
        height: parent.height
        visible: index < root.story.length - 1
        color: root.t ? root.t.hair(0.08) : "transparent"
      }

      // A trigger step carries the alarm colour; a context step -- something
      // the user had already allowed -- is the same neutral dot 2b gives a
      // benign step, because it is there for the story and not as a charge.
      Rectangle {
        x: parent.railX - (root.t ? root.t.s(4) : 3)
        y: root.t ? root.t.s(4) : 3
        width: root.t ? root.t.s(9) : 7
        height: width
        radius: width / 2
        color: modelData.isContext ? (root.t ? root.t.ghost : "grey")
                                   : (root.t ? root.t.alarm : "red")
      }

      Text {
        x: 0
        y: root.t ? root.t.s(3) : 2
        width: root.t ? root.t.s(74) : 56
        horizontalAlignment: Text.AlignRight
        text: modelData.time
        color: root.t ? root.t.fainter : "grey"
        font.family: root.t ? root.t.family : "monospace"
        font.pixelSize: root.t ? root.t.fMeta : 11
        textFormat: Text.PlainText
      }

      Column {
        id: stepText
        x: root.t ? root.t.s(104) : 78
        width: parent.width - x - (root.t ? root.t.s(136) : 100)
        spacing: root.t ? root.t.s(4) : 2

        Text {
          width: parent.width
          text: modelData.title
          // The step the reader arrived on is the bright one, so landing on
          // the `.git/config` alert and reading the sequence still says which
          // line was the one they clicked.
          color: modelData.isContext ? (root.t ? root.t.secondary : "white")
                                     : (root.t ? root.t.primary : "white")
          font.family: root.t ? root.t.family : "monospace"
          font.pixelSize: root.t ? root.t.fBody : 13
          wrapMode: Text.WordWrap
          maximumLineCount: 2
          elide: Text.ElideRight
          textFormat: Text.PlainText
        }

        Text {
          width: parent.width
          visible: text !== ""
          text: {
            var note = String(modelData.note || "")
            if (!modelData.isCurrent) return note
            // Which step the card's own buttons and evidence are about. A
            // chain is one incident but the actions still name one alert id
            // (CONTRACT 5), and saying which is the difference between an
            // honest button and a surprising one.
            var here = "the step the buttons below act on"
            return note ? note + "  ·  " + here : here
          }
          color: root.t ? root.t.faint : "grey"
          font.family: root.t ? root.t.family : "monospace"
          font.pixelSize: root.t ? root.t.fMeta : 11
          wrapMode: Text.WordWrap
          maximumLineCount: 2
          elide: Text.ElideRight
          textFormat: Text.PlainText
        }
      }

      Text {
        anchors.right: parent.right
        y: root.t ? root.t.s(3) : 2
        width: root.t ? root.t.s(130) : 96
        horizontalAlignment: Text.AlignRight
        text: modelData.status.label
        color: {
          if (!root.t) return "grey"
          switch (modelData.status.tone) {
          case "accent":
            return root.t.accent
          case "calm":
            return root.t.calm
          default:
            return root.t.faint
          }
        }
        font.family: root.t ? root.t.family : "monospace"
        font.pixelSize: root.t ? root.t.fMeta : 11
        elide: Text.ElideRight
        textFormat: Text.PlainText
      }
    }
  }

  // The correlator keeps a bounded number of steps per chain, so a long one is
  // truncated on the daemon's side and says so rather than quietly showing a
  // shorter story than happened.
  Text {
    width: parent.width
    visible: !!root.chain && root.chain.truncated
    text: root.chain
      ? "… " + Math.max(0, root.chain.steps_total - root.chain.steps.length)
        + " more not shown"
      : ""
    color: root.t ? root.t.ghost : "grey"
    font.family: root.t ? root.t.family : "monospace"
    font.pixelSize: root.t ? root.t.fMeta : 11
    textFormat: Text.PlainText
  }

  // 2b's closing card: one cause covers several alerts, and one decision
  // closes all of them.
  Rectangle {
    width: parent.width
    implicitHeight: closing.implicitHeight + (root.t ? root.t.smallCardPadY * 2 : 16)
    radius: root.t ? root.t.rCard : 0
    // One surface step further in than the incident card this sits inside. 2b
    // draws the closing card on the panel, where `card` reads as a card; here
    // it is a card on a card, and `card` on `card` is an invisible boundary.
    color: root.t ? root.t.chip : "transparent"

    Column {
      id: closing
      x: root.t ? root.t.smallCardPadX : 8
      y: root.t ? root.t.smallCardPadY : 8
      width: parent.width - (root.t ? root.t.smallCardPadX * 2 : 16)
      spacing: root.t ? root.t.s(10) : 6

      Text {
        width: parent.width
        text: Copy.chainClosingLine(root.chain)
        color: root.t ? root.t.body : "white"
        font.family: root.t ? root.t.family : "monospace"
        font.pixelSize: root.t ? root.t.fSecondary : 12
        lineHeight: root.t ? root.t.lhBody : 1.7
        wrapMode: Text.WordWrap
        textFormat: Text.PlainText
      }

      // NOT "allow". CONTRACT 5's chain verb is `ack --chain`, which marks the
      // sequence seen; it writes no rule and silences nothing in future. The
      // design calls this "Allow the whole chain" because in its world the two
      // are the same button -- here they are not, and the label says which one
      // this is.
      Button {
        text: "Close the whole sequence"
        tooltipText: "Marks every step of this sequence as seen. It writes no rule and silences nothing later."
        bordered: true
        foreground: root.t ? root.t.accent : "orange"
        accent: root.t ? root.t.accent : "orange"
        fontSize: root.t ? root.t.fSecondary : 12
        onClicked: root.allowChain(root.chain ? root.chain.id : "")
      }
    }
  }
}
