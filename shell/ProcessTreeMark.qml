// The small mark beside a process in the tree.
//
// Drawn, not a glyph and not an image, for the reason MoatMark gives: it has
// to follow the colour it is handed -- the alarm tone on the process that
// tripped the rule, a muted one on the ordinary ancestors -- and an `Image` of
// an SVG cannot do that without a recoloured copy per state.
//
// Two marks, because the tree makes two claims:
//
//   flagged   a ring with a filled centre. A target: this is the process the
//             alert is about, and it is the only row drawn in the alarm colour.
//   lineage   a small open dot. Present on every other ancestor so the column
//             of marks reads as one run rather than one odd row with an icon
//             and a ragged gap where the others would be.
//
// Sized off the row's own type rather than a constant: the panel scales with
// the theme, and a mark that stays 10px while the text grows is the detail
// that makes a scaled UI look broken.
import QtQuick
import QtQuick.Shapes

Item {
    id: mark

    /// `flagged` | `lineage`
    property string kind: "lineage"
    property color tone: "grey"

    implicitWidth: mark.height
    implicitHeight: 10

    Shape {
        anchors.centerIn: parent
        width: 24
        height: 24
        scale: Math.min(mark.width, mark.height) / 24
        preferredRendererType: Shape.CurveRenderer
        // The tree is static between polls; antialiasing it every frame buys
        // nothing. Same call MoatMark makes.
        asynchronous: false

        // The ring, on both kinds. Thinner on an ancestor: the flagged row
        // should be the one the eye lands on first.
        ShapePath {
            strokeColor: mark.tone
            strokeWidth: mark.kind === "flagged" ? 3 : 2
            fillColor: "transparent"
            capStyle: ShapePath.RoundCap

            PathAngleArc {
                centerX: 12
                centerY: 12
                radiusX: mark.kind === "flagged" ? 8 : 5
                radiusY: mark.kind === "flagged" ? 8 : 5
                startAngle: 0
                sweepAngle: 360
            }
        }

        // The centre, only on the flagged one. A filled middle is what turns a
        // circle into a target, and it is the whole difference between "a
        // process" and "the process".
        ShapePath {
            strokeColor: "transparent"
            fillColor: mark.kind === "flagged" ? mark.tone : "transparent"

            PathAngleArc {
                centerX: 12
                centerY: 12
                radiusX: 3
                radiusY: 3
                startAngle: 0
                sweepAngle: 360
            }
        }
    }
}
