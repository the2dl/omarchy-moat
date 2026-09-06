// The Moat mark: a monoline M with its right leg broken -- the drawbridge
// raised -- over a single horizontal bar, the water.
// Drawn rather than loaded from a file, because the mark has to follow the
// colour of whatever it sits in: the bar's foreground, the panel's heading
// colour, a verdict tone. An `Image` of an SVG cannot do that without a
// recoloured copy per state, and the brand handoff says so directly --
// "inline SVG, not <img>, wherever the mark should follow theme colour".
// Geometry is the handoff's, verbatim, on its 64x64 grid:
//   M, left leg + diagonals + upper right leg   M12 46 V12 L32 32 L52 12 V24
//   lower right leg                             M52 36 V46
//   water                                       M10 56 H54
// Three constraints from the handoff that are easy to break by "tidying":

import QtQuick
import QtQuick.Shapes

//   * The gap in the right leg is 12 units (y 24..36) and holds at 16px. Do
//     not close it, shrink it, or add a second one -- it IS the drawbridge.
//   * The water is stroke 5 where the M is 6, so it reads lighter. The M is
//     the subject; the bar is the ground it stands over.
//   * One form at every size. No small variant, no opacity, no second colour.
Item {
    id: root

    /// The M. Defaults to the parent's colour the way an inline SVG would.
    property color markColor: "#f2a25a"
    /// The water bar. Same colour as the M unless a caller tints it -- the
    /// handoff allows a verdict state to colour the water ALONE (e.g. the
    /// blocked red) while the M stays foreground-coloured, so the mark never
    /// becomes a status light.
    property color waterColor: root.markColor

    /// Minimum 16px. Below that the handoff says draw nothing rather than
    /// drop the water bar to make it fit.
    implicitWidth: 20
    implicitHeight: 20

    Shape {
        anchors.centerIn: parent
        width: 64
        height: 64
        scale: Math.min(root.width, root.height) / 64
        preferredRendererType: Shape.CurveRenderer
        // Off: the mark is static, and antialiasing a 20px icon every frame
        // on a bar that repaints constantly is not worth it.
        asynchronous: false

        ShapePath {
            strokeColor: root.markColor
            strokeWidth: 6
            capStyle: ShapePath.RoundCap
            joinStyle: ShapePath.RoundJoin
            fillColor: "transparent"

            PathSvg {
                path: "M12 46 V12 L32 32 L52 12 V24"
            }

        }

        ShapePath {
            strokeColor: root.markColor
            strokeWidth: 6
            capStyle: ShapePath.RoundCap
            fillColor: "transparent"

            PathSvg {
                path: "M52 36 V46"
            }

        }

        ShapePath {
            strokeColor: root.waterColor
            strokeWidth: 5
            capStyle: ShapePath.RoundCap
            fillColor: "transparent"

            PathSvg {
                path: "M10 56 H54"
            }

        }

    }

}
