import QtQuick

// The scrollable page. Every pane that scrolls -- Now, History and its
// incident detail, Rules, Settings, Setup, first run -- is one of these, and
// nothing else in the plugin may scroll on its own: seven bare Flickables had
// seven copies of the same four lines, and the one decision that mattered was
// in none of them.
//
// That decision is how far a wheel notch moves the page. Stock Flickable
// (Qt 6.11, wheelDeceleration 15000 > _q_MaximumWheelDeceleration) moves
// QStyleHints::wheelScrollLines * 24 = 72 px per notch, over a 300 ms OutExpo
// animation that the next notch *resets from wherever it has got to*. Measured
// on this machine, offscreen, with the declaration the panes used to have:
//
//   one notch, settled                72 px
//   five notches 400 ms apart         72 px each
//   five notches  40 ms apart         47 px each
//   five notches in a burst           14 px each  (72 px in total)
//
// So a slow notch went 60% as far as in any other window, and a flick of the
// wheel went almost nowhere -- the faster you scrolled, the less you moved.
// No easing tweak can fix that; the distance has to stop depending on cadence.
//
// What one notch (angleDelta 120) moves in the other windows on this machine,
// in the panel's units (logical px; Hyprland at 2x, mouse scroll_factor 1.0):
//
//   Chrome 152, native Wayland        120 px   ui/events/event.cc: kWheelDelta
//                                              is 120 on Linux "to match Windows
//                                              and (roughly) Firefox";
//                                              wayland_pointer.cc passes
//                                              axis_value120 through unscaled
//   GTK 3/4 scrolled windows          page^(2/3): 124 px for a full-height
//                                              window here, 84 px at this
//                                              panel's own height
//   foot (scrollback.multiplier=7)    ~110 px  seven 9pt JetBrains Mono lines
//   Qt Flickable, stock               72 px    and less, as above
//
// 120: Chrome's number exactly, inside GTK's range, and one logical px per
// angleDelta unit, so the compositor's scroll_factor scales this page by the
// same factor it scales every other window. shell/tests/tst_scroll.qml pins
// it and the adding-up.
Flickable {
  id: root

  /// Logical px per wheel notch. Read the note above before changing it.
  readonly property int wheelStep: 120

  /// How long a notch takes to arrive. In Chrome's smooth-scroll range: long
  /// enough to read as motion, short enough never to lag the wheel. It can
  /// never cost distance either way -- notches add to `goal`, not to the
  /// animation, so five in a burst land at exactly five steps.
  readonly property int glideMs: 110

  /// Where the wheel is taking the page. Meaningful only while `glide` runs.
  property real goal: 0

  /// The device types the wheel handler answers to. Exposed so the test can
  /// pin TouchPad in it -- see note 2 on the handler for why that matters.
  readonly property alias acceptedWheelDevices: wheel.acceptedDevices

  contentWidth: width
  flickableDirection: Flickable.VerticalFlick
  clip: true
  boundsBehavior: Flickable.StopAtBounds

  function clampY(y) {
    return Math.max(0, Math.min(y, Math.max(0, root.contentHeight - root.height)))
  }

  NumberAnimation {
    id: glide
    target: root
    property: "contentY"
    duration: root.glideMs
    easing.type: Easing.OutCubic
  }

  // Where the wheel is decided. Two things about this handler are not what
  // the QtQuick docs lead you to expect, and both were found live, not
  // offscreen (see shell/tests/tst_scroll.qml for what offscreen can and
  // cannot see):
  //
  //  1. It lives on the Flickable's contentItem, not on the Flickable. A
  //     Flickable's default property re-parents every declared handler to
  //     contentItem (qt.quick.handler.parent: "reparenting handler ... to
  //     contentItem"), and it does so again if you write `parent: root`.
  //     That is fine: contentItem is under the cursor and is visited before
  //     the Flickable, so the handler still sees the event first and, being
  //     blocking, keeps Flickable::wheelEvent out of the loop.
  //
  //  2. acceptedDevices MUST include TouchPad. On Wayland, qtwayland tags a
  //     physical mouse wheel notch with a QPointingDevice of type TouchPad
  //     ("touchpad", ptrType=Finger), and WheelHandler's default
  //     acceptedDevices is Mouse alone. With the default the handler is
  //     reached and DECLINES every notch (qt.quick.handler.dispatch), the
  //     event falls through to Flickable::wheelEvent, and the page scrolls
  //     the stock 72 px, cadence-damped, with nothing else looking broken.
  //     Offscreen, QTest's mouseWheel() comes from the core Mouse device, so
  //     the offscreen suite passes either way.
  WheelHandler {
    id: wheel
    acceptedDevices: PointerDevice.Mouse | PointerDevice.TouchPad
    onWheel: (event) => {
      if (event.pixelDelta.y !== 0) {
        // A touchpad. The compositor has already turned the fingers into
        // logical px, with the user's touchpad scroll_factor applied, and
        // every other window moves 1:1 on that. So does this one.
        glide.stop()
        root.contentY = root.clampY(root.contentY - event.pixelDelta.y)
        return
      }
      if (event.angleDelta.y === 0)
        return
      const from = glide.running ? root.goal : root.contentY
      root.goal = root.clampY(from - event.angleDelta.y / 120 * root.wheelStep)
      glide.stop()
      glide.from = root.contentY
      glide.to = root.goal
      glide.restart()
    }
  }
}
