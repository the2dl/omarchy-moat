import QtQuick
import QtTest
import ".."

// MoatScroll.qml carries the one scroll decision in the plugin: a wheel notch
// moves the page `wheelStep` logical px, and N notches move N steps whatever
// the cadence. This suite measures that with real wheel events rather than
// trusting it, because the stock Flickable it replaced failed exactly there:
// 72 px for a lone notch, 14 px per notch in a burst (see the note in
// MoatScroll.qml for the numbers and where they come from).
//
// It can run under a bare qmltestrunner because MoatScroll imports only
// QtQuick, like Tokens.qml -- keep it that way.
//
// What this suite cannot see, and once missed: mouseWheel() sends its event
// from QTest's core Mouse device, but on Wayland qtwayland tags a physical
// wheel notch with a TouchPad-typed device, and a WheelHandler's default
// acceptedDevices (Mouse) makes it decline that event. Every test below
// passed while the live panel was scrolling the stock 72 px, because the
// stock Flickable path is what the declined event fell through to. There is
// no QML API to send a wheel event from a chosen device type, so the device
// filter is pinned directly in test_it_answers_the_devices_wayland_uses; the
// distance tests only prove the arithmetic once the handler is reached.
TestCase {
  id: suite
  name: "MoatScroll"
  when: windowShown
  // TestCase is invisible by default, and invisible items are not hit-tested:
  // without this no wheel event ever reaches the page and every test reads 0.
  visible: true
  width: 800
  height: 600

  MoatScroll {
    id: page
    anchors.fill: parent
    contentHeight: body.implicitHeight

    Column {
      id: body
      width: parent.width
      Repeater {
        model: 100
        Item { width: parent.width; height: 50 }
      }
    }
  }

  readonly property int step: page.wheelStep
  readonly property real endY: page.contentHeight - page.height

  /// `n` notches, `gapMs` apart, towards the user (dir 1, page moves down)
  /// or away (dir -1). One notch is angleDelta 120, which is what qtwayland
  /// hands a Flickable for one click of a physical wheel.
  function notches(n, gapMs, dir) {
    for (var i = 0; i < n; i++) {
      mouseWheel(page, 400, 300, 0, -120 * dir)
      if (gapMs > 0)
        wait(gapMs)
    }
  }

  function settle() { wait(page.glideMs + 150) }

  function init() {
    page.contentY = 0
    wait(20)
  }

  function test_geometry_is_what_the_suite_assumes() {
    compare(page.contentHeight, 5000)
    verify(endY > 20 * step, "content must be tall enough for the burst tests")
  }

  function test_the_step_is_chromes() {
    // 120: kWheelDelta on Linux in Chromium, and one px per angleDelta unit.
    compare(step, 120)
  }

  function test_it_answers_the_devices_wayland_uses() {
    // qtwayland's wheel events arrive from a "touchpad" TouchPad device even
    // for a mouse; QTest's arrive from a Mouse. The handler must take both,
    // or the live panel silently falls back to the stock Flickable.
    verify(page.acceptedWheelDevices & PointerDevice.TouchPad,
           "WheelHandler must accept TouchPad: that is what qtwayland tags a wheel notch with")
    verify(page.acceptedWheelDevices & PointerDevice.Mouse,
           "WheelHandler must accept Mouse: that is what QTest and X11 send")
  }

  function test_one_notch_moves_one_step() {
    notches(1, 0, 1)
    settle()
    fuzzyCompare(page.contentY, step, 0.5)
  }

  function test_a_burst_adds_up() {
    notches(5, 0, 1)
    settle()
    fuzzyCompare(page.contentY, 5 * step, 0.5)
  }

  function test_a_fast_cadence_adds_up() {
    notches(5, 40, 1)
    settle()
    fuzzyCompare(page.contentY, 5 * step, 0.5)
  }

  function test_a_slow_cadence_adds_up() {
    notches(5, 400, 1)
    settle()
    fuzzyCompare(page.contentY, 5 * step, 0.5)
  }

  function test_reversing_mid_glide_still_adds_up() {
    notches(3, 0, 1)
    notches(1, 0, -1)
    settle()
    fuzzyCompare(page.contentY, 2 * step, 0.5)
  }

  function test_it_stops_at_the_end() {
    notches(60, 0, 1)
    settle()
    fuzzyCompare(page.contentY, endY, 0.5)
    notches(1, 0, -1)
    settle()
    fuzzyCompare(page.contentY, endY - step, 0.5)
  }

  function test_it_stops_at_the_top() {
    notches(1, 0, -1)
    settle()
    fuzzyCompare(page.contentY, 0, 0.5)
  }

  function test_nothing_keeps_moving_after_it_lands() {
    notches(2, 0, 1)
    settle()
    var landed = page.contentY
    wait(400)
    compare(page.contentY, landed)
  }
}
