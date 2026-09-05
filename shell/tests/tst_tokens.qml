import QtQuick
import QtTest
import ".."

// Tokens.qml derives the redesign's palette from the user's theme instead of
// copying the handoff's hex values (docs/design/PLAN.md). The part that will
// break silently is polarity: every "one step off the background" in the design
// is a step lighter because the handoff is dark, and on a light Omarchy theme
// the same step has to go the other way. Nobody running a dark theme will ever
// notice it is wrong.
//
// This is the only suite that instantiates a view component. It can, because
// Tokens.qml takes its theme values as properties and imports nothing from
// Quickshell -- which is most of why it was written that way.
TestCase {
  id: suite
  name: "MoatTokens"

  // The handoff's own palette: a dark panel with near-white text.
  Tokens {
    id: dark
    base: "#0d0e10"
    ink: "#f6f4f2"
    themeAccent: "#f2a25a"
    themeUrgent: "#e0523f"
  }

  // An Omarchy light theme: the case the handoff's fixed hex cannot survive.
  Tokens {
    id: light
    base: "#f4f2ef"
    ink: "#1c1b19"
    themeAccent: "#8a5a1f"
    themeUrgent: "#a3301f"
  }

  Tokens {
    id: square
    rounded: false
    scale: 1.0
  }

  // The panel in a window shorter than the design's page: a tiled slot.
  Tokens {
    id: tight
    base: "#0d0e10"
    ink: "#f6f4f2"
    compact: true
  }

  Tokens {
    id: scaled
    scale: 1.5
  }

  function luma(c) {
    return 0.2126 * c.r + 0.7152 * c.g + 0.0722 * c.b
  }

  function test_polarity_is_measured_not_assumed() {
    verify(dark.isDark, "a #0d0e10 panel is dark")
    verify(!light.isDark, "a #f4f2ef panel is not")
  }

  function test_surfaces_step_away_from_the_page_whichever_way_that_is() {
    // On dark, a card is lighter than the panel. On light it must be darker,
    // or the whole surface stack inverts into mud.
    verify(luma(dark.card) > luma(dark.panel), "dark: card lifts off the panel")
    verify(luma(light.card) < luma(light.panel), "light: card sinks into the page")

    // And the stack keeps its order in both.
    verify(luma(dark.chip) > luma(dark.card), "dark: chip sits above card")
    verify(luma(light.chip) < luma(light.card), "light: chip sits below card")

    // `sunken` is the footer strip and code insets, which sit *under* the page
    // in the handoff -- so it goes the opposite way from `card` in both themes.
    verify(luma(dark.sunken) < luma(dark.panel), "dark: footer is darker than the panel")
    verify(luma(light.sunken) > luma(light.panel), "light: footer is lighter than the page")
  }

  function test_the_text_ramp_runs_from_readable_to_nearly_gone() {
    // Eleven steps, monotonic in contrast against the page, in both polarities.
    var steps = function (t) {
      return [t.primary, t.bright, t.body, t.secondary, t.muted, t.dim,
              t.dimmer, t.faint, t.fainter, t.ghost, t.deepest]
    }
    var themes = [dark, light]
    for (var i = 0; i < themes.length; i++) {
      var t = themes[i]
      var s = steps(t)
      var pageLuma = luma(t.panel)
      var prev = Math.abs(luma(s[0]) - pageLuma)
      for (var j = 1; j < s.length; j++) {
        var contrast = Math.abs(luma(s[j]) - pageLuma)
        verify(contrast <= prev + 0.001,
               "step " + j + " must not be more readable than step " + (j - 1))
        prev = contrast
      }
      // The ends mean something: primary is the text colour, deepest is nearly
      // the page.
      verify(Math.abs(luma(s[0]) - luma(t.ink)) < 0.01, "primary is the ink")
      verify(Math.abs(luma(s[10]) - pageLuma) < 0.12, "deepest is nearly the page")
    }
  }

  function test_text_on_a_filled_button_is_chosen_by_contrast() {
    // These are deliberately not called onAccent/onAlarm: QML reads any
    // `on<Capital>` identifier as a signal handler, and the binding silently
    // resolves to black instead of erroring. This test caught exactly that.
    // The handoff hardcodes near-black on accent because its accent is light.
    // A theme with a dark accent needs the opposite.
    verify(luma(dark.accentLabel) < 0.5, "dark theme, light accent -> dark label")
    verify(luma(light.accentLabel) > 0.5, "light theme, dark accent -> light label")
    verify(Math.abs(luma(light.alarmLabel) - luma(light.alarm)) > 0.3,
           "the label must not vanish into its own button")
  }

  function test_calm_stays_legible_on_a_light_theme() {
    // It is the one fixed hue -- no theme role exists for it -- so it has to
    // carry its own polarity. #7ba37f on white is not readable.
    verify(luma(dark.calm) > luma(light.calm), "calm darkens for a light page")
    verify(Math.abs(luma(light.calm) - luma(light.panel)) > 0.2, "and stays visible")
  }

  function test_square_corner_themes_win_over_the_design() {
    // Omarchy's square-corner setting must beat the handoff's radii, or a themed
    // desktop grows one rounded rectangle in the middle of it.
    compare(square.rCard, 0)
    compare(square.rPanel, 0)
    verify(dark.rPanel > dark.rCard, "the panel is rounder than a card")
  }

  function test_type_and_spacing_follow_the_shell_scale() {
    // A fixed 26px headline is wrong on a 4K display at 1.5x.
    compare(scaled.fVerdict, Math.round(26 * 1.5))
    compare(scaled.bodyPadX, Math.round(44 * 1.5))
    verify(scaled.fVerdict > scaled.fHeading)
    verify(scaled.fHeading > scaled.fBody)
    verify(scaled.fBody > scaled.fMeta)
  }

  function test_a_short_window_gives_up_height_and_never_measure() {
    // The design's rhythm is drawn for an 860px page. Tiled into half that, the
    // 40px gaps spend a tenth of the window on nothing while the list with
    // something to say gets three rows. Vertical distances give way.
    verify(tight.bodyPadTop < dark.bodyPadTop, "top padding gives way")
    verify(tight.bodyPadBottom < dark.bodyPadBottom)
    verify(tight.smallCardPadY < dark.smallCardPadY)
    verify(tight.v(40) < dark.v(40))

    // HORIZONTAL padding does not: the measure of a line of prose is not a
    // function of how tall the window is, and narrowing the gutters to buy one
    // more row makes the page harder to read in exchange.
    compare(tight.bodyPadX, dark.bodyPadX)
    compare(tight.cardPadX, dark.cardPadX)
    compare(tight.s(40), dark.s(40))

    // Nor does type. A shorter window is not a smaller one.
    compare(tight.fVerdict, dark.fVerdict)
    compare(tight.fBody, dark.fBody)

    // Still a real gap, not a collapse: sections that were apart stay apart.
    verify(tight.bodyPadTop > 0)
    verify(tight.v(40) > tight.v(26), "the rhythm keeps its order")
  }

  function test_hairlines_are_the_ink_not_a_fixed_white() {
    // rgba(255,255,255,0.05) is right on the handoff's dark panel and invisible
    // on a light one; taking it from the ink makes it a dark line on a light page.
    verify(luma(light.hairlineRow) < luma(light.panel), "light: hairline is darker than the page")
    verify(luma(dark.hairlineRow) > luma(dark.panel), "dark: hairline is lighter than the panel")
  }
}
