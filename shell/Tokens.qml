// The redesign's design tokens (docs/design/README.md), derived from the user's
// Omarchy theme rather than copied from the handoff's hex values.
// The handoff specifies a fixed dark palette and says every hex is intentional.
// It is right that the values are intentional -- but what they encode is a set
// of *relationships*: eleven steps of text from "read this" to "barely there",
// a stack of surfaces each one notch off the page, accent for Moat's own voice,
// alarm for what needs you, calm for what is resolved. Those relationships are
// what the design is made of, and they survive being re-derived. The literal
// hex does not survive a light theme at all -- #0d0e10 panels with #f6f4f2 text
// on a light Omarchy theme is not a compromise, it is a different product
// sitting in the middle of the user's desktop.
// So: relationships preserved exactly, hue taken from the theme. Layout,
// spacing, type scale and copy follow the handoff to the letter.
// Instantiate once and pass down, the way `service` is passed -- the plugin has
// no qmldir, so it has no singletons.

import QtQuick

// Every theme value arrives as a property rather than being read from
// qs.Commons here. That keeps this file free of Quickshell imports, which is
// what lets the suite instantiate it against a light theme and a dark one and
// check that the polarity logic actually flips -- the one thing in here that
// will break silently and only on someone else's desktop.
QtObject {
    // --------------------------------------------------------------- polarity
    // ------------------------------------------------------------- text ramp
    // -------------------------------------------------------------- surfaces
    // -------------------------------------------------------------- hairlines
    // --------------------------------------------------------------- semantic
    // Three meanings, and the design never uses colour for anything else:
    //   accent -- Moat's own voice (its verdict, its one primary action)
    //   alarm  -- this needs you
    //   calm   -- resolved, or healthy
    // Text drawn on a filled accent or alarm button. The handoff uses near-black
    // (#1a1006, #1a0805) because its accent is light; a theme whose accent is
    // dark needs the opposite, so this is chosen by contrast rather than fixed.
    // ----------------------------------------------------------------- shape
    // ------------------------------------------------------------------ type
    // --------------------------------------------------------------- spacing

    id: root

    // --- theme inputs, wired by the caller from Color/Style ------------------
    // The surface this instance is drawn on. The panel and the bar widget sit on
    // different theme surfaces, so each makes its own Tokens.
    property color base: "#0d0e10"
    property color ink: "#f6f4f2"
    property color themeAccent: "#f2a25a"
    property color themeUrgent: "#e0523f"
    property string family: "monospace"
    /// Style.space(1) -- the shell's UI scale factor.
    property real scale: 1
    /// Style.cornerRadius > 0 -- Omarchy's square-corner themes must win.
    property bool rounded: true
    // Omarchy's theme API exposes no light/dark flag, so it is measured. Every
    // "one step off the background" in the design is a step *lighter* because the
    // handoff is dark; on a light theme the same step has to go darker or the
    // whole stack of surfaces inverts into mud.
    readonly property real baseLuma: 0.2126 * root.base.r + 0.7152 * root.base.g + 0.0722 * root.base.b
    readonly property bool isDark: root.baseLuma < 0.5
    readonly property color primary: root.ramp(0) // #f6f4f2 -- headlines, the one thing to read
    readonly property color bright: root.ramp(0.06) // #e8e4e0 -- a verdict body that matters
    readonly property color body: root.ramp(0.14) // #d6d2ce -- normal prose
    readonly property color secondary: root.ramp(0.26) // #b3aea8 -- row titles
    readonly property color muted: root.ramp(0.34) // #a09b95 -- sub-lines
    readonly property color dim: root.ramp(0.4) // #9d9892
    readonly property color dimmer: root.ramp(0.48) // #837e79 -- detail columns
    readonly property color faint: root.ramp(0.58) // #6d6863 -- meta rows, state words
    readonly property color fainter: root.ramp(0.68) // #55514d -- section labels
    readonly property color ghost: root.ramp(0.79) // #3d3a37 -- chevrons, machine counters
    readonly property color deepest: root.ramp(0.9) // #26241f -- the rule-covered tick
    readonly property color panel: root.base // #0d0e10
    // The same page colour with the theme's translucency taken out. A popup
    // surface is allowed to be see-through because the compositor blurs what is
    // behind it; a WINDOW is not -- what is behind it is another window, and its
    // text reads straight through a 0.94 page. This is what the toplevel paints
    // itself; every surface above still uses `base`, so the alpha the theme asked
    // for keeps doing its work between the panel's own layers.
    readonly property color pageOpaque: Qt.rgba(root.base.r, root.base.g, root.base.b, 1)
    readonly property color evidence: root.off(0.012) // #0e0f12 -- the evidence drawer
    readonly property color card: root.off(0.035) // #121316 -- incident and info cards
    readonly property color chipDim: root.off(0.048) // #141518 -- the deliberately duller chip
    readonly property color chip: root.off(0.065) // #191a1d -- chips, insets, user bubbles
    readonly property color track: root.off(0.105) // #23252a -- toggle track
    readonly property color sunken: root.under(0.28) // #0a0b0d -- footer strip, code, diff
    readonly property color hairlineRow: root.hair(0.05)
    readonly property color hairlineChrome: root.hair(0.06)
    readonly property color divider: root.hair(0.09)
    // accent and alarm come from the theme. `calm` has no theme role, and a
    // derived one would land wherever the theme's hue wheel happens to point, so
    // it is the one fixed hue here -- picked per polarity so it stays legible on
    // a light theme, where the handoff's #7ba37f is too pale to read.
    readonly property color accent: root.themeAccent
    readonly property color alarm: root.themeUrgent
    readonly property color calm: root.isDark ? "#7ba37f" : "#4a7a4f"
    readonly property color accentLabel: root.labelOn(root.accent)
    readonly property color alarmLabel: root.labelOn(root.alarm)
    readonly property int rBadge: root.r(5)
    readonly property int rChipSmall: root.r(7)
    readonly property int rTab: root.r(8)
    readonly property int rChip: root.r(9)
    readonly property int rButton: root.r(10)
    readonly property int rInner: root.r(11)
    readonly property int rCard: root.r(12)
    readonly property int rToast: root.r(13)
    readonly property int rIncident: root.r(14)
    readonly property int rPanel: root.r(16)
    readonly property int fVerdict: root.pt(26) // the one sentence at the top
    readonly property int fHeading: root.pt(19) // card and section headings
    readonly property int fTitle: root.pt(14) // incident title in a row
    readonly property int fBody: root.pt(13) // row titles, prose
    readonly property int fSecondary: root.pt(12) // detail columns, links
    readonly property int fMeta: root.pt(11) // section labels, captions
    readonly property real fCode: 12.5 * root.scale // diff and evidence
    // Line heights the handoff pins, as multipliers for Text.lineHeight.
    readonly property real lhVerdictBody: 1.75
    readonly property real lhBody: 1.7
    readonly property real lhMeta: 1.6
    readonly property real lhCode: 2
    // Letter-spacing, in px at the size it applies to.
    readonly property real lsVerdict: -0.01
    readonly property real lsLabel: 0.16
    readonly property real lsVerdictLabel: 0.14
    /// The panel is in a window shorter than the design is drawn for.
    ///
    /// The redesign's rhythm is measured against an 860px page. A real toplevel
    /// gets whatever slot the compositor's layout hands it -- half that, on a
    /// two-window workspace -- and at 686px the same 40px gaps spend a tenth of
    /// the window on nothing while the list that has something to say gets three
    /// rows. Set by the panel from the window's own height.
    property bool compact: false
    readonly property int bodyPadX: root.s(44)
    readonly property int bodyPadTop: root.v(40)
    readonly property int bodyPadBottom: root.v(34)
    readonly property int cardPadX: root.s(28)
    readonly property int cardPadTop: root.v(26)
    readonly property int cardPadBottom: root.v(24)
    readonly property int smallCardPadX: root.s(20)
    readonly property int smallCardPadY: root.v(18)
    readonly property int rowPadY: root.s(14)
    // ----------------------------------------------------------------- misc
    readonly property int dotSize: root.s(9)
    // the verdict dot
    readonly property int tickWidth: root.s(3)
    // history severity tick
    readonly property int tickHeight: root.s(22)
    readonly property int headerHeight: root.s(54)

    // The handoff's eleven steps, as fractions of the distance from the panel's
    // text colour to its background. Named for what they are for, not for how
    // bright they are, so a caller never has to know which end is which.
    function ramp(t) {
        return Qt.tint(root.ink, Qt.rgba(root.base.r, root.base.g, root.base.b, Math.max(0, Math.min(1, t))));
    }

    // `off(n)` steps away from the page toward the text, which is lighter on a
    // dark theme and darker on a light one. `under(n)` goes the other way, for
    // the footer strip and code insets that sit *below* the page.
    function off(n) {
        return Qt.tint(root.base, Qt.rgba(root.ink.r, root.ink.g, root.ink.b, Math.max(0, Math.min(1, n))));
    }

    function under(n) {
        var away = root.isDark ? Qt.rgba(0, 0, 0, 1) : Qt.rgba(1, 1, 1, 1);
        return Qt.tint(root.base, Qt.rgba(away.r, away.g, away.b, Math.max(0, Math.min(1, n))));
    }

    // The handoff's rgba(255,255,255,0.05/0.06/0.09) are the text colour at low
    // alpha, which on a light theme correctly becomes a dark line on a light page.
    function hair(a) {
        return Qt.rgba(root.ink.r, root.ink.g, root.ink.b, a);
    }

    // NOT named onAccent/onFill: QML reads any `on<Capital>` identifier as a
    // signal handler, so `function onFill()` is never callable and a
    // `property color onAccent` binding resolves to black with no error at all.
    function labelOn(c) {
        var l = 0.2126 * c.r + 0.7152 * c.g + 0.0722 * c.b;
        return l > 0.5 ? Qt.rgba(0.1, 0.06, 0.02, 1) : Qt.rgba(0.98, 0.96, 0.95, 1);
    }

    function accentTint(a) {
        return Qt.rgba(root.accent.r, root.accent.g, root.accent.b, a);
    }

    function alarmTint(a) {
        return Qt.rgba(root.alarm.r, root.alarm.g, root.alarm.b, a);
    }

    function calmTint(a) {
        return Qt.rgba(root.calm.r, root.calm.g, root.calm.b, a);
    }

    // Radii are literal from the handoff: they are geometry, not colour, so there
    // is nothing to derive. Style.cornerRadius == 0 is Omarchy's square-corner
    // theme setting, and it has to win over the design or a themed desktop grows
    // one rounded rectangle in the middle of it.
    function r(px) {
        return root.rounded ? Math.round(px * root.scale) : 0;
    }

    // The handoff's scale, in the shell's own font. Sizes are scaled through
    // `scale` so the panel follows the user's UI scale like every other Omarchy
    // surface -- a fixed 26px headline is wrong on a 4K display at 1.5x.
    function pt(px) {
        return Math.round(px * root.scale);
    }

    // The handoff's scale. Through `scale` for the same reason as type.
    function s(px) {
        return Math.round(px * root.scale);
    }

    /// A VERTICAL distance, which is the only kind that gives way in a short
    /// window. `s()` is still the general scale, and horizontal padding stays on
    /// it deliberately: the measure of a line of prose is not a function of how
    /// tall the window is, and narrowing the gutters to buy height would make the
    /// page harder to read in exchange for one more row.
    function v(px) {
        return Math.round(px * root.scale * (root.compact ? 0.6 : 1));
    }

}
