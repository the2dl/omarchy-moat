# Implementing the redesign

`README.md` in this directory is the handoff; `Moat.dc.html` is the design
document (open it and search `id="1b"` for a screen). This file is the order
the work happens in and the decisions that shape it.

## Two decisions taken up front

**Colour is mapped onto theme roles, not copied.** The handoff specifies fixed
hex (`#0d0e10` panel, `#f2a25a` accent, `#e0523f` alarm) and says the tokens
are the source of truth. Every other Omarchy surface follows the user's theme,
and a fixed dark palette collapses on a light one, so `Tokens.qml` derives the
whole design ramp from `Color.popups.background` / `.text` / `Color.accent` /
`Color.urgent` and adapts to theme polarity. What is preserved is the thing the
design is actually made of — the *relationships*: eleven text steps, layered
surfaces, accent for Moat's own voice, alarm for what needs you, calm for
resolved. What is given up is exact hue. Layout, hierarchy, spacing, type scale
and copy are followed exactly.

**The panel becomes a centred floating window.** It is a 900x640 card pinned to
a screen corner today. At 1400px with 44px body padding it is no longer a
glanceable widget, and 3a ("nothing else today is being shown while this is
open") only makes sense if the panel is what you are looking at. Not fullscreen:
the 16px radius and the large shadow only read as a surface over the desktop.
The glanceable role moves to the bar glyph, which 3e redesigns as exactly three
states matching the verdict line, so bar and panel can never disagree.

## Stages

Each stage is a working panel. Nothing here is a refactor that leaves the thing
unusable in between, and no stage is thrown away by a later one.

### Stage 0 — the token and copy layer  *(no visible change)*

- `shell/Tokens.qml`: the design's ramp, surfaces, semantic colours, radii,
  spacing scale and type scale, derived from the theme and passed down like
  `service`. Polarity-aware: "one step off the background" is lighter on a dark
  theme and darker on a light one.
- `shell/MoatCopy.js`: the 3g copy contract — `title` and `stake` per detection,
  the four verdict-line forms, and the banned-word list as a test rather than a
  comment.

### Stage 1 — panel shell and Now

1a, 1b. Chrome (three tabs + gear, shield as state indicator, badge only on Now
and only counting needs-you), the verdict line in its four forms, the quiet-day
summary rows, the one-incident-is-the-page layout, evidence collapsed by
default, two actions instead of five.

Incidents are grouped **client-side** in `MoatModel.js` at this stage — by
(rule, program), carrying count and first/last seen. Stage 4 moves that into the
daemon; the model API does not change when it does.

### Stage 2 — History, Rules, Settings

1d (3px ticks and text brightness instead of severity pills), 1e (16 shipped
rules grouped into 5 lines, "Yours" first, silenced-counts), 1f (daemon options
rewritten as questions, Advanced collapsed), 2e (trusted programs, from the
baseline tuples we already have). The Quarantine tab folds into Rules as 2c's
holding list.

### Stage 3 — bar, notifications, keyboard

3e (three bar states), 2h (three notification shapes, only needs-you
interrupts), 2g (j/k, a, s, e, ?, u — same verbs as the buttons and moatctl).

### Stage 4 — incidents in the daemon

Incident as a first-class record: dedup by (rule, program), chain correlation
across families within one process tree (2b, 3a), a chain-level allow that
resolves siblings. AI verdict on incident creation rather than on a timer, with
a pending state in the UI while the paragraph resolves.

### Stage 5 — the new capabilities

2a Ask Moat (a thread on an incident, streaming), 2d file snapshots + diff +
revert, 3b containment steps, 2i "I don't know" as a third answer.

### Stage 6 — copy and the lifecycle screens

3g applied to all 32 policies (title + stake per detection, rule ids to
evidence only), 1g learning cards, 3f first run, 3d the post-block apology.

## Sequencing notes

- Stage 1 depends only on Stage 0. Stages 2 and 3 depend on Stage 1's tokens
  and incident model but not on each other.
- Stage 4 replaces the client-side grouping with the daemon's, behind the same
  model API, so Stages 1-3 do not get rewritten.
- Stage 6 can start any time; it is policy YAML and strings, not UI.
- The four screenshots in `original-screens/` are the before. Keep them.
