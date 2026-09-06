# The mark

A monoline M with its right leg broken — the drawbridge raised — over a single
horizontal bar, the water. Two shapes, one colour.

    M, left leg + diagonals + upper right leg   M12 46 V12 L32 32 L52 12 V24   stroke 6
    lower right leg                             M52 36 V46                     stroke 6
    water                                       M10 56 H54                     stroke 5

64 × 64 grid, round caps and joins, `#f2a25a`.

## Rules that are easy to break by tidying

- **The gap is the subject.** 12 units, y 24–36. It holds at 16px. Do not close
  it, shrink it, or add a second one.
- **The water is lighter on purpose.** Stroke 5 against the M's 6, and 2 units
  wider each side, so the M sits *over* the water rather than on it.
- **One form at every size.** No small variant, no opacity, no second colour, no
  gradient, no glow.
- **Minimum 16px.** Below that, draw nothing — do not drop the water to fit.

## Which file

| Use | File |
| --- | --- |
| Anywhere it must follow theme colour | `svg/mark-currentcolor.svg`, or `shell/MoatMark.qml` |
| Default standalone | `svg/mark-accent.svg` |
| Knocked out of an accent tile | `svg/mark-on-accent.svg` |
| App icon | `svg/icon-dark.svg`, `svg/icon-accent.svg`, `png/icon-*-256/512.png` |
| Favicon | `png/mark-16.png` and `png/mark-32.png` — 16 is a separate entry, never a downscale |

**In the panel and the bar, use `shell/MoatMark.qml`,** not an image. The mark
has to follow the surface it sits in, and an `<img>` cannot. The bar tints the
**water alone** with the verdict tone and leaves the M in the bar's foreground,
so the mark stays a mark rather than becoming a status light.

## `lockup-horizontal.svg` — read before using

It contains a live `<text>` element in JetBrains Mono at `fill="#f6f4f2"`. That
means two things:

1. It **falls back to a generic monospace** anywhere the font is absent, which
   includes GitHub's renderer.
2. The wordmark is near-white, so it is **invisible on a light background**.

Outline the text and re-colour before using it anywhere that is not a dark
surface with the font installed. The README uses the mark plus real text
instead, which is why.
