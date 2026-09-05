# Handoff: Moat — decluttered EDR panel

## Overview

Moat is an EDR-like agent that runs on a single Linux endpoint (Omarchy / Arch + Hyprland). It watches process behaviour in the kernel via Tetragon, raises alerts, and has AI analysis built in. This handoff covers a full redesign of its UI.

The problem being solved: the original panel showed every alert as `HIGH`, repeated the same alert dozens of times as separate rows, split each alert into four prose sections (what happened / why flagged / what to do / analysis), offered five equally-weighted action buttons, and led with a status strip of daemon jargon. The intended user is a power user with **no security background**.

The redesign is built on one idea: **answer first, evidence on request.**

- AI analysis runs on arrival and its verdict *is* the alert summary — one plain paragraph, not four sections.
- Alerts collapse by rule + program into **incidents** with a count and a time range.
- Severity is replaced by three states describing what is wanted from the user: **needs you** (act), **explained** (Moat decided, you may look), **expected** (a rule covers it).
- Five actions become two: `This was me` (primary) and `Stop it`. Scope for "was me" is a follow-up choice, not another button. `Ack` is removed — reading a resolved incident acknowledges it.
- Four tabs become three (Now / History / Rules) plus a gear for Settings.
- The top level is a single verdict line, and the panel refuses to claim calm unless the sensor can prove it was watching.

## About the Design Files

`Moat.dc.html` in this bundle is a **design reference created in HTML** — a prototype showing intended look and behaviour, not production code to copy directly. It is a single scrolling design document containing ~22 screen mockups grouped into three turns, each with an id badge (1a, 2b, 3g…) and a note on the reasoning behind it.

The task is to **recreate these designs in the target codebase's existing environment** using its established patterns and libraries. Moat's panel is a native desktop surface on a Hyprland desktop, so the real implementation is likely GTK4/libadwaita, Qt, or a webview shell — the HTML is a specification of layout, hierarchy, copy and colour, not a suggested stack. If no UI environment exists yet, choose the framework that fits a Wayland-native single-machine agent panel and implement there.

Open the file in a browser and scroll; it pans and zooms as a canvas. Screens are referenced throughout this README by their id badge.

## Fidelity

**High fidelity.** Final colours, typography, spacing, copy and states. Every hex value, font size and pixel measurement in the file is intentional and listed under Design Tokens below. Recreate the UI faithfully using the codebase's existing components where they exist; where they don't, the tokens here are the source of truth.

Two caveats: the mockups are drawn at a fixed 1400px panel width and are static (no live interaction), and the copy is exact and should be treated as approved product copy, not placeholder.

---

## Screens / Views

Screens are grouped by the turn they were designed in. Turn 1 is the core redesign; turn 2 adds the features around the verdict; turn 3 covers the real-incident case, entry points, and the copy system.

### Global panel chrome (all Now / History / Rules screens)

- **Frame**: 1400px wide, `border-radius: 16px`, `background: #0d0e10`, `box-shadow: 0 30px 80px rgba(0,0,0,0.6)`, `overflow: hidden`, flex column.
- **Header bar**: 54px tall, `padding: 0 22px`, `border-bottom: 1px solid rgba(255,255,255,0.06)`. Left: shield glyph 18px + wordmark "Moat" at 14px/500. Right (margin-left auto, gap 6px): three tab labels at 12px, then a settings gear and a close glyph at 17px in `#55514d`.
- **Shield colour is the panel's state indicator**: `#7ba37f` calm, `#e0523f` something needs you, `#f2a25a` sensor gap.
- **Active tab**: `color: #f2a25a`, `background: rgba(242,162,90,0.11)`, `padding: 6px 13px`, `border-radius: 8px`. Inactive: `color: #837e79`, same padding, no background.
- **Tab badge** (count of things needing you): 10px/700, `color: #1a1006`, `background: #e0523f`, `border-radius: 5px`, `padding: 2px 5px`. Only ever appears on `Now`, and only counts needs-you incidents — never events.
- On a real incident (3a) the header gains `background: rgba(224,82,63,0.06)`. This is the only chrome-level alarm signal in the product.

### 1a — Now, a quiet day

**Purpose**: the state the panel is in ~95% of the time. It should read like a sentence, not a console.

**Layout**: header, then body `padding: 46px 44px 30px`, flex column `gap: 40px`, then a footer strip.

**Components**:
1. **Verdict block** (max-width 800px, gap 13px): a 9px `#7ba37f` dot + "Nothing needs you." at 26px/500, `letter-spacing: -0.01em`, `#f6f4f2`. Sub-line at 13px/1.7 `#a09b95`, indented 21px to align under the headline: "Moat looked at 1,204 things today. Three were worth a second look; it read all three and closed them. Nothing has been blocked, because you are still in monitor mode."
2. **"What it watched today"** section label: 11px, `letter-spacing: 0.16em`, uppercase, `#55514d`, 10px bottom padding.
3. **Four summary rows**: `display: grid; grid-template-columns: 250px 1fr 130px 22px; gap: 16px; padding: 14px 0`, each with `border-top: 1px solid rgba(255,255,255,0.05)` (last row also gets a bottom border). Col 1 = category at 13px `#d6d2ce`; col 2 = plain-language detail at 12px `#837e79`; col 3 = state word at 11px (`expected` → `#6d6863`, `explained` → `#a09b95`); col 4 = chevron 16px `#3d3a37`.
   - Rows: "Package installs / 14 runs, all started by pacman or your AUR helper / expected"; "Writes to your config / 6 files under ~/.config, by your editor and hyprctl / expected"; "Reads of your SSH keys / 22, all by ssh, ssh-agent and git / expected"; "Claude, during installs / 68 times — Moat read it as your own workflow / explained".
4. **Last-needed-you card**: `padding: 16px 18px`, `border-radius: 12px`, `background: #121316`, history glyph + two lines ("The last thing that needed you was 6 days ago." / "A shell wrote to /etc/ld.so.preload. You stopped it.") + "Open it" link at 12px `#f2a25a` pushed right.
5. **Footer strip**: `padding: 14px 44px`, `border-top: 1px solid rgba(255,255,255,0.06)`, `background: #0a0b0d`, 11px text `#6d6863` separated by 1px × 11px dividers `rgba(255,255,255,0.09)`. Contents in order: "Watching, not blocking" · "Still learning your machine — 7 days left" · "Threat feeds have never updated" + "Fix" in `#f2a25a` · then right-aligned "32 detections · tetragon running" in `#3d3a37`.

**Key rule**: the two facts that change what Moat *does* (not blocking, still learning) are sentences; machine counters sit far right in the dimmest colour. The old `unacked 24` counter is deliberately gone — a backlog counter is a to-do list the user never asked for.

### 1b — Now, one thing needs you

**Purpose**: when one incident needs a decision, the incident *is* the page. No list/detail split.

**Layout**: body `padding: 40px 44px 34px`, gap 30px.

**Components**:
1. **Verdict**: 9px `#e0523f` dot + "One thing needs you." 26px/500 + trailing "everything else today is explained" at 12px `#6d6863`.
2. **Incident card**: `border-radius: 14px`, `background: #121316`, `border: 1px solid rgba(224,82,63,0.22)`, inner `padding: 26px 28px 24px`, gap 22px.
   - **Title** 19px/500, `line-height: 1.4`, `text-wrap: pretty`, max-width 900px: "A program you don't edit with rewrote a file that runs at every login".
   - **Meta row** 12px `#6d6863`, dot-separated: program name in `#b3aea8`, "10 hours ago", "first time on this machine", "nothing has run yet".
   - **Verdict block**: `padding-left: 16px`, `border-left: 2px solid rgba(242,162,90,0.4)`. Label "MOAT READ IT THIS WAY" 11px, `letter-spacing: 0.14em`, uppercase, `#f2a25a`. Body 14px/1.75 `#d6d2ce`. Then a softer follow-up line 12px/1.7 `#837e79` that names the likely benign explanation.
   - **Two facts** as a `120px 1fr` grid, 12px: labels `#55514d`, values `#b3aea8`. Only "The file" and "The program" — everything else is evidence.
   - **Action row**: primary `This was me` (check glyph + label, `background: #f2a25a`, `color: #1a1006`, 13px/500, `padding: 11px 20px`, `border-radius: 10px`); secondary `Stop it` (block glyph, `background: rgba(224,82,63,0.13)`, `border: 1px solid rgba(224,82,63,0.3)`, `color: #e0523f`); then text links `Show evidence` and `Ask Moat a question` at 12px `#837e79`; rule id far right at 11px `#3d3a37`.
   - **Evidence block** (collapsed by default; expanded in the mock): `border-top: 1px solid rgba(255,255,255,0.06)`, `background: #0e0f12`, `padding: 20px 28px 24px`. Header row: chevron + "EVIDENCE" 11px uppercase `#55514d` + "Copy bundle" right. Body is a `110px 1fr` grid at 12px: process, cwd, ancestry, wrote, hook, severity. Note severity appears **here** as a fact with its reason ("medium → high, raised because the write landed in an autostart path"), never as a badge.
3. **"Also today"** — three rows, grid `1fr 90px 130px 22px`, 13px `#b3aea8` title, count 11px `#55514d`, state word, chevron.

### 1c — One incident, 68 times (the dedup + silence choice)

**Purpose**: replaces both the wall of identical rows and the four stacked TOML scope blocks.

**Components**:
1. Title "Claude ran inside package installs" 19px/500; meta "68 times · Tuesday to 3 minutes ago · always the same program and rule".
2. Verdict block (same orange left-rule pattern as 1b) explaining the repeats are the user's own workflow, and why the detection exists at all.
3. **Pattern strip**: three-column grid inside `padding: 18px 20px; border-radius: 12px; background: #121316`. Each cell: 11px `#55514d` label over 13px `#b3aea8` value — "every time by /usr/bin/claude", "every time under makepkg → bash", "busiest hour 14:00, 19 runs".
4. **Silence scope as chips**: prompt "This keeps firing. Stop asking about it?" at 13px `#d6d2ce`, then four chips (`padding: 9px 16px`, `border-radius: 9px`): selected = `background: #f2a25a; color: #1a1006`; unselected = `background: #191a1d; color: #b3aea8`; the broadest option ("this detection, everywhere") is deliberately dimmer (`background: #141518; color: #837e79`). Labels are consequences, not config: "when claude does it" / "only claude, only this folder" / "anything a package build starts" / "this detection, everywhere".
5. **Consequence card** for the *selected* chip only: `background: #121316`, check glyph `#7ba37f`, one sentence on what gets silenced plus one on what still gets through and where to undo it.
6. Actions: `Stop asking` primary, `Keep asking` text, `Show the rule it writes` far right at 11px `#3d3a37`.

**Key rule**: only the chosen scope is explained. The TOML stays one click away.

### 1d — History

**Purpose**: scanning past incidents without a page of red pills.

**Components**:
1. **Filter row** below the header: `padding: 16px 44px`, `border-bottom: 1px solid rgba(255,255,255,0.05)`. Chips "Everything" (selected), "Needed you", "Silenced by a rule"; right-aligned "last 7 days" 12px `#55514d`.
2. **Day groups**, gap 30px. Each has a header row: day name 13px `#f6f4f2` + summary counts 11px `#55514d` ("1 needed you · 3 explained · 41 covered by a rule", or "nothing needed you").
3. **Incident rows**: grid `3px 1fr 110px 120px`, gap 20px, `padding: 14px 0`, top border hairline. Col 1 is a 22px-tall, 3px-wide rounded tick: `#e0523f` needs-you, `#3d3a37` explained, `#26241f` rule-covered. Title brightness carries the same signal: `#f6f4f2` → `#b3aea8` → `#6d6863`. Col 3 relative time; col 4 status word ("waiting on you" `#e0523f`, "explained" `#6d6863`, "covered" `#3d3a37`, "you stopped it" `#7ba37f`).
4. Repeat counts and covering rule names are appended inline to the title in a dimmer colour, e.g. "· 68 times", "· 22 times · rule: your SSH tools".

**Key rule**: severity is a 3px tick and text brightness, so a page of history carries at most one red mark.

### 1e — Rules

**Purpose**: 16 near-identical shipped-rule cards become 5 grouped lines.

**Components**:
1. Heading "What Moat has been told to ignore" 19px/500 + explainer 13px/1.7 `#a09b95`: "Every time you say this was me, a line lands here. You can take any of them back."
2. **"Yours · 2"** section (first, deliberately): each rule is a card `padding: 16px 20px; border-radius: 12px; background: #121316`, grid `1fr 150px 130px 80px`. Title 13px `#f6f4f2`, provenance line 11px `#6d6863` ("you added this 3 minutes ago, after 68 alerts"), binary path 11px `#55514d`, **"silenced 4 since"** 11px `#6d6863`, `Undo` 12px `#f2a25a` right-aligned.
3. **"Came with Moat · 16"** section, with the upgrade caveat stated **once** in the header at 11px `#3d3a37` ("grouped by what they cover · replaced on upgrade"). Rows are grid `260px 1fr 90px 22px`, hairline-separated: recognisable group name ("Your SSH tools", "git", "Your package manager", "Your desktop", "Browsers"), one-line reason, "N rules", chevron.

**Key rule**: the silenced-count column is the only way a user can tell whether a rule they added was a good idea.

### 1f — Settings

**Purpose**: daemon options rewritten as questions.

**Layout**: rows of `display: grid; grid-template-columns: 1fr 320px; gap: 40px; padding: 24px 0`, hairline between, control right-aligned (`justify-self: end`).

**Rows**:
1. "Should Moat stop things, or just tell you?" — segmented `Just tell me` / `Stop things`; help text explains a wrong guess kills a real program mid-write and to stay on telling-you until Rules has been quiet for a week.
2. "When should Moat interrupt you?" — `Anything odd` / `Only if it needs me` / `Never`, with "at most one every 10 minutes" as an 11px `#55514d` fact underneath rather than its own control. (This row absorbs the old notify-at *and* notify-cooldown settings.)
3. "Hide your keys from package installs" — toggle, off.
4. "A weekly note on what happened" — toggle, on, labelled "on, Mondays".
5. **Advanced**, collapsed: chevron + label + a dim 11px list of what's inside ("show rule-covered events · notification threshold by severity · cooldown window · policy paths"). The old show-suppressed setting lives here; it turned out to be an implementation detail.

**Controls**: segmented chips as in 1c. Toggle = 42×23px pill, `border-radius: 12px`; off `background: #23252a` with a 17px `#6d6863` knob left; on `background: #f2a25a` with a 17px `#1a1006` knob right.

### 1g — The first week (two cards, 686px each)

1. **Learning card**: "Moat is learning your machine" 20px/500; explainer; a 5px progress bar (`background: #191a1d`, fill `#f2a25a` at 22%) with "day 2 of 9" and "412 things learned" beneath at 11px `#55514d`; an "It already knows" chip cloud (11px chips, `background: #191a1d`, `border-radius: 7px`, `padding: 6px 11px`) listing learned programs + "+ 9 more"; closing reassurance that serious things still reach you during learning.
2. **Day-9 card**: "Done learning. Here's what changed." with a three-row stat list (alerts in week one 312 / expected from here ~4 a week / rules written for you 11 · review them) and the **enforce prompt** — `Let Moat stop things now` primary + `Keep just telling me`. This is the only place the enforce question is asked, because it is the only moment it can be asked honestly.

---

### 2a — Ask Moat

**Purpose**: makes the AI verdict arguable. Replaces the old `Analyze with claude` button, which ran an analysis and produced more prose (the analysis now already happened on arrival).

**Layout**: the incident card collapses to a 24px 28px 20px header strip (state dot + title + "still waiting on you"), then a thread at `padding: 28px 28px 30px`.

**Thread rows**: grid of a 46px speaker gutter + content, gap 16px, 20px between turns. User turns: label "you" 11px `#55514d`; bubble 13px/1.7 `#f6f4f2`, `padding: 12px 16px`, `border-radius: 11px`, `background: #191a1d`. Moat turns: label "moat" 11px `#f2a25a`; body 13px/1.75 `#d6d2ce` with no bubble, plus optional softer 12px `#837e79` follow-up.

**Recommendation card** inside a Moat turn: `background: #121316`, `padding: 12px 16px`, lightbulb glyph + "On what I can see, this is your own package doing its job late. I'd allow it." + a `This was me` link `#f2a25a` right-aligned — the agent proposes, the user acts.

**Composer**: hairline-bordered row (`border: 1px solid rgba(255,255,255,0.08)`, `border-radius: 11px`, `padding: 13px 16px`), placeholder "Ask about this incident…" `#55514d`, and the agent's boundary as a single 11px `#3d3a37` line: "Moat can read the evidence bundle · it cannot run kill, quarantine or allow on its own". Above it, three suggested-question chips seeded with what a non-specialist actually asks.

### 2b — What led here

**Purpose**: ancestry as a story with times. The old panel had the data (`kernel → systemd → systemd → herdr → bash → flea`) but as one line with no times and no sibling events.

**Layout**: `padding: 32px 34px 34px`. Chain rows are grid `92px 20px 1fr`, gap 20px: right-aligned 11px `#55514d` timestamp; a rail column holding a 9px dot (`#3d3a37` benign, `#e0523f` the alert) above a 1px `rgba(255,255,255,0.08)` connector; then title 13px `#b3aea8` (with key tokens in `#f6f4f2`) over an 12px `#6d6863` note. 24px bottom padding per step.

**Closing card**: route glyph `#f2a25a` + "One install explains all four events. Allowing this incident closes the curl alert too — same chain, same decision." + `Allow the whole chain` action. Below, an 11px `#3d3a37` retention note.

**Behavioural implication**: allowing one incident can resolve others in the same chain.

### 2c — Undoing a stop (two cards)

1. **Toast card (620px)**: post-action state. `background: #121316`, `border: 1px solid rgba(255,255,255,0.07)`, `border-radius: 13px`. Check glyph `#7ba37f` + "Stopped flea" 14px + a "28s" countdown 11px `#55514d` right. Body: "The process was killed and the file it wrote is held in quarantine. Nothing else changed." A 3px progress bar (`#23252a` track, `#55514d` fill at 88%) counts down 30 seconds. `Undo` primary + an 11px note on what undo does.
2. **Quarantine list (754px)**: "Rules → things Moat is holding · 2". Rows grid `1fr 110px 90px`: filename 13px `#d6d2ce`, provenance 11px `#6d6863` ("taken from ~/.config/hypr · flea · 4 minutes ago"), size, `Restore`. Footer card: lock glyph + "Held files can't run from here. They are deleted after 30 days unless you keep them." Killed processes with no file get the same row shape carrying the command line and cwd, so relaunching is copy-paste.

**Rule this encodes**: a destructive primary is only honest if the worst case is 30 seconds long.

### 2d — What the file used to say

**Purpose**: turns "a file you care about was modified" into four readable lines and a revert.

**Diff block**: `border-radius: 12px`, `background: #0a0b0d`, `border: 1px solid rgba(255,255,255,0.06)`; grid `48px 1fr` at 12.5px/2. Gutter numbers `#3d3a37`, context lines `#6d6863`, added line `#a8c9a9` on `rgba(123,163,127,0.07)` with its gutter number in `#7ba37f`. Only ±1 line of context each side.

Then the standard verdict block, then actions: `Keep the change` primary, `Put the file back as it was` secondary chip, `Open in editor` link, and an 11px `#3d3a37` provenance note ("previous version held since 11:22 · from Moat's own snapshot, not your backups").

**Implementation note**: snapshots are taken only for paths a detection watches, so storage cost is bounded.

### 2e — Programs Moat knows

**Purpose**: the positive mirror of Rules — what is considered normal. Lives as a section of Rules, not a new tab.

**Table**: grid `200px 1fr 150px 110px 22px`, hairline rows, with a header row at 12px `#3d3a37` (program / trusted for / last seen / silenced). Program 13px `#d6d2ce`; scope 12px `#837e79` stated as permissions in plain words ("running during package installs, writing under ~/dev"); last seen 11px `#55514d`; silenced-count 11px `#6d6863`. A program with an open incident is highlighted with `background: rgba(242,162,90,0.04)` and its scope cell reads "nothing yet — one incident waiting on you" in `#f2a25a`. Final row collapses the remaining 10 programs into one line.

**Footer card**: fingerprint glyph + "Trust is pinned to the binary. If one of these is replaced by an upgrade or anything else, it comes back as a new program and you'll hear about it once."

### 2f — Is it actually watching (686px)

**Purpose**: a blind sensor and a quiet machine look identical.

Verdict line "Watching, with one gap" 20px/500 with a `#f2a25a` dot. Four rows, grid `1fr 130px 80px`: Kernel hooks (up 6 days, "fine" `#7ba37f`), Detections loaded (32 of 32, fine), Known-bad list (never — with a plain-language reassurance that Moat judges behaviour anyway, and a `Fix` action), Blind spells (1 · 4 min at boot, "logged").

**Cross-screen contract**: if any row here is broken, 1a's verdict line must read "Watching, with one gap" instead of "Nothing needs you."

### 2g — The keyboard pass (686px)

Five rows, grid `100px 1fr`: `j / k` next/previous · `a` this was me, then 1–4 to pick scope · `s` stop it (confirms once, undoable 30s) · `e / ?` evidence / ask Moat · `u` undo the last thing you did. Keys 12px `#f2a25a`, descriptions 12px `#9d9892`. Footer: same verbs as the buttons, and `moatctl` exposes exactly these four actions.

### 2h — Notifications (860px)

Three shapes, and **only the first may interrupt**. Each is a card `padding: 18px 20px`, `border-radius: 13px`, `background: #121316`, with a shield glyph in a 18px column.

1. **Needs you**: `border: 1px solid rgba(224,82,63,0.22)`, glyph `#e0523f`. Title "Something added itself to your login" 13px `#f6f4f2`; body "flea wrote a startup file. It hasn't run yet."; three inline actions at 11px — `This was me` (filled `#f2a25a`), `Stop it`, `Look`.
2. **Weekly note**: `border: 1px solid rgba(255,255,255,0.06)`, glyph `#6d6863`. "Quiet week" + counts + "Moat has been watching the whole time."
3. **Counted burst**: same neutral treatment. "Claude tripped the same detection 40 more times" / "Counted, not shown one by one. Want it silenced?"

**Rule**: titles are consequences — "something added itself to your login", never "HIGH: moat-persist-hypr-config-write".

### 2i — When you still don't know (514px)

A third answer besides yes and no. `I don't know` leaves the incident open, mutes it until something new happens, and packages evidence as one file. Bundle preview: `background: #0a0b0d`, `border-radius: 9px`, filename + size 11px `#9d9892`, then "plain text · paths under your home redacted · nothing sent anywhere" 11px `#55514d`. Actions: `Save the bundle` primary, `Copy as text`.

**Why it exists**: it stops an honest non-answer from becoming a permanent red dot, which is what pushes people to click allow on things they don't understand.

---

### 3a — Now, a chain not four alerts (the real incident)

**Purpose**: the case the product exists for. Four alerts in nine minutes sharing a process tree are one incident; the fourth event changes the meaning of the first.

**Differences from 1b**:
- Header bar tinted `rgba(224,82,63,0.06)`.
- Verdict: "This one needs you now." + sub-line "Four things happened in nine minutes and they were all the same program. Moat has already cut its network access while you read this."
- Card border `rgba(224,82,63,0.3)`; verdict-block left rule is `rgba(224,82,63,0.5)` and its label is `#e0523f` (the only place the orange verdict label turns red). Verdict body is brighter (`#e8e4e0`) and ends with a standalone `#f6f4f2` line: "Assume the key that lives at ~/.ssh/id_ed25519 is no longer private."
- **Embedded chain**: grid `74px 20px 1fr 130px`, same rail pattern as 2b, with a status column ("happened" `#6d6863`, "reverted" `#7ba37f`, "Moat did this" `#f2a25a`). Five steps: postinstall ran (benign), key read, 4 kB sent to an unfamiliar host, systemd user unit added, Moat cut network + froze the process.
- **Primary action is `Contain it — 4 steps`**: `background: #e0523f`, `color: #1a0805`, shield_lock glyph. `This was me` demotes to a text link.
- **Focus card** at the bottom: "Nothing else today is being shown while this is open. It'll be here when you come back."

**Two behaviours that only apply here**: Moat acts before the user reads (three high-confidence steps in one tree trigger automatic network cut + freeze), and the panel suppresses everything else.

### 3b — Containment (860px + 514px)

**Purpose**: under pressure a non-specialist needs a numbered list, not five buttons.

**Steps list**: each step is grid `26px 1fr 100px` in a `#121316` card. Number coloured by state (`#7ba37f` done, `#f2a25a` next, `#e0523f` yours). Done steps show "done" `#7ba37f`; the actionable step is bordered `rgba(242,162,90,0.28)` with a `Do it` chip; step 4 is bordered `rgba(224,82,63,0.28)` with a `How` chip.
1. Stop the process and hold its files — done (already frozen at 09:23).
2. Undo the login entry it added — done.
3. Remove the package and its lockfile entry — with the cost stated: "your project won't build until you replace it".
4. **Replace your SSH key — only you can do this**, with the reason Moat can't: "Moat can't reach those services and shouldn't."

Bulk action `Do steps 1–3` (`background: #e0523f`) + "Everything here is undoable except step 3".

**Side card — what Moat keeps**: the incident stays open until step 4 (reminded once a day); a watch on the host it talked to (anything else reaching it becomes needs-you immediately, no learning, no cooldown); a written record of timeline, evidence and actions taken. Actions: `Save the record`, `Remind me tomorrow`.

### 3c — Now, several things need you

**Purpose**: coming back after a week.

Verdict "Three things need you." + "about two minutes · press j to walk them" + sub-line "Ordered by what Moat is least sure about. The other 61 things this week are explained and closed."

**Queue rows**: grid `26px 1fr 200px 120px`, `padding: 20px 22px`, `border-radius: 12px`, `background: #121316`. Rank number `#e0523f` for the first, `#6d6863` after. Title 14px, then a 11px `#837e79` line stating *why Moat is unsure*. Right: `Was me` + `Open` chips at 11px.

**Bulk accept card**: done_all glyph + "All three are things Moat leans towards allowing… you can accept the lot — it writes three rules and lists them under Rules" + `All three were me`.

**Two rules**: order is by Moat's uncertainty, not severity (a HIGH it is sure about matters less than a MEDIUM it can't place); the bulk accept **must not render** if any queue item is one Moat would not allow, or it becomes a way to click past 3a.

### 3d — After Moat blocked something

**Purpose**: enforce mode's real UI is the apology, not the switch.

Heading "Moat stopped something while you were working" + "Your terminal will have shown this as a program dying for no reason. That is what a kernel-level block looks like from the outside, so this screen exists to explain it after the fact."

**Two columns**:
- *What you saw*: a terminal transcript in `background: #0a0b0d`, 12px/1.9 — command `#9d9892`, output `#837e79`, `Killed` in `#e0523f`, trailing prompt `#55514d`.
- *What happened*: 12px/1.75 `#b3aea8` explaining the pattern matched, that it is also exactly what a deploy script does, and ending "Moat was wrong."

**Recovery card** (`border: 1px solid rgba(242,162,90,0.24)`): "Let it run and don't stop it again" — adds the script to rules for reading keys **and nothing else**; the user re-runs it themselves (Moat won't restart things). Actions: `Allow deploy.sh`, `Copy the command to re-run`, and `Go back to just telling me` right-aligned. Footer: two blocks in a week offers to turn enforce off, and says why.

### 3e — The waybar glyph (686px)

Three bar states, each drawn as a mock bar segment (`padding: 9px 16px`, `border-radius: 10px`, `background: #121316`, with dim neighbour modules for context):
1. **Quiet**: shield glyph 14px `#55514d`, no text.
2. **Needs you**: shield `#e0523f` + a count `#e0523f`.
3. **Sensor gap**: shield `#f2a25a` + the word "gap" `#f2a25a`.

Tooltip (only for the two loud states): incident title + relative time, then "click to open · middle-click to say it was you" `#55514d`.

**Rule**: no event counter, no rule name, no severity palette — three states matching the verdict line exactly, so bar and panel can never disagree.

### 3f — First run (686px)

"Moat watches four things" 20px/500 + "It reads what programs do, in the kernel. It never reads the contents of your files, and it never sends anything anywhere."

Four hairline rows, each a 13px `#d6d2ce` category over an 11px `#6d6863` example list: reads of keys and tokens; things that make a program start at login; ways to become root; what package installs and build scripts do ("the most common way something bad gets onto a developer's machine").

Then a `#121316` card setting expectations for learning ("First it spends 9 days learning what's normal here." / won't stop anything, only interrupts for something serious, expect it to be quiet), and `Start watching` + `See the 32 detections`.

### 3g — How titles get written (the copy spec)

**Purpose**: without this, detection 33 reintroduces log-speak.

**Contract**: every detection ships two strings — a **title** naming the consequence in the user's terms, and a **stake** saying what it costs them. Rule ids stay in evidence. Three tests: no jargon a new Arch user wouldn't know; no verb the user didn't do; it must make sense with no other context.

**Was / is table** (grid `280px 1fr 1fr`, hairline rows — detection id `#55514d`, old string `#6d6863`, new string `#d6d2ce`):

| detection | was | is |
| --- | --- | --- |
| moat-persist-hypr-config-write | Hyprland configuration modified by a non-editor | Something added itself to your login |
| moat-cred-ssh-read | Private SSH key read by an unexpected program | A program you don't recognise read your SSH key |
| moat-priv-ldso-preload | /etc/ld.so.preload created or modified | Something is trying to load itself into every program you run |
| moat-pkg-downloader-exec | Package install ran a downloader or decoder | An install pulled something extra off the internet |
| moat-x-noisy-rule | Noise guard demoted rule after threshold | Moat stopped asking about something that kept happening |

**The verdict line has exactly four forms** — no other sentence may occupy that slot, and it is never a count of events:
- `● #7ba37f` Nothing needs you.
- `● #e0523f` One thing needs you. / Three things need you.
- `● #e0523f` This one needs you now.
- `● #f2a25a` Watching, with one gap.

**Words the panel doesn't use** (fine in evidence, in `moatctl`, and in TOML — never in a title): unacked, policies, tetragon, allowlist, suppressed, demoted, ancestry, exe, tuple.

---

## Interactions & Behavior

**Navigation**
- Three tabs: Now, History, Rules. Settings is a gear in the header, not a tab. Nothing else is top-level.
- `Now` shows one of four states: quiet (1a), one needs-you (1b), several needs-you (3c), or a live chain (3a). The state is derived, never chosen.
- Summary rows in 1a and "Also today" rows in 1b navigate to the incident (chevron affordance).

**Incident actions**
- `This was me` → opens the scope chips (1c). Choosing a scope and confirming writes one allowlist line, closes the incident, and adds a row to Rules → Yours.
- `Stop it` → kills the process, quarantines the written file, shows the 30-second undo toast (2c), then leaves a permanent `Restore` on the incident while the quarantined file exists.
- `Contain it` (3a only) → the step list in 3b; steps 1–3 are machine-side and reversible, step 4 is the user's and is what actually closes the incident.
- `I don't know` → incident stays open but muted until something new happens; offers the evidence bundle.
- `Show evidence` toggles the evidence block in place. `Ask Moat` opens the thread (2a) with the incident card collapsed to a header strip.

**Grouping and dedup**
- Alerts collapse by (rule, program) into one incident carrying a count and a first/last time.
- A repeat **must not** re-sort the list or re-notify; it increments the count.
- Alerts sharing a process tree within a short window and crossing two or more detection families correlate into a chain incident (3a) whose verdict is written about the sequence.
- A chain-level allow resolves sibling alerts in the same chain (2b).

**Notifications** — three shapes (2h); only needs-you interrupts. Bursts are counted and delivered as one "N more" message. Weekly digest is the only scheduled send.

**Keyboard** (2g): j/k, a (then 1–4), s, e, ?, u. Same verbs as the buttons and as `moatctl`.

**Learning mode**: 9 days. No blocking, only serious interrupts, visible progress (1g). At the end, one notification summarising what changed and the single honest prompt for enforce mode.

**Enforce mode**: after any block, show 3d. Two blocks in a week prompts to turn it off.

**Sensor health** gates the verdict line: no calm claim unless every row in 2f is healthy.

**Undo window**: 30 seconds for a stop, with a visible countdown; `u` undoes the last action.

## State Management

Panel-level:
- `verdictState`: `quiet | needsYou | chain | gap` — derived from open incidents plus sensor health, never set directly.
- `activeTab`: `now | history | rules`; `settingsOpen`.
- `sensorHealth`: per-subsystem status (hooks, detections loaded, feed freshness, blind spells) — inputs to `verdictState`.
- `learning`: `{ active, dayIndex, dayTotal, learnedCount, knownPrograms[] }`.
- `mode`: `monitor | enforce`; `notifyLevel`; `weeklyDigest`; `sandboxShims`.

Incident:
- `id`, `ruleId`, `program`, `title`, `stake`, `state` (`needsYou | explained | expected | contained | closed`), `count`, `firstSeen`, `lastSeen`, `verdict` (AI paragraph + optional benign-explanation line), `facts[]`, `evidence{}`, `chain[]`, `snapshot` (previous file bytes, if any), `quarantine[]`, `thread[]`, `uncertainty` (sorts 3c).
- Transitions: `needsYou → closed` via this-was-me (writes a rule) · `needsYou → contained` via stop/contain (reversible for 30s, then via Restore) · `needsYou → muted` via I-don't-know · `explained → needsYou` if a new event breaks the earlier verdict.

Rules:
- `userRules[]` (`{ label, scope, binary, addedAt, silencedCount }`), `shippedRuleGroups[]`, `trustedPrograms[]` (`{ program, scope, lastSeen, silencedCount, binaryHash }`), `quarantine[]`.

Async: the AI verdict is generated on incident creation, not on demand — the UI needs a pending state for it (the incident is still listed, with the title and facts, while the paragraph resolves). The thread in 2a streams.

## Design Tokens

**Colours**
- Page background `#08090b`
- Panel `#0d0e10` · panel footer `#0a0b0d` · inset/code `#0a0b0d`
- Card `#121316` · chip/inset `#191a1d` · dim chip `#141518` · toggle track `#23252a` · evidence panel `#0e0f12`
- Hairline `rgba(255,255,255,0.05)` (rows) · `rgba(255,255,255,0.06)` (chrome) · divider `rgba(255,255,255,0.09)`
- Text: primary `#f6f4f2` · bright body `#e8e4e0` · body `#d6d2ce` · secondary `#b3aea8` · muted `#a09b95` · dim `#9d9892` · dimmer `#837e79` · faint `#6d6863` · fainter `#55514d` · ghost `#3d3a37` · deepest `#26241f`
- Accent (Moat's own) `#f2a25a`; on-accent text `#1a1006`; accent tints `rgba(242,162,90,0.04 / 0.11 / 0.24 / 0.28 / 0.4)`
- Alarm `#e0523f`; on-alarm text `#1a0805`; tints `rgba(224,82,63,0.06 / 0.13 / 0.22 / 0.3 / 0.5)`
- Calm `#7ba37f`; diff-add text `#a8c9a9` on `rgba(123,163,127,0.07)`

**Typography** — JetBrains Mono throughout (400/500/700). Material Symbols Rounded for glyphs (weight 300, optical size 24).
- Verdict line 26px/500, `letter-spacing: -0.01em`
- Card/section heading 19–20px/500
- Incident title in a row 14px
- Verdict paragraph 14px, `line-height: 1.75`
- Body / row title 13px, `line-height: 1.7`
- Secondary 12px, `line-height: 1.6–1.7`
- Meta / caption 11px, `line-height: 1.6`
- Section label 11px, `letter-spacing: 0.16em`, uppercase (verdict-block label uses `0.14em`)
- Code / diff 12.5px, `line-height: 2`
- `text-wrap: pretty` on every paragraph

**Spacing** — 2 · 4 · 5 · 7 · 9 · 10 · 12 · 14 · 16 · 18 · 20 · 22 · 24 · 26 · 28 · 30 · 34 · 40 · 44 · 46 · 52px. Panel body padding `40px 44px 34px`; card padding `26px 28px 24px`; small card `18px 20px`; row padding `14px 0`.

**Radii** — 5px badge · 7px small chip · 8px tab · 9px chip/inset · 10px button · 11px inner card · 12px card · 13px notification/toast · 14px incident card · 16px panel · 50% dots.

**Shadow** — panels only: `0 30px 80px rgba(0,0,0,0.6)`.

**Other** — state dot 9px; history tick 3px wide × 22px tall, radius 2px; progress bars 3px (undo) and 5px (learning); toggle 42×23px with a 17px knob; chain rail 1px connector with 8–9px dots.

## Assets

No images. Glyphs are **Material Symbols Rounded** (Google Fonts): shield, shield_lock, settings, close, history, chevron_right, expand_less, check, check_circle, block, lightbulb, route, lock_clock, fingerprint, visibility_off, done_all. Fonts are **JetBrains Mono** and Material Symbols Rounded, both Google Fonts. Substitute the codebase's own monospace and icon set if it has them — the icon choices are conventional and portable.

## Files

- `Moat.dc.html` — the full design document. Three `<section>` elements, newest turn first (turn 3, turn 2, turn 1). Every screen has an id badge (`1a`…`3g`) matching the ids used throughout this README, plus a short note beneath it explaining what changed from the original and why.
- `support.js` — runtime for the design file; not part of the design.
- `original-screens/` — the four screenshots of the current Moat UI that this redesign replaces (Alerts, Timeline, Allowlist, Settings), for before/after reference.

To read a specific screen, open `Moat.dc.html` and search for `id="1b"` (or any other id).
