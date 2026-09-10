# Moat — omarchy-shell plugin

The user-facing half of `omarchy-moat`. It reads the alert log moatd
writes, shows a shield in the bar, and gives every alert a panel that explains
what happened and offers the two things you can do about it.

**The panel is the redesign in `docs/design/`.** `docs/design/PLAN.md` is the
staged plan and the two decisions that shape it; `docs/design/README.md` is the
handoff, and every screen id used in a comment in this directory (`1b`, `2e`,
`3g`…) refers to it. One idea runs through all of it: **answer first, evidence
on request.** Severity stops being a pill on every row and becomes three states
saying what is wanted from the user; alerts collapse by (rule, program) into
incidents; four tabs become three plus a gear; five action buttons become one
primary and one secondary with scope as a follow-up question.

The plugin never touches processes or files itself. Every action is a
`moatctl` call that names an **alert id** — the daemon looks up what it
already recorded for that id and acts on that. A plugin bug therefore cannot
kill or quarantine something the sensor did not flag.

## Files

| File | What it is |
|------|------------|
| `../manifest.json` | Plugin manifest: kinds `service`, `bar-widget`, `panel`, `keepLoaded: true`, and the `barWidget.defaults` + `schema` for the seven settings. |
| `MoatModel.js` | All the logic, as pure functions: JSONL parsing, update folding, rotation detection, severity ordering, surface/visibility selection, timeline grouping, unacked counts, the notification decision, `explain` normalization, ignore-scope ordering, allowlist parsing, baseline status/proposal/export parsing, rotate guidance, relative time, LEARNING's rarity classes, install receipts, incident snapshots, agent-name/bundle-response parsing — plus the redesign's own derivations: `buildIncidents`, `alertState`, `needsYouIncidents`, `verdict`, `sensorHealthy`, `silenceScopes`, `historyDays`, `shippedRuleGroups`, `userRuleRows`, `trustedPrograms`, `chainSteps`, `barState`, `learningCard`, `blockedIncidents`. `.pragma library`, no QML types — which is what makes it unit-testable. |
| `MoatCopy.js` | The 3g copy contract: a `title` and a `stake` for every shipped detection, the four forms of the verdict line, the state words, the scope chips and their consequences (1c), the shipped-rule group names (1e), the notification shapes (2h), the keyboard table (2g), what Moat watches (3f) — and `bannedWordsIn`, which is 3g's banned list as a test rather than a comment. Also `oneLine`, which every process-derived string in a row goes through. |
| `Tokens.qml` | The design's palette, type scale, spacing scale and radii, **derived from the user's Omarchy theme** rather than copied from the handoff's fixed hex. Polarity-aware, so "one step off the background" goes the right way on a light theme. Instantiated once per surface and passed down like `service`; the plugin has no qmldir and therefore no singletons. |
| `Service.qml` | Kind `service`. The single owner of state: tails `alerts.jsonl`, polls `moatctl status --json`, loads the allowlist and the baseline export, reads `omarchy default agent` once at start, queues actions, sends notifications, and exposes `alerts` / `receipts` / `incidents` / `allIncidents` / `needsYou` / `verdict` / `barState` / `trustedPrograms` / `baselineTuples` / `status` / `proposals` / `quarantineItems` plus the action functions. The old `alertsSurface` / `timelineGroups` / `timelineRows` bindings are gone with the tabs they fed — the model functions stay, because `alertSurface` is still what the badge and the notification decision read. |
| `BarWidget.qml` | Kind `bar-widget`. 3e: exactly **three** states — quiet (dim shield, no text), needs you (alarm shield + a count of decisions), sensor gap (accent shield + the word "gap") — read from the same `Model.barState` over the same `Model.verdict` the panel prints, so the bar and the panel cannot disagree. |
| `Panel.qml` | Kind `panel`. The `FloatingWindow` (a real toplevel — see *The panel is a window*), the three tabs and the gear, the keyboard (2g), the confirms, and the routing between views. |
| `NowView.qml` | The Now tab (1a, 1b, 3c): the verdict line in its four forms, the incident that needs you as the page, the rest of the queue ordered by uncertainty, the quiet-day summary rows, the learning card, the post-block apology, and the footer strip. |
| `IncidentCard.qml` | One incident (1b, 1c): title, meta row, the AI verdict as one paragraph, two facts, rotate guidance, two actions plus "I don't know" and "Show evidence", and the drawers those open. |
| `ScopeChoice.qml` | 1c. "This was me" writes nothing; it asks how wide. Four consequence-labelled chips, a consequence card for the selected one only, and the exact TOML one click away. The scopes are the daemon's own `explain.if_expected.options[]`. |
| `EvidenceBlock.qml` | 1b's evidence drawer with 2b's chain inside it. Where severity finally appears — once, as a fact with its reason, never as a badge. |
| `SummaryRow.qml` | One row of "What it watched today" / "Also today". |
| `HistoryView.qml` | The History tab (1d): filter chips, day groups with their counts, and the installs Moat watched through. |
| `HistoryRow.qml` | One History row: a 3px tick and the brightness of the title instead of a severity pill, so a page of history carries at most one alarm-coloured mark. |
| `RulesView.qml` | The Rules tab: 1e (Yours first, with what each rule has silenced since; shipped rules grouped into about five lines), 2e (programs Moat treats as yours, and what each is trusted for), 2c's holding list, and the baseline proposals. |
| `SettingsView.qml` | 1f. Every row is a question and the control is its answer, with one line of consequence. Advanced is collapsed and its contents are listed in the header. |
| `SettingsRow.qml` | One Settings row: question and consequence left, answer right. |
| `MoatKeyed.qml` | A Column of one item per key, kept across changes of its list. History's day groups and rows sit in it: a Repeater over a JS array remakes every delegate when the array changes, and the array changes on every poll. Pure QtQuick, so `tests/tst_keyed.qml` can instantiate it. |
| `MoatChip.qml` | The chip. Three states, and the third is the point: `dim` is for an option that is available but must never look like the easy one. |
| `LearningCard.qml` | 1g. The learning window as a finite job with an end, and the one honest moment the enforce question can be asked. |
| `FirstRunView.qml` | 3f. What Moat watches, what it never does, and what the first nine days will look like. |
| `BlockedCard.qml` | 3d. Enforce mode's real UI is the apology, not the switch. |
| `SetupView.qml` | Shown instead of everything when the package or the group is missing, with the exact commands. |
| `tests/tst_model.qml` | 140 unit tests over `MoatModel.js`. |
| `tests/fixtures/alerts.jsonl` | 21 realistic alerts across every family, plus 5 update lines including a dedupe `count` update, plus 2 install receipts. |
| `tests/fixtures/status.json` | A `status` response with `baseline`, `proposals[]` and `demoted_rules[]`. |
| `tests/tst_wire.qml` | 36 wire tests: `MoatModel.js` against output a REAL `moatd` produced, not hand-written examples of what it ought to produce. |
| `tests/tst_keyed.qml` | `MoatKeyed` keeps the item for a key: a new array of the same objects touches nothing, a changed value reaches the kept item, a reorder moves items rather than remaking them. |
| `tests/tst_tokens.qml` | The one suite that instantiates a view component. `Tokens.qml` imports nothing from Quickshell precisely so this can run; it checks that the derived palette still points the right way on a **light** theme, which is the failure nobody running a dark theme will ever see. |
| `tests/fixtures/wire/*` | Those captures. 14 files: `alerts.jsonl` plus twelve `--json` responses and one `bundle.md`. |
| `tests/capture-wire-fixtures.sh` | Regenerates `fixtures/wire/*` by running a real `moatd` unprivileged over a synthetic Tetragon export. Run it whenever the alert record or a socket response changes shape. |
| `tests/gen-export-log.py` | The synthetic export that capture script replays. |
| `tests/run-tests.sh` | Syntax pass over every `.qml` plus all three suites, headless. |

### Files the redesign deleted

`AlertRow.qml`, `AlertDetail.qml`, `TimelineView.qml`, `AllowlistView.qml` and
`QuarantineView.qml` are gone. Each was the old panel's answer to a question the
redesign answers differently — a severity pill per row, five headed prose blocks,
a fourth tab of medium-and-below, a list of TOML, a tab that was empty on almost
every machine on almost every day. Nothing they showed was lost:

- the five prose blocks collapse into one verdict paragraph plus `EvidenceBlock`;
- the rotate guidance moved onto `IncidentCard`, above the actions, because
  replacing a leaked key is the one thing no button on that card does;
- the triage undo moved into `EvidenceBlock`, beside the verdict it reverses;
- the install receipts moved into `HistoryView`, capped and below the day groups;
- the allowlist and the quarantine list are both sections of `RulesView`.

## Installing for development

The plugin is the **repository root** (`manifest.json` lives there, entry points
point into `shell/`), so the whole repo is the plugin directory.

```bash
# From a git remote — clones into ~/.config/omarchy/plugins/<id>/, disabled.
omarchy plugin add https://github.com/the2dl/omarchy-moat.git
omarchy plugin enable io.github.the2dl.moat

# From a local checkout — copy it, do not symlink: omarchy-plugin-validate
# refuses a plugin folder containing any symlink, and the shell agrees.
cp -r /path/to/omarchy-moat ~/.config/omarchy/plugins/io.github.the2dl.moat
omarchy-shell shell rescanPlugins
omarchy plugin enable io.github.the2dl.moat
```

Saving a file anywhere under `~/.config/omarchy/plugins/` hot-reloads the plugin
code. If a change does not take, `omarchy-shell shell rescanPlugins`, then
`omarchy restart shell`.

Validate before installing:

```bash
omarchy-plugin-validate /path/to/omarchy-moat
```

The bar widget lands in the right section. Move it with
`omarchy bar move io.github.the2dl.moat --before omarchy.clock`, and change
its settings with `omarchy bar set io.github.the2dl.moat minNotifySeverity critical`
(or from the panel's Settings, which writes the same entry). Without `--json`
that command stores the value as a string, so `BarWidget._flag` reads `"true"`,
`"1"`, `"yes"` and `"on"` as true — before it did not, and every boolean setting
was settable from the panel and silently dead from the command line. The eight settings
are `notifyMuted`, `minNotifySeverity`, `notifyCooldownMinutes`, `pollSeconds`,
`showCountBadge`, `showSuppressed`, `weeklyDigest` and `rawDetail`.

`rawDetail` is Advanced: the panel in the detection's own words instead of the
redesign's. It is the only setting on that screen that changes **nothing** about
what Moat does — the daemon's titles rather than `MoatCopy.js`'s, the rule id and
the severity beside every incident instead of only the state word, the recorded
process fields as fields, and the evidence open rather than behind a disclosure.
It reaches exactly two lines of `buildIncidents` (the title and the stake) and is
deliberately absent from `baselineOptions()` and `notifyOptions()`, so what is
surfaced, counted, notified and demoted is identical in both modes. 3g's banned
words are suspended in this mode and nowhere else: the list still binds every
entry in `Copy.COPY`, and `tst_model` asserts both halves of that.

`notifyMuted` is 1f's third answer to "when should Moat interrupt you?".
The severity floor cannot express it — "critical only" is not "never" — and the
enum the manifest declares for `minNotifySeverity` has no room for a fifth
value, so it is its own boolean. It is checked FIRST in `shouldNotify`, ahead of
every exception below it including the noise guard's, because a "never" with
exceptions is not never. Everything still lands in the panel and the bar glyph
still changes; nothing is dropped.

## Running the tests

```bash
shell/tests/run-tests.sh
```

Two environment variables are load-bearing and the script sets them:
`QT_QPA_PLATFORM=offscreen` (nothing is ever mapped) and
`QML_XHR_ALLOW_FILE_READ=1` (the suite reads its fixture over `XMLHttpRequest`,
which Qt blocks for `file://` URLs by default).

**There is almost no view-instantiation suite**, and this is not an oversight.
`tst_tokens.qml` is the exception and works only because `Tokens.qml` takes its
theme values as properties and imports nothing from Quickshell — keep it that
way. Every other view component imports `qs.Commons`, which imports `Quickshell` — and the Quickshell
QML plugin is *linked into the `quickshell` executable* (`Quickshell/qmldir`
declares `linktarget quickshell-coreplugin` and `prefer :/qt/qml/Quickshell/`).
A bare `qmltestrunner` cannot load it at any import path, so the views can only
be instantiated inside a running quickshell process. During development they
were checked exactly that way: a throwaway `quickshell -p` config that creates
every component with a fake service and creates **no windows** (`Panel.qml`'s
`FloatingWindow` starts `visible: false` and only `open()` maps it).
`run-tests.sh` covers those files with a `qmlformat` parse pass instead.

## Baselining: what the panel does with it

`docs/BASELINE.md` exists because 500 alerts a day means the user turns the
thing off. The daemon does the deciding; the plugin's job is to put every one of
those decisions somewhere the user can see it and undo it. Four moving parts:

**What a suppression means to the panel.** `alertVisible()` says whether an
alert is shown at all, and `alertState()` turns the same inputs into one of the
redesign's five states — the thing that decides whether an incident is on Now or
is a receding row in History. (`alertSurface()` still returns `alerts` or
`timeline`; it is what the badge and the notification decision read, and it
predates the redesign's three-tab navigation.) The rules, in the order they
apply:

1. a `suppressed_by` value → timeline, and hidden unless "show suppressed" is on
   — except `"demoted:<rule>"`, which BASELINE 8 lists as a `suppressed_by`
   value but BASELINE 5 wants visible and grouped. A demotion is quiet, not
   hidden; treating it as a suppression would erase from the panel the exact
   thing the noise guard wants the user to be able to look at;
2. a rule in `status.demoted_rules[]` → timeline, **whatever the severity** (this
   is the point of demoting a rule instead of deleting it, BASELINE 4);
3. otherwise high and critical → Alerts, medium and low → Timeline.

Both are computed from the folded alerts rather than stored on them, so the
moment the status poll reports a new demotion the shield, the badge and both
tabs re-sort with no re-read of `alerts.jsonl`.

**History sees them either way.** 1d's third filter chip is literally "Silenced
by a rule", so `Service.allIncidents` builds the same collapse with nothing
hidden and History reads that for the covered filter. The redesign's answer to
noise is that a covered row recedes into a 3px tick, not that it vanishes; the
Advanced setting still decides whether those rows join the other two filters.

**The badge means one thing.** `unackedCounts()` skips suppressed alerts and
demoted rules entirely and precomputes `badge` = unacked critical + high, which
is exactly what the `alerts` surface holds. `tst_model.qml` asserts the two
agree. The **tab badge** is a different number and deliberately so: it is
`needsYouCount`, a count of DECISIONS rather than of records, and it is the one
the bar glyph shows too.
`badgeCount()` falls back to critical+high for the daemon's own
`status.unacked`, which has no `badge` field and is only consulted when the log
is unreadable.

**One deliberate notification exception.** BASELINE 5 says medium never
notifies. `moat-x-noisy-rule` is medium and notifies anyway, because it is the
noise guard announcing that it has just stopped a rule from notifying — if that
alert sits silently in the timeline the user never learns a detection went
quiet. The exception is to the severity threshold *only*: ack, suppression and
demotion all still silence it, and the store's seen-set means it is still one
toast per alert id. It is spelled `NOISY_RULE_NOTIFIES` in `shouldNotify()`.
A toast from it opens the panel on **History**, since that is where the alert
lives. It is also the one alert exempt from the cooldown below.

**Notification cooldown and burst collapse.** BASELINE 5. At most one toast per
**rule** per `notifyCooldownMinutes` (manifest setting, integer 1–120, default
10). Alerts of that rule inside the window are counted, not toasted, and when
the window ends a single toast says `<program> tripped the same detection N more
times` (2h's third shape, sent at `low` urgency because a burst that has already
been counted is not news) whose click opens **History**. So a rule that floods costs two toasts per window,
never 173 — which is what the first live run actually produced in 15 minutes.
Nothing is dropped: every alert is still in the panel, still in the timeline
group, still counted.

The policy is pure functions over the store in `MoatModel.js`, so it is tested
without a clock:

- `notifyDecision(store, alert, nowMs, opts)` → `{ toast, collapsed, reason }`.
  It calls `shouldNotify()` itself (reason `filtered`), so `Service.qml` makes
  one call and BASELINE 5's table and the cooldown cannot drift apart. Other
  reasons: `noisy-rule`, `first`, `window-reset`, `critical-first-seen`,
  `cooldown`.
- Per-rule window state `{ rule, title, program, windowStart, windowMs, toasted,
  suppressedCount }` in `store.notifyWindows`; the window carries its own
  `windowMs` so a setting change mid-window cannot retroactively re-time it.
- `flushCollapsed(store, nowMs)` → `[{ rule, title, program, count }]` for every window
  whose time is up with a non-zero count, and clears what it returns. A 30 s
  `Timer` in `Service.qml` calls it, because the tail of a burst is exactly when
  no further alert arrives to drive the decision. A window rolled over early by
  a new alert parks its debt in `store.notifyPending` so the summary survives.
- **Bypasses:** `critical` **and** `rarity === "first_seen"` only — critical
  alone does not bypass, since a critical rule in a loop is the storm the
  cooldown exists for. A bypassing toast neither extends the window nor counts
  into its summary. `moat-x-noisy-rule` keeps its one-shot exception and opens
  no window at all.
- Filtered alerts (below threshold, priming load, acked, suppressed, demoted)
  never open or feed a window, so no summary can ever be toasted for something
  the user was never going to be told about.

**Timeline grouping.** Rows are keyed by (rule, actor exe), where the actor exe
is `actor.script` when an interpreter is carrying one and `process.exe`
otherwise — BASELINE 1 makes the script the actor, so `/tmp/a.sh` and
`/tmp/b.sh` under one `/usr/bin/bash` are two rows. The row's count is the sum
of the members' dedupe counts, so "a thousand identical events read as one row
with a count" is literally true.

**Older daemons.** Every BASELINE 8 field is optional. `actor.provenance` and
`context` fall back to `unknown` (never to `official` or `interactive` — those
are the values that buy a downgrade, and a typo must not buy one),
`severity_base` falls back to the shipped severity so the "high → medium" line
stays empty, and `suppressed_by` falls back to "" so nothing is hidden. A
`status` response with no `baseline` block reads as "not learning, nothing
proposed, nothing demoted", which is how the plugin behaved before any of this
existed.

## Learning, analysis, receipts and incidents

`docs/LEARNING-AND-ANALYSIS.md` adds five things to the alert record and one to
the settings. All six are optional: an alert from a daemon that predates them
renders exactly as it did before.

**Rarity (LEARNING 1).** `rarity` is one of `first_seen` / `rare` / `common` and
`rarity_text` is the sentence that explains it — "first time /usr/bin/node has
read ~/.aws on this machine". The detail pane puts it directly under WHAT
HAPPENED with a pill, because it is the single most useful line for deciding
whether something is worth caring about. It is **evidence, not a verdict**:
`normalizeRarity` never lets an unrecognized value become a class, nothing in
the model reads `rarity` when computing severity, surface, badge or
notification, and a `common` pill is styled as the quietest thing on the pane so
it cannot read as an all-clear.

**Agent verdict (LEARNING 2c).** `triage` is what an unattended agent pass made
of the alert: `verdict`, `confidence`, `summary`, `reasoning`, an optional
`proposed_allowlist`, and `outcome` (`annotated` / `demoted` /
`withheld: <reason>`). It gets an AGENT VERDICT block after the five CONTRACT 7
blocks, for the same reason ANALYSIS sits there — the kernel's evidence is read
before a model's opinion of it — and one italic line on the row.

Four rules govern it, and all four exist because these strings were written by
a language model that had just read hostile input:

- Every string renders as `Text.PlainText`. A verdict does not get to bring
  markup with it.
- `normalizeTriage` degrades an unrecognized `verdict` or `confidence` to
  `unclear` / `low` — towards "nobody knows", never towards "benign" — and a
  block with neither summary nor reasoning is not a verdict at all.
- `proposed_allowlist` is **displayed, never applied**. The plugin has no verb
  that writes an allowlist file from a string, and this is exactly the string
  that must not be given one; the IF THIS IS EXPECTED buttons stay the only way
  an entry gets written.
- The pill is quiet unless the verdict is `suspicious` or `malicious`. A
  confident-sounding benign verdict that shouts is how an injected one would
  get the user to stop reading.

`outcome: "demoted"` is the one thing that moves an alert, from the badge to
the timeline, and `alertSurface` reads it as a **third** source of demotion
beside `status.demoted_rules[]` and the `demoted:<rule>` marker. Without that
the panel would derive the tab from rule and severity alone and a demotion
would change nothing visible. The block carries an Undo button that calls
`triage-undo`: a demotion the user cannot reverse from the panel is a demotion
they have to trust.

**Install receipts (LEARNING 3).** A line of the form `{"v":1,"receipt":{...}}`
in `alerts.jsonl` is a receipt, not an alert. They are separated at parse time
rather than filtered later: `parseLine` admits them, `foldRecords` skips them,
and `ingestText` returns them in their own `receipts` array. That is what makes
"receipts never notify and never count" true by construction — there is no path
by which one can reach `newIds`, `unackedCounts` or an incident, and
`tst_model.qml` asserts appending one moves neither the badge nor the totals.

`timelineRows()` interleaves them with the alert groups, newest first, in one
list. Two kinds in one list rather than two stacked lists is deliberate: the
point of a timeline is chronology, and filing the install in a separate panel
from the one alert that install raised breaks both. A row reads
`npm install in ~/Projects/app · 41 s · 3 postinstall · 3 hosts` and expands
into the six-line block LEARNING 3 prints verbatim.

LEARNING 3 names the receipt's fields in prose rather than as a schema, so
`normalizeReceipt` accepts the two plausible spellings of each and everything
degrades to an empty list or a zero. The **primary** spelling — what the daemon
should send — is the one the document names: `root_exe`, `root_args`, `cwd`,
`started`, `duration_s`, `exit`, `postinstall_scripts[]`,
`writes_outside_project[]`, `network[]`, `credential_reads[]`,
`persistence_writes[]`, `execs_from_tree`, `execs_from_tmp`. Accepted as
fallbacks: `exe`/`args` for the root pair, `project`/`dir` for `cwd`,
`start_ts`/`ts` for `started`. Every list entry may be a bare string or an
object (`{path}`, `{host}`, `{name}`); `persistence_writes[]` entries may carry
`alerted` and `severity`, which is what renders
`.husky/pre-commit (alerted, low)`.

**Incident snapshots (LEARNING 4).** `incident: {dir, files: [...]}` names what
the daemon captured into `/var/lib/moat/incidents/<id>/` before any kill. The
evidence drawer names the directory as a fact ("kept at"), and **Copy bundle**
puts the path of the bundle beside it on the clipboard. Nothing opens them: they are a byte-for-byte copy of exactly the
untrusted material the alert is about. A file entry may be a bare name or
`{name, size|bytes, sha256}`, and a relative name is resolved against `dir`
because the path is the thing that goes on the clipboard.

**Open in the Omarchy agent (LEARNING 2, and NOT the design's 2a).** It is the
last text link on the incident card, after the two answers and after the
evidence: the user reads what happened and decides before being offered a
second opinion.

Three things about the label, and the third is the one that keeps being got
wrong. It does not say "Ask Moat", because the design's 2a is a thread inside
the panel and the daemon has no endpoint for one — this opens a **terminal**.
It does not name the agent, because `omarchy default agent` may be claude,
codex, opencode or anything else and Moat does not put one vendor's name on its
own button; which one it is lives in the tooltip, with the warning that the
panel will close. And it is absent entirely with no default set, replaced by
the hint `Set a default agent: omarchy default agent <name>` — a next step
rather than a dead control.

`normalizeAgentName` accepts only `[A-Za-z0-9._-]{1,64}`, so a wrapper that
prints "no default agent set" cannot become anything. The name is read once at
service start through `bash -c`, so a machine without `omarchy` on PATH is a
quiet empty answer rather than a failed-to-start process.

**The panel closes when it is pressed.** It is a Wayland overlay layer: a
terminal spawned underneath it is invisible, and a button that opened one and
left the panel on top read as a button that did nothing at all.

Clicking runs `moatctl analyze <id>` and nothing else. **The plugin builds no
prompt and reads no bundle**, and that is a security property rather than a
layering preference: `moatctl` writes `bundle.md` with every process-derived
field inside ```` ```DATA ```` fences precisely because an alert about a
malicious postinstall must not become a prompt-injection channel into the agent
analyzing it — the s1ngularity attack drove the victim's own AI CLIs. A prompt
assembled here out of alert fields would be exactly that channel. The result is
a transient line next to the button ("opened in claude", or the daemon's own
error when moatctl exits non-zero), cleared after 12 s.

**Copy bundle path** is the smaller sibling for someone already talking to an
agent: `moatctl bundle <id> --json`, then the path onto the clipboard.
`parseBundleResponse` accepts `path` / `bundle` / `bundle_path` / `file`, or a
daemon that just prints the path, and **refuses anything that is not absolute**
— the only use for that value is to be pasted into a terminal. The copy itself
goes through `bash -c 'printf %s "$1" | wl-copy'` with the text as a
**positional parameter**, never interpolated into the script, so a path out of a
daemon response cannot become a command. Same rule `Util.execArgv` enforces for
the notification vector.

**Weekly digest (LEARNING 5).** `weeklyDigest` (boolean, default true) is a bar
widget setting like the other four, and the Settings tab's toggle writes it. The
daemon owns the schedule and sends the notification; the toggle runs
`moatctl set digest on|off` and the plugin does nothing else with it. It is the
only scheduled notification moat sends, which is why its switch is a headed
section rather than a line in a list.

## The notification mechanism, and why

**Mechanism:** `omarchy-notification-send --app-name Moat -u <urgency>
-g <glyph> <title> <body> --exec omarchy-shell shell summon
io.github.the2dl.moat '{"alert":"<id>"}'`, run through
`Commons.Util.execArgv` (which executes the vector as bash *positional
parameters*, never a shell string, so an alert id or a file path can never
become a command).

**Why that and not `notify-send`, and not a libnotify action:**

`omarchy-notification-send` calls `org.freedesktop.Notifications.Notify`
directly over `busctl` rather than shelling out to `notify-send`. That matters
here specifically: `notify-send`'s argv parsing is the surface that would
reinterpret a relayed headline like `--hint=…` as an option, and Moat's
headlines and bodies contain attacker-influenced text (process paths, args,
domains). Going through `busctl` makes the summary and body typed D-Bus strings
that cannot become hints.

The click action rides as the `omarchy-exec-argv` hint, which `--exec` is the
only way to set. `NotificationLogic.parseExecArgv` +
`Service.invokePopupDefault` in `/usr/share/omarchy/shell/plugins/notifications/`
are what make that clickable, and because the hint is persisted with the toast,
a Moat alert stays clickable across a shell restart — a libnotify action
would not, since its sender is gone.

**Deviation from CONTRACT 7, deliberate:** the contract asks for toast actions
*Kill / Quarantine / Ignore*. The omarchy-shell notification server renders
**exactly one** click action per toast — `omarchy-notification-send` always
sends an empty `actions` array, and `NotificationCard.qml` draws no action row;
`invokePopupDefault` runs the `execArgv` vector, or failing that a single
libnotify action whose identifier is literally `"default"`. There is no way to
put three buttons on a toast in this shell. So the single click opens the panel
*on that alert*, which is where Kill / Quarantine / Ack / Ignore live, and the
toast body names them so the click is not a mystery. Wiring the click directly
to `kill` was considered and rejected: a one-click irreversible kill with no
confirmation, fired from a surface that can be clicked by accident, is worse
than one extra click.

Urgency follows the contract: critical → `critical` (and `-t 0`, so it does not
expire on its own), high and medium → `normal`, low → `low`. `minNotifySeverity`
(default `high`) filters below that. Alerts that already existed when the shell
started **never** notify: `MoatModel.ingestText` marks the first ingest as
the priming load and returns no new ids for it, and `shouldNotify` refuses on
`initialLoad` independently, so a login does not replay the backlog as toasts.
Everything that survives that filter then passes the per-rule cooldown above.

## Notes on the shell's real API

Things worth knowing before changing this plugin.

- **A bar widget must be a `WidgetButton`.** The bar overlays its own MouseArea
  per slot and forwards presses only to items that registered themselves as
  click targets, which `WidgetButton` does in `Component.onCompleted`. A bare
  `Item` with a `MouseArea` or `TapHandler` never sees the press.
- **`escape` is an illegal method name in QML.** The panel's dismiss handler is
  called `dismiss()` for that reason.
- **Do not add a second `Keys.onPressed` to a `PanelKeyCatcher` instance** — it
  shadows the component's own handler and silently kills every key binding it
  provides. Wire its semantic signals instead. That is why the confirm dialog is
  driven from `moveSelection`/`activate`/`dismiss` rather than from
  `ConfirmDialog.handleKey`.
- **`baseline` is a reserved property name on an `Item`.** `readonly property var
  baseline` on a QML `Item` fails at load with "Cannot override FINAL property",
  and `qmlformat` parses it happily — only instantiating the component catches
  it. The service's is called `baselineState`. Property names beginning with an
  upper-case letter (`TABS`) are rejected for the same class of reason and are
  equally invisible to the syntax pass.
- **Settings live on the bar widget, not the service.** `barWidget.defaults` and
  `schema` are stored on the widget's `shell.json` layout entry; a `service`
  entry gets no settings. `BarWidget.qml` pushes them into the service, and the
  service's own defaults apply when the widget is not on the bar. The panel
  persists a change through `shell.pluginRegistry.setBarWidget(...)` — the same
  call `omarchy bar set` makes — and says so in the notice line when there is no
  entry to write.
- **The panel is a real window, not a layer-shell overlay.** See the section
  below.
- **The control socket was not used directly.** `Quickshell.Io.Socket` does
  exist in 0.3.1 and can connect to a unix path, but CONTRACT 5 is one
  request/response *per connection*, so a socket client would reconnect for every
  call anyway — and `moatctl` is the contract's own documented client for it.
  `Process` running `moatctl <verb> --json` costs one fork and removes a
  reconnect/framing state machine from inside the shell. `Service.qml`'s
  `_argvFor()` is the single place the CLI's argv is spelled out.

## The panel is a window

`Panel.qml` declares a Quickshell **`FloatingWindow`** — an ordinary xdg
toplevel that the compositor tiles, moves, resizes, stacks and focuses like any
other application window. It used to be a `PanelWindow` on `WlrLayer.Overlay`:
a full-screen layer surface with a 1400x860 card drawn inside it and
click-anywhere-outside to dismiss. That was right while the card was a
glanceable 900x640 corner popup. It stopped being right when the redesign made
it the surface you sit in front of and read: an expanded receipt had nowhere to
grow, and there was no way to move the thing, resize it, or put it beside the
terminal it is telling you about.

What that costs, and what it buys:

| Layer-shell overlay | Toplevel window |
|---|---|
| Always above every window | Takes its place in the stack; `SUPER`+click-drag moves it |
| Click outside to dismiss | Escape, the ✕, or the compositor's close |
| Fixed 1400x860 centred, bar clearance computed by hand | 1400x860 *preferred*; the user resizes it and everything reflows |
| Opened on the layer surface's default screen | Opens on the focused workspace, on whichever monitor that is |
| Keyboard focus asked for with `WlrLayershell.keyboardFocus` | Keyboard focus given by the compositor when the window maps |

Losing click-outside-to-dismiss is deliberate and is only acceptable because
the bar glyph exists: 3e gives it three states derived from the same
`Model.verdict` the panel prints, so nothing needs the panel open to be
glanceable.

### Window rules

**None are required, and none should be shipped.** The window identifies itself
as class `org.quickshell`, title `Moat`, and asks for 1400x860 through
`FloatingWindow.implicitWidth` / `implicitHeight`, with a floor of 820x520 in
`minimumSize`. With no rules at all Hyprland tiles it into the focused workspace
like any other window, and that is the intended default: the size request is
honoured when it floats and ignored when it tiles, which is exactly right.

Shipping `float` + `center` as a requirement would rebuild the overlay this
conversion exists to get away from — a surface that demands its own geometry and
cannot take part in the workspace is most of what was wrong with the layer-shell
version. The page adapts to the slot instead; see *A short window* below.

**Optional**, for someone who wants it floating over their work anyway — a
preference, not a dependency (Omarchy 4 parses Lua; one rule per call, the way
`default/hypr/apps/system.lua` writes them):

```lua
o.window({ class = "^org.quickshell$", title = "^Moat$" }, { float = true })
o.window({ class = "^org.quickshell$", title = "^Moat$" }, { center = true })
```

No `size` rule is needed — `implicitWidth`/`implicitHeight` already ask for
1400x860 and a floating window gets it. Add one only to override the plugin.

### A short window

The redesign's vertical rhythm is measured against its 860px page. A toplevel
gets whatever slot the layout hands it, and in a half-height tile (1263x686 on a
two-window workspace) the full rhythm spent a tenth of the window on gaps while
"What it watched today" got three of its four rows.

`Tokens.compact` is set by `Panel.qml` from the window's own height — under
`Style.space(780)` — and `Tokens.v(px)` scales **vertical** distances to 0.6
under it: `bodyPadTop`, `bodyPadBottom`, `cardPadTop`/`Bottom`, `smallCardPadY`
and every section gap. Keyed off the window rather than the screen, so the same
panel tightens when tiled and relaxes the instant it is floated or dragged
bigger; nobody on a large monitor pays for the small case.

Two things deliberately do **not** compact, and `tst_tokens` asserts both:
horizontal padding (`bodyPadX`, `cardPadX`, and `s()` generally) and the type
scale. The measure of a line of prose is not a function of how tall the window
is, and a shorter window is not a smaller one — narrowing the gutters to buy one
more row makes the page harder to read in exchange.

The learning card moved below the queue for the same reason. It is reassurance —
"the job has an end, here is how far through it is" — and it was sitting between
the incident that needs a decision and the list of the others, cutting the one
flow on the page in half (read the incident, press `j`, read the next) and, in a
short window, pushing that list off the bottom. On a quiet day the queue and the
card above it are both hidden, so it lands immediately under the verdict exactly
as it used to — which is where it belongs when it is the most interesting thing
on the screen.

### Opacity: the one thing a toplevel inherits that a layer surface did not

**This is the most visible difference, and it is not the plugin's doing.**
Omarchy tags every window for a default translucency —
`default/hypr/windows.lua` ends with

```lua
o.window(".*", { tag = "+default-opacity" })
o.window({ tag = "default-opacity" }, { opacity = "0.985 0.96" })
```

— and **window rules never applied to the layer surface this panel used to be**.
As a toplevel it now gets the same 1.5–4% transparency every other window gets.
On a terminal that reads as depth. On a dense dark reading surface over a
patterned wallpaper it reads as *grime*: the wallpaper's texture ghosts through
the header and the cards, and the whole panel looks smudged rather than
translucent.

To opt out, the way an app that should not be see-through does:

```lua
o.window({ class = "^org.quickshell$", title = "^Moat$" }, { tag = "-default-opacity" })
```

(Or `{ opacity = "1.0 1.0" }`, which forces it rather than untagging it.)

Separately, the theme's `popups.background-alpha` (0.94 here) is deliberately
**not** applied by the plugin: a popup may be see-through because the compositor
blurs what is behind it, but a window has another window behind it and its text
reads straight through. The toplevel paints `Tokens.pageOpaque` — the same
colour at alpha 1 — and every surface *inside* still uses `base`, so the alpha
the theme asked for keeps doing its work between the panel's own layers. To ask
for translucency anyway, ask the compositor, which is where a window's
transparency belongs:

```lua
o.window({ class = "^org.quickshell$", title = "^Moat$" }, { opacity = "0.94" })
```

### What the verbs mean now

`omarchy-shell shell toggle|summon|hide io.github.the2dl.moat` are unchanged,
and so are the `{"alert":"<id>"}` and `{"tab":"rules"}` payloads. What changed
is underneath:

- `opened` is `window.visible`, not a separate boolean. A toplevel can be closed
  by things the plugin never hears about first — the titlebar, `killactive`, a
  workspace being torn down — and a separate flag would let the shell's
  `openPanelIds` drift out of step with what is on screen, at which point a
  toggle does nothing.
- **`summon` on an already-open window raises it.** Under layer-shell an overlay
  was on top of everything, so summon and map were the same act. A toplevel can
  be behind something or on another workspace, and a notification click that
  changed nothing visible reads as Moat being broken. `raiseWindow()` shells out
  to `hyprctl dispatch` in **both** spellings — `hl.dsp.focus({ window = ... })`
  for Hyprland's Lua parser (Omarchy 4) and `focuswindow <selector>` for the
  legacy one — because each parser rejects the other's form outright and the
  rejected one is a harmless no-op. It matches on title, because a Hyprland
  window selector takes exactly one criterion: `class:... title:...` together
  finds nothing.
- **`close` has two callers with different meanings.** `close()` is the host's
  (`shell hide`, and `toggle` when it finds us open) and drops the surface
  without calling back. `requestClose()` is the user's (Escape, the ✕) and goes
  through `shell.hide()` so `openPanelIds` stays consistent. The window's own
  `onVisibleChanged` covers the third case — the compositor closing it — by
  calling `requestClose()` unless `closingFromHost` says the shell already knows.
- **Focus is the compositor's to give.** `WlrLayershell.keyboardFocus` and its
  75 ms `Exclusive` prime are gone. `PanelKeyCatcher` takes focus in a
  `Qt.callLater` after `open()` (the content tree is not mounted until the window
  maps) and again whenever `Window.active` goes true, which is what makes Escape
  work after you click away and back.

## Keyboard

2g. The same verbs as the buttons, and the same four things `moatctl` does.

| Key | Action |
|-----|--------|
| `j` / `k`, `↓` / `↑` | Next / previous incident |
| `a` | This was me — then `1`-`4` to pick how wide (1c's chips) |
| `s` | Stop it (confirms once) |
| `e` | Show / hide the evidence |
| `?` | Hand the evidence bundle to the Omarchy agent — this opens a terminal and closes the panel |
| `u` | Undo the last thing you did |
| `Esc` | Close the panel (or cancel the confirm) |
| `Enter` / `Space` | Confirm the open dialog |
| `t` | Cycle Now → History → Rules → Settings |
| `r` | Refresh |

**`u` only claims what the daemon can actually reverse.** Holding a file is
undone by `quarantine --restore`; a rule the last "this was me" wrote is undone
by `unignore`, found by what the rule is ABOUT because the daemon assigns its
(fragment, index) only after the reload — the panel never renumbers. Stopping a
process is **not** undoable and the notice says so, because an Undo that
silently does nothing is worse than no Undo.

## Ignore scopes, and 1c

CONTRACT 5's `ignore` takes `exe`, `exe+file`, `parent` or `rule`, and the alert
declares which of them the daemon is prepared to write, each with the exact TOML
block it would append. `Model.silenceScopes` turns those into 1c's chips.

Three rules the model enforces:

- An unrecognized scope normalizes to `exe`, never to `rule`. A typo must narrow
  an allowlist entry, not widen it.
- When an alert offers options but no `if_expected.hint`, the recommendation
  falls back to the **narrowest** offered scope.
- The machine-wide scope (`rule`) is drawn last and duller, and can never arrive
  recommended or pre-selected however the daemon ordered its options. It is the
  one choice whose consequences cannot be seen from the screen it is offered on.

Every chip is labelled with its **consequence** ("when claude does it", "only
claude, only this file"), and only the chosen one is explained — with two halves
always: what stops asking, and what still gets through. The TOML stays one click
away behind "Show the rule it writes".

A **proposal** (BASELINE 3) is the same decision one step earlier, and sits at
the top of Rules: `moatctl baseline accept <id>` / `dismiss <id>`. Neither goes
through a confirm — an accepted entry appears in the same tab with an Undo, and
a dismissed pattern proposes itself again if it keeps recurring.

## Strings that came out of a process

Two rules, and both are needed.

**`textFormat: Text.PlainText` on anything derived from process or model
output.** Titles, args, paths, hosts, verdict paragraphs, allowlist comments,
receipt lines, daemon error strings. This is what stops such a string being read
as *markup*.

**`Copy.oneLine(text, max)` on anything that shares a row with something else.**
This is what stops it being read as *layout*, and it is not optional: an elided
`Text` still honours an embedded newline, so one alert whose command line
carried a 3 kB argument rendered a single History row as forty lines of somebody
else's text. `titleFor`, `stakeFor`, `receiptCommand`, `receiptSummary` and the
2e scope column all go through it, and the single-line rows say
`maximumLineCount: 1` as well.

## What is deliberately not built

Three things the handoff asks for have no daemon endpoint behind them, and none
of them is faked:

- **2a, Ask Moat.** The design's is a streaming thread on an incident. There is
  no socket verb for one. What exists is `moatctl analyze`, which writes the
  evidence bundle and hands it to `omarchy-agent` — a **terminal**, not a panel.
  The button says "Open in the Omarchy agent" and the panel closes on the way,
  because a button that spawns a window under a Wayland overlay reads as a
  button that does nothing. The label never carries the agent's own name:
  `omarchy default agent` may be any of them, and which one it is belongs in the
  tooltip.
- **2d, file diffs and revert.** moatd takes no before-snapshot of a written
  file, so there is nothing to diff against and nothing to put back.
- **3b, containment steps.** There is no verb that cuts network access or
  freezes a process tree, and a numbered list whose steps do not run is worse
  than no list.
- **2i's mute.** The bundle half is real (`moatctl bundle`, saved or copied).
  Leaving an incident open-but-muted until something new happens is a state the
  daemon does not have — `ack` closes an alert, which is a different promise —
  so the panel offers the file and says nothing about muting.

Stage 4 of `docs/design/PLAN.md` (incidents in the daemon, chain correlation) is
someone else's work and lands behind the model API this panel already uses.

