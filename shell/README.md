# Moat — omarchy-shell plugin

The user-facing half of `omarchy-moat`. It reads the alert log moatd
writes, shows a shield in the bar, and gives every alert a panel that explains
what happened and offers the four things you can do about it.

The plugin never touches processes or files itself. Every action is a
`moatctl` call that names an **alert id** — the daemon looks up what it
already recorded for that id and acts on that. A plugin bug therefore cannot
kill or quarantine something the sensor did not flag.

## Files

| File | What it is |
|------|------------|
| `../manifest.json` | Plugin manifest: kinds `service`, `bar-widget`, `panel`, `keepLoaded: true`, and the `barWidget.defaults` + `schema` for the six settings. |
| `MoatModel.js` | All the logic, as pure functions: JSONL parsing, update folding, rotation detection, severity ordering, surface/visibility selection, timeline grouping and row interleaving, unacked counts, the notification decision, `explain` normalization, ignore-scope ordering, allowlist parsing, baseline status/proposal parsing, rotate guidance, relative time, plus LEARNING's rarity classes, install receipts, incident snapshots and agent-name/bundle-response parsing. `.pragma library`, no QML types — which is what makes it unit-testable. |
| `Service.qml` | Kind `service`. The single owner of state: tails `alerts.jsonl`, polls `moatctl status --json`, reads `omarchy default agent` once at start, queues actions, sends notifications, exposes `alerts` / `receipts` / `alertsSurface` / `timelineGroups` / `timelineRows` / `unacked` / `status` / `proposals` / `available` / `groupOk`, the action functions, and the three out-of-queue calls `analyze` / `copyBundlePath` / `copyText`. |
| `BarWidget.qml` | Kind `bar-widget`. A `WidgetButton` drawing the shield glyph plus a count badge. |
| `Panel.qml` | Kind `panel`. The window, the four tabs, keyboard handling, confirmations and the status strip. |
| `AlertRow.qml` | One row of the alert list: severity pill, title, exe basename, relative time, ack state. |
| `AlertDetail.qml` | The five headed blocks: WHAT HAPPENED (with the rarity line and pill, the context/actor and the severity-adjustment lines), WHY IT WAS FLAGGED, EVIDENCE, INCIDENT SNAPSHOT, IF THIS IS EXPECTED, WHAT TO DO — plus a sixth, ANALYSIS, after them. |
| `SetupView.qml` | Shown instead of the alert list when the package or the group is missing, with the exact commands. |
| `TimelineView.qml` | The Timeline tab: medium, low, demoted and (on request) suppressed alerts, grouped by (rule, actor exe) with a count and the latest time, each row expandable into its alerts — interleaved chronologically with the install receipts, which expand into the six-line receipt block. |
| `AllowlistView.qml` | The Allowlist tab: proposals with Accept / Dismiss, the user's own `user.toml` rules and the learning window's `baseline.toml` entries tagged "learned" (each with a Remove button that names the fragment as well as the index), and the package's `omarchy-default.toml` entries — listed with their reason and no Remove button, because the daemon reports them `removable: false`. |
| `SettingsView.qml` | The Settings tab: mode, sandbox shims, minimum notify severity, notification cooldown, show suppressed, weekly digest, and Relearn baseline. |
| `tests/tst_model.qml` | 90 unit tests over `MoatModel.js`. |
| `tests/fixtures/alerts.jsonl` | 21 realistic alerts across every family, plus 5 update lines including a dedupe `count` update, plus 2 install receipts. Seven carry BASELINE 8's fields: an interactive-context downgrade, a pkg-install upgrade, a suppressed alert, three alerts of a demoted rule, and a `moat-x-noisy-rule` alert. The last alert carries LEARNING's `rarity`, `rarity_text` and `incident`. |
| `tests/fixtures/status.json` | A `status` response with `baseline`, `proposals[]` and `demoted_rules[]`. |
| `tests/tst_wire.qml` | 36 wire tests: `MoatModel.js` against output a REAL `moatd` produced, not hand-written examples of what it ought to produce. Covers the fold, BASELINE 8's `actor`/`context`/`severity_base`/`surface`/`rarity`, the 2b context matrix (the same credential read scored medium interactively and critical inside `npm install`), LEARNING 3 receipts, LEARNING 4 incident blocks, the noise guard, `status` with `baseline`/`proposals`/`demoted_rules`/`digest`, `allowlist` with `source`/`removable`, and the bundle path. |
| `tests/fixtures/wire/*` | Those captures. 14 files: `alerts.jsonl` plus twelve `--json` responses and one `bundle.md`. |
| `tests/capture-wire-fixtures.sh` | Regenerates `fixtures/wire/*` by running a real `moatd` unprivileged over a synthetic Tetragon export. Run it whenever the alert record or a socket response changes shape. |
| `tests/gen-export-log.py` | The synthetic export that capture script replays: real Tetragon v1.7.1 event shapes, a fake home, fake pids, one live stand-in process so the incident snapshot reads a real `/proc`. |
| `tests/run-tests.sh` | Syntax pass over every `.qml` plus both suites, headless. |

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
(or from the panel's Settings tab, which writes the same entry). The six
settings are `minNotifySeverity`, `notifyCooldownMinutes`, `pollSeconds`,
`showCountBadge`, `showSuppressed` and `weeklyDigest`.

## Running the tests

```bash
shell/tests/run-tests.sh
```

Two environment variables are load-bearing and the script sets them:
`QT_QPA_PLATFORM=offscreen` (nothing is ever mapped) and
`QML_XHR_ALLOW_FILE_READ=1` (the suite reads its fixture over `XMLHttpRequest`,
which Qt blocks for `file://` URLs by default).

**There is no view-instantiation suite**, and this is not an oversight. The view
components import `qs.Commons`, which imports `Quickshell` — and the Quickshell
QML plugin is *linked into the `quickshell` executable* (`Quickshell/qmldir`
declares `linktarget quickshell-coreplugin` and `prefer :/qt/qml/Quickshell/`).
A bare `qmltestrunner` cannot load it at any import path, so the views can only
be instantiated inside a running quickshell process. During development they
were checked exactly that way: a throwaway `quickshell -p` config that creates
every component with a fake service and creates **no windows** (`Panel.qml`'s
`PanelWindow` is bound to `opened`, which stays false). `run-tests.sh` covers
those files with a `qmlformat` parse pass instead.

## Baselining: what the panel does with it

`docs/BASELINE.md` exists because 500 alerts a day means the user turns the
thing off. The daemon does the deciding; the plugin's job is to put every one of
those decisions somewhere the user can see it and undo it. Four moving parts:

**Two alert surfaces.** `MoatModel.alertSurface()` returns `alerts` or
`timeline` for every alert, and `alertVisible()` says whether it is shown at
all. The rules, in the order they apply:

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

**The badge means one thing.** `unackedCounts()` skips suppressed alerts and
demoted rules entirely and precomputes `badge` = unacked critical + high, which
is exactly what the Alerts tab holds. `tst_model.qml` asserts the two agree.
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
A toast from it opens the panel on the **Timeline** tab, since that is where the
alert lives. It is also the one alert exempt from the cooldown below.

**Notification cooldown and burst collapse.** BASELINE 5. At most one toast per
**rule** per `notifyCooldownMinutes` (manifest setting, integer 1–120, default
10). Alerts of that rule inside the window are counted, not toasted, and when
the window ends a single toast says `N more from <title>, see panel` whose click
opens the **Timeline** tab. So a rule that floods costs two toasts per window,
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
- Per-rule window state `{ rule, title, windowStart, windowMs, toasted,
  suppressedCount }` in `store.notifyWindows`; the window carries its own
  `windowMs` so a setting change mid-window cannot retroactively re-time it.
- `flushCollapsed(store, nowMs)` → `[{ rule, title, count }]` for every window
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

`docs/LEARNING-AND-ANALYSIS.md` adds four things to the alert record and one to
the settings. All five are optional: an alert from a daemon that predates them
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

**Install receipts (LEARNING 3).** A line of the form `{"v":1,"receipt":{...}}`
in `alerts.jsonl` is a receipt, not an alert. They are separated at parse time
rather than filtered later: `parseLine` admits them, `foldRecords` skips them,
and `ingestText` returns them in their own `receipts` array. That is what makes
"receipts never notify and never count" true by construction — there is no path
by which one can reach `newIds`, `unackedCounts` or the Alerts tab, and
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
detail pane lists the files with sizes and offers **Copy path** for the
directory. It never opens them: they are a byte-for-byte copy of exactly the
untrusted material the alert is about. A file entry may be a bare name or
`{name, size|bytes, sha256}`, and a relative name is resolved against `dir`
because the path is the thing that goes on the clipboard.

**Analyze with &lt;agent&gt; (LEARNING 2).** The ANALYSIS block is a sixth block
*after* the five CONTRACT 7 pins in order — the user reads what happened and
what to do about it before being offered a second opinion, and the five headed
blocks keep the order the contract fixes them in.

The button's label comes from `omarchy default agent`, read once at service
start through `bash -c` so a machine without `omarchy` on PATH is a quiet "no
default agent" rather than a failed-to-start process. `normalizeAgentName`
accepts only `[A-Za-z0-9._-]{1,64}`: a wrapper that prints "no default agent
set" must not become a button label. With no default set the block shows the
hint `Set a default agent: omarchy default agent claude` instead of a button.

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
- **The panel is a `panel`-kind plugin, so it has no anchor item.** First-party
  popups (`KeyboardPanel`) position themselves against the bar widget they were
  opened from; a panel-kind plugin is mounted by the shell's panel loader with
  no such handle. This one reads `shell.bar.position` / `shell.bar.barSize` and
  places its card under the bar on the widget's default side. **Known limit:**
  on a multi-monitor setup it opens on the `PanelWindow` default screen, not
  necessarily the one whose bar you clicked.
- **Keyboard focus needs the Exclusive prime.** Hyprland focuses an `OnDemand`
  layer surface when it first maps but not when an already-mapped one returns to
  `OnDemand`, and this panel can be summoned with no pointer involved at all (a
  notification click). The window primes with `Exclusive` for 75 ms and then
  settles on `OnDemand`, mirroring what `Ui/KeyboardPanel.qml` does.
- **The control socket was not used directly.** `Quickshell.Io.Socket` does
  exist in 0.3.1 and can connect to a unix path, but CONTRACT 5 is one
  request/response *per connection*, so a socket client would reconnect for every
  call anyway — and `moatctl` is the contract's own documented client for it.
  `Process` running `moatctl <verb> --json` costs one fork and removes a
  reconnect/framing state machine from inside the shell. `Service.qml`'s
  `_argvFor()` is the single place the CLI's argv is spelled out.

## Keyboard

| Key | Action |
|-----|--------|
| `Esc` | Close the panel (or cancel the confirm) |
| `j` / `k`, `↓` / `↑` | Move through the alert list — on the Timeline, through the rows of the groups that are actually expanded (or switch confirm buttons) |
| `Enter` / `Space` | Confirm the open dialog |
| `a` | Ack the selected alert |
| `t` | Cycle the tabs: Alerts → Timeline → Allowlist → Settings |
| `r` | Refresh |

## Ignore scopes

CONTRACT 5's `ignore` takes `exe`, `exe+file`, `parent` or `rule`, and the
detail pane offers one button per scope the alert declares, recommended first.
Two rules the model enforces:

- An unrecognized scope normalizes to `exe`, never to `rule`. A typo must narrow
  an allowlist entry, not widen it.
- When an alert offers options but no `if_expected.hint`, the recommendation
  falls back to the **narrowest** offered scope. Accidentally recommending
  `rule` would silence a detection machine-wide.

Every write shows the exact TOML block it would append in a collapsible
monospace panel before you press the button, and the daemon returns the block it
actually wrote, which the panel echoes back. Rules are listed and removable in
the Allowlist tab; `unignore` addresses them by the daemon's index, so the panel
displays that index verbatim and never renumbers.

A **proposal** (BASELINE 3) is the same deal one step earlier: it shows the block
that accepting would write, and Accept / Dismiss run
`moatctl baseline accept <id>` / `dismiss <id>`. Neither goes through a confirm —
an accepted entry appears in the same tab with a Remove button, and a dismissed
pattern proposes itself again if it keeps recurring. **Relearn baseline** does
confirm: it re-opens a window in which recurring medium and low alerts are
written to `baseline.toml` instead of shown.

A learned entry can only be removed when the daemon gives it an index, because
`unignore`'s index is the only handle CONTRACT 5 defines. One that arrives
without an index renders with its source file and the instruction to edit that
file, exactly like a rule merged from any other `allowlist.d` fragment.
