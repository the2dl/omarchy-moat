# Sentinel — omarchy-shell plugin

The user-facing half of `omarchy-sentinel`. It reads the alert log sentineld
writes, shows a shield in the bar, and gives every alert a panel that explains
what happened and offers the four things you can do about it.

The plugin never touches processes or files itself. Every action is a
`sentinelctl` call that names an **alert id** — the daemon looks up what it
already recorded for that id and acts on that. A plugin bug therefore cannot
kill or quarantine something the sensor did not flag.

## Files

| File | What it is |
|------|------------|
| `../manifest.json` | Plugin manifest: kinds `service`, `bar-widget`, `panel`, `keepLoaded: true`, and the `barWidget.defaults` + `schema` for the three settings. |
| `SentinelModel.js` | All the logic, as pure functions: JSONL parsing, update folding, rotation detection, severity ordering, unacked counts, the notification decision, `explain` normalization, ignore-scope ordering, allowlist parsing, rotate guidance, relative time. `.pragma library`, no QML types — which is what makes it unit-testable. |
| `Service.qml` | Kind `service`. The single owner of state: tails `alerts.jsonl`, polls `sentinelctl status --json`, queues actions, sends notifications, exposes `alerts` / `unacked` / `status` / `available` / `groupOk` and the action functions. |
| `BarWidget.qml` | Kind `bar-widget`. A `WidgetButton` drawing the shield glyph plus a count badge. |
| `Panel.qml` | Kind `panel`. The window, tabs, keyboard handling, confirmations, status strip and settings row. |
| `AlertRow.qml` | One row of the alert list: severity pill, title, exe basename, relative time, ack state. |
| `AlertDetail.qml` | The five headed blocks: WHAT HAPPENED, WHY IT WAS FLAGGED, EVIDENCE, IF THIS IS EXPECTED, WHAT TO DO. |
| `SetupView.qml` | Shown instead of the alert list when the package or the group is missing, with the exact commands. |
| `AllowlistView.qml` | The Allowlist tab: user.toml rules with their comment and a Remove button. |
| `tests/tst_model.qml` | 39 unit tests over `SentinelModel.js`. |
| `tests/fixtures/alerts.jsonl` | 13 realistic alerts across every family, plus 5 update lines including a dedupe `count` update. |
| `tests/run-tests.sh` | Syntax pass over every `.qml` plus the unit suite, headless. |

## Installing for development

The plugin is the **repository root** (`manifest.json` lives there, entry points
point into `shell/`), so the whole repo is the plugin directory.

```bash
# From a git remote — clones into ~/.config/omarchy/plugins/<id>/, disabled.
omarchy plugin add https://github.com/the2dl/omarchy-sentinel.git
omarchy plugin enable io.github.the2dl.sentinel

# From a local checkout — copy it, do not symlink: omarchy-plugin-validate
# refuses a plugin folder containing any symlink, and the shell agrees.
cp -r /path/to/omarchy-sentinel ~/.config/omarchy/plugins/io.github.the2dl.sentinel
omarchy-shell shell rescanPlugins
omarchy plugin enable io.github.the2dl.sentinel
```

Saving a file anywhere under `~/.config/omarchy/plugins/` hot-reloads the plugin
code. If a change does not take, `omarchy-shell shell rescanPlugins`, then
`omarchy restart shell`.

Validate before installing:

```bash
omarchy-plugin-validate /path/to/omarchy-sentinel
```

The bar widget lands in the right section. Move it with
`omarchy bar move io.github.the2dl.sentinel --before omarchy.clock`, and change
its settings with `omarchy bar set io.github.the2dl.sentinel minNotifySeverity critical`
(or from the panel's settings row, which writes the same entry).

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

## The notification mechanism, and why

**Mechanism:** `omarchy-notification-send --app-name Sentinel -u <urgency>
-g <glyph> <title> <body> --exec omarchy-shell shell summon
io.github.the2dl.sentinel '{"alert":"<id>"}'`, run through
`Commons.Util.execArgv` (which executes the vector as bash *positional
parameters*, never a shell string, so an alert id or a file path can never
become a command).

**Why that and not `notify-send`, and not a libnotify action:**

`omarchy-notification-send` calls `org.freedesktop.Notifications.Notify`
directly over `busctl` rather than shelling out to `notify-send`. That matters
here specifically: `notify-send`'s argv parsing is the surface that would
reinterpret a relayed headline like `--hint=…` as an option, and Sentinel's
headlines and bodies contain attacker-influenced text (process paths, args,
domains). Going through `busctl` makes the summary and body typed D-Bus strings
that cannot become hints.

The click action rides as the `omarchy-exec-argv` hint, which `--exec` is the
only way to set. `NotificationLogic.parseExecArgv` +
`Service.invokePopupDefault` in `/usr/share/omarchy/shell/plugins/notifications/`
are what make that clickable, and because the hint is persisted with the toast,
a Sentinel alert stays clickable across a shell restart — a libnotify action
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
started **never** notify: `SentinelModel.ingestText` marks the first ingest as
the priming load and returns no new ids for it, and `shouldNotify` refuses on
`initialLoad` independently, so a login does not replay the backlog as toasts.

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
  call anyway — and `sentinelctl` is the contract's own documented client for it.
  `Process` running `sentinelctl <verb> --json` costs one fork and removes a
  reconnect/framing state machine from inside the shell. `Service.qml`'s
  `_argvFor()` is the single place the CLI's argv is spelled out.

## Keyboard

| Key | Action |
|-----|--------|
| `Esc` | Close the panel (or cancel the confirm) |
| `j` / `k`, `↓` / `↑` | Move through the alert list (or switch confirm buttons) |
| `Enter` / `Space` | Confirm the open dialog |
| `a` | Ack the selected alert |
| `t` | Switch between the Alerts and Allowlist tabs |
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
