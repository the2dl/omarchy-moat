import QtQuick
import Quickshell
import Quickshell.Io
import qs.Commons
import "MoatModel.js" as Model

// Moat service: the single owner of alert state for the whole plugin.
//
// The shell instantiates exactly one of these (kind "service", keepLoaded), and
// hands the same instance to the bar widget (bar.shell.serviceFor(id)) and to
// the panel (injected as `service`). Nothing else reads alerts.jsonl or runs
// moatctl, so there is one fold, one poll, and one notification decision.
//
// Everything testable lives in MoatModel.js; this file is the I/O shell
// around it: a FileView tail, a status poll, a command queue, and notifications.
Item {
  id: root

  // Injected by shell.qml's service loader.
  property var shell: null
  property var manifest: null

  // ------------------------------------------------------------------ config
  //
  // CONTRACT 7 puts these in manifest.barWidget.defaults/schema, which the
  // shell stores on the BAR WIDGET's shell.json layout entry — the service
  // entry gets no settings of its own. BarWidget.qml pushes them here, and the
  // defaults below are what the service uses when the widget is not on the bar.
  property string minNotifySeverity: "high"
  property int pollSeconds: 10
  property bool showCountBadge: true

  readonly property string pluginId: "io.github.the2dl.moat"

  // -------------------------------------------------------------- filesystem
  //
  // Settable rather than readonly so a probe or a test harness can point the
  // service at a fixture instead of the real /var/lib/moat. Nothing in the
  // shell ever writes them.
  property string alertsPath: "/var/lib/moat/alerts.jsonl"
  property string ctlPath: "/usr/bin/moatctl"

  // ------------------------------------------------------------------- state
  property var alerts: []
  property var unacked: ({ critical: 0, high: 0, medium: 0, low: 0, total: 0 })
  property var status: Model.normalizeStatus(null)

  // `available` is the package: no /usr/bin/moatctl means nothing else can
  // be true. `groupOk` is membership of the `moat` group, without which
  // both the control socket (0660 root:moat) and alerts.jsonl (0640
  // root:moat) are unreadable. Both drive the panel's setup screen.
  property bool available: false
  property bool groupOk: false
  property bool daemonOk: false

  // The log is readable, i.e. we are actually seeing alerts rather than
  // rendering an empty list that looks like "all clear".
  property bool logReadable: false

  property string lastError: ""
  property bool busy: false
  property int actionSerial: 0

  readonly property string widgetState: Model.widgetState({
    available: root.available,
    groupOk: root.groupOk,
    daemonOk: root.daemonOk,
    unacked: root.unacked
  })
  readonly property int badgeCount: Model.badgeCount(root.unacked)
  readonly property string statusSummary: Model.statusSummary(root.status, root.unacked, root.nowMs)

  // One clock for every relative timestamp in the UI, ticked once a minute so
  // "3m ago" ages without every row owning a Timer.
  property double nowMs: Date.now()

  signal alertsUpdated()
  signal actionFinished(string command, bool ok, string message)

  // --------------------------------------------------------------- alert tail

  property var _store: Model.createStore()

  function _ingest(text) {
    var result = Model.ingestText(root._store, text)
    root.alerts = result.alerts
    root.unacked = result.unacked
    root.logReadable = true
    if (result.reloaded) {
      // moatd renamed alerts.jsonl to alerts.1.jsonl at 20 MB and opened a
      // fresh file, or the file was truncated. ingestText already re-folded
      // from the new content and kept the seen-set, so rotated-out ids cannot
      // come back as "new" and re-notify.
      console.log("moat: alerts.jsonl rotated or truncated, re-folded")
    }
    for (var i = 0; i < result.newIds.length; i++) {
      var alert = root.alertById(result.newIds[i])
      if (alert) root._maybeNotify(alert, result.initialLoad)
    }
    root.alertsUpdated()
  }

  FileView {
    id: alertsFile
    path: root.alertsPath
    watchChanges: true
    // The file legitimately does not exist before the package is installed and
    // legitimately cannot be opened before the user joins the group. Neither is
    // worth a console warning every reload; the panel says so in words instead.
    printErrors: false

    // text() is only guaranteed fresh in onLoaded, so onFileChanged asks for a
    // re-read rather than parsing here. Append-heavy files fire this often;
    // the fold is O(file) but the file is capped at 20 MB by moatd.
    onFileChanged: reload()
    onLoaded: root._ingest(text())
    onLoadFailed: function(error) {
      root.logReadable = false
      root.alerts = []
      root.unacked = ({ critical: 0, high: 0, medium: 0, low: 0, total: 0 })
      root.lastError = "cannot read " + root.alertsPath
      // A failed open is the strongest signal we get that the group or the
      // package is missing; re-probe rather than sit on a stale answer.
      root.probe()
    }
  }

  function alertById(id) {
    var key = String(id || "")
    for (var i = 0; i < root.alerts.length; i++) {
      if (root.alerts[i].id === key) return root.alerts[i]
    }
    return null
  }

  // ------------------------------------------------------------ notifications
  //
  // Sent through omarchy-notification-send, which calls
  // org.freedesktop.Notifications.Notify directly (never notify-send, whose
  // argv parsing would let an alert title become a hint). The click action
  // rides as the `omarchy-exec-argv` hint via --exec: that is the ONE clickable
  // action the omarchy-shell notification server renders
  // (NotificationLogic.parseExecArgv + Service.invokePopupDefault), and unlike
  // a libnotify action it survives a shell restart because it is persisted with
  // the toast. See shell/README.md for why Kill/Quarantine/Ignore are not three
  // separate toast buttons.
  function _maybeNotify(alert, initialLoad) {
    if (!Model.shouldNotify(alert, root.minNotifySeverity, initialLoad)) return

    var urgency = Model.notifyUrgency(alert.severity)
    var argv = ["omarchy-notification-send",
                "--app-name", "Moat",
                "-u", urgency,
                "-g", Model.notifyGlyphFor(alert.severity)]

    // Critical alerts stay on screen until acted on; everything else takes the
    // server's default lifetime for its urgency.
    if (urgency === "critical") argv.push("-t", "0")

    argv.push(root._notifyText(alert.title))
    argv.push(root._notifyText(root._notifyBody(alert)))

    // --exec consumes the rest of the line as argv, so it comes last. The
    // vector is run as bash positional parameters, never re-tokenized, so the
    // alert id cannot become a command.
    argv.push("--exec", "omarchy-shell", "shell", "summon", root.pluginId,
              JSON.stringify({ alert: alert.id }))

    Util.execArgv(argv)
  }

  // omarchy-notification-send takes the headline as a positional after its
  // options, so a value that begins with a dash could land in option position.
  // Alert text comes from root-owned policy annotations and from process paths,
  // neither of which should start with a dash, but a leading dash is cheap to
  // neutralize and expensive to debug.
  function _notifyText(value) {
    var text = String(value || "").replace(/^[-\s]+/, "")
    return text === "" ? "Moat alert" : text
  }

  function _notifyBody(alert) {
    var parts = []
    if (alert.summary) parts.push(alert.summary)
    var offered = Model.offeredActions(alert)
    if (offered.length > 0) {
      // Name the actions in the body: the toast has one click, and this says
      // where the buttons are.
      parts.push("Click to open Moat (" +
                 offered.map(function(a) { return a.charAt(0).toUpperCase() + a.slice(1) }).join(" / ") + ").")
    }
    return parts.join("\n")
  }

  // --------------------------------------------------------- capability probe
  //
  // One bash call answers both halves of the setup screen: is the package
  // installed, and is this session in the moat group. `id -nG` reflects the
  // session's credentials, which is exactly the question — a usermod without a
  // re-login must still read as "not yet".
  function probe() {
    if (probeProc.running) return
    probeProc.running = true
  }

  property string _probeOutput: ""

  Process {
    id: probeProc
    command: ["bash", "-c",
      "if [ -x /usr/bin/moatctl ]; then a=true; else a=false; fi; " +
      "if id -nG 2>/dev/null | tr ' ' '\\n' | grep -qx moat; then g=true; else g=false; fi; " +
      "printf '{\"available\":%s,\"group\":%s}\\n' \"$a\" \"$g\""]
    stdout: StdioCollector { id: probeStdout; waitForEnd: true; onStreamFinished: root._probeOutput = text }
    onExited: function(exitCode) {
      var raw = String(probeStdout.text || root._probeOutput || "").trim()
      try {
        var value = JSON.parse(raw || "{}")
        root.available = value.available === true
        root.groupOk = value.group === true
      } catch (e) {
        root.available = false
        root.groupOk = false
      }
      if (root.available) root.pollStatus()
      else root.daemonOk = false
    }
  }

  // ------------------------------------------------------------- status poll
  //
  // CONTRACT 5 defines a newline-delimited JSON control socket, and
  // Quickshell.Io.Socket can speak to a unix path — but moatctl is the
  // documented client for it and is one request/response per connection
  // anyway, so shelling out to `moatctl status --json` costs one fork and
  // removes an entire reconnect/framing state machine from the shell. See
  // shell/README.md.
  function pollStatus() {
    if (!root.available || statusProc.running) return
    statusProc.running = true
  }

  property string _statusOutput: ""
  property string _statusError: ""

  Process {
    id: statusProc
    command: [root.ctlPath, "status", "--json"]
    stdout: StdioCollector { id: statusStdout; waitForEnd: true; onStreamFinished: root._statusOutput = text }
    stderr: StdioCollector { id: statusStderr; waitForEnd: true; onStreamFinished: root._statusError = text }
    onExited: function(exitCode) {
      var stdout = String(statusStdout.text || root._statusOutput || "").trim()
      var stderr = String(statusStderr.text || root._statusError || "").trim()

      if (exitCode !== 0 && !stdout) {
        // The daemon is not answering. Keep the last known status shape but
        // mark it not-ok so the UI stops claiming a mode it cannot verify.
        root.status = Model.normalizeStatus(null)
        root.daemonOk = false
        root.lastError = stderr || ("moatctl status exited " + exitCode)
        return
      }

      var next = Model.normalizeStatus(stdout)
      root.status = next
      root.daemonOk = next.ok
      if (next.ok) root.lastError = ""
      else root.lastError = next.error || stderr || "moatd is not reachable"

      // group_ok from the daemon is authoritative about socket access; it can
      // only ever take groupOk away, never grant it.
      if (next.group_ok === false) root.groupOk = false

      // With no readable log, the daemon's counts are the only ones there are.
      // With a readable log ours are fresher, so they win.
      if (!root.logReadable && next.unacked) {
        var u = next.unacked
        root.unacked = {
          critical: Number(u.critical || 0),
          high: Number(u.high || 0),
          medium: Number(u.medium || 0),
          low: Number(u.low || 0),
          total: Number(u.critical || 0) + Number(u.high || 0) +
                 Number(u.medium || 0) + Number(u.low || 0)
        }
      }
    }
  }

  Timer {
    interval: Math.max(5, Math.min(60, root.pollSeconds)) * 1000
    running: root.available
    repeat: true
    triggeredOnStart: false
    onTriggered: root.pollStatus()
  }

  Timer {
    // Relative-time clock for the panel and the tooltip.
    interval: 30000
    running: true
    repeat: true
    onTriggered: root.nowMs = Date.now()
  }

  // ------------------------------------------------------------------ actions
  //
  // Every action names an alert id, never a pid or a path (CONTRACT 5): that is
  // what makes the control socket safe to expose to the user's group, and the
  // plugin does not get to widen it.
  //
  // moatctl's argv is the moatd agent's surface; it is spelled out once
  // here so a change there is a change in one place.
  function _argvFor(command, arg, arg2) {
    switch (command) {
    case "kill": return [root.ctlPath, "kill", String(arg), "--json"]
    case "quarantine": return [root.ctlPath, "quarantine", String(arg), "--json"]
    case "ack": return [root.ctlPath, "ack", String(arg), "--json"]
    case "ignore": return [root.ctlPath, "ignore", String(arg), "--scope", Model.normalizeIgnoreScope(arg2), "--json"]
    // CONTRACT 5: unignore takes the index of the [[rule]] block in
    // user.toml, which is why the panel never renumbers what allowlist returns.
    case "unignore": return [root.ctlPath, "unignore", String(arg), "--json"]
    case "mode": return [root.ctlPath, "set", "mode", Model.normalizeMode(arg), "--json"]
    case "sandbox": return [root.ctlPath, "set", "sandbox", arg === true || arg === "on" ? "on" : "off", "--json"]
    case "feeds": return [root.ctlPath, "feeds", "refresh", "--json"]
    }
    return null
  }

  property var _queue: []

  function _enqueue(command, arg, arg2) {
    if (!root.available) {
      root.lastError = "moatctl is not installed"
      root.actionFinished(command, false, root.lastError)
      return false
    }
    var argv = root._argvFor(command, arg, arg2)
    if (!argv) return false
    var queue = root._queue.slice()
    queue.push({ command: command, argv: argv })
    root._queue = queue
    root._pump()
    return true
  }

  function _pump() {
    if (actionProc.running || root._queue.length === 0) return
    var next = root._queue[0]
    var queue = root._queue.slice(1)
    root._queue = queue
    root.busy = true
    actionProc.pendingCommand = next.command
    actionProc.command = next.argv
    actionProc.running = true
  }

  property string _actionOutput: ""
  property string _actionError: ""

  Process {
    id: actionProc
    property string pendingCommand: ""
    stdout: StdioCollector { id: actionStdout; waitForEnd: true; onStreamFinished: root._actionOutput = text }
    stderr: StdioCollector { id: actionStderr; waitForEnd: true; onStreamFinished: root._actionError = text }
    onExited: function(exitCode) {
      var stdout = String(actionStdout.text || root._actionOutput || "").trim()
      var stderr = String(actionStderr.text || root._actionError || "").trim()
      root._actionOutput = ""
      root._actionError = ""

      var ok = exitCode === 0
      var message = ok ? "" : (stderr || "moatctl exited " + exitCode)
      try {
        var value = JSON.parse(stdout || "{}")
        if (value.ok === false) { ok = false; message = String(value.error || message) }
        // `set mode` answers ok:true even when `tetra tp set-mode` failed on
        // every policy: moatd deliberately persists the mode so a restart
        // reapplies it. But nothing in the kernel changed, and a panel that
        // says "enforce" over a sensor still in monitor is the one lie this UI
        // must not tell. Treat "0 of N applied" as a failure and name it.
        if (ok && actionProc.pendingCommand === "mode" && Number(value.policies || 0) > 0
            && Number(value.applied || 0) === 0) {
          ok = false
          message = "moatd recorded mode " + String(value.mode || "?") +
                    " but could not apply it to any of " + Number(value.policies) +
                    " policies (" + String(value.tetra || "tetra") +
                    " failed). Tetragon is still in the previous mode."
        }
        // CONTRACT 5: ignore returns the exact block it appended to user.toml.
        // Show it rather than a "done" — the point of the flow is that the user
        // sees what got written on their behalf.
        if (ok && actionProc.pendingCommand === "ignore") {
          root.lastIgnoreBlock = String(value.block || value.line || value.rule || "")
        }
      } catch (e) {
        // Not JSON. exitCode already decided ok; stderr already carries why.
      }
      if (!ok) root.lastError = message || ("moatctl " + actionProc.pendingCommand + " failed")
      // Both halves of the allowlist tab move when a rule is added or removed.
      if (ok && (actionProc.pendingCommand === "ignore" || actionProc.pendingCommand === "unignore"))
        root.loadAllowlist()
      root.actionFinished(actionProc.pendingCommand, ok, message)
      root.actionSerial++
      root.busy = false
      // moatd appends the resulting update line, so the FileView watch will
      // fire on its own — but ask anyway so a same-millisecond write is not
      // missed, and re-poll status because mode/sandbox/feeds live there.
      root.refresh()
      root._pump()
    }
  }

  // ------------------------------------------------------------- public API

  function kill(id) { return root._enqueue("kill", id) }
  function quarantine(id) { return root._enqueue("quarantine", id) }
  function ack(id) { return root._enqueue("ack", id) }
  // scope is exe | exe+file | parent | rule (CONTRACT 5). Anything else is
  // narrowed to "exe" rather than widened.
  function ignore(id, scope) {
    root.lastIgnoreBlock = ""
    return root._enqueue("ignore", id, scope)
  }
  function unignore(index) { return root._enqueue("unignore", Number(index)) }
  function setMode(mode) { return root._enqueue("mode", mode) }
  function setSandbox(on) { return root._enqueue("sandbox", on === true || on === "on") }
  function refreshFeeds() { return root._enqueue("feeds") }

  function refresh() {
    alertsFile.reload()
    root.pollStatus()
    root.loadAllowlist()
    root.nowMs = Date.now()
  }

  // ---------------------------------------------------------- allowlist tab
  //
  // Reads, so they get their own processes rather than the action queue: the
  // queue's completion handler refreshes everything, which would loop.
  property var allowlistRules: []
  property string allowlistFile: "/etc/moat/allowlist.d/user.toml"
  property string allowlistError: ""
  property bool allowlistLoading: false
  property string lastIgnoreBlock: ""
  property string _allowlistOutput: ""
  property string _allowlistError: ""

  function loadAllowlist() {
    if (!root.available || allowlistProc.running) return
    root.allowlistLoading = true
    allowlistProc.running = true
  }

  Process {
    id: allowlistProc
    command: [root.ctlPath, "allowlist", "--json"]
    stdout: StdioCollector { id: allowlistStdout; waitForEnd: true; onStreamFinished: root._allowlistOutput = text }
    stderr: StdioCollector { id: allowlistStderr; waitForEnd: true; onStreamFinished: root._allowlistError = text }
    onExited: function(exitCode) {
      root.allowlistLoading = false
      var stdout = String(allowlistStdout.text || root._allowlistOutput || "").trim()
      var stderr = String(allowlistStderr.text || root._allowlistError || "").trim()
      if (exitCode !== 0 && !stdout) {
        root.allowlistError = stderr || ("moatctl allowlist exited " + exitCode)
        return
      }
      var parsed = Model.parseAllowlist(stdout)
      root.allowlistRules = parsed.rules
      root.allowlistFile = parsed.file
      root.allowlistError = parsed.ok ? "" : (parsed.error || stderr)
    }
  }

  // --------------------------------------------------------------- explain
  //
  // The alert on disk normally carries its own explain block, so this is the
  // repair path: an alert written by an older moatd, or one whose line was
  // truncated, can be re-fetched by id (CONTRACT 5's `explain` command) without
  // touching anything else the sensor recorded.
  property string _explainId: ""
  property string _explainOutput: ""

  function loadExplain(id) {
    if (!root.available || explainProc.running) return
    var alert = root.alertById(id)
    if (!alert || Model.hasExplain(alert)) return
    root._explainId = String(id)
    explainProc.command = [root.ctlPath, "explain", root._explainId, "--json"]
    explainProc.running = true
  }

  Process {
    id: explainProc
    stdout: StdioCollector { id: explainStdout; waitForEnd: true; onStreamFinished: root._explainOutput = text }
    onExited: function(exitCode) {
      var stdout = String(explainStdout.text || root._explainOutput || "").trim()
      root._explainOutput = ""
      if (exitCode !== 0 || !stdout) return
      var alert = root.alertById(root._explainId)
      if (!alert) return
      Model.mergeExplainResponse(alert, stdout)
      // alerts is a plain array; reassigning it is what re-evaluates the
      // panel's bindings on the alert we just filled in.
      root.alerts = root.alerts.slice()
      root.alertsUpdated()
    }
  }

  // Persist a bar-widget setting through the registry, which is where the
  // shell keeps per-widget values (shell.json's layout entry). Returns "" on
  // success or the registry's error string; the panel surfaces it rather than
  // pretending the change stuck.
  function persistSetting(key, value) {
    if (!root.shell || !root.shell.pluginRegistry
        || typeof root.shell.pluginRegistry.setBarWidget !== "function") {
      return "the shell did not expose a settings writer"
    }
    var error = root.shell.pluginRegistry.setBarWidget(root.pluginId, key, value, {})
    return error ? String(error) : ""
  }

  // Helpers the panel and widget share, forwarded so neither has to import the
  // JS module separately (a relative-path import would be a second copy).
  function relativeTime(iso) { return Model.relativeTime(iso, root.nowMs) }
  function basename(path) { return Model.basename(path) }
  function ancestryChain(alert) { return Model.ancestryChain(alert) }
  function rotateItems(alert) { return Model.rotateItems(alert) }
  function severityRank(severity) { return Model.severityRank(severity) }
  function widgetGlyph(state) { return Model.widgetGlyph(state) }
  function setupSteps() { return Model.setupSteps(!root.available, !root.groupOk, root.status.socket_group) }
  function feedsAge() { return Model.relativeTime(root.status.feeds.updated, root.nowMs) }
  function hasExplain(alert) { return Model.hasExplain(alert) }
  function ignoreOptions(alert) { return Model.ignoreOptions(alert) }
  function ignoreScopeLabel(scope) { return Model.ignoreScopeLabel(scope) }
  function ignoreScopeCaution(scope) { return Model.ignoreScopeCaution(scope) }

  onAvailableChanged: if (root.available) root.loadAllowlist()

  Component.onCompleted: root.probe()
}
