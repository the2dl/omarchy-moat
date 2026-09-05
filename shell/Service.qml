// Moat service: the single owner of alert state for the whole plugin.
// The shell instantiates exactly one of these (kind "service", keepLoaded), and
// hands the same instance to the bar widget (bar.shell.serviceFor(id)) and to
// the panel (injected as `service`). Nothing else reads alerts.jsonl or runs
// moatctl, so there is one fold, one poll, and one notification decision.

import "MoatCopy.js" as Copy
import "MoatModel.js" as Model
import QtQuick
import Quickshell
import Quickshell.Io
import qs.Commons

// Everything testable lives in MoatModel.js; this file is the I/O shell
// around it: a FileView tail, a status poll, a command queue, and notifications.
Item {
    // ------------------------------------------------------------------ config
    // Advanced. The panel in the detection's own words instead of the redesign's
    // plain-language ones: raw titles, the rule id and the severity beside every
    // incident, the recorded process fields as fields, evidence open.
    // -------------------------------------------------------------- filesystem
    // The sensor's own health, which outranks the alert counts: see
    // Model.widgetState.
    // ---------------------------------------------------------------- baseline
    // BASELINE 5's two surfaces are GONE from this file, and not by accident.
    // `alertsSurface` / `timelineGroups` / `timelineRows` fed the Alerts and
    // Timeline tabs, which the redesign replaced with incidents on Now and day
    // groups in History -- and `Model.timelineRows` regrouped every alert in the
    // log on every append to fill a view nothing renders any more. The model
    // functions stay (tst_wire pins them against a real daemon's output, and
    // `alertSurface` is still what `unackedCounts` and the notification decision
    // read); it is only the standing bindings that are gone.
    // ------------------------------------------------------------- incidents
    // The redesign's unit of attention (docs/design/README.md 1c): alerts
    // collapsed by (rule, program), each carrying a count and a time range.
    // --------------------------------------------------------------- alert tail
    // Whether the rotated file has been looked for at all. The live file is not
    // folded until the rotated one has loaded or failed: the first ingest is the
    // one that primes the seen-set, and priming it from the live file alone
    // would make every rotated-out alert "new" -- and toast -- the moment the
    // rotated file arrived.
    // ------------------------------------------------------------ notifications
    // A second, unconditional guard on top of `initialLoad`.
    // `initialLoad` only suppresses the ingest that PRIMES the store, and any
    // path that re-primes -- a rotation, a reload that folds a second file, a
    // seen-set reset -- makes every historical alert "new" again and toasts the
    // lot. On 2026-09-05 folding the rotated log did exactly that: thousands of
    // notifications on one shell restart, then again on every poll.
    // --------------------------------------------------------- capability probe
    // ------------------------------------------------------------- status poll
    // ------------------------------------------------------------------ actions
    // Every action names an alert id, never a pid or a path (CONTRACT 5): that is
    // what makes the control socket safe to expose to the user's group, and the
    // plugin does not get to widen it.
    // ------------------------------------------------------------- public API
    // ---------------------------------------------------------- allowlist tab
    // ------------------------------------------------- programs Moat knows (2e)
    // ------------------------------------------------ "I don't know" (2i)
    // The third answer. The bundle itself is the daemon's: `moatctl bundle <id>`
    // writes /var/lib/moat/incidents/<id>/bundle.md with every process-derived
    // field inside ```DATA``` fences. These two verbs only move that file where
    // the user asked for it.
    // Both run the path as a bash POSITIONAL PARAMETER, never interpolated, and
    // parseBundleResponse has already refused anything that is not absolute --
    // the only thing this value is ever used for is to be opened.
    // --------------------------------------------------------------- explain
    // ------------------------------------------------------------- AI analysis
    // LEARNING 2. One button: hand this alert to whatever agent the user already
    // chose. The plugin's part of that is deliberately small — it asks
    // `omarchy default agent` what to call the button, and it runs
    // `moatctl analyze <id>`. moatctl bundles the alert into
    // /var/lib/moat/incidents/<id>/bundle.md and launches
    // `omarchy-agent --prompt <preamble + path>` itself.
    // The plugin never builds the prompt and never reads the bundle. That is the
    // point: the bundle fences every process-derived field in ```DATA``` blocks
    // because an alert about a malicious postinstall must not become a
    // prompt-injection channel into the agent that analyzes it. A prompt
    // assembled here out of alert fields would be exactly that channel.
    // moatd renamed alerts.jsonl to alerts.1.jsonl at 20 MB and opened a
    // fresh file, or the file was truncated. ingestText already re-folded
    // from the new content and kept the seen-set, so rotated-out ids cannot
    // come back as "new" and re-notify.

    id: root

    // Injected by shell.qml's service loader.
    property var shell: null
    property var manifest: null
    // CONTRACT 7 puts these in manifest.barWidget.defaults/schema, which the
    // shell stores on the BAR WIDGET's shell.json layout entry — the service
    // entry gets no settings of its own. BarWidget.qml pushes them here, and the
    // defaults below are what the service uses when the widget is not on the bar.
    property string minNotifySeverity: "high"
    // BASELINE 5: at most one toast per rule per this many minutes; the rest of
    // the burst is counted and lands as one "N more from ..." toast when the
    // window ends. 10 minutes is the manifest default.
    property int notifyCooldownMinutes: 10
    property int pollSeconds: 10
    property bool showCountBadge: true
    // BASELINE 8: suppressed alerts are logged so the timeline CAN show them, and
    // hidden by default so it normally does not. This is the switch.
    property bool showSuppressed: false
    // LEARNING 5: the weekly digest is the only scheduled notification moat ever
    // sends, and the DAEMON sends it. This flag is the user's off switch and
    // nothing else — flipping it runs `moatctl set digest on|off`.
    property bool weeklyDigest: true
    // 1f: the "Never" answer to "when should Moat interrupt you?". The severity
    // threshold cannot express it -- "critical only" is not "never" -- and the
    // enum the manifest declares for it has no room for a fifth value, so this is
    // its own switch. Everything still lands in the panel; nothing is dropped.
    property bool notifyMuted: false
    // PRESENTATION ONLY. It is deliberately absent from `baselineOptions()` and
    // from `notifyOptions()` -- what is surfaced, counted, notified and demoted
    // must be the same in both modes, or the two modes are two products.
    property bool rawDetail: false
    readonly property string pluginId: "io.github.the2dl.moat"
    // Settable rather than readonly so a probe or a test harness can point the
    // service at a fixture instead of the real /var/lib/moat. Nothing in the
    // shell ever writes them.
    property string alertsPath: "/var/lib/moat/alerts.jsonl"
    /// The rotated half of the same log. moatd renames alerts.jsonl to this at
    /// 20 MB and then reads BOTH back -- `AlertStore::load` folds the rotated
    /// file first, then the live one -- so its `status.unacked`, its watchdog
    /// and its triage queue all see alerts a panel reading one file cannot. On
    /// 2026-09-05 five unacked critical moat-rootkit-evidence-tamper alerts sat
    /// in alerts.1.jsonl: `moatctl status` said "critical 5", the watchdog was
    /// about to say five things were waiting, and this panel could neither show
    /// nor ack them. The panel folds the same two files in the same order.
    property string rotatedPath: "/var/lib/moat/alerts.1.jsonl"
    property string ctlPath: "/usr/bin/moatctl"
    // ------------------------------------------------------------------- state
    property var alerts: []
    // LEARNING 3: install receipts share alerts.jsonl with the alerts. They are
    // kept apart from `alerts` from the moment the file is parsed, which is what
    // makes "receipts never notify and never count" true by construction rather
    // than by a filter someone has to remember.
    property var receipts: []
    property var unacked: ({
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "total": 0
    })
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
    /// The last thing the USER asked for that failed. Shown as a banner.
    property string lastError: ""
    /// The last background poll failure. Not shown as a banner: see the note in
    /// the status handler.
    property string _pollError: ""
    property bool busy: false
    property int actionSerial: 0
    /// Files held in quarantine: moved aside and mode 000, never deleted, so the
    /// panel can show what caught you and put it back.
    property var quarantineItems: []
    readonly property string widgetState: Model.widgetState({
        "available": root.available,
        "groupOk": root.groupOk,
        "daemonOk": root.daemonOk,
        "sensorUnhealthy": root.status ? root.status.sensorUnhealthy === true : false,
        "unacked": root.unacked
    })
    readonly property int badgeCount: Model.badgeCount(root.unacked)
    readonly property string statusSummary: Model.statusSummary(root.status, root.unacked, root.nowMs)
    // BASELINE 4's demoted rule ids and BASELINE 3's proposals both ride on the
    // status poll, so the surfacing rules re-evaluate the moment the daemon
    // demotes a rule — no re-read of alerts.jsonl, because `surface` and
    // `visible` are computed from the folded alerts rather than stored in them.
    readonly property var demotedRules: root.status.demoted_rules
    /// LEARNING 2c. `IncidentCard` reads this to decide whether an incident with
    /// no verdict is waiting for one or will never get one. It was referenced
    /// before it existed, so the "reading the evidence…" state never rendered and
    /// AI analysis was invisible in the panel until a verdict happened to land.
    readonly property bool autoTriageOn: String(root.status.autoTriage || "off") !== "off"
    readonly property int triagePending: Number(root.status.triagePending) || 0
    readonly property var proposals: root.status.proposals
    readonly property var baselineState: root.status.baseline
    readonly property string learningSummary: Model.learningSummary(root.status, root.nowMs)
    // It lives HERE rather than in Panel.qml because the bar widget needs the
    // same answer. 3e's rule is that the glyph has exactly three states matching
    // the verdict line, and the only way bar and panel can be guaranteed never to
    // disagree is for both to read one derivation. Stage 4 of docs/design/PLAN.md
    // moves the grouping into the daemon behind this same API.
    readonly property var incidents: Model.buildIncidents(root.alerts, root.renderOptions())
    // The same collapse with nothing hidden. History's third filter chip is
    // literally "Silenced by a rule" (1d), so that screen has to be able to reach
    // the rows the `showSuppressed` setting keeps off Now -- and 1d's answer to
    // noise is that a covered row recedes into a 3px tick, not that it vanishes.
    readonly property var allIncidents: Model.buildIncidents(root.alerts, {
        "demotedRules": root.demotedRules,
        "showSuppressed": true,
        "rawDetail": root.rawDetail
    })
    readonly property var needsYou: Model.needsYouIncidents(root.incidents)
    readonly property int needsYouCount: root.needsYou.length
    /// quiet | needsYou | chain | gap, derived and never set.
    readonly property var verdict: Model.verdict(root.incidents, root.status)
    /// 3e: the three bar states, from the same verdict the panel prints.
    readonly property var barState: Model.barState(root.verdict.state, root.needsYouCount)
    readonly property string barTooltip: Model.barTooltip(root.verdict.state, root.incidents, root.nowMs)
    // One clock for every relative timestamp in the UI, ticked once a minute so
    // "3m ago" ages without every row owning a Timer.
    property double nowMs: Date.now()
    property var _store: Model.createStore()
    // The rotated text itself lives in the store (Model.setLogPrefix), handed
    // over ONCE per change of that file, not concatenated in front of the live
    // file on every reload.
    property bool _rotatedSettled: false
    // Sent through omarchy-notification-send, which calls
    // org.freedesktop.Notifications.Notify directly (never notify-send, whose
    // argv parsing would let an alert title become a hint). The click action
    // rides as the `omarchy-exec-argv` hint via --exec: that is the ONE clickable
    // action the omarchy-shell notification server renders
    // (NotificationLogic.parseExecArgv + Service.invokePopupDefault), and unlike
    // a libnotify action it survives a shell restart because it is persisted with
    // the toast. See shell/README.md for why Kill/Quarantine/Ignore are not three
    // separate toast buttons.
    /// When this panel started. Nothing that happened before it is news.
    readonly property real startedMs: Date.now()
    property string _probeOutput: ""
    property string _statusOutput: ""
    property string _statusError: ""
    // moatctl's argv is the moatd agent's surface; it is spelled out once
    // here so a change there is a change in one place.
    /// Commands moatd refuses to anyone but root (control.rs ROOT_ONLY).
    ///
    /// The socket is group-owned so a person can read their own alerts without
    /// sudo; the verbs that make Moat watch LESS are not there, because the
    /// attacker in this threat model runs as that same person. From a panel that
    /// means asking polkit, which is the only way a GUI can raise privilege
    /// honestly -- with a prompt the user sees and can refuse.
    readonly property var privilegedCommands: ["mode", "rule-mode", "contain", "kill", "sandbox", "ignore", "unignore"]
    property var _queue: []
    property var _lastArg: undefined
    property var _lastArg2: undefined
    property string _actionOutput: ""
    property string _actionError: ""
    // Reads, so they get their own processes rather than the action queue: the
    // queue's completion handler refreshes everything, which would loop.
    property var allowlistRules: []
    property string allowlistFile: "/etc/moat/allowlist.d/user.toml"
    property string allowlistError: ""
    property bool allowlistLoading: false
    property string lastIgnoreBlock: ""
    property string _allowlistOutput: ""
    property string _allowlistError: ""
    // `moatctl baseline export --json` is the daemon's own per-(rule, exe, parent,
    // dir) counter table: what it has seen, how often, on how many days, and
    // whether an allowlist entry is already hiding it. That is exactly the data
    // 2e's table wants and 1e's "silenced N since" column wants, and it is a
    // READ -- so like the allowlist it gets its own process rather than the action
    // queue, whose completion handler refreshes everything and would loop.
    property var baselineTuples: []
    property string baselineExportError: ""
    property string _exportOutput: ""
    property string _exportError: ""
    /// 2e's table and 1e's silenced-since column.
    readonly property var trustedPrograms: Model.trustedPrograms(root.baselineTuples, root.incidents)
    // NOT DONE, and deliberately: 2i also says the incident stays open but MUTED
    // until something new happens. There is no daemon verb for that state --
    // `ack` closes an alert, which is a different promise -- so the panel does not
    // pretend to offer it.
    property string bundleMode: "copy"
    // "copy" | "save" | "text"
    property string bundleSavedPath: ""
    // The alert on disk normally carries its own explain block, so this is the
    // repair path: an alert written by an older moatd, or one whose line was
    // truncated, can be re-fetched by id (CONTRACT 5's `explain` command) without
    // touching anything else the sensor recorded.
    property string _explainId: ""
    property string _explainOutput: ""
    // The agent name from `omarchy default agent`, read once at service start.
    // "" means no default is set, and the panel shows the hint instead of a
    // button rather than launching something the user never chose.
    property string defaultAgent: ""
    readonly property string agentButtonLabel: Model.analyzeLabel(root.defaultAgent)
    readonly property string agentTooltip: Model.analyzeTooltip(root.defaultAgent)
    readonly property string agentHint: Model.ANALYZE_HINT
    // Transient result state for the two analysis buttons. Cleared on a timer so
    // "opened in claude" does not sit under an alert forever.
    property string analyzeState: ""
    // "" | "running" | "opened" | "failed"
    property string analyzeMessage: ""
    property string analyzeId: ""
    property string copyState: "" // "" | "running" | "copied" | "failed"
    property string copyMessage: ""

    signal alertsUpdated()
    signal actionFinished(string command, bool ok, string message)

    // The single place the surfacing inputs are assembled. Written as a function
    // rather than a property so every caller re-reads it; it is cheap and the
    // bindings above already depend on demotedRules/showSuppressed through it.
    function baselineOptions() {
        return {
            "demotedRules": root.demotedRules,
            "showSuppressed": root.showSuppressed
        };
    }

    // The surfacing inputs plus the one rendering choice `buildIncidents` takes.
    // A separate function on purpose: `baselineOptions()` is what decides what is
    // shown, counted and notified, and Advanced must never be able to reach it.
    // The two lines of buildIncidents that read `rawDetail` are the title and the
    // stake, and that is the whole of its authority.
    function renderOptions() {
        var o = root.baselineOptions();
        o.rawDetail = root.rawDetail;
        return o;
    }

    // The same inputs plus the two the notification decision needs. Kept apart
    // from baselineOptions() so the surfacing calls cannot come to depend on a
    // notification setting.
    function notifyOptions(initialLoad) {
        return {
            "demotedRules": root.demotedRules,
            "showSuppressed": root.showSuppressed,
            "minNotifySeverity": root.minNotifySeverity,
            "notifyMuted": root.notifyMuted,
            "notifyCooldownMinutes": root.notifyCooldownMinutes,
            "initialLoad": initialLoad === true
        };
    }

    function _ingest(text) {
        var result = Model.ingestText(root._store, text, root.baselineOptions());
        // Identity guards, not micro-optimisation. FileView fires onFileChanged
        // more than once per append, and a re-read that folded nothing new hands
        // back the SAME arrays. Assigning them anyway would fire alertsChanged and
        // rebuild every incident, every day group and every delegate on the panel
        // for a file that did not change.
        if (result.alerts !== root.alerts)
            root.alerts = result.alerts;

        if (result.receipts !== root.receipts)
            root.receipts = result.receipts;

        if (!Model.sameCounts(result.unacked, root.unacked))
            root.unacked = result.unacked;

        root.logReadable = true;
        if (result.reloaded)
            console.log("moat: alerts.jsonl rotated or truncated, re-folded");

        for (var i = 0; i < result.newIds.length; i++) {
            var alert = result.byId[result.newIds[i]];
            if (alert)
                root._maybeNotify(alert, result.initialLoad);

        }
        root.alertsUpdated();
    }

    // A rule the daemon just demoted stops counting toward the shield, and
    // "show suppressed" changes what the timeline holds. Neither re-reads the
    // log, so the counts have to be recomputed from the alerts already folded.
    function _recount() {
        if (!root.logReadable)
            return ;

        root.unacked = Model.unackedCounts(root.alerts, root.baselineOptions());
        root.alertsUpdated();
    }

    function alertById(id) {
        var key = String(id || "");
        for (var i = 0; i < root.alerts.length; i++) {
            if (root.alerts[i].id === key)
                return root.alerts[i];

        }
        return null;
    }

    function _maybeNotify(alert, initialLoad) {
        // Say it once per window, not once per collapsed alert.

        // The panel has no business announcing something that happened before it
        // was running, whatever the ingest thinks is new. This cannot be defeated
        // by a re-prime because it does not depend on the store at all.
        var when = Date.parse(String(alert.ts || ""));
        if (!isNaN(when) && when < root.startedMs - 60000)
            return ;

        // shouldNotify (BASELINE 5's table) is inside notifyDecision, together with
        // the per-rule cooldown: one call, one answer, one place the policy lives.
        var decision = Model.notifyDecision(root._store, alert, Date.now(), root.notifyOptions(initialLoad));
        if (!decision.toast) {
            if (decision.reason === "cooldown" && decision.collapsed === 1)
                console.log("moat: " + alert.rule + " is inside its notification cooldown, collapsing");

            return ;
        }
        // 2h shape 1, the only one that may interrupt. shouldNotify has already
        // refused everything that is not a needs-you incident, so an urgency above
        // `low` can only ever be reached from here.
        var urgency = Copy.notifyShapeUrgency(Copy.NOTIFY_NEEDS_YOU, alert.severity);
        var argv = ["omarchy-notification-send", "--app-name", "Moat", "-u", urgency, "-g", Model.notifyGlyphFor(alert.severity)];
        // Critical alerts stay on screen until acted on; everything else takes the
        // server's default lifetime for its urgency.
        if (urgency === "critical")
            argv.push("-t", "0");

        // 3g: the title is the consequence in the user's terms, never the detection
        // id and never a severity word. "Something added itself to your login", not
        // "HIGH: moat-persist-hypr-config-write".
        argv.push(root._notifyText(Copy.titleFor(alert)));
        argv.push(root._notifyText(root._notifyBody(alert)));
        // --exec consumes the rest of the line as argv, so it comes last. The
        // vector is run as bash positional parameters, never re-tokenized, so the
        // alert id cannot become a command.
        argv.push("--exec", "omarchy-shell", "shell", "summon", root.pluginId, JSON.stringify({
            "alert": alert.id
        }));
        Util.execArgv(argv);
    }

    // The other half of the cooldown: when a rule's window ends with alerts
    // collapsed into it, one toast says how many and points at the panel. Driven
    // by a clock rather than by the next alert, because the tail of a burst is
    // exactly when no next alert arrives.
    function _flushCollapsed() {
        var summaries = Model.flushCollapsed(root._store, Date.now());
        for (var i = 0; i < summaries.length; i++) root._notifyCollapsed(summaries[i])
    }

    // 2h shape 3, the counted burst. Sent at `low` on purpose: a burst that has
    // already been counted is by definition not news, and the whole point of
    // counting it was to stop it interrupting anyone.
    function _notifyCollapsed(summary) {
        var argv = ["omarchy-notification-send", "--app-name", "Moat", "-u", Copy.notifyShapeUrgency(Copy.NOTIFY_BURST, "medium"), "-g", Model.notifyGlyphFor("medium")];
        argv.push(root._notifyText(Copy.burstTitle(summary.program || summary.title, summary.count)));
        argv.push(root._notifyText(Copy.BURST_BODY));
        // The collapsed alerts are one incident in History, not one alert waiting
        // on Now, so the click opens the tab rather than selecting an id.
        argv.push("--exec", "omarchy-shell", "shell", "summon", root.pluginId, JSON.stringify({
            "tab": "history"
        }));
        Util.execArgv(argv);
    }

    // omarchy-notification-send takes the headline as a positional after its
    // options, so a value that begins with a dash could land in option position.
    // Alert text comes from root-owned policy annotations and from process paths,
    // neither of which should start with a dash, but a leading dash is cheap to
    // neutralize and expensive to debug.
    function _notifyText(value) {
        var text = String(value || "").replace(/^[-\s]+/, "");
        return text === "" ? "Moat alert" : text;
    }

    // 2h: title is the consequence, body is what it costs you plus what has
    // happened so far. The old body listed moatctl's verbs (Kill / Quarantine /
    // Ignore), which are three words the user does not have and two the panel no
    // longer offers -- the panel's answer is "This was me" or "Stop it".
    function _notifyBody(alert) {
        var parts = [];
        var stake = Copy.stakeFor(alert);
        if (stake)
            parts.push(stake);
        else if (alert.summary)
            parts.push(String(alert.summary));
        if (alert.action_taken === "none")
            parts.push("Nothing has been stopped.");

        parts.push("Click to open Moat.");
        return parts.join(" ");
    }

    // One bash call answers both halves of the setup screen: is the package
    // installed, and can this session reach the daemon. Access is what matters,
    // not how it was granted: group membership after a re-login, or an ACL on
    // the socket and the alerts file (the no-logout path), both count. `test -w`
    // and `test -r` honour ACLs, so a usermod without a re-login and without ACLs
    // still reads as "not yet".
    function probe() {
        if (probeProc.running)
            return ;

        probeProc.running = true;
    }

    // CONTRACT 5 defines a newline-delimited JSON control socket, and
    // Quickshell.Io.Socket can speak to a unix path — but moatctl is the
    // documented client for it and is one request/response per connection
    // anyway, so shelling out to `moatctl status --json` costs one fork and
    // removes an entire reconnect/framing state machine from the shell. See
    // shell/README.md.
    function pollStatus() {
        if (!root.available || statusProc.running)
            return ;

        statusProc.running = true;
    }

    function _argvFor(command, arg, arg2) {
        var argv = root._plainArgvFor(command, arg, arg2);
        if (!argv)
            return argv;

        if (root.privilegedCommands.indexOf(command) < 0)
            return argv;

        // `pkexec` runs it as root once polkit has authenticated the user.
        // Omarchy ships its own agent as a keepLoaded service plugin in this very
        // shell process, so this is the same themed password dialog every other
        // privileged action here uses -- and the user can refuse it, which is the
        // point of asking rather than assuming.
        return ["pkexec"].concat(argv);
    }

    /// The command as it would run unprivileged. Also what the panel shows the
    /// user when it has to hand the job over to a terminal.
    function _plainArgvFor(command, arg, arg2) {
        switch (command) {
        case "kill":
            return [root.ctlPath, "kill", String(arg), "--json"];
        case "quarantine":
            return [root.ctlPath, "quarantine", String(arg), "--json"];
        case "ack":
            return [root.ctlPath, "ack", String(arg), "--json"];
        case "ack-chain":
            // CONTRACT 5: acking a chain is opt-in and names one alert id like every
            // other action — the daemon expands it to the ids in that alert's
            // `chain.steps[]`. The panel never sends the sibling ids itself, so it
            // cannot ack anything moatd did not already put in the same sequence.
            return [root.ctlPath, "ack", String(arg), "--chain", "--json"];
        case "ignore":
            return [root.ctlPath, "ignore", String(arg), "--scope", Model.normalizeIgnoreScope(arg2), "--json"];
        case "unignore":
            // CONTRACT 5 + BASELINE 8: unignore takes the index of the [[rule]] block
            // WITHIN ONE allowlist.d fragment, which is why the panel never renumbers
            // what allowlist returns -- and why the fragment has to travel with the
            // index. Every file restarts at 1, so "index 1" alone would remove the
            // first rule of user.toml no matter which row was clicked.
            return arg2 ? [root.ctlPath, "unignore", String(arg), "--file", String(arg2), "--json"] : [root.ctlPath, "unignore", String(arg), "--json"];
        case "mode":
            return [root.ctlPath, "set", "mode", Model.normalizeMode(arg), "--json"];
        case "rule-mode":
            // Arming ONE rule, leaving the daemon-wide mode and every other rule alone.
            // `moatctl set --rule` calls this the safe way to start enforcing, and it
            // is the only form the panel offers: a switch that armed everything at once
            // is not a switch anybody should be given.
            return [root.ctlPath, "set", "mode", Model.normalizeMode(arg2), "--rule", String(arg), "--json"];
        case "sandbox":
            return [root.ctlPath, "set", "sandbox", arg === true || arg === "on" ? "on" : "off", "--json"];
        case "digest":
            // LEARNING 5: the daemon owns the schedule and sends the digest; this is
            // only the on/off switch, so it is a `set` like mode and sandbox.
            return [root.ctlPath, "set", "digest", arg === true || arg === "on" ? "on" : "off", "--json"];
        case "contain":
            // Containment is a switch like the three above, not a config file. It
            // shipped as a root-owned TOML edit plus a `systemctl restart`, which put a
            // security feature behind a text editor while every other switch here
            // needed neither -- and "how does a real user do that" has one answer: they
            // do not.
            return [root.ctlPath, "set", "contain", arg === true || arg === "on" ? "on" : "off", "--json"];
        case "kill":
            return [root.ctlPath, "set", "kill", String(arg), "--json"];
        case "ack-many":
            // Every id in one argv. `moatctl ack` is variadic and the daemon
            // answers the whole list in a single request.
            return [root.ctlPath, "ack"].concat(arg).concat(["--json"]);
        case "release":
            return [root.ctlPath, "contain", "--release", String(arg), "--json"];
        case "unexclude":
            // Watching something AGAIN needs no privilege: the rule here is that
            // weakening protection takes root and restoring it does not.
            return [root.ctlPath, "exclusions", "--remove", String(arg) + ":" + String(arg2), "--json"];
        case "feeds":
            return [root.ctlPath, "feeds", "refresh", "--json"];
        case "baseline-accept":
            // CONTRACT 11 / BASELINE 3: `moatctl baseline list|accept|dismiss|relearn`
            // over {"cmd":"baseline","action":...}. Accept and dismiss name a proposal
            // id, the same way every other action names an alert id — the plugin never
            // sends the tuple itself, so it cannot widen what the daemon proposed.
            return [root.ctlPath, "baseline", "accept", String(arg), "--json"];
        case "baseline-dismiss":
            return [root.ctlPath, "baseline", "dismiss", String(arg), "--json"];
        case "baseline-relearn":
            return [root.ctlPath, "baseline", "relearn", "--json"];
        case "quarantine-list":
            // Quarantine holds rather than deletes, so what is held has to be visible
            // and reversible from the panel, not only from a terminal: the whole point
            // of not deleting is that you can go and look at what caught you.
            return [root.ctlPath, "quarantine", "--list", "--json"];
        case "quarantine-restore":
            return [root.ctlPath, "quarantine", String(arg), "--restore", "--json"];
        case "triage-undo":
            // LEARNING 2c: drop an agent verdict and put a demoted alert back in the
            // badge. It names an alert id like ack and kill do, so it widens nothing —
            // and a demotion the user cannot reverse from the panel is a demotion they
            // have to trust, which is the opposite of the point.
            return [root.ctlPath, "triage", "--undo", String(arg), "--json"];
        }
        return null;
    }

    function _enqueue(command, arg, arg2) {
        if (!root.available) {
            root.lastError = "moatctl is not installed";
            root.actionFinished(command, false, root.lastError);
            return false;
        }
        var argv = root._argvFor(command, arg, arg2);
        if (!argv)
            return false;

        var queue = root._queue.slice();
        queue.push({
            "command": command,
            "argv": argv,
            "arg": arg,
            "arg2": arg2
        });
        root._queue = queue;
        root._pump();
        return true;
    }

    /// What to tell the user when an action failed.
    ///
    /// The privileged ones go through `pkexec`, which asks Omarchy's own polkit
    /// agent -- a keepLoaded service plugin running in this same shell process,
    /// so the prompt is the themed dialog the user already knows from every other
    /// privileged action on this machine.
    ///
    /// Cancelling that prompt is a perfectly ordinary answer and must not be
    /// reported as a fault. Anything else gets the exact command to run in a
    /// terminal, because a toggle that snaps back with no explanation is the
    /// worst possible way to report a refusal -- and this refusal is deliberate.
    function _explainFailure(command, message) {
        var raw = String(message || "");
        if (root.privilegedCommands.indexOf(command) < 0)
            return raw || ("moatctl " + command + " failed");

        if (raw.indexOf("dismissed") >= 0 || raw.indexOf("cancel") >= 0 || raw.indexOf("Not authorized") >= 0 || raw.indexOf("not authorized") >= 0)
            return "Left as it was: the authentication prompt was not completed.";

        var argv = root._plainArgvFor(command, root._lastArg, root._lastArg2) || [];
        var line = "sudo " + argv.join(" ").replace(" --json", "");
        return (raw ? raw + "\n\n" : "") + "This one needs root. If the prompt did not appear, run:\n\n    " + line;
    }

    function _pump() {
        if (actionProc.running || root._queue.length === 0)
            return ;

        var next = root._queue[0];
        var queue = root._queue.slice(1);
        root._queue = queue;
        root.busy = true;
        root._lastArg = next.arg;
        root._lastArg2 = next.arg2;
        actionProc.pendingCommand = next.command;
        actionProc.command = next.argv;
        actionProc.running = true;
    }

    function kill(id) {
        return root._enqueue("kill", id);
    }

    function quarantine(id) {
        return root._enqueue("quarantine", id);
    }

    /// Everything currently held, for the Quarantine tab.
    function loadQuarantine() {
        return root._enqueue("quarantine-list");
    }

    function restoreQuarantined(id) {
        return root._enqueue("quarantine-restore", id);
    }

    /// LEARNING 2c: drop this alert's agent verdict, and if the verdict had
    /// demoted it, put it back in the badge. moatd appends the update line, so
    /// the refresh after every action is what redraws the row.
    function undoTriage(id) {
        return root._enqueue("triage-undo", id);
    }

    function ack(id) {
        return root._enqueue("ack", id);
    }

    /// Every member of a card, in ONE request. One `moatctl ack` per member is
    /// one fork+exec, one socket round trip and one full list repaint each,
    /// and a card can hold dozens of alerts.
    function ackMany(ids) {
        if (!ids || ids.length === 0)
            return false;

        if (ids.length === 1)
            return root.ack(ids[0]);

        return root._enqueue("ack-many", ids);
    }

    /// 2b's "same chain, same decision": one decision closes every step of the
    /// sequence this alert belongs to. Errors if the alert is not in one, which
    /// is why only ChainBlock offers it.
    function ackChain(id) {
        return root._enqueue("ack-chain", id);
    }

    // scope is exe | exe+file | parent | rule (CONTRACT 5). Anything else is
    // narrowed to "exe" rather than widened.
    function ignore(id, scope) {
        root.lastIgnoreBlock = "";
        return root._enqueue("ignore", id, scope);
    }

    // `file` is the bare fragment name (`user.toml`, `baseline.toml`), which is
    // what `moatctl unignore --file` expects; omitting it means user.toml.
    function unignore(index, file) {
        return root._enqueue("unignore", Number(index), file || "");
    }

    function setMode(mode) {
        return root._enqueue("mode", mode);
    }

    function setRuleMode(rule, mode) {
        return root._enqueue("rule-mode", rule, mode);
    }

    /// The rules that can be armed, each with `armed` and whether arming it
    /// kills the process or refuses the operation. Straight from the daemon --
    /// the panel never decides what is enforceable.
    function enforceableRules() {
        var list = root.status && root.status.enforceable;
        return Array.isArray(list) ? list : [];
    }

    function setSandbox(on) {
        return root._enqueue("sandbox", on === true || on === "on");
    }

    function setDigest(on) {
        return root._enqueue("digest", on === true || on === "on");
    }

    function setContain(on) {
        return root._enqueue("contain", on === true || on === "on");
    }

    /// What containment does to processes: off | log | kill. Separate from
    /// `setContain`, which is whether it cuts the network at all -- the network
    /// cut expires in ten minutes and names one address, and SIGKILL does
    /// neither, so they are not one switch.
    function setKill(mode) {
        return root._enqueue("kill", String(mode));
    }

    /// "off" | "log" | "kill", defaulting to the safe reading.
    function containKill() {
        return (root.status && root.status.containKill) ? root.status.containKill : "log";
    }

    function releaseContainment(chain) {
        return root._enqueue("release", chain);
    }

    function watchAgain(rule, exe) {
        return root._enqueue("unexclude", rule, exe);
    }

    /// Binaries a rule has been told to stop watching. Straight from the daemon.
    function exclusions() {
        var list = root.status && root.status.exclusions;
        return Array.isArray(list) ? list : [];
    }

    /// Whether moatd may contain a sequence on its own, and what it is refusing
    /// right now. Both come from the daemon; the panel decides nothing here.
    function containEnabled() {
        return !!root.status && root.status.containEnabled === true;
    }

    function containments() {
        var list = root.status && root.status.contained;
        return Array.isArray(list) ? list : [];
    }

    function refreshFeeds() {
        return root._enqueue("feeds");
    }

    // Baseline proposals (BASELINE 3). Accepting writes the proposed block to
    // baseline.toml, so both halves of the Allowlist tab move afterwards — the
    // action queue's completion handler already reloads the allowlist for
    // ignore/unignore, and these are added to that set.
    function acceptProposal(id) {
        if (!String(id || "")) {
            root.lastError = "this proposal carries no id, so it cannot be accepted";
            root.actionFinished("baseline-accept", false, root.lastError);
            return false;
        }
        return root._enqueue("baseline-accept", id);
    }

    function dismissProposal(id) {
        if (!String(id || "")) {
            root.lastError = "this proposal carries no id, so it cannot be dismissed";
            root.actionFinished("baseline-dismiss", false, root.lastError);
            return false;
        }
        return root._enqueue("baseline-dismiss", id);
    }

    // Restarts the learning window (BASELINE 3). Destructive enough to deserve a
    // confirm, which the panel owns.
    function relearnBaseline() {
        return root._enqueue("baseline-relearn");
    }

    function refresh() {
        alertsFile.reload();
        root.pollStatus();
        root.loadAllowlist();
        root.loadBaselineExport();
        root.nowMs = Date.now();
    }

    function loadAllowlist() {
        if (!root.available || allowlistProc.running)
            return ;

        root.allowlistLoading = true;
        allowlistProc.running = true;
    }

    function loadBaselineExport() {
        if (!root.available || exportProc.running)
            return ;

        exportProc.running = true;
    }

    function saveBundle(id) {
        root.bundleMode = "save";
        return root._bundleFor(id);
    }

    function copyBundleText(id) {
        root.bundleMode = "text";
        return root._bundleFor(id);
    }

    function _bundleFor(id) {
        var key = String(id || "");
        if (!key)
            return false;

        if (!root.available) {
            root._setCopy("failed", "moatctl is not installed");
            return false;
        }
        if (bundleProc.running || copyProc.running || saveProc.running)
            return false;

        root._setCopy("running", "");
        root.analyzeId = key;
        bundleProc.command = [root.ctlPath, "bundle", key, "--json"];
        bundleProc.running = true;
        return true;
    }

    function loadExplain(id) {
        if (!root.available || explainProc.running)
            return ;

        var alert = root.alertById(id);
        if (!alert || Model.hasExplain(alert))
            return ;

        root._explainId = String(id);
        explainProc.command = [root.ctlPath, "explain", root._explainId, "--json"];
        explainProc.running = true;
    }

    function _setAnalyze(state, message) {
        root.analyzeState = String(state);
        root.analyzeMessage = String(message || "");
        if (state === "opened" || state === "failed")
            analyzeResetTimer.restart();

    }

    function _setCopy(state, message) {
        root.copyState = String(state);
        root.copyMessage = String(message || "");
        if (state === "copied" || state === "failed")
            copyResetTimer.restart();

    }

    // Runs outside the action queue on purpose: the queue's completion handler
    // refreshes everything and reports through actionFinished, and analyze is not
    // a state change to the daemon — it is a launch, and its result is a line
    // next to the button rather than a panel-wide notice.
    function analyze(id) {
        var key = String(id || "");
        if (!key)
            return false;

        if (!root.available) {
            root._setAnalyze("failed", "moatctl is not installed");
            return false;
        }
        if (!root.defaultAgent) {
            root._setAnalyze("failed", Model.ANALYZE_HINT);
            return false;
        }
        if (analyzeProc.running)
            return false;

        root.analyzeId = key;
        root._setAnalyze("running", "");
        analyzeProc.command = [root.ctlPath, "analyze", key];
        analyzeProc.running = true;
        return true;
    }

    // The smaller sibling: get the bundle written and put its path on the
    // clipboard, for the user who would rather paste it into an agent they are
    // already talking to. Two steps because the path comes back as JSON.
    function copyBundlePath(id) {
        root.bundleMode = "copy";
        return root._bundleFor(id);
    }

    // Clipboard. The text is passed as a bash POSITIONAL PARAMETER, never
    // interpolated into the script, so a path out of a daemon response cannot
    // become a command — the same rule Util.execArgv exists to enforce for the
    // notification vector.
    function copyText(text, label) {
        var value = String(text || "");
        if (!value) {
            root._setCopy("failed", "nothing to copy");
            return false;
        }
        if (copyProc.running)
            return false;

        root._setCopy("running", "");
        copyProc.copiedLabel = String(label || "path");
        copyProc.copiedValue = value;
        copyProc.command = ["bash", "-c", "printf %s \"$1\" | wl-copy", "moat-copy", value];
        copyProc.running = true;
        return true;
    }

    // Persist a bar-widget setting through the registry, which is where the
    // shell keeps per-widget values (shell.json's layout entry). Returns "" on
    // success or the registry's error string; the panel surfaces it rather than
    // pretending the change stuck.
    function persistSetting(key, value) {
        if (!root.shell || !root.shell.pluginRegistry || typeof root.shell.pluginRegistry.setBarWidget !== "function")
            return "the shell did not expose a settings writer";

        var error = root.shell.pluginRegistry.setBarWidget(root.pluginId, key, value, {
        });
        return error ? String(error) : "";
    }

    // Helpers the panel and widget share, forwarded so neither has to import the
    // JS module separately (a relative-path import would be a second copy).
    function relativeTime(iso) {
        return Model.relativeTime(iso, root.nowMs);
    }

    function basename(path) {
        return Model.basename(path);
    }

    function ancestryChain(alert) {
        return Model.ancestryChain(alert);
    }

    function rotateItems(alert) {
        return Model.rotateItems(alert);
    }

    function severityRank(severity) {
        return Model.severityRank(severity);
    }

    function widgetGlyph(state) {
        return Model.widgetGlyph(state);
    }

    function setupSteps() {
        return Model.setupSteps(!root.available, !root.groupOk, root.status.socket_group);
    }

    function feedsAge() {
        return Model.relativeTime(root.status.feeds.updated, root.nowMs);
    }

    function hasExplain(alert) {
        return Model.hasExplain(alert);
    }

    function actorLine(alert) {
        return Model.actorLine(alert);
    }

    function severityChangeLine(alert) {
        return Model.severityChangeLine(alert);
    }

    function suppressedLine(alert) {
        return Model.suppressedLine(alert);
    }

    // Advanced (`rawDetail`). Presentation only; see MoatModel.js.
    function rawFacts(alert) {
        return Model.rawFacts(alert);
    }

    function rawSeverityLine(alert) {
        return Model.rawSeverityLine(alert);
    }

    function ancestryLines(alert) {
        return Model.ancestryLines(alert);
    }

    function proposalDetail(proposal) {
        return Model.proposalDetail(proposal);
    }

    function allowlistSections() {
        return Model.allowlistSections(root.allowlistRules);
    }

    function ignoreOptions(alert) {
        return Model.ignoreOptions(alert);
    }

    function otherOptions(alert) {
        return Model.otherOptions(alert);
    }

    function ignoreScopeLabel(scope) {
        return Model.ignoreScopeLabel(scope);
    }

    function ignoreScopeCaution(scope) {
        return Model.ignoreScopeCaution(scope);
    }

    function rarityPill(rarity) {
        return Model.rarityPill(rarity);
    }

    function rarityLine(alert) {
        return Model.rarityLine(alert);
    }

    // LEARNING 2c: the unattended agent verdict, for the row chip and the block.
    function triageChip(alert) {
        return Model.triageChip(alert);
    }

    function triageOutcomeText(alert) {
        return Model.triageOutcomeText(alert);
    }

    function formatBytes(bytes) {
        return Model.formatBytes(bytes);
    }

    function receiptSummary(receipt) {
        return Model.receiptSummary(receipt);
    }

    function receiptBlock(receipt) {
        return Model.receiptBlock(receipt);
    }

    onDemotedRulesChanged: root._recount()
    onShowSuppressedChanged: root._recount()
    onAvailableChanged: {
        if (!root.available)
            return ;

        root.loadAllowlist();
        root.loadBaselineExport();
    }
    Component.onCompleted: {
        root.probe();
        // Once, at service start: the button label is the user's own default agent
        // and it does not change under us mid-session.
        agentProc.running = true;
    }

    FileView {
        id: rotatedFile

        path: root.rotatedPath
        watchChanges: true
        // Legitimately absent until the first rotation.
        printErrors: false
        onFileChanged: reload()
        onLoaded: {
            Model.setLogPrefix(root._store, text());
            root._rotatedSettled = true;
            alertsFile.reload();
        }
        onLoadFailed: function(error) {
            Model.setLogPrefix(root._store, "");
            root._rotatedSettled = true;
            alertsFile.reload();
        }
    }

    // One reload per burst, not one per line. moatd writes an alert and then
    // the update lines that follow it (a chain, an incident snapshot, a
    // dedupe count) as separate appends milliseconds apart, and FileView fires
    // fileChanged for each write. Every reload re-reads the whole live file,
    // folds it and republishes to every view, so a burst of five lines cost
    // five of those. The first change starts the window; the reload at its end
    // reads everything that landed in it. One second is the most a
    // notification can lag behind the daemon for it.
    Timer {
        id: alertsReloadTimer

        interval: 1000
        repeat: false
        onTriggered: alertsFile.reload()
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
        // re-read rather than parsing here -- coalesced, see alertsReloadTimer.
        // Append-heavy files fire this often; the fold is incremental over what
        // was appended, but the re-read is the whole file, capped at 20 MB by
        // moatd.
        onFileChanged: {
            if (!alertsReloadTimer.running)
                alertsReloadTimer.start();

        }
        // The live half only. The store already holds the rotated half in front
        // of it -- the order moatd folds them in, so an update in the live file
        // lands on a record that was rotated out.
        onLoaded: {
            if (root._rotatedSettled)
                root._ingest(text());

        }
        onLoadFailed: function(error) {
            root.logReadable = false;
            root.alerts = [];
            root.receipts = [];
            root.unacked = ({
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "total": 0
            });
            root.lastError = "cannot read " + root.alertsPath;
            // A failed open is the strongest signal we get that the group or the
            // package is missing; re-probe rather than sit on a stale answer.
            root.probe();
        }
    }

    Timer {
        // Cooldown windows end on their own, with or without another alert.
        interval: 30000
        running: true
        repeat: true
        onTriggered: root._flushCollapsed()
    }

    Process {
        id: probeProc

        command: ["bash", "-c", "if [ -x /usr/bin/moatctl ]; then a=true; else a=false; fi; " + "if id -nG 2>/dev/null | tr ' ' '\\n' | grep -qx moat; then g=true; " + "elif [ -w /run/moat/control.sock ] && [ -r /var/lib/moat/alerts.jsonl ]; then g=true; " + "else g=false; fi; " + "printf '{\"available\":%s,\"group\":%s}\\n' \"$a\" \"$g\""]
        onExited: function(exitCode) {
            var raw = String(probeStdout.text || root._probeOutput || "").trim();
            try {
                var value = JSON.parse(raw || "{}");
                root.available = value.available === true;
                root.groupOk = value.group === true;
            } catch (e) {
                root.available = false;
                root.groupOk = false;
            }
            if (root.available)
                root.pollStatus();
            else
                root.daemonOk = false;
        }

        stdout: StdioCollector {
            id: probeStdout

            waitForEnd: true
            onStreamFinished: root._probeOutput = text
        }

    }

    Process {
        // Deliberately NOT `lastError`.
        // `lastError` means "the last thing you asked for failed", and it is
        // drawn as a red strip across the page. A background poll is not
        // something the user asked for: on a shell restart the first one can
        // lose a race with the socket and answer "connection refused", which
        // then healed on the next tick a second later -- a red banner for a
        // blip that had already fixed itself. Losing trust in the strip costs
        // more than the blip.

        id: statusProc

        command: [root.ctlPath, "status", "--json"]
        onExited: function(exitCode) {
            var stdout = String(statusStdout.text || root._statusOutput || "").trim();
            var stderr = String(statusStderr.text || root._statusError || "").trim();
            if (exitCode !== 0 && !stdout) {
                // The daemon is not answering. Keep the last known status shape but
                // mark it not-ok so the UI stops claiming a mode it cannot verify.
                root.status = Model.normalizeStatus(null);
                root.daemonOk = false;
                // A daemon that is genuinely unreachable already has its own surface:
                // `daemonOk` and `available` route the whole panel to the setup screen,
                // which explains it properly instead of shouting one line.
                root._pollError = stderr || ("moatctl status exited " + exitCode);
                return ;
            }
            var next = Model.normalizeStatus(stdout);
            root.status = next;
            root.daemonOk = next.ok;
            if (next.ok)
                root._pollError = "";
            else
                root._pollError = next.error || stderr || "moatd is not reachable";
            // group_ok from the daemon is authoritative about socket access; it can
            // only ever take groupOk away, never grant it.
            if (next.group_ok === false)
                root.groupOk = false;

            // With no readable log, the daemon's counts are the only ones there are.
            // With a readable log ours are fresher, so they win.
            if (!root.logReadable && next.unacked) {
                var u = next.unacked;
                root.unacked = {
                    "critical": Number(u.critical || 0),
                    "high": Number(u.high || 0),
                    "medium": Number(u.medium || 0),
                    "low": Number(u.low || 0),
                    "total": Number(u.critical || 0) + Number(u.high || 0) + Number(u.medium || 0) + Number(u.low || 0)
                };
            }
        }

        stdout: StdioCollector {
            id: statusStdout

            waitForEnd: true
            onStreamFinished: root._statusOutput = text
        }

        stderr: StdioCollector {
            id: statusStderr

            waitForEnd: true
            onStreamFinished: root._statusError = text
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

    Process {
        // Not JSON. exitCode already decided ok; stderr already carries why.

        id: actionProc

        property string pendingCommand: ""

        onExited: function(exitCode) {
            var stdout = String(actionStdout.text || root._actionOutput || "").trim();
            var stderr = String(actionStderr.text || root._actionError || "").trim();
            root._actionOutput = "";
            root._actionError = "";
            var ok = exitCode === 0;
            var message = ok ? "" : (stderr || "moatctl exited " + exitCode);
            try {
                var value = JSON.parse(stdout || "{}");
                if (value.ok === false) {
                    ok = false;
                    message = String(value.error || message);
                }
                // `set mode` answers ok:true even when `tetra tp set-mode` failed on
                // every policy: moatd deliberately persists the mode so a restart
                // reapplies it. But nothing in the kernel changed, and a panel that
                // says "enforce" over a sensor still in monitor is the one lie this UI
                // must not tell. Treat "0 of N applied" as a failure and name it.
                if (ok && actionProc.pendingCommand === "mode" && Number(value.policies || 0) > 0 && Number(value.applied || 0) === 0) {
                    ok = false;
                    message = "moatd recorded mode " + String(value.mode || "?") + " but could not apply it to any of " + Number(value.policies) + " policies (" + String(value.tetra || "tetra") + " failed). Tetragon is still in the previous mode.";
                }
                // CONTRACT 5: ignore returns the exact block it appended to user.toml.
                // Show it rather than a "done" — the point of the flow is that the user
                // sees what got written on their behalf.
                if (ok && actionProc.pendingCommand === "ignore")
                    root.lastIgnoreBlock = String(value.block || value.line || value.rule || "");

                if (ok && actionProc.pendingCommand === "quarantine-list")
                    root.quarantineItems = Model.quarantineView(value);

            } catch (e) {
            }
            if (!ok)
                root.lastError = root._explainFailure(actionProc.pendingCommand, message);

            // Both halves of the allowlist tab move when a rule is added or removed,
            // and accepting a proposal writes one to baseline.toml.
            if (ok && (actionProc.pendingCommand === "ignore" || actionProc.pendingCommand === "unignore" || actionProc.pendingCommand.indexOf("baseline-") === 0))
                root.loadAllowlist();

            // Quarantining or restoring changes what is held, and so does the very
            // first look at the tab.
            if (ok && (actionProc.pendingCommand === "quarantine" || actionProc.pendingCommand === "quarantine-restore"))
                root.loadQuarantine();

            root.actionFinished(actionProc.pendingCommand, ok, message);
            root.actionSerial++;
            root.busy = false;
            // moatd appends the resulting update line, so the FileView watch will
            // fire on its own — but ask anyway so a same-millisecond write is not
            // missed, and re-poll status because mode/sandbox/feeds live there.
            root.refresh();
            root._pump();
        }

        stdout: StdioCollector {
            id: actionStdout

            waitForEnd: true
            onStreamFinished: root._actionOutput = text
        }

        stderr: StdioCollector {
            id: actionStderr

            waitForEnd: true
            onStreamFinished: root._actionError = text
        }

    }

    Process {
        id: allowlistProc

        command: [root.ctlPath, "allowlist", "--json"]
        onExited: function(exitCode) {
            root.allowlistLoading = false;
            var stdout = String(allowlistStdout.text || root._allowlistOutput || "").trim();
            var stderr = String(allowlistStderr.text || root._allowlistError || "").trim();
            if (exitCode !== 0 && !stdout) {
                root.allowlistError = stderr || ("moatctl allowlist exited " + exitCode);
                return ;
            }
            var parsed = Model.parseAllowlist(stdout);
            root.allowlistRules = parsed.rules;
            root.allowlistFile = parsed.file;
            root.allowlistError = parsed.ok ? "" : (parsed.error || stderr);
        }

        stdout: StdioCollector {
            id: allowlistStdout

            waitForEnd: true
            onStreamFinished: root._allowlistOutput = text
        }

        stderr: StdioCollector {
            id: allowlistStderr

            waitForEnd: true
            onStreamFinished: root._allowlistError = text
        }

    }

    Process {
        id: exportProc

        command: [root.ctlPath, "baseline", "export", "--json"]
        onExited: function(exitCode) {
            var stdout = String(exportStdout.text || root._exportOutput || "").trim();
            var stderr = String(exportStderr.text || root._exportError || "").trim();
            if (exitCode !== 0 && !stdout) {
                // Not fatal and not worth a panel-wide error: an older daemon simply
                // does not have this verb, and every screen that reads it degrades to
                // "not counted" rather than to a wrong number.
                root.baselineExportError = stderr || ("moatctl baseline export exited " + exitCode);
                return ;
            }
            var parsed = Model.parseBaselineExport(stdout);
            root.baselineTuples = parsed.tuples;
            root.baselineExportError = parsed.ok ? "" : (parsed.error || stderr);
        }

        stdout: StdioCollector {
            id: exportStdout

            waitForEnd: true
            onStreamFinished: root._exportOutput = text
        }

        stderr: StdioCollector {
            id: exportStderr

            waitForEnd: true
            onStreamFinished: root._exportError = text
        }

    }

    Process {
        id: saveProc

        property string savedTo: ""

        onExited: function(exitCode) {
            if (exitCode === 0) {
                root.bundleSavedPath = saveProc.savedTo;
                root._setCopy("copied", "saved to " + saveProc.savedTo);
            } else {
                root._setCopy("failed", String(saveStderr.text || "").trim() || "could not write the file");
            }
        }

        stderr: StdioCollector {
            id: saveStderr

            waitForEnd: true
        }

    }

    Process {
        id: explainProc

        onExited: function(exitCode) {
            var stdout = String(explainStdout.text || root._explainOutput || "").trim();
            root._explainOutput = "";
            if (exitCode !== 0 || !stdout)
                return ;

            var alert = root.alertById(root._explainId);
            if (!alert)
                return ;

            Model.mergeExplainResponse(alert, stdout);
            // alerts is a plain array; reassigning it is what re-evaluates the
            // panel's bindings on the alert we just filled in.
            root.alerts = root.alerts.slice();
            root.alertsUpdated();
        }

        stdout: StdioCollector {
            id: explainStdout

            waitForEnd: true
            onStreamFinished: root._explainOutput = text
        }

    }

    Process {
        id: agentProc

        // Through bash so a machine without `omarchy` on PATH is a quiet empty
        // answer (no default agent) rather than a failed-to-start process.
        command: ["bash", "-c", "omarchy default agent 2>/dev/null || true"]
        onExited: function(exitCode) {
            root.defaultAgent = Model.normalizeAgentName(agentStdout.text);
        }

        stdout: StdioCollector {
            id: agentStdout

            waitForEnd: true
        }

    }

    Timer {
        id: analyzeResetTimer

        interval: 12000
        onTriggered: {
            root.analyzeState = "";
            root.analyzeMessage = "";
        }
    }

    Timer {
        id: copyResetTimer

        interval: 12000
        onTriggered: {
            root.copyState = "";
            root.copyMessage = "";
        }
    }

    Process {
        id: analyzeProc

        onExited: function(exitCode) {
            var stderr = String(analyzeStderr.text || "").trim();
            // The transient line names the agent, because by now the terminal has
            // already opened and saying which one is a fact rather than a promise.
            if (exitCode === 0)
                root._setAnalyze("opened", "opened in a terminal (" + root.defaultAgent + ")");
            else
                root._setAnalyze("failed", stderr || ("moatctl analyze exited " + exitCode));
        }

        stderr: StdioCollector {
            id: analyzeStderr

            waitForEnd: true
        }

    }

    Process {
        id: bundleProc

        onExited: function(exitCode) {
            var stdout = String(bundleStdout.text || "").trim();
            var stderr = String(bundleStderr.text || "").trim();
            if (exitCode !== 0 && !stdout) {
                root._setCopy("failed", stderr || ("moatctl bundle exited " + exitCode));
                return ;
            }
            var parsed = Model.parseBundleResponse(stdout);
            if (!parsed.ok) {
                root._setCopy("failed", parsed.error || stderr);
                return ;
            }
            if (root.bundleMode === "save") {
                // The name the design shows the user before they press the button
                // (2i): one file, named after the incident, in their home directory.
                var target = "moat-incident-" + root.analyzeId + ".md";
                saveProc.savedTo = "~/" + target;
                saveProc.command = ["bash", "-c", "cd \"$HOME\" && cp -- \"$1\" \"$2\"", "moat-save", parsed.path, target];
                saveProc.running = true;
                return ;
            }
            if (root.bundleMode === "text") {
                copyProc.copiedLabel = "bundle text";
                copyProc.copiedValue = parsed.path;
                copyProc.command = ["bash", "-c", "wl-copy < \"$1\"", "moat-copy", parsed.path];
                copyProc.running = true;
                return ;
            }
            root.copyText(parsed.path, "bundle path");
        }

        stdout: StdioCollector {
            id: bundleStdout

            waitForEnd: true
        }

        stderr: StdioCollector {
            id: bundleStderr

            waitForEnd: true
        }

    }

    Process {
        id: copyProc

        property string copiedLabel: "path"
        property string copiedValue: ""

        onExited: function(exitCode) {
            if (exitCode === 0)
                root._setCopy("copied", copyProc.copiedLabel + " copied: " + copyProc.copiedValue);
            else
                root._setCopy("failed", String(copyStderr.text || "").trim() || "wl-copy is not available");
        }

        stderr: StdioCollector {
            id: copyStderr

            waitForEnd: true
        }

    }

}
