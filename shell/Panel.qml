// Moat's panel. Declared as kind "panel" with keepLoaded, so the shell
// mounts it once at startup and drives it through the standard verbs:
//   omarchy-shell shell toggle io.github.the2dl.moat '{}'
//   omarchy-shell shell summon io.github.the2dl.moat '{"alert":"<id>"}'
// The shell's panel loader injects `shell`, `manifest` and `service` (the
// matching service singleton) and calls open(payloadJson) / close(); `opened`
// is what it reads back to decide whether a toggle should summon or hide. The
// bar widget click and the notification click both arrive through those verbs,
// which is why nothing here reaches for the bar widget instance.

import "MoatCopy.js" as Copy
import "MoatModel.js" as Model
import QtQuick
import QtQuick.Window
import Quickshell
import Quickshell.Io
import qs.Commons
import qs.Ui

// The surface is a real toplevel (Quickshell's FloatingWindow), not a
// layer-shell overlay. At 1400x860 this stopped being a card you glance at and
// became something you sit down in front of: an expanded receipt has to be able
// to push the rows under it down, and a window has to be movable, resizable and
// stackable like every other window on the workspace. The glanceable role it
// gave up is the bar glyph's (3e), which prints the same verdict.
Item {
    // transient result line under the header
    // ---------------------------------------------------------------- lifecycle
    // ------------------------------------------------------------- act + confirm
    // ------------------------------------------------------------- keyboard nav
    // 2g: j/k, a (then 1-4), s, e, ?, u. The same verbs as the buttons, and the
    // same four things moatctl does. After a week away there may be six
    // incidents, and clearing them should feel like reading mail in a terminal --
    // which is the machine this runs on.
    // PanelKeyCatcher already owns the raw Keys handler, so the panel wires its
    // semantic signals rather than declaring a second Keys.onPressed (which would
    // shadow the component's own and kill every binding it provides). While the
    // confirm is up, the same signals drive the dialog instead of the list.
    // -------------------------------------------------------------------- window

    id: root

    // Injected by shell.qml's panel loader.
    property var shell: null
    property var manifest: null
    property var service: null
    /// True while the SHELL is the one closing the window, so the window's own
    /// onVisibleChanged does not call shell.hide() straight back at it.
    property bool closingFromHost: false
    /// The window IS the open state now. A toplevel can be closed by things this
    /// plugin never hears about first -- the titlebar button, `killactive`, a
    /// workspace being torn down -- so deriving `opened` from a separate boolean
    /// would let the shell's openPanelIds drift out of step with what is on
    /// screen, and a toggle would then do nothing.
    readonly property bool opened: window.visible
    property string selectedId: ""
    // The redesign's navigation (docs/design/README.md): three tabs and a gear.
    // Settings stops being a tab because it is not a place you go while working,
    // and Quarantine folds into Rules as the list of things being held -- it was
    // a tab that was empty on almost every machine on almost every day.
    property string tab: "now"
    // "now" | "history" | "rules" | "settings"
    property string notice: ""
    readonly property var tabNames: ["now", "history", "rules", "settings"]
    // The old vocabulary still arrives from notifications, the bar widget and
    // `omarchy-shell -q`, so it is translated rather than rejected.
    readonly property var tabAliases: ({
        "alerts": "now",
        "timeline": "history",
        "allowlist": "rules",
        "quarantine": "rules"
    })
    readonly property string pluginId: "io.github.the2dl.moat"
    // The redesign's unit of attention (docs/design/README.md 1c): alerts
    // collapsed by (rule, program). It lives on the SERVICE rather than here,
    // because the bar widget reads the same derivation -- 3e's rule is that the
    // glyph and the verdict line can never disagree.
    readonly property var incidents: service ? service.incidents : []
    // The badge counts DECISIONS, never events. "Alerts 24" was a backlog
    // counter; this is how many things are actually waiting on the user.
    readonly property int needsYouCount: service ? service.needsYouCount : 0
    readonly property var queue: service ? service.needsYou : []
    readonly property bool ready: !!service && service.available && service.groupOk
    readonly property bool enforcing: !!service && service.status.mode === "enforce"
    // 3f. The daemon is reachable and has recorded nothing at all: not an empty
    // list, a machine that has not started yet. Dismissed for the session by
    // "Start watching", because it is not a wizard and has nothing to answer.
    property bool firstRunSeen: false
    /// The History row that has been opened into a page of its own.
    ///
    /// Held as a KEY, not as the incident object. `buildIncidents` allocates new
    /// objects on every rebuild -- the status poll and every append to
    /// alerts.jsonl -- so a pinned object is a snapshot that silently stops
    /// counting repeats and stops noticing that the user just closed it.
    property string historyKey: ""
    readonly property var historyIncident: root.incidentByKey(root.historyKey)
    readonly property bool firstRun: root.ready && !root.firstRunSeen && !!service && service.logReadable && service.alerts.length === 0 && service.receipts.length === 0
    /// Which full-page view is on screen. ONE decision, in one place.
    ///
    /// Every page below is an `anchors.fill: parent` sibling, so nothing about
    /// the layout stops two of them being visible at once -- the only thing that
    /// ever did was that their `visible:` expressions happened to be mutually
    /// exclusive. History's detail was given its own condition
    /// (`tab === "history" && historyIncident`) while the list kept the older one
    /// (`tab === "history"`), and the two stopped being exclusive: opening a row
    /// drew the incident ON TOP of the still-visible list, buttons over text.
    ///
    /// Binding every page to this one string is what makes that unrepresentable.
    readonly property string page: {
        if (!root.ready)
            return root.service ? "setup" : "";

        if (root.firstRun)
            return "firstRun";

        if (root.tab === "history" && !!root.historyIncident)
            return "historyDetail";

        return root.tab;
    }
    // Stopping and holding are the two irreversible-from-here actions — one ends
    // a process tree, the other chmod 000s a file into /var/lib/moat/quarantine —
    // so both go through a confirm, and so does removing a rule (it silently
    // re-arms a detection). Saying "this was me" does not: 1c already asked the
    // only question it has, and the rule it writes is listed with an Undo one tab
    // away.
    property string _pendingCommand: ""
    property string _pendingArg: ""
    property string _pendingArg2: ""
    property string _lastActionId: ""
    property string _lastIgnoreRule: ""
    property string _lastIgnoreExe: ""
    /// What `u` would take back, or null. Set by the action results above.
    property var undoable: null
    /// The incident the keys act on: the one actually on screen. Reading
    /// `queue[0]` here meant `s` (stop it) and `?` (open in the agent) always hit
    /// the first incident, whichever one the user had walked to.
    readonly property var focused: root.tab === "now" && nowView.current ? nowView.current : (root.queue.length > 0 ? root.queue[0] : null)

    // The shell hands open() the raw payload string. `{"alert":"<id>"}` selects
    // an alert — this is how a notification click lands on the right one.
    // `{"tab":"rules"}` opens straight to Rules.
    function open(payloadJson) {
        var payload = {
        };
        try {
            payload = JSON.parse(String(payloadJson || "") || "{}");
        } catch (e) {
            payload = {
            };
        }
        if (payload && payload.alert) {
            root.selectAlert(String(payload.alert));
            // Land on the surface that actually holds it. An alert that still needs a
            // decision is the page on Now; anything else is a row in History.
            var target = service ? service.alertById(String(payload.alert)) : null;
            var state = target ? Model.alertState(target, service.demotedRules) : "";
            root.tab = state === "needsYou" ? "now" : "history";
            // Land ON the incident, not merely on the tab that holds it. A toast
            // names one alert; the incident it belongs to may be a repeat group or a
            // chain, and both surfaces address incidents by KEY. Without this the
            // click that says "the .git/config thing needs you" dropped the reader on
            // a list and left them to find it.
            var incident = root.incidentById(String(payload.alert));
            if (incident) {
                if (root.tab === "now")
                    nowView.showIncident(String(incident.key));
                else
                    root.historyKey = String(incident.key);
            }
        }
        if (payload && payload.tab)
            root.selectTab(String(payload.tab));

        root.notice = "";
        root.closingFromHost = false;
        // A summon that arrives while the window is already mapped has to RAISE it.
        // Under layer-shell an overlay was always on top of everything, so "summon"
        // and "map" were the same act; a toplevel can be behind another window or on
        // another workspace entirely, and a notification click that changed nothing
        // the user could see would read as Moat being broken.
        var wasVisible = window.visible;
        window.visible = true;
        if (wasVisible)
            root.raiseWindow();

        if (service)
            service.refresh();

        // The content tree is only mounted once the window maps, so the key catcher
        // cannot take focus in the same turn as the surface is asked for.
        Qt.callLater(function() {
            if (window.visible)
                keys.forceActiveFocus();

        });
    }

    /// Host-initiated close (`omarchy-shell shell hide`, and the shell's own
    /// `toggle` when it finds us open). Drops the surface without telling the
    /// shell back -- it already knows.
    function close() {
        confirm.opened = false;
        root._pendingCommand = "";
        root.closingFromHost = true;
        window.visible = false;
        root.closingFromHost = false;
    }

    /// User-initiated close (Escape, the panel's own ✕, the titlebar). Routed
    /// through the shell so its openPanelIds map stays consistent; it calls
    /// close() straight back.
    function requestClose() {
        if (root.shell && typeof root.shell.hide === "function")
            root.shell.hide(root.pluginId);
        else
            root.close();
    }

    /// Ask the compositor to bring the window forward, and to follow it to the
    /// workspace it is on. Quickshell's FloatingWindow has no raise or activate
    /// of its own, and Wayland gives no client a way to focus itself unprompted,
    /// so this goes through Hyprland -- which is the only compositor
    /// omarchy-shell runs on.
    ///
    /// Both dispatch spellings are sent because Hyprland has two config parsers
    /// in the wild and each rejects the other's form outright: Omarchy 4 runs the
    /// Lua parser, where `hyprctl dispatch focuswindow ...` answers "dispatch in
    /// lua is a shorthand for hl.dispatch(...)", and a legacy-parser session
    /// reads the Lua call as an unknown dispatcher name. The rejected one is a
    /// no-op with a message on stderr nobody sees; the accepted one raises the
    /// window. Best effort either way -- a failed raise leaves the window mapped,
    /// just not in front.
    ///
    /// Matched on title, because a Hyprland window selector takes exactly one
    /// criterion -- `class:... title:...` together finds nothing.
    function raiseWindow() {
        var selector = "title:^(" + window.title + ")$";
        Quickshell.execDetached(["hyprctl", "dispatch", "hl.dsp.focus({ window = '" + selector + "' })"]);
        Quickshell.execDetached(["hyprctl", "dispatch", "focuswindow", selector]);
    }

    function toggle() {
        root.opened ? root.requestClose() : root.open("{}");
    }

    function selectAlert(id) {
        root.selectedId = String(id || "");
        // Repair path for an alert whose line predates the explain block.
        if (service && root.selectedId)
            service.loadExplain(root.selectedId);

    }

    function requestKill(id) {
        root._confirm("kill", id, "Stop this? Moat kills the process tree it recorded. It cannot start it again for you.");
    }

    function requestQuarantine(id) {
        root._confirm("quarantine", id, "Hold this file? It is moved aside and made unreadable, not deleted — anything still using it will break, and you can put it back from Rules.");
    }

    function requestRestoreQuarantined(id) {
        root._confirm("quarantine-restore", id, "Put this file back where it came from? Moat held it because a detection matched it.");
    }

    function requestUnignore(index, file) {
        root._pendingArg2 = String(file || "");
        root._confirm("unignore", String(index), "Take this rule back? What it was silencing starts reaching you again.");
    }

    // BASELINE 3: relearning re-opens the window in which recurring medium/low
    // alerts are silently written to baseline.toml instead of shown. That is a
    // week of deliberately reduced visibility, so it asks first.
    function requestRelearn() {
        root._confirm("baseline-relearn", "", "Learn this machine again? For the next window, activity that keeps repeating from packaged programs is written down as normal instead of being shown to you.");
    }

    /// 1c's answer. `scope` is one the DAEMON offered for this alert; the panel
    /// never invents one, and Model.normalizeIgnoreScope narrows anything it does
    /// not recognise rather than widening it.
    function requestWasMe(id, scope) {
        if (!service)
            return ;

        var alert = service.alertById(String(id));
        root._lastIgnoreRule = alert ? String(alert.rule || "") : "";
        root._lastIgnoreExe = alert && alert.process ? String(alert.process.exe || "") : "";
        root._lastActionId = String(id);
        service.ignore(id, scope);
    }

    /// 2b: "same chain, same decision". CONTRACT 5's opt-in
    /// `{"cmd":"ack","id":...,"chain":true}` marks every step of the sequence
    /// seen. It writes no rule and silences nothing in future, so — like "this
    /// was me" and unlike stopping — it does not go through a confirm.
    function requestAckChain(id) {
        if (service)
            service.ackChain(id);

    }

    function requestAcceptProposal(id) {
        if (service)
            service.acceptProposal(id);

    }

    function requestDismissProposal(id) {
        if (service)
            service.dismissProposal(id);

    }

    function setMode(mode) {
        if (service)
            service.setMode(mode);

    }

    /// Hand the evidence bundle to `omarchy-agent`, which opens a TERMINAL.
    ///
    /// The panel closes on the way. It is a Wayland overlay layer: a terminal
    /// spawned underneath it is invisible, so a button that opened one and left
    /// the panel on top read as a button that did nothing at all.
    ///
    /// This is not 2a. The design's "Ask Moat" is a thread in the panel, and the
    /// daemon has no endpoint for one -- see shell/README.md.
    function openInAgent(id) {
        if (!service)
            return ;

        if (!service.defaultAgent) {
            root.notice = service.agentHint;
            noticeTimer.restart();
            return ;
        }
        if (service.analyze(id))
            root.requestClose();

    }

    // 2g's `u`. Two of the three things a person can do here are reversible
    // through a verb the daemon already has, and the third says so out loud
    // rather than offering an Undo that quietly does nothing.
    function undoLast() {
        if (!service || !root.undoable) {
            root.notice = "Nothing to take back.";
            noticeTimer.restart();
            return ;
        }
        if (root.undoable.command === "quarantine") {
            root.requestRestoreQuarantined(root.undoable.id);
            return ;
        }
        if (root.undoable.command === "ignore") {
            // The rule the daemon just appended, found by what it is about. `unignore`
            // addresses it by (fragment, index) and those are the daemon's own
            // numbers, so the panel reads them back rather than counting for itself.
            var rules = service.allowlistRules;
            var found = null;
            for (var i = 0; i < rules.length; i++) {
                if (rules[i].shipped || !rules[i].removable)
                    continue;

                if (rules[i].name !== root.undoable.rule)
                    continue;

                if (root.undoable.exe && rules[i].exe !== root.undoable.exe)
                    continue;

                found = rules[i];
            }
            if (!found) {
                root.notice = "That rule is not listed yet — open Rules and take it back there.";
                noticeTimer.restart();
                return ;
            }
            root.requestUnignore(found.index, found.file);
        }
    }

    function _confirm(command, arg, message) {
        root._pendingCommand = command;
        root._pendingArg = String(arg);
        root._lastActionId = String(arg);
        if (command !== "unignore")
            root._pendingArg2 = "";

        confirm.message = message;
        confirm.confirmText = command === "baseline-relearn" ? "Learn again" : command === "quarantine-restore" ? "Put it back" : command === "kill" ? "Stop it" : command === "quarantine" ? "Hold it" : command === "unignore" ? "Take it back" : command.charAt(0).toUpperCase() + command.slice(1);
        confirm.selectedIndex = 0; // a destructive prompt defaults to Cancel
        confirm.opened = true;
    }

    function _runPending() {
        var command = root._pendingCommand;
        var arg = root._pendingArg;
        var arg2 = root._pendingArg2;
        confirm.opened = false;
        root._pendingCommand = "";
        root._pendingArg2 = "";
        if (!service)
            return ;

        if (command === "kill")
            service.kill(arg);
        else if (command === "quarantine")
            service.quarantine(arg);
        else if (command === "unignore")
            service.unignore(Number(arg), arg2);
        else if (command === "baseline-relearn")
            service.relearnBaseline();
        else if (command === "quarantine-restore")
            service.restoreQuarantined(arg);
    }

    /// What j/k walks: the needs-you queue on Now, every incident on History.
    function navigable() {
        if (root.tab === "now")
            return root.queue;

        if (root.tab === "history")
            return historyView.shown;

        return [];
    }

    function moveSelection(delta) {
        if (confirm.opened) {
            confirm.selectedIndex = confirm.selectedIndex === 0 ? 1 : 0;
            return ;
        }
        // On Now, j/k walk the needs-you queue -- 3c's "press j to walk them".
        // The card owns the cursor, because the card is the page there; the
        // list/detail selection below is History's, and applying it here moved a
        // selection nothing on screen was showing.
        if (root.tab === "now") {
            nowView.step(delta);
            return ;
        }
        var list = root.navigable();
        if (list.length === 0)
            return ;

        var index = 0;
        for (var i = 0; i < list.length; i++) {
            if (list[i].id === root.selectedId) {
                index = i;
                break;
            }
        }
        index = Math.max(0, Math.min(list.length - 1, index + delta));
        root.selectAlert(list[index].id);
    }

    function activate() {
        if (!confirm.opened)
            return ;

        if (confirm.selectedIndex === 0) {
            confirm.opened = false;
            root._pendingCommand = "";
        } else {
            root._runPending();
        }
    }

    function dismiss() {
        if (confirm.opened) {
            confirm.opened = false;
            root._pendingCommand = "";
            return ;
        }
        root.requestClose();
    }

    function handleTextKey(text) {
        if (confirm.opened)
            return ;

        switch (text) {
        case "a":
            // `a` opens the scope chips rather than writing anything, and 1-4 then
            // picks one. Two keystrokes for a rule, and the second one is the question
            // "how wide" -- which is the whole point of 1c.
            if (root.tab === "now" && root.focused)
                nowView.card.openScope();

            break;
        case "1":
        case "2":
        case "3":
        case "4":
            if (root.tab === "now")
                nowView.card.chooseScope(Number(text));

            break;
        case "s":
            if (root.focused)
                root.requestKill(root.focused.id);

            break;
        case "e":
            if (root.tab === "now")
                nowView.card.toggleEvidence();

            break;
        case "?":
            if (root.focused)
                root.openInAgent(root.focused.id);

            break;
        case "u":
            root.undoLast();
            break;
        case "r":
            if (service)
                service.refresh();

            break;
        case "t":
            root.cycleTab(1);
            break;
        }
    }

    // `t` cycles the four surfaces in order rather than toggling two.
    function cycleTab(delta) {
        var index = root.tabNames.indexOf(root.tab);
        if (index < 0)
            index = 0;

        root.selectTab(root.tabNames[(index + delta + root.tabNames.length) % root.tabNames.length]);
    }

    function selectTab(name) {
        var wanted = String(name);
        // Notifications, the bar widget and `omarchy-shell -q` all still say
        // "alerts"/"allowlist"; translate rather than land on a blank panel.
        if (root.tabAliases[wanted])
            wanted = root.tabAliases[wanted];

        if (wanted !== "history")
            root.historyKey = "";

        root.tab = root.tabNames.indexOf(wanted) === -1 ? "now" : wanted;
        if (root.tab === "rules" && service) {
            service.loadAllowlist();
            service.loadQuarantine();
            service.loadBaselineExport();
        }
    }

    // Persisting a setting means writing the bar widget's shell.json entry,
    // because that is where the manifest's barWidget.defaults live. When the
    // widget is not on the bar there is no entry to write, so the change applies
    // for this session and the notice says so rather than lying.
    function _persist(key, value, saidWhat, saidWhatSession) {
        if (!service)
            return ;

        var error = service.persistSetting(key, value);
        root.notice = error ? saidWhatSession + " (not saved: " + error + ")" : saidWhat;
        noticeTimer.restart();
    }

    function setMinNotifySeverity(value) {
        if (!service)
            return ;

        service.minNotifySeverity = value;
        root._persist("minNotifySeverity", value, "Notification threshold: " + value + " and above.", "Notification threshold " + value + " for this session");
    }

    function setNotifyCooldown(minutes) {
        if (!service)
            return ;

        var value = Number(minutes);
        service.notifyCooldownMinutes = value;
        root._persist("notifyCooldownMinutes", value, "At most one notification per detection every " + value + " minutes.", "Cooldown " + value + " min for this session");
    }

    /// 1f's three answers, written onto the two settings that carry them. "Never"
    /// is its own switch because a severity floor cannot express it: "critical
    /// only" is not "never".
    function setNotifyLevel(level) {
        if (!service)
            return ;

        if (level === "never") {
            service.notifyMuted = true;
            root._persist("notifyMuted", true, "Moat will not interrupt you. Everything still lands here.", "Notifications off for this session");
            return ;
        }
        var severity = level === "odd" ? "medium" : "high";
        service.notifyMuted = false;
        service.minNotifySeverity = severity;
        service.persistSetting("notifyMuted", false);
        root._persist("minNotifySeverity", severity, level === "odd" ? "Moat will mention anything odd." : "Moat will only interrupt you when it needs you.", "Set for this session");
    }

    /// Advanced: the panel in the detection's own words. Persisted the same way
    /// as every other setting, which means the same honest caveat -- with the
    /// widget off the bar there is no shell.json entry to write and the notice
    /// says the change is for this session rather than pretending it stuck.
    function setRawDetail(value) {
        if (!service)
            return ;

        var on = value === true;
        service.rawDetail = on;
        root._persist("rawDetail", on, on ? "Showing what the detection recorded, in its own words." : "Back to plain language.", "Raw detail " + (on ? "on" : "off") + " for this session");
    }

    function setShowSuppressed(value) {
        if (!service)
            return ;

        service.showSuppressed = value === true;
        var label = value === true ? "shown" : "hidden";
        root._persist("showSuppressed", value === true, "Events a rule already covers are " + label + ".", "Rule-covered events " + label + " for this session");
    }

    // LEARNING 5. The digest is the daemon's to send; this switch is the user's
    // to turn off. Two writes, because they answer different questions: the bar
    // widget entry is what the panel reads back, and `moatctl set digest` is what
    // actually stops the notification being scheduled.
    function setWeeklyDigest(value) {
        if (!service)
            return ;

        var on = value === true;
        service.weeklyDigest = on;
        service.setDigest(on);
        root._persist("weeklyDigest", on, on ? "A note every Monday." : "No weekly note.", "Weekly note " + (on ? "on" : "off") + " for this session");
    }

    /// The incident an ALERT id belongs to.
    ///
    /// A notification, a `moatctl` id pasted by hand and the `open({"alert":...})`
    /// payload all name one alert, and an incident carries several: repeats under
    /// (rule, program), and — since chains — several different detections that
    /// share a process tree. Matching only `incident.id` (the newest member, the
    /// one actions are aimed at) meant a toast about the FIRST step of a sequence
    /// opened nothing at all, which is precisely the user 3a is written for.
    /// Close an incident: ack EVERY member, not just the one the card names.
    ///
    /// A card is a group of alerts -- same rule, same program -- and its `id` is
    /// the newest member, because that is the one an action names. Acking only
    /// that left the older members unanswered, so the incident stayed on the
    /// badge and the button looked broken: it reported success and nothing moved.
    /// Two toggles of the same rule minutes apart is all it took.
    function ackIncident(id) {
        if (!root.service)
            return ;

        var inc = root.incidentById(id);
        var members = inc && inc.alerts ? inc.alerts : [];
        if (members.length === 0) {
            root.service.ack(id);
            return ;
        }
        // One request for the whole card. This used to be one `moatctl ack` per
        // member, serialized: a 37-alert card spawned 37 processes and repainted
        // the list 37 times, which pegged a core and made the button feel broken
        // while it was in fact working.
        var pending = [];
        for (var i = 0; i < members.length; i++) {
            if (!members[i].acked)
                pending.push(members[i].id);

        }
        root.service.ackMany(pending);
    }

    function incidentById(id) {
        var wanted = String(id || "");
        if (!wanted)
            return null;

        var list = root.service ? root.service.allIncidents : root.incidents;
        for (var i = 0; i < list.length; i++) {
            if (list[i].id === wanted)
                return list[i];

        }
        for (var j = 0; j < list.length; j++) {
            var members = list[j].alerts || [];
            for (var k = 0; k < members.length; k++) {
                if (members[k] && members[k].id === wanted)
                    return list[j];

            }
        }
        return null;
    }

    /// The live incident for a key, re-resolved on every rebuild so an opened
    /// History page keeps counting rather than freezing at the moment it opened.
    function incidentByKey(key) {
        var wanted = String(key || "");
        if (!wanted)
            return null;

        var list = root.service ? root.service.allIncidents : root.incidents;
        for (var i = 0; i < list.length; i++) {
            if (list[i].key === wanted)
                return list[i];

        }
        return null;
    }

    onOpenedChanged: {
        if (!opened)
            return ;

        if (!root.selectedId && root.queue.length > 0)
            root.selectAlert(root.queue[0].id);

    }

    // The redesign's palette, derived from the user's theme rather than copied
    // from the handoff's fixed hex (docs/design/PLAN.md). Passed down like
    // `service`; the plugin has no qmldir and therefore no singletons.
    Tokens {
        id: moatTokens

        base: Color.popups.background
        ink: Color.popups.text
        themeAccent: Color.accent
        themeUrgent: Color.urgent
        family: Style.font.family
        scale: Style.space(1)
        rounded: Style.cornerRadius > 0
        // The design's vertical rhythm is measured against its 860px page. A
        // toplevel takes whatever slot the compositor's layout gives it, and in a
        // half-height tile the full rhythm spends the window on gaps. Keyed off the
        // window rather than a screen size, so the same panel tightens when it is
        // tiled and relaxes the moment it is floated or resized bigger -- a user on
        // a large monitor never pays for the small case.
        compact: window.height > 0 && window.height < Style.space(780)
    }

    Connections {
        // A read, not an action. "Quarantine-list done." is the daemon's own
        // vocabulary reporting that a list refreshed, which is neither news nor
        // English.
        // setWeeklyDigest already wrote the notice, and it says more than this
        // would (whether the setting was persisted). Leave it alone.

        function onActionFinished(command, ok, message) {
            if (!ok) {
                root.notice = "Failed: " + command + (message ? " — " + message : "");
            } else if (command === "ignore") {
                // 2g's `u` and 1c's promise that a rule can be taken back. The daemon
                // addresses a rule by (fragment, index) and only knows those AFTER the
                // reload the action queue kicks off, so what is remembered here is what
                // the rule was ABOUT -- and the undo looks it up when it is asked for.
                root.undoable = {
                    "command": "ignore",
                    "rule": root._lastIgnoreRule,
                    "exe": root._lastIgnoreExe
                };
                root.notice = "Rule written. Press u to take it back.";
            } else if (command === "unignore") {
                root.undoable = null;
                root.notice = "Rule removed. Its detection starts asking again.";
            } else if (command === "quarantine") {
                root.undoable = {
                    "command": "quarantine",
                    "id": root._lastActionId
                };
                root.notice = "File held. Press u to put it back.";
            } else if (command === "kill") {
                // Deliberately NOT undoable, and it says so: the process is gone, and
                // an Undo that silently did nothing would be worse than no Undo.
                root.undoable = null;
                root.notice = "Stopped. Moat does not restart things — re-run it yourself if that was wrong.";
            } else if (command === "quarantine-restore") {
                root.undoable = null;
                root.notice = "Put back where it came from.";
            } else if (command === "baseline-accept")
                root.notice = "Moat will stop asking about that one.";
            else if (command === "baseline-dismiss")
                root.notice = "Left alone. It will ask again if it keeps happening.";
            else if (command === "baseline-relearn")
                root.notice = "Learning again from now.";
            else if (command === "mode")
                root.notice = root.enforcing ? "Moat will stop things now. It shows you what it stopped, afterwards." : "Moat is back to telling you and not stopping anything.";
            else if (command === "quarantine-list")
                return ;
            else if (command === "digest")
                return ;
            else
                root.notice = command.charAt(0).toUpperCase() + command.slice(1) + " done.";
            noticeTimer.restart();
        }

        target: root.service
        enabled: !!root.service
    }

    Timer {
        id: noticeTimer

        interval: 12000
        onTriggered: root.notice = ""
    }

    IpcHandler {
        function open(payloadJson: string) : string {
            root.open(payloadJson);
            return "ok";
        }

        function close() : string {
            root.close();
            return "ok";
        }

        function toggle() : string {
            root.toggle();
            return "ok";
        }

        function state() : string {
            return root.opened ? "open" : "closed";
        }

        function refresh() : string {
            if (root.service)
                root.service.refresh();

            return "ok";
        }

        function ping() : string {
            return "ok";
        }

        target: "moat"
    }

    FloatingWindow {
        id: window

        // Not visible at load. The manifest marks this panel keepLoaded, so the
        // shell mounts it at startup and would otherwise put a Moat window on the
        // user's screen before anything asked for one. FloatingWindow defaults to
        // visible; this is the only thing stopping that.
        visible: false
        // The title is the window's identity to the compositor, and therefore the
        // handle every Hyprland rule and every `focuswindow` dispatch keys off. It
        // is deliberately a bare, stable noun; see shell/README.md for the rules.
        title: "Moat"
        // Opaque, unlike the layer-shell card this replaces: see Tokens.pageOpaque.
        // A user who wants the theme's translucency back asks the compositor for it
        // (`opacity` window rule), which is where a window's transparency belongs.
        color: moatTokens.pageOpaque
        // The redesign is drawn at 1400x860 with 44px body padding (docs/design/
        // PLAN.md). Those are the window's PREFERRED size now rather than its
        // measured one: the compositor places and sizes a toplevel, the user can
        // drag it to whatever they want, and everything inside is anchored so it
        // follows. Style.space() keeps the request in the shell's scaled units.
        implicitWidth: Style.space(1400)
        implicitHeight: Style.space(860)
        // Below this the three-column footer strip and the scope chips start
        // colliding rather than eliding.
        minimumSize: Qt.size(Style.space(820), Style.space(520))
        // The compositor owns closing now. The titlebar button, `hyprctl dispatch
        // killactive` and a workspace being torn down all arrive as visible going
        // false without root.close() ever running, so the shell has to be told or
        // its openPanelIds map keeps this plugin marked open forever and the next
        // toggle hides an already-closed window instead of summoning it.
        onVisibleChanged: {
            if (!visible && !root.closingFromHost)
                root.requestClose();

        }

        FocusScope {
            id: content

            // Keyboard focus arrives from the compositor now, not from a layer-shell
            // keyboardFocus mode, and it arrives at the WINDOW -- something inside
            // still has to hold it. Qt restores the last focus item when a window is
            // re-activated, but nothing has focus the first time a window maps, and
            // an unfocused key catcher means Escape does not close.
            readonly property bool windowActive: Window.active

            anchors.fill: parent
            focus: true
            onWindowActiveChanged: {
                if (windowActive)
                    keys.forceActiveFocus();

            }

            PanelKeyCatcher {
                // Header and body are anchored rather than stacked in a Column so the
                // body takes exactly the leftover height. A Column would need the body
                // to subtract every sibling's height by hand, which silently goes wrong
                // the moment a row wraps.
                // ------------------------------------------------------------ header

                id: keys

                anchors.fill: parent
                focus: true
                onCloseRequested: root.dismiss()
                onMoveRequested: function(dx, dy) {
                    if (dy !== 0)
                        root.moveSelection(dy);

                }
                onActivateRequested: root.activate()
                onTextKey: function(text) {
                    root.handleTextKey(text);
                }

                // 54px, one hairline, and nothing else. The status strip that used to
                // sit under it -- "mode monitor · tetragon running · policies 32 ·
                // feeds never · sandbox off · unacked 24" -- is gone: six pieces of
                // daemon jargon and a backlog counter, above the thing the user came to
                // read. The two facts that change what Moat DOES are now sentences in
                // the verdict sub-line, the machine counters are a footer strip in the
                // dimmest colour there is, and `unacked` was deleted outright.
                Item {
                    id: headerBlock

                    anchors.top: parent.top
                    anchors.left: parent.left
                    anchors.right: parent.right
                    height: moatTokens.headerHeight

                    // On a real incident the header itself tints. This is the only
                    // chrome-level alarm signal in the product.
                    Rectangle {
                        anchors.fill: parent
                        color: root.needsYouCount > 0 ? moatTokens.alarmTint(0.06) : "transparent"
                    }

                    Row {
                        id: titleRow

                        anchors.left: parent.left
                        anchors.leftMargin: moatTokens.s(22)
                        anchors.verticalCenter: parent.verticalCenter
                        spacing: moatTokens.s(10)

                        // The mark, and it carries the panel's state the same way the
                        // bar does: the M in the heading colour, the water in the
                        // verdict tone. Same rule in both places, so the two cannot
                        // disagree about what colour "something needs you" is -- which
                        // they did, when each switched on the state string separately.
                        MoatMark {
                            anchors.verticalCenter: parent.verticalCenter
                            implicitWidth: moatTokens.s(20)
                            implicitHeight: moatTokens.s(20)
                            markColor: moatTokens.primary
                            waterColor: {
                                if (!root.service)
                                    return moatTokens.fainter;

                                switch (root.service.barState.tone) {
                                case "alarm":
                                    return moatTokens.alarm;
                                case "accent":
                                    return moatTokens.accent;
                                default:
                                    return moatTokens.calm;
                                }
                            }
                        }

                        Text {
                            anchors.verticalCenter: parent.verticalCenter
                            text: "Moat"
                            color: moatTokens.primary
                            font.family: moatTokens.family
                            font.pixelSize: moatTokens.fTitle
                            font.weight: Font.Medium
                        }

                    }

                    Row {
                        id: tabRow

                        anchors.right: parent.right
                        anchors.rightMargin: moatTokens.s(22)
                        anchors.verticalCenter: parent.verticalCenter
                        spacing: moatTokens.s(6)

                        Repeater {
                            model: [{
                                "tab": "now",
                                "label": "Now"
                            }, {
                                "tab": "history",
                                "label": "History"
                            }, {
                                "tab": "rules",
                                "label": "Rules"
                            }]

                            delegate: Rectangle {
                                required property var modelData

                                anchors.verticalCenter: parent.verticalCenter
                                width: tabLabel.implicitWidth + badge.width + moatTokens.s(26)
                                height: tabLabel.implicitHeight + moatTokens.s(12)
                                radius: moatTokens.rTab
                                color: root.tab === modelData.tab ? moatTokens.accentTint(0.11) : (tabMouse.containsMouse ? moatTokens.hair(0.04) : "transparent")

                                Text {
                                    id: tabLabel

                                    anchors.verticalCenter: parent.verticalCenter
                                    x: moatTokens.s(13)
                                    text: modelData.label
                                    color: root.tab === modelData.tab ? moatTokens.accent : moatTokens.dimmer
                                    font.family: moatTokens.family
                                    font.pixelSize: moatTokens.fSecondary
                                }

                                // The badge appears ONLY on Now and counts only incidents that
                                // need a decision -- never events. The old "Alerts 24" counted
                                // every unacked record, which is a backlog the user never asked
                                // for rather than a number of decisions.
                                Rectangle {
                                    id: badge

                                    anchors.verticalCenter: parent.verticalCenter
                                    anchors.left: tabLabel.right
                                    anchors.leftMargin: visible ? moatTokens.s(6) : 0
                                    visible: modelData.tab === "now" && root.needsYouCount > 0
                                    width: visible ? badgeLabel.implicitWidth + moatTokens.s(10) : 0
                                    height: badgeLabel.implicitHeight + moatTokens.s(4)
                                    radius: moatTokens.rBadge
                                    color: moatTokens.alarm

                                    Text {
                                        id: badgeLabel

                                        anchors.centerIn: parent
                                        text: String(root.needsYouCount)
                                        color: moatTokens.alarmLabel
                                        font.family: moatTokens.family
                                        font.pixelSize: moatTokens.fMeta
                                        font.bold: true
                                    }

                                }

                                MouseArea {
                                    id: tabMouse

                                    anchors.fill: parent
                                    hoverEnabled: true
                                    cursorShape: Qt.PointingHandCursor
                                    onClicked: root.selectTab(modelData.tab)
                                }

                            }

                        }

                        // Settings is a gear, not a tab: it is not a place you go while
                        // working.
                        PanelActionButton {
                            anchors.verticalCenter: parent.verticalCenter
                            iconText: "󰒓"
                            tooltipText: "Settings"
                            foreground: root.tab === "settings" ? moatTokens.accent : moatTokens.fainter
                            onClicked: root.selectTab("settings")
                        }

                        PanelActionButton {
                            anchors.verticalCenter: parent.verticalCenter
                            iconText: "󰅖"
                            tooltipText: "Close (Esc)"
                            foreground: moatTokens.fainter
                            onClicked: root.requestClose()
                        }

                    }

                    Rectangle {
                        anchors.bottom: parent.bottom
                        width: parent.width
                        height: 1
                        color: moatTokens.hairlineChrome
                    }

                }

                // The result of the last thing the user asked for. One line, under the
                // header, gone after twelve seconds.
                Rectangle {
                    id: noticeBlock

                    anchors.top: headerBlock.bottom
                    anchors.left: parent.left
                    anchors.right: parent.right
                    visible: root.notice !== ""
                    height: visible ? noticeText.implicitHeight + moatTokens.s(20) : 0
                    color: moatTokens.chip

                    Text {
                        id: noticeText

                        anchors.verticalCenter: parent.verticalCenter
                        x: moatTokens.bodyPadX
                        width: parent.width - moatTokens.bodyPadX * 2
                        text: root.notice
                        color: root.notice.indexOf("Failed") === 0 ? moatTokens.alarm : moatTokens.muted
                        font.family: moatTokens.family
                        font.pixelSize: moatTokens.fSecondary
                        wrapMode: Text.WrapAnywhere
                        maximumLineCount: 4
                        elide: Text.ElideRight
                        // The daemon's own error strings arrive here, and they carry paths
                        // and arguments out of the process that raised the alert.
                        textFormat: Text.PlainText
                    }

                }

                // -------------------------------------------------------------- body
                Item {
                    // What went wrong with the last thing the user asked for.

                    id: bodyArea

                    anchors.top: noticeBlock.bottom
                    anchors.bottom: parent.bottom
                    anchors.left: parent.left
                    anchors.right: parent.right

                    // `lastError` was set on every failed action and rendered nowhere, so
                    // a refused command looked like a toggle that flipped back on its
                    // own. That matters most for the one refusal that is deliberate:
                    // arming a rule needs root, and "nothing happened" is the worst way
                    // to say so.
                    Rectangle {
                        id: errorStrip

                        anchors.top: parent.top
                        anchors.left: parent.left
                        anchors.right: parent.right
                        anchors.margins: moatTokens.bodyPadX
                        height: visible ? errorText.implicitHeight + moatTokens.s(18) : 0
                        visible: !!root.service && root.service.lastError !== ""
                        z: 5
                        radius: moatTokens.rChipSmall
                        color: moatTokens.hair(0.06)
                        border.width: 1
                        border.color: moatTokens.alarm

                        Text {
                            id: errorText

                            anchors.fill: parent
                            anchors.margins: moatTokens.s(9)
                            text: root.service ? root.service.lastError : ""
                            color: moatTokens.body
                            font.family: moatTokens.family
                            font.pixelSize: moatTokens.fSecondary
                            wrapMode: Text.WordWrap
                            textFormat: Text.PlainText
                        }

                        MouseArea {
                            anchors.fill: parent
                            cursorShape: Qt.PointingHandCursor
                            onClicked: {
                                if (root.service)
                                    root.service.lastError = "";

                            }
                        }

                    }

                    // The setup screen wins over everything: an empty alert list with no
                    // group membership would read as "all clear", which is the one thing
                    // a security panel must never say while it is blind.
                    SetupView {
                        anchors.fill: parent
                        anchors.margins: moatTokens.bodyPadX
                        visible: root.page === "setup"
                        service: root.service
                        foreground: moatTokens.primary
                        needsPackage: !!root.service && !root.service.available
                        needsGroup: !!root.service && !root.service.groupOk
                        onRecheckRequested: {
                            if (root.service)
                                root.service.probe();

                        }
                    }

                    // 3f. Before there is anything to say, say what Moat watches and what
                    // it never does.
                    FirstRunView {
                        anchors.fill: parent
                        visible: root.page === "firstRun"
                        tokens: moatTokens
                        service: root.service
                        status: root.service ? root.service.status : null
                        onDismissed: root.firstRunSeen = true
                    }

                    // Now is a single surface, not a list/detail split (1b): when
                    // something needs a decision the incident IS the page. The split is
                    // what forced a severity pill onto every row to say where to look.
                    NowView {
                        id: nowView

                        anchors.fill: parent
                        visible: root.page === "now"
                        service: root.service
                        tokens: moatTokens
                        incidents: root.incidents
                        status: root.service ? root.service.status : null
                        onOpenIncident: function(id) {
                            root.selectAlert(id);
                            root.selectTab("history");
                        }
                        onRequestWasMe: function(id, scope) {
                            root.requestWasMe(id, scope);
                        }
                        onRequestClose: function(id) {
                            root.ackIncident(id);
                        }
                        onRequestStop: function(id) {
                            root.requestKill(id);
                        }
                        onRequestAsk: function(id) {
                            root.openInAgent(id);
                        }
                        onRequestCopyBundle: function(id) {
                            if (root.service)
                                root.service.copyBundlePath(id);

                        }
                        onRequestSaveBundle: function(id) {
                            if (root.service)
                                root.service.saveBundle(id);

                        }
                        onRequestCopyBundleText: function(id) {
                            if (root.service)
                                root.service.copyBundleText(id);

                        }
                        onRequestAllowChain: function(id) {
                            root.requestAckChain(id);
                        }
                        onRequestEnforce: root.setMode("enforce")
                        // One rule, not the whole daemon: the button names the rule that
                        // killed the program the user is looking at, so that is what it
                        // disarms. Needs root, so this raises the polkit prompt.
                        onRequestMonitor: function(rule) {
                            if (!root.service)
                                return ;

                            if (rule)
                                root.service.setRuleMode(rule, "monitor");
                            else
                                root.setMode("monitor");
                        }
                        onOpenRules: root.selectTab("rules")
                    }

                    // History: day groups, 3px ticks, no severity pills anywhere (1d).
                    HistoryView {
                        id: historyView

                        anchors.fill: parent
                        visible: root.page === "history"
                        service: root.service
                        tokens: moatTokens
                        incidents: root.incidents
                        coveredIncidents: root.service ? root.service.allIncidents : []
                        selectedId: root.selectedId
                        onOpenIncident: function(id) {
                            root.selectAlert(id);
                            var opened = root.incidentById(id);
                            root.historyKey = opened ? String(opened.key) : "";
                        }
                    }

                    // Opening a row from History makes that incident the page, exactly
                    // the way Now does. The list/detail split is what made the old panel
                    // need a severity pill on every row to say where to look, so it is
                    // not reintroduced here.
                    MoatScroll {
                        anchors.fill: parent
                        visible: root.page === "historyDetail"
                        contentHeight: detailColumn.implicitHeight

                        Column {
                            id: detailColumn

                            x: moatTokens.bodyPadX
                            width: parent.width - moatTokens.bodyPadX * 2
                            topPadding: moatTokens.bodyPadTop
                            bottomPadding: moatTokens.bodyPadBottom
                            spacing: moatTokens.v(22)

                            Button {
                                text: "Back to History"
                                foreground: moatTokens.dimmer
                                fontSize: moatTokens.fSecondary
                                onClicked: root.historyKey = ""
                            }

                            IncidentCard {
                                id: historyDetail

                                width: parent.width
                                tokens: moatTokens
                                service: root.service
                                incident: root.historyIncident
                                onWasMe: function(id, scope) {
                                    root.requestWasMe(id, scope);
                                }
                                onCloseIt: function(id) {
                                    root.ackIncident(id);
                                }
                                onStopIt: function(id) {
                                    root.requestKill(id);
                                }
                                onAskMoat: function(id) {
                                    root.openInAgent(id);
                                }
                                onCopyBundle: function(id) {
                                    if (root.service)
                                        root.service.copyBundlePath(id);

                                }
                                onSaveBundle: function(id) {
                                    if (root.service)
                                        root.service.saveBundle(id);

                                }
                                onCopyBundleText: function(id) {
                                    if (root.service)
                                        root.service.copyBundleText(id);

                                }
                                onAllowChain: function(id) {
                                    root.requestAckChain(id);
                                }
                            }

                        }

                    }

                    // 1e + 2e + 2c: what has been silenced, what is considered normal,
                    // and what Moat is holding.
                    RulesView {
                        anchors.fill: parent
                        visible: root.page === "rules"
                        service: root.service
                        tokens: moatTokens
                        incidents: root.incidents
                        onRemoveRequested: function(index, file) {
                            root.requestUnignore(index, file);
                        }
                        onRestoreRequested: function(id) {
                            root.requestRestoreQuarantined(id);
                        }
                        onAcceptRequested: function(id) {
                            root.requestAcceptProposal(id);
                        }
                        onDismissRequested: function(id) {
                            root.requestDismissProposal(id);
                        }
                    }

                    // 1f: the daemon's options, rewritten as questions.
                    SettingsView {
                        anchors.fill: parent
                        visible: root.page === "settings"
                        service: root.service
                        tokens: moatTokens
                        onMinNotifySeverityRequested: function(value) {
                            root.setMinNotifySeverity(value);
                        }
                        onNotifyCooldownRequested: function(minutes) {
                            root.setNotifyCooldown(minutes);
                        }
                        onNotifyLevelRequested: function(level) {
                            root.setNotifyLevel(level);
                        }
                        onShowSuppressedRequested: function(value) {
                            root.setShowSuppressed(value);
                        }
                        onRawDetailRequested: function(value) {
                            root.setRawDetail(value);
                        }
                        onWeeklyDigestRequested: function(value) {
                            root.setWeeklyDigest(value);
                        }
                        onRelearnRequested: root.requestRelearn()
                    }

                }

            }

            // Sits above the content, inside the window. PanelKeyCatcher's signals are
            // routed to it by root.dismiss()/root.activate()/root.moveSelection while
            // it is open, so it never needs a second raw key handler.
            ConfirmDialog {
                id: confirm

                anchors.fill: parent
                background: Color.popups.background
                foreground: Color.popups.text
                cancelText: "Cancel"
                onCanceled: {
                    confirm.opened = false;
                    root._pendingCommand = "";
                }
                onConfirmed: root._runPending()
            }

        }

    }

}
