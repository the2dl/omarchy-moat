// Settings (docs/design/README.md 1f).
// **Every row is a question, and the control is its answer.** The old tab had
// six headed sections in the vocabulary of the daemon -- MODE, SANDBOX SHIMS,
// NOTIFY AT, NOTIFY COOLDOWN, SHOW SUPPRESSED, WEEKLY DIGEST -- each with a
// paragraph the user had to decode before they could touch the switch. Rewritten
// as questions, two of them merge (notify-at and notify-cooldown answer one
// question, and the cooldown is a fact under the answer rather than a control),
// and one of them turns out to be an implementation detail and moves to
// Advanced.

import "MoatCopy.js" as Copy
import "MoatModel.js" as Model
import QtQuick
import qs.Commons
import qs.Ui

// One line of consequence per row. Nothing here is a bare switch, because every
// one of these changes what the sensor does or what the user is told.
Item {
    id: root

    property var service: null
    property var tokens: null
    readonly property var t: root.tokens
    readonly property var status: service ? service.status : null
    readonly property var baselineState: service ? service.baselineState : null
    readonly property bool enforcing: !!root.status && root.status.mode === "enforce"
    property bool advancedOpen: false
    /// Which of 1f's three answers the current settings add up to.
    readonly property string notifyLevel: {
        if (!root.service)
            return "needsMe";

        if (root.service.notifyMuted)
            return "never";

        return root.service.minNotifySeverity === "medium" || root.service.minNotifySeverity === "low" ? "odd" : "needsMe";
    }

    signal minNotifySeverityRequested(string value)
    signal notifyCooldownRequested(int minutes)
    signal notifyMutedRequested(bool value)
    signal notifyLevelRequested(string level)
    signal showSuppressedRequested(bool value)
    signal rawDetailRequested(bool value)
    signal weeklyDigestRequested(bool value)
    signal relearnRequested()

    MoatScroll {
        anchors.fill: parent
        contentHeight: body.implicitHeight

        Column {
            // -------------------------------- when should Moat interrupt? (row 2)
            // ------------------------------------------- contain a sequence (row 2b)
            // ------------------------------------ what containment does (row 2b)
            // Deliberately its own row, directly under the containment toggle and
            // only meaningful when that is on. `contain` answers "may moatd act on
            // its own judgement"; this answers "how far". They were one setting in
            // the first draft and that was wrong: a ten-minute network cut naming
            // one address is recoverable by waiting, and SIGKILL on a process tree
            // is not recoverable at all.
            // ---------------------------------------------------------- Advanced

            id: body

            x: root.t ? root.t.bodyPadX : 0
            width: parent.width - (root.t ? root.t.bodyPadX * 2 : 0)
            topPadding: root.t ? root.t.bodyPadTop : 0
            bottomPadding: root.t ? root.t.bodyPadBottom : 0
            spacing: 0

            // ------------------------------------- should Moat stop things? (row 1)
            SettingsRow {
                width: parent.width
                tokens: root.t
                question: "Should Moat stop things, or just tell you?"
                help: "Stopping happens in the kernel, before this panel sees it — a wrong guess kills a real program mid-write. Stay on telling you until Rules has been quiet for a week."
                helpLoud: root.enforcing

                Row {
                    anchors.right: parent.right
                    spacing: root.t ? root.t.s(9) : 6

                    MoatChip {
                        tokens: root.t
                        text: "Just tell me"
                        selected: !root.enforcing
                        onClicked: {
                            if (root.service) {
                                root.service.setMode("monitor");
                            }
                        }
                    }

                    MoatChip {
                        tokens: root.t
                        text: "Stop things"
                        selected: root.enforcing
                        // Deliberately the duller chip even when it is the honest answer:
                        // it is the option whose worst case the user cannot see from here.
                        dim: !root.enforcing
                        onClicked: {
                            if (root.service) {
                                root.service.setMode("enforce");
                            }
                        }
                    }

                }

            }

            // This row absorbs the old NOTIFY AT and NOTIFY COOLDOWN sections. The
            // cooldown is not a question anybody has; it is a fact about what the
            // answer above already means, so it sits under the chips as one line.
            SettingsRow {
                width: parent.width
                tokens: root.t
                question: "When should Moat interrupt you?"
                help: "Everything still lands in the panel either way. Repeats of the same thing are counted up and arrive as one notification, so a noisy detection costs you two interruptions instead of two hundred."

                Column {
                    anchors.right: parent.right
                    spacing: root.t ? root.t.s(7) : 4

                    Row {
                        id: notifyChips

                        spacing: root.t ? root.t.s(9) : 6

                        MoatChip {
                            tokens: root.t
                            text: "Anything odd"
                            selected: root.notifyLevel === "odd"
                            onClicked: root.notifyLevelRequested("odd")
                        }

                        MoatChip {
                            tokens: root.t
                            text: "Only if it needs me"
                            selected: root.notifyLevel === "needsMe"
                            onClicked: root.notifyLevelRequested("needsMe")
                        }

                        MoatChip {
                            tokens: root.t
                            text: "Never"
                            selected: root.notifyLevel === "never"
                            onClicked: root.notifyLevelRequested("never")
                        }

                    }

                    Text {
                        width: notifyChips.width
                        horizontalAlignment: Text.AlignRight
                        visible: root.notifyLevel !== "never"
                        text: "at most one every " + (root.service ? root.service.notifyCooldownMinutes : 10) + " minutes"
                        color: root.t ? root.t.fainter : "grey"
                        font.family: root.t ? root.t.family : "monospace"
                        font.pixelSize: root.t ? root.t.fMeta : 11
                        textFormat: Text.PlainText
                    }

                }

            }

            // The only switch here that lets moat ACT on its own judgement rather
            // than on a rule the user armed, so it says exactly what it will do and
            // exactly how long for. It is a switch and not a config file because
            // every other switch on this daemon is: turning on a security feature
            // must not require root, an editor and a service restart.
            SettingsRow {
                width: parent.width
                tokens: root.t
                question: "Cut off a sequence Moat is sure about"
                help: "When several things line up into one high-severity sequence and it reaches out " + "somewhere this machine has never been, refuse that one program's connections to " + "that one address for 10 minutes. Nothing is killed and nothing else is affected."

                Row {
                    anchors.right: parent.right
                    spacing: root.t ? root.t.s(10) : 6

                    Text {
                        anchors.verticalCenter: parent.verticalCenter
                        text: {
                            if (!root.service || !root.service.containEnabled())
                                return "off";

                            var n = root.service.containments().length;
                            return n === 0 ? "on" : "on  ·  " + n + " active";
                        }
                        color: root.t ? root.t.faint : "grey"
                        font.family: root.t ? root.t.family : "monospace"
                        font.pixelSize: root.t ? root.t.fSecondary : 12
                        textFormat: Text.PlainText
                    }

                    ToggleSwitch {
                        anchors.verticalCenter: parent.verticalCenter
                        checked: !!root.service && root.service.containEnabled()
                        busy: !!root.service && root.service.busy
                        foreground: root.t ? root.t.secondary : "white"
                        accent: root.t ? root.t.accent : "orange"
                        trackHeight: root.t ? root.t.s(23) : 18
                        onToggled: {
                            if (root.service) {
                                root.service.setContain(!root.service.containEnabled());
                            }
                        }
                    }

                }

            }

            // `kill` is the only control in this product that destroys work a user
            // cannot get back, so it is the dull chip, it says what it will do in
            // the present tense, and the row tells you the one thing that earns it:
            // a week of `log` you have actually read.
            SettingsRow {
                width: parent.width
                tokens: root.t
                visible: !!root.service && root.service.containEnabled()
                question: "And what should it do to the programs involved?"
                help: {
                    var k = root.service ? root.service.containKill() : "log";
                    if (k === "kill")
                        return "Moat ends the process tree a high-severity sequence implicates, keeping the " + "program you started and killing what it spawned. Work in those processes is " + "lost with no prompt and no undo.";

                    if (k === "off")
                        return "Moat cuts the network and leaves every process running.";

                    return "Moat works out which processes it would end and writes that to the journal " + "without ending anything: journalctl -u moatd | grep 'WOULD HAVE'. A week of " + "those with nothing wrong in them is the argument for the next step.";
                }
                helpLoud: !!root.service && root.service.containKill() === "kill"

                Row {
                    anchors.right: parent.right
                    spacing: root.t ? root.t.s(9) : 6

                    MoatChip {
                        tokens: root.t
                        text: "Nothing"
                        selected: !!root.service && root.service.containKill() === "off"
                        onClicked: {
                            if (root.service) {
                                root.service.setKill("off");
                            }
                        }
                    }

                    MoatChip {
                        tokens: root.t
                        text: "Write down what it would end"
                        selected: !!root.service && root.service.containKill() === "log"
                        onClicked: {
                            if (root.service) {
                                root.service.setKill("log");
                            }
                        }
                    }

                    MoatChip {
                        tokens: root.t
                        text: "End them"
                        selected: !!root.service && root.service.containKill() === "kill"
                        // Dull unless it is already the answer, like "Stop things" above:
                        // the option whose worst case cannot be seen from this screen
                        // should never be the brightest thing on it.
                        dim: !(!!root.service && root.service.containKill() === "kill")
                        onClicked: {
                            if (root.service) {
                                root.service.setKill("kill");
                            }
                        }
                    }

                }

            }

            // ----------------------------------------------- hide your keys (row 3)
            SettingsRow {
                width: parent.width
                tokens: root.t
                question: "Hide your keys from package installs"
                help: "Runs npm, pip, cargo and makepkg in a box where ~/.ssh and your tokens do not exist. Takes effect in new shells."

                Row {
                    anchors.right: parent.right
                    spacing: root.t ? root.t.s(10) : 6

                    Text {
                        anchors.verticalCenter: parent.verticalCenter
                        text: !!root.status && root.status.sandbox ? "on" : "off"
                        color: root.t ? root.t.faint : "grey"
                        font.family: root.t ? root.t.family : "monospace"
                        font.pixelSize: root.t ? root.t.fSecondary : 12
                    }

                    ToggleSwitch {
                        anchors.verticalCenter: parent.verticalCenter
                        checked: !!root.status && root.status.sandbox
                        busy: !!root.service && root.service.busy
                        foreground: root.t ? root.t.secondary : "white"
                        accent: root.t ? root.t.accent : "orange"
                        trackHeight: root.t ? root.t.s(23) : 18
                        onToggled: {
                            if (root.service) {
                                root.service.setSandbox(!root.service.status.sandbox);
                            }
                        }
                    }

                }

            }

            // ------------------------------------------------- the weekly note (row 4)
            SettingsRow {
                width: parent.width
                tokens: root.t
                question: "A weekly note on what happened"
                help: "The only thing Moat sends on a schedule."

                Row {
                    anchors.right: parent.right
                    spacing: root.t ? root.t.s(10) : 6

                    Text {
                        anchors.verticalCenter: parent.verticalCenter
                        text: !!root.service && root.service.weeklyDigest ? "on, Mondays" : "off"
                        color: root.t ? root.t.faint : "grey"
                        font.family: root.t ? root.t.family : "monospace"
                        font.pixelSize: root.t ? root.t.fSecondary : 12
                    }

                    ToggleSwitch {
                        anchors.verticalCenter: parent.verticalCenter
                        checked: !!root.service && root.service.weeklyDigest
                        busy: !!root.service && root.service.busy
                        foreground: root.t ? root.t.secondary : "white"
                        accent: root.t ? root.t.accent : "orange"
                        trackHeight: root.t ? root.t.s(23) : 18
                        onToggled: {
                            if (root.service) {
                                root.weeklyDigestRequested(!root.service.weeklyDigest);
                            }
                        }
                    }

                }

            }

            // Collapsed, and the header lists what is inside so nobody has to open it
            // to find out. Everything in here is either a knob the question above
            // already answers more usefully, or an implementation detail that turned
            // out not to be a decision at all.
            Item {
                width: parent.width
                implicitHeight: (root.t ? root.t.s(24) * 2 : 24) + advancedHeader.implicitHeight

                Rectangle {
                    anchors.top: parent.top
                    width: parent.width
                    height: 1
                    color: root.t ? root.t.hairlineRow : "transparent"
                }

                Row {
                    id: advancedHeader

                    anchors.verticalCenter: parent.verticalCenter
                    spacing: root.t ? root.t.s(10) : 6

                    Text {
                        anchors.verticalCenter: parent.verticalCenter
                        text: root.advancedOpen ? "⌄" : "›"
                        color: root.t ? root.t.ghost : "grey"
                        font.family: root.t ? root.t.family : "monospace"
                        font.pixelSize: root.t ? root.t.fBody : 13
                    }

                    Text {
                        anchors.verticalCenter: parent.verticalCenter
                        text: "Advanced"
                        color: root.t ? root.t.body : "white"
                        font.family: root.t ? root.t.family : "monospace"
                        font.pixelSize: root.t ? root.t.fBody : 13
                    }

                    Text {
                        anchors.verticalCenter: parent.verticalCenter
                        visible: !root.advancedOpen
                        text: "raw detection detail · show rule-covered events · notification threshold · cooldown window · the keyboard · relearn"
                        color: root.t ? root.t.ghost : "grey"
                        font.family: root.t ? root.t.family : "monospace"
                        font.pixelSize: root.t ? root.t.fMeta : 11
                        textFormat: Text.PlainText
                    }

                }

                MouseArea {
                    anchors.fill: parent
                    cursorShape: Qt.PointingHandCursor
                    onClicked: root.advancedOpen = !root.advancedOpen
                }

            }

            Column {
                width: parent.width
                visible: root.advancedOpen
                spacing: 0

                // The one row on this screen that changes nothing about what Moat does.
                // It is a reading choice: the plain-language voice is right for almost
                // everybody almost always, and wrong for the person who is about to go
                // and look at the process themselves.
                SettingsRow {
                    width: parent.width
                    tokens: root.t
                    question: "Show raw detection detail?"
                    help: "Prints what the sensor recorded instead of what Moat made of it: the detection's own title, its rule id and severity beside every incident, the process, pid, args, working directory and parent chain as plain fields, and the evidence already open. Nothing about what is watched, flagged or notified changes."

                    Row {
                        anchors.right: parent.right
                        spacing: root.t ? root.t.s(10) : 6

                        Text {
                            anchors.verticalCenter: parent.verticalCenter
                            text: !!root.service && root.service.rawDetail ? "raw" : "plain language"
                            color: root.t ? root.t.faint : "grey"
                            font.family: root.t ? root.t.family : "monospace"
                            font.pixelSize: root.t ? root.t.fSecondary : 12
                        }

                        ToggleSwitch {
                            anchors.verticalCenter: parent.verticalCenter
                            checked: !!root.service && root.service.rawDetail
                            foreground: root.t ? root.t.secondary : "white"
                            accent: root.t ? root.t.accent : "orange"
                            trackHeight: root.t ? root.t.s(23) : 18
                            onToggled: {
                                if (root.service) {
                                    root.rawDetailRequested(!root.service.rawDetail);
                                }
                            }
                        }

                    }

                }

                SettingsRow {
                    width: parent.width
                    tokens: root.t
                    question: "Show events a rule already covers"
                    help: "moatd records an alert even when a rule hides it, so History can show it greyed out with the rule that covered it. Off by default; either way it never interrupts you and never counts as a decision."

                    Row {
                        anchors.right: parent.right
                        spacing: root.t ? root.t.s(10) : 6

                        Text {
                            anchors.verticalCenter: parent.verticalCenter
                            text: !!root.service && root.service.showSuppressed ? "shown" : "hidden"
                            color: root.t ? root.t.faint : "grey"
                            font.family: root.t ? root.t.family : "monospace"
                            font.pixelSize: root.t ? root.t.fSecondary : 12
                        }

                        ToggleSwitch {
                            anchors.verticalCenter: parent.verticalCenter
                            checked: !!root.service && root.service.showSuppressed
                            foreground: root.t ? root.t.secondary : "white"
                            accent: root.t ? root.t.accent : "orange"
                            trackHeight: root.t ? root.t.s(23) : 18
                            onToggled: {
                                if (root.service) {
                                    root.showSuppressedRequested(!root.service.showSuppressed);
                                }
                            }
                        }

                    }

                }

                SettingsRow {
                    width: parent.width
                    tokens: root.t
                    question: "Notification threshold, by severity"
                    help: "The exact floor behind the answer above. The noise guard's own alert goes through regardless, because it is the one that tells you a detection just went quiet."

                    Row {
                        anchors.right: parent.right
                        spacing: root.t ? root.t.s(7) : 4

                        Repeater {
                            model: ["low", "medium", "high", "critical"]

                            delegate: MoatChip {
                                required property string modelData

                                tokens: root.t
                                text: modelData
                                selected: !!root.service && root.service.minNotifySeverity === modelData
                                onClicked: root.minNotifySeverityRequested(modelData)
                            }

                        }

                    }

                }

                SettingsRow {
                    width: parent.width
                    tokens: root.t
                    question: "Cooldown window"
                    help: "One notification per detection per window. The rest of a burst is counted and arrives as a single message when the window ends, so something that floods costs two interruptions instead of hundreds. Nothing is dropped."

                    Row {
                        anchors.right: parent.right
                        spacing: root.t ? root.t.s(7) : 4

                        Repeater {
                            model: [1, 5, 10, 30, 60]

                            delegate: MoatChip {
                                required property int modelData

                                tokens: root.t
                                text: modelData + " min"
                                selected: !!root.service && root.service.notifyCooldownMinutes === modelData
                                onClicked: root.notifyCooldownRequested(modelData)
                            }

                        }

                    }

                }

                // 2g. The keys are the same verbs as the buttons, so they are
                // documented next to the settings rather than behind a help overlay
                // nobody opens.
                SettingsRow {
                    width: parent.width
                    tokens: root.t
                    question: "The keyboard"
                    help: "Same verbs as the buttons, and the same things moatctl does."

                    Column {
                        anchors.right: parent.right
                        spacing: root.t ? root.t.s(5) : 3

                        Repeater {
                            model: Copy.KEYS

                            delegate: Row {
                                required property var modelData

                                spacing: root.t ? root.t.s(14) : 8

                                Text {
                                    width: root.t ? root.t.s(60) : 46
                                    text: modelData.key
                                    color: root.t ? root.t.accent : "orange"
                                    font.family: root.t ? root.t.family : "monospace"
                                    font.pixelSize: root.t ? root.t.fSecondary : 12
                                }

                                Text {
                                    text: modelData.what
                                    color: root.t ? root.t.dim : "grey"
                                    font.family: root.t ? root.t.family : "monospace"
                                    font.pixelSize: root.t ? root.t.fSecondary : 12
                                    textFormat: Text.PlainText
                                }

                            }

                        }

                    }

                }

                SettingsRow {
                    width: parent.width
                    tokens: root.t
                    question: "Learn this machine again"
                    help: "Reopens the window in which recurring low-level activity from packaged programs is written down as normal instead of shown. That is what you want after a new toolchain or a new job, and not what you want otherwise."

                    Column {
                        anchors.right: parent.right
                        spacing: root.t ? root.t.s(7) : 4

                        Text {
                            text: {
                                if (!root.service || !root.baselineState)
                                    return "";

                                var bits = [root.service.learningSummary, root.baselineState.learned + " learned"];
                                return bits.join("  ·  ");
                            }
                            color: root.t ? root.t.faint : "grey"
                            font.family: root.t ? root.t.family : "monospace"
                            font.pixelSize: root.t ? root.t.fMeta : 11
                            textFormat: Text.PlainText
                        }

                        MoatChip {
                            tokens: root.t
                            text: "Learn again"
                            dim: true
                            onClicked: root.relearnRequested()
                        }

                    }

                }

                // Where the files are. The last thing anyone needs, and the only place
                // in the panel a path is the answer to the question.
                SettingsRow {
                    width: parent.width
                    tokens: root.t
                    question: "Where things are"
                    help: "Rules are TOML under /etc/moat/allowlist.d — Moat's own writes go to user.toml and baseline.toml, and it never edits the file the package ships. What it recorded is under /var/lib/moat."

                    Column {
                        anchors.right: parent.right
                        spacing: root.t ? root.t.s(4) : 2

                        Repeater {
                            model: [root.service ? root.service.allowlistFile : "/etc/moat/allowlist.d/user.toml", "/var/lib/moat/alerts.jsonl", "/var/lib/moat/incidents", "/var/lib/moat/quarantine"]

                            delegate: Text {
                                required property string modelData

                                text: modelData
                                color: root.t ? root.t.ghost : "grey"
                                font.family: root.t ? root.t.family : "monospace"
                                font.pixelSize: root.t ? root.t.fMeta : 11
                                textFormat: Text.PlainText
                            }

                        }

                    }

                }

            }

        }

    }

}
