// Moat's bar slot (docs/design/README.md 3e).
// **Exactly three states, and they are the verdict line's states.** Quiet: the
// shield, dim, no text -- this is what it looks like all day. Needs you: the
// shield in alarm plus a count of DECISIONS. Sensor gap: the shield in accent
// plus the word "gap".
// What was here before: five colours (grey / green / amber / red, plus a badge
// that took the same colour) and a count of unacked high+critical RECORDS. That
// is four more colours and a different number from the top of the panel, so the
// bar and the panel could disagree -- and on a machine with 24 unacked records
// and nothing actually waiting, they did. Both now read one derivation on the
// service (`Model.barState` over `Model.verdict`), so they cannot.

import QtQuick
import qs.Commons
import qs.Ui

// The clickable thing MUST be a WidgetButton. The bar overlays its own
// MouseArea per slot and forwards presses only to items registered as click
// targets — which WidgetButton does in its Component.onCompleted — so a bare
// Item with a MouseArea or TapHandler never sees the press at all.
BarWidget {
    // Three tones, and the design never uses a fourth. `blind` borrows the gap
    // tone because it is the same claim: Moat is not able to tell you anything.
    // The TONE the model computed, not a second opinion about the state.

    id: root

    readonly property var service: root.bar && root.bar.shell && typeof root.bar.shell.serviceFor === "function" ? root.bar.shell.serviceFor(root.moduleName) : null
    // The setup states are still the bar's job: a shield that looks quiet while
    // the package is missing is the one lie this widget must not tell, and it is
    // a state the verdict line never has to describe because the panel shows the
    // setup screen instead of a verdict at all.
    readonly property bool blind: !service || !service.available || !service.groupOk
    readonly property var verdictBar: service && service.barState ? service.barState : ({
        "state": "quiet",
        "tone": "quiet",
        "label": "",
        "glyph": "󰒃"
    })
    readonly property string glyphState: root.blind ? "blind" : String(root.verdictBar.state)
    readonly property string label: root.blind ? "" : String(root.verdictBar.label)
    readonly property bool showLabel: setting("showCountBadge", true) === true && root.label !== ""
    // This switched on the state string and had a case per state, so every state
    // added after it was written fell through to the calm grey: `stopped` was
    // introduced for "Moat killed something", `barState` gave it the accent tone,
    // and the shield stayed grey while the panel headline underneath it read
    // "Moat stopped one thing" in orange. Two places deciding one colour is the
    // fault this codebase produces most often; mapping the model's own answer
    // means a sixth state cannot arrive silently grey.
    readonly property color stateColor: {
        if (root.blind)
            return tokens.accent;

        switch (String(root.verdictBar.tone)) {
        case "alarm":
            return tokens.alarm;
        case "accent":
            return tokens.accent;
        default:
            return tokens.fainter;
        }
    }
    readonly property string tooltip: {
        if (!service)
            return "Moat";

        if (!service.available)
            return "Moat is not installed — click for the setup steps";

        if (!service.groupOk)
            return "Moat cannot read its own log yet — click for the setup steps";

        // 3e: a tooltip only for the two loud states. Hovering the quiet shield to
        // be told nothing is happening is a tooltip nobody ever needed, and it is
        // the state the glyph is in ~95% of the time.
        var text = service.barTooltip;
        return text ? text : "Moat";
    }

    // A stored boolean is not always a boolean. The panel's own toggles go
    // through pluginRegistry.setBarWidget and land in shell.json as `true`, but
    // `omarchy bar set io.github.the2dl.moat showSuppressed true` -- which this
    // plugin's README tells people to use -- stores the STRING "true" unless the
    // caller remembers `--json`, and `=== true` silently read that as off. Every
    // boolean setting here was therefore settable from the panel and quietly
    // dead from the documented command line.
    function _flag(key, fallback) {
        var value = setting(key, fallback);
        if (typeof value === "string") {
            var s = value.toLowerCase().trim();
            if (s === "true" || s === "1" || s === "yes" || s === "on")
                return true;

            if (s === "false" || s === "0" || s === "no" || s === "off")
                return false;

            return fallback === true;
        }
        return value === true;
    }

    // The bar owns the settings the manifest declares (they live on this widget's
    // shell.json layout entry), and the service owns the behavior they change.
    // Push them across on every change rather than have the service read config.
    function _syncSettings() {
        if (!service)
            return ;

        service.minNotifySeverity = setting("minNotifySeverity", "high");
        service.notifyCooldownMinutes = Number(setting("notifyCooldownMinutes", 10));
        service.pollSeconds = Number(setting("pollSeconds", 10));
        service.showCountBadge = _flag("showCountBadge", true);
        service.showSuppressed = _flag("showSuppressed", false);
        service.weeklyDigest = _flag("weeklyDigest", true);
        service.notifyMuted = _flag("notifyMuted", false);
        service.rawDetail = _flag("rawDetail", false);
    }

    function togglePanel() {
        if (root.bar && root.bar.shell && typeof root.bar.shell.toggle === "function")
            root.bar.shell.toggle(root.moduleName, "{}");

    }

    moduleName: "io.github.the2dl.moat"
    implicitWidth: button.implicitWidth
    implicitHeight: button.implicitHeight
    onSettingsChanged: _syncSettings()
    onServiceChanged: _syncSettings()
    Component.onCompleted: _syncSettings()

    // The panel's own tokens, made from the BAR's surface rather than the popup
    // surface -- the two sit on different theme colours, and `calm` has to stay
    // legible on whichever this widget landed on.
    Tokens {
        id: tokens

        base: root.bar ? root.bar.background : Color.bar.background
        ink: root.bar ? root.bar.barForeground : Color.foreground
        themeAccent: Color.accent
        themeUrgent: root.bar ? root.bar.urgent : Color.urgent
        family: root.bar ? root.bar.fontFamily : Style.font.family
        scale: Style.space(1)
        rounded: Style.cornerRadius > 0
    }

    WidgetButton {
        // Scroll is a no-op on purpose: every setting behind this glyph changes
        // enforcement or notification behavior, and none of them should be
        // reachable by a stray touchpad flick.

        id: button

        anchors.fill: parent
        bar: root.bar
        // The label is our own composed content, not WidgetButton's centered Text.
        labelVisible: false
        hasVisualContent: true
        fontSize: Style.bar.iconFont
        fixedWidth: root.vertical ? -1 : Style.bar.iconSlot + (root.showLabel ? stateLabel.implicitWidth + Style.space(4) : 0)
        fixedHeight: root.vertical ? Style.bar.iconSlot + (root.showLabel ? Style.space(6) : 0) : -1
        tooltipText: root.tooltip
        active: root.glyphState === "needsYou"
        useActiveColor: false
        onPressed: function(mouseButton) {
            if (mouseButton === Qt.LeftButton)
                root.togglePanel();
            else if (mouseButton === Qt.RightButton && root.service)
                root.service.refresh();
        }

        Item {
            // The Moat mark, drawn, not a font glyph.

            id: content

            anchors.centerIn: parent
            width: shield.implicitWidth + (root.showLabel ? stateLabel.implicitWidth + Style.space(4) : 0)
            height: parent.height

            // The brand handoff is specific about how it carries state here: "a
            // verdict state may tint the water bar only -- the M stays
            // foreground-coloured". So the M sits in the bar's own ink like every
            // other widget, and the water underneath it takes the verdict tone.
            // That keeps the mark a mark rather than a status light, and it matches
            // what the panel does one layer down: colour appears only when
            // something is being asked of you.
            MoatMark {
                id: shield

                anchors.verticalCenter: parent.verticalCenter
                anchors.left: parent.left
                implicitWidth: Style.bar.iconFont
                implicitHeight: Style.bar.iconFont
                // Blind is the exception: if Moat cannot see, the mark itself goes to
                // the accent, because "the sensor is down" is not a verdict about
                // your machine -- it is a statement about Moat, and the whole mark
                // should say so.
                markColor: root.blind ? tokens.accent : (root.bar ? root.bar.barForeground : Color.foreground)
                waterColor: root.stateColor

                Behavior on markColor {
                    enabled: !root.bar || root.bar.foregroundAnimationEnabled

                    ColorAnimation {
                        duration: 160
                    }

                }

                Behavior on waterColor {
                    enabled: !root.bar || root.bar.foregroundAnimationEnabled

                    ColorAnimation {
                        duration: 160
                    }

                }

            }

            // The count, or the word "gap". Not a pill: the design's badge is on the
            // Now TAB, where it labels a place you can go, and a filled pill in the
            // bar reads as an unread counter -- which is the backlog to-do list this
            // redesign deleted. Here the number simply takes the shield's colour.
            Text {
                id: stateLabel

                visible: root.showLabel
                anchors.verticalCenter: parent.verticalCenter
                anchors.left: shield.right
                anchors.leftMargin: Style.space(4)
                text: root.label
                color: root.stateColor
                font.family: root.bar ? root.bar.fontFamily : Style.font.family
                font.pixelSize: Style.font.caption
                font.bold: true
                renderType: Text.NativeRendering
                textFormat: Text.PlainText
            }

        }

    }

}
