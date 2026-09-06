.pragma library

// The copy contract (docs/design/README.md 3g).
//
// Every detection ships two strings: a **title** naming the consequence in the
// user's own terms, and a **stake** saying what it costs them. Rule ids,
// severities and hook names stay in evidence. Without this file, detection 33
// reintroduces log-speak.
//
// Three tests every title has to pass:
//   1. no jargon a new Arch user wouldn't know
//   2. no verb the user didn't do
//   3. it makes sense with no other context
//
// The daemon is the long-term home for these (a `title` and `stake` on each
// policy, LEARNING/CONTRACT work in stage 6 of docs/design/PLAN.md). Until it
// carries them, `titleFor` prefers what the daemon sent, falls back to this
// table, and falls back again to the old string -- so a detection added
// tomorrow degrades to its own wording rather than to a blank row.

// ---------------------------------------------------------------- the table
//
// Keyed by rule id. `title` answers "what happened, to me?"; `stake` answers
// "why should I care?" and is the line shown under a title in a notification
// or a queue row.
var COPY = {
  // --- credentials: something read a secret ---------------------------------
  "moat-cred-ssh-private-key-read": {
    title: "A program you don't recognise read your SSH key",
    stake: "That key is what logs you into your servers and pushes your code."
  },
  "moat-cred-ai-credentials-read": {
    title: "Something read the login for your AI tools",
    stake: "Whoever has it can spend your account and read your chats."
  },
  "moat-cred-cloud-credentials-read": {
    title: "Something read your cloud account keys",
    stake: "Those keys can create machines and read storage on your bill."
  },
  "moat-cred-vcs-token-read": {
    title: "Something read your GitHub login",
    stake: "It could push code to your repositories as you."
  },
  "moat-cred-registry-token-read": {
    title: "Something read your npm or PyPI login",
    stake: "It could publish a package under your name."
  },
  "moat-cred-browser-secrets-read": {
    title: "Something read your browser's saved passwords",
    stake: "Every site you stay signed in to is in there."
  },
  "moat-cred-gnupg-keyring-read": {
    title: "Something read your GPG keys",
    stake: "Those keys sign your commits and decrypt your files."
  },
  "moat-cred-etc-shadow-read": {
    title: "Something read the machine's password file",
    stake: "Only a program running as root can do this at all."
  },
  "moat-cred-project-token-read": {
    title: "Something read a secret stored inside your project",
    stake: "A .env or a project .npmrc holds keys to your services and your packages."
  },
  "moat-cred-ssh-agent-socket": {
    title: "Something asked your key agent to sign for it",
    stake: "It can log into your servers without ever opening the key itself."
  },
  "moat-cred-ssh-recon-read": {
    title: "Something read the list of machines you log into",
    stake: "That list is the map an intruder uses to pick where to go next."
  },

  // --- persistence: something arranged to run again -------------------------
  "moat-persist-hypr-config-write": {
    title: "Something added itself to your login",
    stake: "It will start on its own every time you sign in."
  },
  "moat-persist-shell-rc-write": {
    title: "Something changed what runs when you open a terminal",
    stake: "It will run again in every new shell, before anything you type."
  },
  "moat-persist-autostart-write": {
    title: "Something added itself to your desktop startup",
    stake: "It will start on its own every time you sign in."
  },
  "moat-persist-system-unit-write": {
    title: "Something installed itself as a background service",
    stake: "It will run at boot, before you have even signed in."
  },
  "moat-persist-authorized-keys-write": {
    title: "A new key was added that can log into this machine",
    stake: "Whoever holds the other half can sign in over the network."
  },
  "moat-persist-git-hook-write": {
    title: "Something added a script that runs on your next git command",
    stake: "It will run the next time you commit or push, as you."
  },
  "moat-persist-agent-config-write": {
    title: "Something changed the instructions your AI tools follow",
    stake: "Your coding agent reads that file and does what it says."
  },
  "moat-persist-desktop-entry-write": {
    title: "Something added itself to your applications menu",
    stake: "It will look like a program you chose to install."
  },
  "moat-persist-omarchy-hooks-write": {
    title: "Something changed a script Omarchy runs for you",
    stake: "Omarchy runs it during updates and theme changes."
  },
  "moat-persist-omarchy-plugin-write": {
    title: "Something added or changed a shell plugin",
    stake: "Plugins run inside your desktop with everything it can reach."
  },
  "moat-persist-omarchy-menu-extension-write": {
    title: "Something added an entry to your Omarchy menu",
    stake: "It runs when you pick it, looking like part of the system."
  },
  "moat-persist-git-config-write": {
    title: "Something changed where one of your repositories pushes to",
    stake: "Your next push would send that code somewhere you did not choose."
  },

  // --- privilege: something reached for more than it had --------------------
  "moat-priv-setuid-chmod": {
    title: "A file was set up to run with root powers",
    stake: "Anyone who runs it gets those powers, not just you."
  },
  "moat-priv-setcap-xattr": {
    title: "A program was granted a root-level power",
    stake: "It keeps that power every time it runs from now on."
  },
  "moat-priv-ptrace-attach": {
    title: "A program attached itself to another one",
    stake: "That lets it read the other program's memory, passwords included."
  },
  "moat-priv-proc-mem-access": {
    title: "Something read another program's memory",
    stake: "Secrets a program is using live there in the clear."
  },
  "moat-priv-container-socket-connect": {
    title: "Something spoke straight to the container service",
    stake: "Anything that can do that can rewrite this whole machine as root."
  },

  // --- rootkit: something went for the kernel -------------------------------
  "moat-rootkit-ldso-preload-write": {
    title: "Something is trying to load itself into every program you run",
    stake: "It would sit inside everything on this machine, including Moat."
  },
  "moat-rootkit-kernel-module-load": {
    title: "New code was loaded into the kernel",
    stake: "Code in the kernel can hide itself from everything above it."
  },
  "moat-rootkit-bpf-prog-load": {
    title: "A program loaded kernel-level tracing of its own",
    stake: "It can watch or change what other programs do."
  },
  "moat-rootkit-bpffs-write": {
    title: "Something wrote to the kernel tracing filesystem",
    stake: "That is where Moat's own sensors live."
  },

  // --- covering tracks: something went after the record ---------------------
  "moat-rootkit-evidence-tamper": {
    title: "Something erased Moat's own record of what happened",
    stake: "That record is the only account of what ran here, and it is now short."
  },
  "moat-rootkit-sensor-tamper": {
    title: "Something changed the files Moat needs in order to keep watching",
    stake: "Edited the right way, Moat stays running and stops telling you anything."
  },
  "moat-rootkit-history-tamper": {
    title: "Your shell history was emptied by something that isn't a shell",
    stake: "Clearing the trail is what gets done after commands worth hiding."
  },
  "moat-rootkit-system-log-tamper": {
    title: "The machine's own logs were deleted or emptied",
    stake: "Who logged in and what started here is what those files answer."
  },
  "moat-rootkit-trust-store-write": {
    title: "Something changed what this machine trusts",
    stake: "Downloads could be swapped in transit and still look perfectly valid."
  },

  // --- what ran, and from where --------------------------------------------
  "moat-exec-untrusted-home": {
    title: "A program ran from a folder that isn't for programs",
    stake: "Downloads and caches are where something dropped in lands first."
  },
  "moat-exec-untrusted-tmpfs": {
    title: "A program ran from temporary storage",
    stake: "Nothing was installed; it appeared, ran, and can vanish."
  },

  // --- the network ----------------------------------------------------------
  "moat-net-suspicious-port-egress": {
    title: "Something connected out on a port used for remote control",
    stake: "That is how a machine gets driven from somewhere else."
  },
  "moat-net-first-contact": {
    title: "Something connected somewhere it never has before",
    stake: "On its own that is normal. Next to a file it just read, it is not."
  },
  "moat-net-tmpfs-binary-egress": {
    title: "A program running from temporary storage called out",
    stake: "It appeared without being installed and is now talking to something."
  },
  "moat-shell-reverse-shell-connect": {
    title: "A command prompt was opened to somewhere on the internet",
    stake: "Someone else would be typing into this machine."
  },
  "moat-shell-lan-connect": {
    title: "A command prompt reached out to another machine on your network",
    stake: "The same trick as over the internet, from something already inside."
  },
  "moat-shell-stdio-socket": {
    title: "A command prompt was wired straight to a network connection",
    stake: "Whatever is on the other end is typing, and reading what comes back."
  },

  // --- Moat talking about itself -------------------------------------------
  "moat-x-noisy-rule": {
    title: "Moat stopped asking about something that kept happening",
    stake: "It is still recorded; it just isn't interrupting you."
  },
  "moat-x-sensor-mismatch": {
    title: "Moat's own sensors don't match what it expected",
    stake: "It may not have been watching everything it says it was."
  },
  "moat-x-baseline-revoked": {
    title: "A program Moat had learned to trust changed",
    stake: "Trust is pinned to the file; this one is not the same file."
  },
  "moat-x-new-exec-ioc": {
    title: "Something ran that matches a known-bad list",
    stake: "The file itself has been seen before, elsewhere, doing harm."
  },
  "moat-pkg-downloader-exec": {
    title: "An install pulled something extra off the internet",
    stake: "Whatever it fetched is not in the package you asked for."
  },
  "moat-pkg-subtree-netcat-exec": {
    title: "An install ran a tool for opening network connections",
    stake: "Build scripts have no reason to do that."
  },
  "moat-pkg-subtree-downloader": {
    title: "An install pulled something extra off the internet",
    stake: "Whatever it fetched is not in the package you asked for."
  },
  "moat-ai-cli-in-pkg-subtree": {
    title: "An install started an AI tool",
    stake: "It would run with your keys and your permissions."
  },
  "moat-x-ai-cli-headless": {
    title: "An AI tool ran with nobody watching",
    stake: "It can act on your machine without anyone to say no."
  },
  "moat-cred-proc-environ-read": {
    title: "Something read another program's environment",
    stake: "Tokens and passwords are often passed that way."
  }
}

// ------------------------------------------------------------- one line only
//
// Every string that reaches a single-line row in this panel is process-derived:
// a title moatd wrote from a policy, a command line, a path. Attacker-supplied
// argv can contain newlines and can be megabytes long, and a Text that elides
// still honours an embedded "\n" -- so one alert about a program invoked with a
// 3 kB argument turned a History row into forty lines of somebody else's text.
//
// PlainText stops that text being read as markup. THIS stops it being read as
// layout. Both are needed, and this one is needed everywhere a value shares a
// row with anything else.
function oneLine(text, max) {
  var limit = Number(max) > 0 ? Number(max) : 120
  var s = String(text === undefined || text === null ? "" : text).replace(/\s+/g, " ").trim()
  return s.length > limit ? s.slice(0, limit - 1) + "…" : s
}

// -------------------------------------------------------------- the lookup

function copyFor(rule) {
  return COPY[String(rule || "")] || null
}

/// The title for an alert or incident: what happened, in the user's terms.
///
/// Preference order is deliberate. The daemon wins when it has been taught the
/// new strings (stage 6), this table covers the detections shipped today, and
/// the original `title` is the floor -- a detection nobody has written copy for
/// yet should read like the old panel, never like an empty row.
///
/// `raw` is the Advanced setting (`rawDetail`): the reader has asked for the
/// detection's own words, so the table is skipped entirely and the daemon's
/// string is used even where copy exists. Presentation only -- nothing about
/// what was detected, scored, surfaced or notified reads this argument.
function titleFor(alert, raw) {
  if (!alert) return ""
  if (raw === true) return rawTitleFor(alert)
  if (alert.stake && alert.copyTitle) return oneLine(alert.copyTitle, 120)
  var c = copyFor(alert.rule)
  if (c) return c.title
  // The floor is the daemon's own string, and the daemon's own string is the
  // one that has been near a process. One line, bounded.
  return oneLine(alert.title || alert.rule || "Something happened", 120)
}

/// The daemon's own title, bounded. Longer than the copy table's ceiling
/// because a machine-written title carries the path or the command that makes
/// it specific, and truncating that is exactly what Advanced exists to undo --
/// but still bounded, because the string has been near a process.
function rawTitleFor(alert) {
  if (!alert) return ""
  return oneLine(alert.title || alert.rule || "Something happened", 200)
}

/// What it costs the user. Empty when nobody has written one, and callers bind
/// `visible: stake !== ""` rather than printing a placeholder.
///
/// In `raw` mode this is the daemon's own `summary` -- the sentence that names
/// the process, the pid and the parent chain -- rather than the table's line
/// about what it costs you.
function stakeFor(alert, raw) {
  if (!alert) return ""
  if (raw === true) return oneLine(alert.summary || "", 400)
  if (alert.stake) return oneLine(alert.stake, 200)
  var c = copyFor(alert.rule)
  return c ? c.stake : ""
}

function hasCopy(rule) {
  return !!copyFor(rule)
}

function coverage(rules) {
  var have = 0
  var missing = []
  var list = Array.isArray(rules) ? rules : []
  for (var i = 0; i < list.length; i++) {
    if (copyFor(list[i])) have++
    else missing.push(list[i])
  }
  return { total: list.length, have: have, missing: missing }
}

// -------------------------------------------------------- the banned words
//
// 3g: fine in evidence, in moatctl and in TOML -- never in a title or a stake.
// A list is a comment nobody reads; a function is a test that fails.
//
// This applies to the DEFAULT voice and always will. The `rawDetail` setting is
// the sanctioned escape hatch for a reader who wants the machine's own words --
// it is not a loophole for putting log-speak back into the copy table, and
// tst_model pins that by running this list over every entry in COPY regardless
// of which mode the panel is in.
var BANNED = [
  "unacked", "policies", "policy", "tetragon", "allowlist", "suppressed",
  "demoted", "ancestry", "exe", "tuple", "severity", "kprobe", "lsm",
  "bpf", "sigkill", "uid", "pid", "toml", "daemon"
]

/// The banned words in `text`, or an empty array. Word-boundary matched so
/// "expected" does not trip on "exe".
function bannedWordsIn(text) {
  var s = String(text || "").toLowerCase()
  var hits = []
  for (var i = 0; i < BANNED.length; i++) {
    var w = BANNED[i]
    if (new RegExp("\\b" + w + "\\b").test(s)) hits.push(w)
  }
  return hits
}

// ------------------------------------------------------- the verdict line
//
// 3g: exactly four forms, and no other sentence may occupy that slot. It is
// never a count of events.
var VERDICT_QUIET = "quiet"
var VERDICT_NEEDS = "needsYou"
var VERDICT_CHAIN = "chain"
var VERDICT_GAP = "gap"
/// Moat ACTED -- killed a process, or refused a connection -- and nobody has
/// acknowledged it yet. Distinct from `quiet` because "Nothing needs you" while
/// a process died in the user's terminal is the panel disagreeing with itself,
/// and distinct from `needsYou` because there is no decision left to make: the
/// thing already happened. What is owed is the telling, not a question.
var VERDICT_STOPPED = "stopped"

function spellNumber(n) {
  var words = ["no", "One", "Two", "Three", "Four", "Five", "Six", "Seven",
               "Eight", "Nine", "Ten"]
  return n >= 0 && n < words.length ? words[n] : String(n)
}

/// The one sentence at the top of the panel.
///
/// `state` is derived, never chosen (docs/design/README.md, State Management).
/// A sensor gap outranks a quiet day: the panel must not claim calm unless the
/// sensor can prove it was watching, because a blind sensor and a quiet machine
/// look identical from here.
function verdictLine(state, count) {
  switch (state) {
  case VERDICT_GAP:
    return "Watching, with one gap."
  case VERDICT_CHAIN:
    return "This one needs you now."
  case VERDICT_NEEDS:
    var n = Number(count) || 0
    return n === 1 ? "One thing needs you."
                   : spellNumber(n) + " things need you."
  case VERDICT_STOPPED:
    var s = Number(count) || 0
    return s === 1 ? "Moat stopped one thing."
                   : "Moat stopped " + spellNumber(s) + " things."
  default:
    return "Nothing needs you."
  }
}

/// Which of the three semantic colours the verdict dot takes.
function verdictTone(state) {
  switch (state) {
  case VERDICT_GAP: return "accent"
  case VERDICT_CHAIN:
  case VERDICT_NEEDS: return "alarm"
  // Not `alarm`: Moat already dealt with it, and shouting about a thing that is
  // over teaches people to ignore the shouting. Not `calm` either -- a killed
  // process is not a quiet day.
  case VERDICT_STOPPED: return "accent"
  default: return "calm"
  }
}

// --------------------------------------------------------- the state words
//
// The three states replace severity, and they describe what is wanted from the
// user rather than how bad the thing is.
function stateWord(state) {
  switch (state) {
  case "needsYou": return "waiting on you"
  case "explained": return "explained"
  case "expected": return "expected"
  case "contained": return "you stopped it"
  case "closed": return "closed"
  default: return ""
  }
}

// ==========================================================================
//  2b / 3a -- a chain, not four alerts
// ==========================================================================
//
// The words for a sequence. Everything here is written in the default voice
// and stays clear of the banned list: the daemon's own `summary` and
// `severity_reason` are full of family names and pids, and they belong in
// Advanced and in the one place the contract requires them, not in the
// sentence at the top of the panel.
//
// Nothing in here decides anything. The panel may not invent an escalation, so
// no function below reads a severity, ranks one, or says a sequence is worse
// than its steps -- moatd wrote that down in `severity_reason` and the panel
// prints it.

/// What a detection family MEANT, as the thing that happened rather than its
/// name. `cred` tells the user nothing; "read a credential" tells them what
/// the step was.
var FAMILY_DID = {
  cred: "read a credential",
  net: "sent something out",
  persist: "set something to run again",
  exec: "ran something new",
  priv: "asked for more access",
  rootkit: "changed the system underneath",
  pkg: "did it during a package install",
  shell: "opened a shell",
  ai: "drove an assistant",
  x: "tripped one of Moat's own checks"
}

function familyDid(family) {
  return FAMILY_DID[String(family || "")] || "did something Moat watches"
}

/// "a", "a and b", "a, b and c".
function joinPhrases(list) {
  var items = Array.isArray(list) ? list : []
  if (items.length === 0) return ""
  if (items.length === 1) return items[0]
  return items.slice(0, -1).join(", ") + " and " + items[items.length - 1]
}

/// How long the sequence took, as a person would say it.
function spanPhrase(seconds) {
  var n = Number(seconds)
  if (!isFinite(n) || n < 0) return ""
  if (n < 1) return "in the same second"
  if (n < 60) return "in " + Math.round(n) + (Math.round(n) === 1 ? " second" : " seconds")
  var mins = Math.round(n / 60)
  if (n < 3600) return "in " + mins + (mins === 1 ? " minute" : " minutes")
  var hours = Math.round(n / 3600)
  return "in " + hours + (hours === 1 ? " hour" : " hours")
}

/// The incident title for a chain (3a).
///
/// Built from what each step DID, in time order, deduplicated by family --
/// which is 3a's own title shape ("read your SSH key, sent something out, and
/// set itself to run at every login"). The program is not in the sentence
/// because the meta row underneath already names it, and because a lowercase
/// binary name at the head of a title reads as a typo.
///
/// `raw` is Advanced, where the daemon's own `summary` is what was asked for.
function chainTitle(chain, raw) {
  var c = chain || {}
  if (raw === true) return oneLine(c.summary || "", 200)
  var steps = Array.isArray(c.steps) ? c.steps : []
  var seen = {}
  var did = []
  for (var i = 0; i < steps.length; i++) {
    var family = String(steps[i].family || "")
    if (!family || seen[family]) continue
    seen[family] = true
    did.push(familyDid(family))
  }
  if (did.length === 0) return "One program did several things Moat watches"
  return oneLine("One program " + joinPhrases(did), 160)
}

/// The stake for a chain: why it is one thing and not several.
///
/// Empty in Advanced, on purpose. There the title is already the daemon's own
/// `summary` and so is the sub-line under the verdict; a third copy of the same
/// sentence in the same card is not more detail, it is the same detail three
/// times.
function chainStake(chain, raw) {
  if (raw === true) return ""
  return "Moat put these together because they came out of one program, close in time. "
       + "Deciding about one of them decides about all of them."
}

/// The sub-line under the verdict when the panel is showing a chain (3a).
///
/// 3a's is "Four things happened in nine minutes and they were all the same
/// program." Advanced gets the daemon's sentence instead, which is the same
/// fact with the family names and the pid in it.
function chainSummaryLine(chain, raw) {
  var c = chain || {}
  if (raw === true) return oneLine(c.summary || "", 400)
  var total = Number(c.steps_total) || 0
  if (total < 2) return ""
  var span = spanPhrase(c.span_secs)
  return spellNumber(total) + " things happened" + (span ? " " + span : "")
       + " and they all came out of the same program."
}

/// The far-right meta on a chain card, where a single alert prints its rule id
/// (3a: "4 detections · one process tree").
function chainRuleNote(chain) {
  var c = chain || {}
  var total = Number(c.steps_total) || 0
  if (total < 2) return ""
  return total + " detections  ·  one process tree"
}

/// 2b's closing card: one cause covers several alerts, so one decision closes
/// all of them.
function chainClosingLine(chain) {
  var c = chain || {}
  var total = Number(c.steps_total) || 0
  if (total < 2) return ""
  if (total === 2) {
    return "One program explains both of these. Closing this one closes the other too — "
         + "same sequence, same decision."
  }
  return "One program explains all " + total + " of these. Closing this one closes the other "
       + (total - 1) + " too — same sequence, same decision."
}

/// The marker on a member: what it means that this row is one step.
var CHAIN_MEMBER_NOTE =
  "This alert is one step. Moat is showing the whole sequence above, because the "
  + "later steps are what change what the first one means."

// ==========================================================================
//  1c -- the silence choice
// ==========================================================================
//
// The four scope blocks become four chips whose labels are CONSEQUENCES, not
// config. "exe+file" tells nobody anything; "only claude, only this folder"
// tells them exactly what they are about to agree to.
//
// Only the SELECTED chip is explained (the design's key rule for this screen),
// and the explanation always has two halves: what stops asking, and what still
// gets through. A silence that only says what it silences is how a user ends up
// with a rule they would not have written.

/// The chip label for a scope, in the user's terms.
///
/// `program` and `parent` are basenames out of the alert, so they render as
/// PlainText everywhere and are never interpolated into a command.
function scopeChipLabel(scope, program, parent) {
  var p = String(program || "this program")
  switch (String(scope || "").toLowerCase()) {
  case "exe": return "when " + p + " does it"
  case "exe+file": return "only " + p + ", only this file"
  case "parent": return parent ? "anything " + parent + " starts"
                               : "anything that same parent starts"
  case "rule": return "this detection, everywhere"
  default: return String(scope || "")
  }
}

/// True for the one chip the design deliberately draws duller: silencing a
/// detection machine-wide is a different kind of decision from the other three
/// and must not look like the easy option.
function scopeIsBroadest(scope) {
  return String(scope || "").toLowerCase() === "rule"
}

/// The consequence card for the selected chip: one sentence on what goes quiet,
/// one on what still reaches you and where to undo it.
function scopeConsequence(scope, program, parent, count) {
  var p = String(program || "this program")
  var n = Number(count) || 0
  var many = n > 1 ? "Silences all " + n + " and anything like them, "
                   : "Silences this, and anything like it, "
  var undo = "One line lands in your own rules — take it back any time under Rules."
  switch (String(scope || "").toLowerCase()) {
  case "exe":
    return {
      silences: many + "as long as it is " + p + " doing it.",
      through: p + " doing something of a different kind still reaches you. " + undo
    }
  case "exe+file":
    return {
      silences: many + "as long as it is " + p + " and this same file.",
      through: p + " touching anything else still reaches you. " + undo
    }
  case "parent":
    return {
      silences: many + "as long as it starts under " +
                (parent ? parent : "that same parent") + ".",
      through: "The same thing started any other way still reaches you. " + undo
    }
  case "rule":
    return {
      silences: "Stops this detection asking about anything, by any program, on this machine.",
      through: "Nothing else is watching for what it was watching for. " + undo
    }
  default:
    return { silences: "", through: "" }
  }
}

// ==========================================================================
//  1e -- what the shipped rules are grouped into
// ==========================================================================
//
// Sixteen cards that differ only in a binary path are a list pretending to be
// cards. Grouped by what they protect, they get names a user recognises -- and
// the "replaced on upgrade" caveat is stated once, in the section header,
// instead of sixteen times.

var PROGRAM_GROUPS = [
  {
    key: "ssh",
    label: "Your SSH tools",
    reason: "reading ~/.ssh is the entire point of ssh, ssh-agent, ssh-add and ssh-keygen",
    match: /^(ssh|sshd|ssh-agent|ssh-add|ssh-keygen|ssh-keyscan|scp|sftp|autossh)$/
  },
  {
    key: "git",
    label: "git",
    reason: "reads ~/.ssh/config and ~/.git-credentials constantly — credential reads only, nothing else",
    match: /^(git|git-remote-\S+|git-credential-\S+|gh|lazygit)$/
  },
  {
    key: "pkg",
    label: "Your package manager",
    reason: "pacman and makepkg write everywhere by design",
    match: /^(pacman|makepkg|yay|paru|pamac|pikaur|pacman-\S+|repo-add|fakeroot|dpkg|apt|apt-get)$/
  },
  {
    key: "desktop",
    label: "Your desktop",
    reason: "omarchy scripts and hyprland rewriting their own config",
    match: /^(hyprctl|hyprland|hyprpm|omarchy\S*|waybar|quickshell|swaync|mako|wl-copy|xdg-\S+|systemd\S*)$/
  },
  {
    key: "browser",
    label: "Browsers",
    reason: "their own profile directories",
    match: /^(firefox|chromium|chrome|google-chrome\S*|brave\S*|vivaldi\S*|librewolf|zen|epiphany)$/
  },
  {
    key: "toolchain",
    label: "Your language toolchains",
    reason: "npm, cargo, pip and their build scripts write into their own caches",
    match: /^(node|npm|npx|pnpm|yarn|bun|deno|cargo|rustc|pip|pip3|python|python3|go|gradle|mvn|make|cc|gcc|ld)$/
  },
  {
    key: "editor",
    label: "Your editor",
    reason: "writing under ~/.config is what you opened it to do",
    match: /^(nvim|vim|vi|emacs|code|codium|helix|hx|zed|micro|nano|kate)$/
  },
  {
    key: "agent",
    label: "Your AI tools",
    reason: "they read your project and write where you told them to",
    match: /^(claude|aider|cursor|copilot\S*|opencode|goose|amp)$/
  }
]

var OTHER_GROUP = {
  key: "other",
  label: "Everything else",
  reason: "one-off entries that do not fall into a group",
  match: null
}

/// Which recognisable group a program belongs to. Never null: an unmatched
/// program lands in "Everything else" rather than getting a group of its own,
/// because a group of one is a card again.
function programGroup(program) {
  var name = String(program || "").toLowerCase()
  for (var i = 0; i < PROGRAM_GROUPS.length; i++) {
    if (PROGRAM_GROUPS[i].match && PROGRAM_GROUPS[i].match.test(name)) return PROGRAM_GROUPS[i]
  }
  return OTHER_GROUP
}

// ==========================================================================
//  1d -- what covered a rule-covered row
// ==========================================================================
//
// 1d appends the covering rule to a row's title in a dimmer colour. The daemon
// names it as a fragment and an index ("baseline.toml#3"), which is a file path
// and an ordinal -- the two things this panel is not allowed to put in a title.
// What the user needs is WHOSE decision silenced it.
function coveredByPhrase(suppressedBy) {
  var by = String(suppressedBy || "")
  if (!by) return ""
  if (by.indexOf("demoted:") === 0) return "Moat stopped asking"
  if (/(^|\/)user\.toml/.test(by)) return "a rule you added"
  if (/(^|\/)baseline\.toml/.test(by)) return "a rule Moat learned"
  return "a rule that came with Moat"
}

// ==========================================================================
//  2h -- the three notification shapes
// ==========================================================================
//
// Only the first may interrupt. The other two are the weekly note and a burst
// that has already been counted, and neither is news -- an interruption for
// either is what teaches someone to dismiss the one that matters.
var NOTIFY_NEEDS_YOU = "needsYou"
var NOTIFY_DIGEST = "digest"
var NOTIFY_BURST = "burst"

/// The urgency each shape is sent at. `critical` keeps the toast on screen
/// until it is acted on; `low` is the shape that must never steal focus.
function notifyShapeUrgency(shape, severity) {
  if (shape !== NOTIFY_NEEDS_YOU) return "low"
  return String(severity || "").toLowerCase() === "critical" ? "critical" : "normal"
}

/// A burst summary title, in consequences rather than rule ids.
/// What arming a rule actually does, in the words the panel owes the user.
///
/// The two are different promises and must never be shown with one label. A
/// kill takes the process out -- and on a developer's machine that process is
/// usually a build, an editor or a shell. A deny refuses the single operation
/// with EPERM and leaves the program running, so the program reports an error
/// rather than vanishing. Somebody deciding whether to arm a rule is deciding
/// between those two, and a switch that does not say which is not a choice.
function enforceConsequence(kind) {
  if (kind === "deny")
    return "the operation is refused; the program keeps running and sees an error"
  if (kind === "kill") return "the program is killed"
  return ""
}

/// The one-word state beside the switch.
function enforceState(armed, kind) {
  if (!armed) return "watching"
  return kind === "deny" ? "refusing" : "stopping"
}

/// How a repeat count is said in a row.
///
/// A `cred` alert folds by (rule, actor) rather than by file, because a process
/// that opens fifteen credential stores in four seconds has done ONE sweep and
/// not fifteen unrelated things (Finding::dedupe_key). Its count is therefore a
/// number of credential-store reads, and "15 times" would read as the same file
/// fifteen times -- the one thing it does not mean.
function repeatPhrase(family, count) {
  var n = Number(count) || 0
  if (n <= 1) return ""
  if (family === "cred") return n + " credential stores"
  return n + " times"
}

function burstTitle(program, count) {
  var n = Number(count) || 0
  var p = String(program || "Something")
  return p + " tripped the same detection " + n + " more time" + (n === 1 ? "" : "s")
}

var BURST_BODY = "Counted, not shown one by one. Open Moat if you want it silenced."

// ==========================================================================
//  2g -- the keyboard pass
// ==========================================================================
//
// Same verbs as the buttons, and the same four things moatctl does.
var KEYS = [
  { key: "j / k", what: "next, previous incident" },
  { key: "a", what: "this was me — then 1-4 to pick how wide" },
  { key: "s", what: "stop it · confirms once, undoable for 30s" },
  { key: "e / ?", what: "evidence · ask Moat" },
  { key: "u", what: "undo the last thing you did" }
]

// ==========================================================================
//  3f -- first run
// ==========================================================================
var WATCHES = [
  { what: "Reads of your keys and tokens",
    like: "~/.ssh, gpg, .npmrc, cloud credentials" },
  { what: "Things that make a program start at login",
    like: "shell rc files, systemd user units, autostart, hyprland config" },
  { what: "Ways to become root",
    like: "sudoers, loader paths, setuid binaries" },
  { what: "What package installs and build scripts do",
    like: "the most common way something bad gets onto a developer's machine" }
]
