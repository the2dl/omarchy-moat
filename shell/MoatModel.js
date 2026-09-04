// Pure logic behind the Moat plugin. No QML types, no I/O: every function
// here takes plain values and returns plain values so shell/tests/tst_model.qml
// can exercise the folding, severity and notification rules without a running
// shell, a running daemon, or a real /var/lib/moat.
//
// The wire format is CONTRACT.md section 4: one JSON object per line in
// /var/lib/moat/alerts.jsonl. A line is either a full alert record or an
// update line `{"v":1,"id":"<same id>","update":{...}}` that readers fold onto
// the alert with the matching id. moatd never rewrites in place, so the
// file is append-only until it rotates at 20 MB.
.pragma library

// ------------------------------------------------------------------ severity

// Ordered weakest to strongest. Index doubles as the rank, so a threshold
// comparison is one integer compare.
var SEVERITIES = ["low", "medium", "high", "critical"]

function severityRank(severity) {
  var index = SEVERITIES.indexOf(String(severity || "").toLowerCase())
  return index < 0 ? -1 : index
}

// True when `severity` is at least as severe as `threshold`. An unrecognized
// severity is never "at least" anything — a garbled line must not be able to
// escalate itself into a critical notification.
function severityAtLeast(severity, threshold) {
  var rank = severityRank(severity)
  if (rank < 0) return false
  var floor = severityRank(threshold)
  if (floor < 0) floor = severityRank("high")
  return rank >= floor
}

// libnotify urgency for a severity. CONTRACT 7: critical -> critical,
// high/medium -> normal, low -> low (and low is filtered out before this by
// the minNotifySeverity threshold in the default configuration).
function notifyUrgency(severity) {
  switch (String(severity || "").toLowerCase()) {
  case "critical": return "critical"
  case "high": return "normal"
  case "medium": return "normal"
  default: return "low"
  }
}

// Bar widget color state, CONTRACT 7. Grey outranks everything: a daemon that
// is down or a group the user is not in means the counts on screen are stale,
// and a green shield would be a lie.
function widgetState(view) {
  var v = view || {}
  if (!v.available || !v.groupOk || !v.daemonOk) return "grey"
  // A sensor that is not loaded outranks every alert count, because the alert
  // counts are exactly what stops being trustworthy when it dies. On
  // 2026-09-03 Tetragon crash-looped for 25 minutes with zero policies in the
  // kernel; nothing here looked at that, so a quiet machine would have shown a
  // green shield over no protection at all. Silence from a dead sensor is the
  // most dangerous kind of quiet there is.
  if (v.sensorUnhealthy) return "red"
  var unacked = v.unacked || {}
  if ((unacked.critical || 0) > 0 || (unacked.high || 0) > 0) return "red"
  if ((unacked.medium || 0) > 0) return "amber"
  return "green"
}


// ------------------------------------------------------- quarantine (held)
//
// Quarantine moves a file aside and chmods it 000; it never deletes. So the
// panel's job is to show what is being held, where it came from, and to offer
// it back — "what got me" is the question a user actually has after an alert,
// and a store you cannot look into does not answer it.
function quarantineView(response) {
  var items = (response && response.quarantine) || []
  if (!Array.isArray(items)) return []
  var out = []
  for (var i = 0; i < items.length; i++) {
    var q = items[i] || {}
    out.push({
      id: String(q.alert || ""),
      rule: String(q.rule || ""),
      title: String(q.title || ""),
      originalPath: String(q.original_path || ""),
      heldAt: String(q.held_at || ""),
      when: String(q.quarantined_at || ""),
      sha256: String(q.sha256 || ""),
      bytes: (q.bytes === null || q.bytes === undefined) ? -1 : Number(q.bytes),
      // A held file that is no longer on disk is worth showing rather than
      // hiding: it means something removed it out from under moat.
      present: q.present === true
    })
  }
  return out
}

// ------------------------------------------------------------------- parsing

function parseLine(line) {
  var text = String(line || "").replace(/^﻿/, "").trim()
  if (!text) return null
  try {
    var value = JSON.parse(text)
    if (!value || typeof value !== "object" || Array.isArray(value)) return null
    // LEARNING 3: an install receipt rides the same file as
    // {"v":1,"receipt":{...}}. It is not an alert and does not need an id at the
    // top level, so it is admitted before the id check and separated out below.
    if (isReceipt(value)) return value
    if (!value.id) return null
    return value
  } catch (e) {
    // A torn final line (moatd appended a partial record between our read
    // and its fsync) or a corrupted byte range. Skip the line, keep the rest;
    // the next FileView change re-reads the whole file anyway.
    return null
  }
}

function isUpdate(record) {
  return !!(record && record.update && typeof record.update === "object")
}

// LEARNING 3. A receipt is the package-manager subtree summary the daemon
// writes when the root of an install exits. It shares alerts.jsonl with the
// alerts, so every reader has to be able to tell them apart — and a receipt
// must never reach the alert path: receipts are informational, they never
// notify and they never count toward the badge.
function isReceipt(record) {
  return !!(record && record.receipt && typeof record.receipt === "object"
            && !Array.isArray(record.receipt))
}

// ------------------------------------------------------- baseline vocabulary
//
// BASELINE.md section 8 extends the alert record with the four things the
// baselining machinery decided about an alert: who acted (`actor`), what they
// were doing at the time (`context`), what the severity was before provenance
// and context adjusted it (`severity_base` / `severity_reason`), and whether a
// learned or user allowlist entry — or a demoted rule — already covers it
// (`suppressed_by`).
//
// None of these exist in a log written by an older moatd, and every one of
// them is optional in a hand-written policy, so each normalizes to a value the
// UI can render without a special case: provenance and context fall back to
// "unknown", severity_base falls back to the severity that actually shipped
// (i.e. "nothing was adjusted"), and suppressed_by falls back to "" (visible).

var PROVENANCE = ["official", "foreign", "user", "unknown"]
var CONTEXTS = ["interactive", "pkg-install", "service", "unknown"]

function normalizeActor(value) {
  var a = value && typeof value === "object" ? value : {}
  var provenance = String(a.provenance || "").toLowerCase()
  return {
    // An unrecognized class is "unknown", never "official": provenance is the
    // only field here that can lower a severity, and a typo must not buy trust.
    provenance: PROVENANCE.indexOf(provenance) !== -1 ? provenance : "unknown",
    package: String(a.package === undefined || a.package === null ? "" : a.package),
    // BASELINE 1: an interpreter carries the provenance of the script it is
    // running, and `script` is that path. null for a non-interpreter actor.
    script: String(a.script === undefined || a.script === null ? "" : a.script)
  }
}

function normalizeContext(value) {
  var c = String(value || "").toLowerCase()
  return CONTEXTS.indexOf(c) !== -1 ? c : "unknown"
}

// ---------------------------------------------------------------- rarity
//
// LEARNING 1. Every alert carries `rarity` — how unusual this exact tuple is on
// THIS machine — plus `rarity_text`, the plain sentence the panel shows ("first
// time /usr/bin/node has read ~/.aws on this machine").
//
// Rarity is evidence, never a verdict: it does not move a severity here any
// more than it does in the daemon. An unrecognized value normalizes to "" and
// the pill simply does not render, because a wrong pill ("common" over a tuple
// nobody has ever seen) is worse than no pill.

var RARITIES = ["first_seen", "rare", "common"]

function normalizeRarity(value) {
  // "first-seen" and "firstSeen" are the spellings a hand-written policy or a
  // different daemon build is most likely to reach for; fold them in rather
  // than dropping a rarity the user could have used.
  var r = String(value === undefined || value === null ? "" : value)
    .toLowerCase().trim().replace(/[-\s]+/g, "_")
  if (r === "firstseen" || r === "new" || r === "never") r = "first_seen"
  return RARITIES.indexOf(r) !== -1 ? r : ""
}

// The small pill next to the rarity sentence. `kind` is the visual weight the
// panel maps to a color; the label is what the pill actually says.
function rarityPill(rarity) {
  switch (normalizeRarity(rarity)) {
  case "first_seen": return { rarity: "first_seen", label: "FIRST SEEN", kind: "strong" }
  case "rare": return { rarity: "rare", label: "RARE", kind: "warn" }
  case "common": return { rarity: "common", label: "COMMON", kind: "quiet" }
  default: return null
  }
}

// The sentence under WHAT HAPPENED. Falls back to a generic phrasing when the
// daemon classified the tuple but did not spell out why — a bare "rare" pill
// with no sentence tells the user nothing.
function rarityLine(alert) {
  if (!alert) return ""
  if (alert.rarity_text) return String(alert.rarity_text)
  switch (normalizeRarity(alert.rarity)) {
  case "first_seen": return "First time this has been seen on this machine."
  case "rare": return "Rarely seen on this machine."
  case "common": return "Routine on this machine."
  default: return ""
  }
}

// -------------------------------------------------------------- incidents
//
// LEARNING 4. On a high or critical alert the daemon snapshots the process,
// the tree, the sockets and (up to a size cap) the acting binary into
// /var/lib/moat/incidents/<id>/ before anything is killed. The alert names the
// result as `incident: {dir, files: [...]}`.
//
// The panel's whole job with it is: say what was captured, say how big, and
// hand over the path. It never reads the files — they are a copy of exactly
// the untrusted bytes the alert is about.

function normalizeIncidentFile(value, dir) {
  var base = String(dir || "").replace(/\/+$/, "")
  if (typeof value === "string") {
    var text = String(value).trim()
    if (!text) return null
    return { name: text, path: text.charAt(0) === "/" ? text : (base ? base + "/" + text : text),
             size: -1, sha256: "" }
  }
  var f = value && typeof value === "object" ? value : {}
  var name = String(f.name || f.file || f.path || "").trim()
  if (!name) return null
  var path = String(f.path || "")
  if (!path || path.charAt(0) !== "/") {
    var relative = path || name
    path = relative.charAt(0) === "/" ? relative : (base ? base + "/" + relative : relative)
  }
  // The name is the leaf, so "file/payload.js" reads as a nested capture rather
  // than as a second copy of the directory.
  var size = f.size === undefined || f.size === null ? f.bytes : f.size
  var n = Number(size)
  return {
    name: name.charAt(0) === "/" ? basename(name) : name,
    path: path,
    size: isFinite(n) && n >= 0 ? n : -1,
    sha256: String(f.sha256 || f.hash || "")
  }
}

function normalizeIncident(value) {
  var v = value && typeof value === "object" && !Array.isArray(value) ? value : null
  if (!v) return null
  var dir = String(v.dir || v.path || "").trim()
  var raw = Array.isArray(v.files) ? v.files : []
  var files = []
  for (var i = 0; i < raw.length; i++) {
    var file = normalizeIncidentFile(raw[i], dir)
    if (file) files.push(file)
  }
  // A block with neither a directory nor a file is nothing to show.
  if (!dir && files.length === 0) return null
  return { dir: dir, files: files, count: files.length }
}

// Human sizes for the incident file list. -1 means the daemon did not say.
function formatBytes(bytes) {
  var n = Number(bytes)
  if (!isFinite(n) || n < 0) return ""
  if (n < 1024) return n + " B"
  if (n < 1024 * 1024) return (n / 1024).toFixed(n < 10240 ? 1 : 0) + " KB"
  return (n / (1024 * 1024)).toFixed(n < 10485760 ? 1 : 0) + " MB"
}

// One alert with defaults filled in, so every consumer can read
// alert.actions.length or alert.process.exe without guarding.
function normalizeAlert(record) {
  var r = record || {}
  var process = r.process && typeof r.process === "object" ? r.process : {}
  var severity = String(r.severity || "low").toLowerCase()
  var base = String(r.severity_base || "").toLowerCase()
  return {
    v: r.v === undefined ? 1 : r.v,
    id: String(r.id || ""),
    ts: String(r.ts || ""),
    severity: severity,
    rule: String(r.rule || ""),
    family: String(r.family || ""),
    title: String(r.title || r.rule || "Alert"),
    summary: String(r.summary || ""),
    process: {
      pid: process.pid === undefined ? 0 : Number(process.pid),
      uid: process.uid === undefined ? -1 : Number(process.uid),
      exe: String(process.exe || ""),
      args: String(process.args || ""),
      cwd: String(process.cwd || ""),
      start_ts: String(process.start_ts || ""),
      ancestry: Array.isArray(process.ancestry) ? process.ancestry.slice(0, 8) : []
    },
    file: r.file && typeof r.file === "object" ? r.file : null,
    net: r.net && typeof r.net === "object" ? r.net : null,
    ioc: r.ioc && typeof r.ioc === "object" ? r.ioc : null,
    rotate: Array.isArray(r.rotate) ? r.rotate.slice() : [],
    explain: normalizeExplain(r.explain),
    action_taken: String(r.action_taken || "none"),
    actions: Array.isArray(r.actions) ? r.actions.slice() : [],
    acked: r.acked === true,
    mode: String(r.mode || "monitor"),
    count: r.count === undefined ? 1 : Number(r.count),

    // --- BASELINE 8 ---------------------------------------------------------
    actor: normalizeActor(r.actor),
    context: normalizeContext(r.context),
    // An absent severity_base means nothing adjusted the severity, which is
    // exactly "base == shipped". Rendering then compares the two and stays
    // silent, instead of the panel needing a "did the daemon tell us?" flag.
    // An unrecognized base is discarded the same way.
    severity_base: severityRank(base) >= 0 ? base : severity,
    severity_reason: String(r.severity_reason || ""),
    // "" is visible. A non-empty value names the thing that hid it:
    // "baseline.toml#3", "user.toml#1", "demoted:moat-...".
    suppressed_by: String(r.suppressed_by === undefined || r.suppressed_by === null
                          ? "" : r.suppressed_by),

    // --- LEARNING 1 and 4 ---------------------------------------------------
    // How unusual this tuple is on this machine, and the sentence that says so.
    rarity: normalizeRarity(r.rarity),
    rarity_text: String(r.rarity_text === undefined || r.rarity_text === null
                        ? "" : r.rarity_text),
    // null when the daemon captured nothing (which is every alert below
    // [incidents] snapshot_min_severity), so the panel binds `visible: !!incident`.
    incident: normalizeIncident(r.incident),

    // Filled in by decorateAlerts() once the demoted-rule list from `status` is
    // known. Defaults are what a lone alert with no status looks like.
    demoted: isDemotionMarker(r.suppressed_by),
    surface: severityAtLeast(severity, "high") && !r.suppressed_by ? SURFACE_ALERTS : SURFACE_TIMELINE,
    visible: !r.suppressed_by || isDemotionMarker(r.suppressed_by)
  }
}

// ------------------------------------------------------------------- explain
//
// CONTRACT 4's `explain` block is what turns an alert from a scary line into
// something a person can act on, and CONTRACT 7 pins its layout: WHAT HAPPENED,
// WHY IT WAS FLAGGED, EVIDENCE, IF THIS IS EXPECTED, WHAT TO DO. Normalizing it
// here means the panel renders five blocks unconditionally and each one either
// has content or hides itself — it never has to guess at a shape.

// The allowlist scopes CONTRACT 5's `ignore` accepts, narrowest first. Order
// matters: it is the tiebreak when an alert offers options in an arbitrary
// order and declares no recommendation.
var IGNORE_SCOPES = ["exe+file", "exe", "parent", "rule"]

function isIgnoreScope(scope) {
  return IGNORE_SCOPES.indexOf(String(scope || "").toLowerCase()) !== -1
}

function stringList(value) {
  if (!Array.isArray(value)) return []
  var out = []
  for (var i = 0; i < value.length; i++) {
    var text = String(value[i] === undefined || value[i] === null ? "" : value[i]).trim()
    if (text) out.push(text)
  }
  return out
}

function normalizeIfExpectedOption(value) {
  var o = value && typeof value === "object" ? value : {}
  var scope = String(o.scope || "").toLowerCase()
  if (!isIgnoreScope(scope)) return null
  return {
    scope: scope,
    cmd: String(o.cmd || ""),
    // The exact TOML the daemon would append. Shown verbatim in a monospace
    // block so the user approves the bytes, not a paraphrase of them.
    line: String(o.line || "")
  }
}

// An option whose scope is NOT one of CONTRACT 5's four. BASELINE 4's
// `moat-x-noisy-rule` ships two of them — "these-are-expected" (propose
// baseline entries for the tuples that flooded) and "keep-watching" (clear the
// demotion) — and they are the entire point of that alert. They cannot become
// Ignore buttons, because `moatctl ignore --scope these-are-expected` is not a
// thing; they carry their own `cmd`. Dropping them, which is what happened
// before, left the noise-guard alert with two Ignore buttons and no way to do
// either thing it was raised to offer.
function normalizeOtherOption(value) {
  var o = value && typeof value === "object" ? value : {}
  var scope = String(o.scope || "").toLowerCase()
  var cmd = String(o.cmd || "").trim()
  if (!scope || isIgnoreScope(scope) || !cmd) return null
  return { scope: scope, cmd: cmd, line: String(o.line || ""), label: otherOptionLabel(scope) }
}

function otherOptionLabel(scope) {
  switch (String(scope || "").toLowerCase()) {
  case "these-are-expected": return "These are expected"
  case "keep-watching": return "Keep watching"
  default:
    // "some-new-option" -> "Some new option": readable without the plugin
    // having to know the vocabulary in advance.
    var words = String(scope || "").replace(/[-_]+/g, " ").trim()
    return words ? words.charAt(0).toUpperCase() + words.slice(1) : ""
  }
}

function normalizeIfExpected(value) {
  var v = value && typeof value === "object" ? value : {}
  var hint = String(v.hint || "").toLowerCase()
  var options = []
  var other = []
  var raw = Array.isArray(v.options) ? v.options : []
  for (var i = 0; i < raw.length; i++) {
    var option = normalizeIfExpectedOption(raw[i])
    if (!option) {
      var extra = normalizeOtherOption(raw[i])
      if (extra) other.push(extra)
      continue
    }
    // A duplicate scope would render two identical buttons.
    var seen = false
    for (var j = 0; j < options.length; j++) if (options[j].scope === option.scope) seen = true
    if (!seen) options.push(option)
  }
  return {
    hint: isIgnoreScope(hint) ? hint : "",
    options: options,
    // Kept out of `options` on purpose: everything that reads `options` builds
    // an `moatctl ignore --scope <scope>` command out of it.
    other: other,
    file: String(v.file || "/etc/moat/allowlist.d/user.toml")
  }
}

function normalizeExplain(value) {
  var v = value && typeof value === "object" ? value : {}
  return {
    what: String(v.what || ""),
    why: String(v.why || ""),
    evidence: stringList(v.evidence),
    expected: String(v.expected || ""),
    if_expected: normalizeIfExpected(v.if_expected),
    next: stringList(v.next)
  }
}

function hasExplain(alert) {
  var e = alert && alert.explain ? alert.explain : null
  if (!e) return false
  return !!(e.what || e.why || e.evidence.length || e.expected ||
            e.if_expected.options.length || e.next.length)
}

// The IF THIS IS EXPECTED buttons, recommended scope first (CONTRACT 7), each
// carrying the exact TOML block the collapsible monospace panel shows.
//
// `if_expected.hint` names the recommended scope. When it is absent or names a
// scope the alert did not offer, fall back to the narrowest offered scope —
// recommending "rule" (which silences the detection everywhere) by accident is
// the one failure mode worth engineering against.
function ignoreOptions(alert) {
  var expected = alert && alert.explain ? alert.explain.if_expected : null
  if (!expected || expected.options.length === 0) return []

  var options = expected.options.slice()
  var recommended = expected.hint
  var offered = {}
  for (var i = 0; i < options.length; i++) offered[options[i].scope] = true
  if (!recommended || !offered[recommended]) {
    for (var s = 0; s < IGNORE_SCOPES.length; s++) {
      if (offered[IGNORE_SCOPES[s]]) { recommended = IGNORE_SCOPES[s]; break }
    }
  }

  options.sort(function(a, b) {
    if (a.scope === recommended) return -1
    if (b.scope === recommended) return 1
    return IGNORE_SCOPES.indexOf(a.scope) - IGNORE_SCOPES.indexOf(b.scope)
  })

  var out = []
  for (var k = 0; k < options.length; k++) {
    out.push({
      scope: options[k].scope,
      cmd: options[k].cmd,
      line: options[k].line,
      recommended: options[k].scope === recommended,
      label: ignoreScopeLabel(options[k].scope)
    })
  }
  return out
}

// The options that are not allowlist scopes, each with the exact command that
// performs it. The panel prints the command rather than offering a button: the
// plugin's whole action surface is the four verbs in `_argvFor`, and inventing
// a fifth from a string the daemon sent would be exactly the widening the
// "actions name alert ids, never paths" rule exists to prevent.
function otherOptions(alert) {
  var expected = alert && alert.explain ? alert.explain.if_expected : null
  return expected && Array.isArray(expected.other) ? expected.other.slice() : []
}

// Button labels. The scope names are the socket's vocabulary; these say what
// each one actually silences, because "parent" on its own tells nobody anything.
function ignoreScopeLabel(scope) {
  switch (String(scope || "").toLowerCase()) {
  case "exe": return "This program"
  case "exe+file": return "This program + this file"
  case "parent": return "This parent process tree"
  case "rule": return "This rule everywhere"
  default: return String(scope || "")
  }
}

function ignoreScopeCaution(scope) {
  switch (String(scope || "").toLowerCase()) {
  case "rule": return "Silences the detection for every program on the machine."
  case "parent": return "Silences it for anything launched under that parent."
  case "exe": return "Silences it for this executable path only."
  case "exe+file": return "Narrowest: this executable touching this path only."
  default: return ""
  }
}

// ------------------------------------------------------------------- folding

// Fold an array of parsed records into alerts, newest first.
//
// Update lines are shallow-merged onto their base alert. An update that
// arrives before its base (possible when a rotation truncates the head of the
// file, or when a reader catches the file mid-append) is parked and applied
// when the base shows up; if the base never shows up, the update is dropped
// rather than materialized into a half-alert with no title or process.
function foldRecords(records) {
  var byId = {}
  var order = []
  var pending = {}
  var list = Array.isArray(records) ? records : []

  for (var i = 0; i < list.length; i++) {
    var record = list[i]
    // A receipt is not an alert. Skipped here rather than filtered by the
    // caller so that no path — badge, notification, Alerts tab — can ever fold
    // one in, even if a receipt line also carries a top-level id.
    if (isReceipt(record)) continue
    if (!record || !record.id) continue
    var id = String(record.id)

    if (isUpdate(record)) {
      if (byId[id]) applyUpdate(byId[id], record.update)
      else {
        // Later updates win over earlier ones for the same key, so merging
        // into one parked patch preserves the append-order semantics.
        pending[id] = pending[id] || {}
        applyUpdate(pending[id], record.update)
      }
      continue
    }

    if (!byId[id]) order.push(id)
    byId[id] = normalizeAlert(record)
    if (pending[id]) {
      applyUpdate(byId[id], pending[id])
      delete pending[id]
    }
  }

  var alerts = []
  for (var j = 0; j < order.length; j++) alerts.push(byId[order[j]])
  alerts.sort(compareAlertsNewestFirst)
  return alerts
}

// ULIDs sort lexicographically by time, which is the whole reason CONTRACT 4
// specifies them, so the id is the primary key. `ts` only breaks ties between
// ids that are somehow equal, and the id is the final tiebreak so the sort is
// total and therefore stable across re-reads.
function compareAlertsNewestFirst(a, b) {
  if (a.id !== b.id) return a.id < b.id ? 1 : -1
  if (a.ts !== b.ts) return a.ts < b.ts ? 1 : -1
  return 0
}

// Merge an update patch. Only fields the contract lets an update carry are
// honored, so a hostile line in the log cannot rewrite an alert's title,
// severity or process into something the sensor never saw — which is what the
// panel's Kill and Quarantine buttons are shown next to.
// `ts` is here because moatd's dedupe update carries it: when the same
// rule+exe+file repeats inside the 60 s window it appends
// {"count":N,"ts":"<latest>"} rather than a second alert, and a panel that kept
// the FIRST occurrence's time would show "8m ago" for something still
// happening. `severity` is deliberately NOT here even though the daemon's own
// fold() honors it — an update line must never be able to escalate an alert
// into a critical toast, and no shipped code path emits one.
// `incident` is on this list because the daemon writes the alert line FIRST and
// the snapshot arrives as an update a moment later (capture happens after the
// alert exists, so the alert can name the directory). Without it, a panel
// reading alerts.jsonl never learned that a snapshot was taken at all -- the
// socket's `list` carried it and the log did not, which is exactly the kind of
// divergence the wire fixtures exist to catch.
var UPDATABLE = ["acked", "action_taken", "count", "mode", "rotate", "actions", "ts", "incident"]

function applyUpdate(target, patch) {
  if (!target || !patch || typeof patch !== "object") return target
  for (var i = 0; i < UPDATABLE.length; i++) {
    var key = UPDATABLE[i]
    if (!(key in patch)) continue
    var value = patch[key]
    switch (key) {
    case "acked":
      target.acked = value === true
      break
    case "count":
      var count = Number(value)
      if (isFinite(count) && count > 0) target.count = count
      break
    case "rotate":
    case "actions":
      if (Array.isArray(value)) target[key] = value.slice()
      break
    case "incident":
      var incident = normalizeIncident(value)
      // Never null out a snapshot that is already recorded: an update that
      // failed to carry one is not an instruction to forget it.
      if (incident) target.incident = incident
      break
    default:
      target[key] = String(value)
      break
    }
  }
  return target
}

function parseText(text) {
  var lines = String(text || "").split("\n")
  var records = []
  for (var i = 0; i < lines.length; i++) {
    var record = parseLine(lines[i])
    if (record) records.push(record)
  }
  return records
}

function foldText(text) {
  return foldRecords(parseText(text))
}

// ------------------------------------------------------------------ receipts
//
// LEARNING 3. For every package-manager subtree the daemon writes one receipt
// when the root exits:
//
//   npm install in ~/Projects/app (41 s, exit 0)
//     postinstall scripts: 3 (esbuild, sharp, husky)
//     wrote outside the project: ~/.npm/_cacache, ~/.cache/prisma
//     network: registry.npmjs.org, github.com, objects.githubusercontent.com
//     credential reads: none · persistence writes: .husky/pre-commit (alerted, low)
//     binaries executed from the tree: 12 · from /tmp: 0
//
// This is the positive picture: the thing a developer actually wants to see
// after `npm install`, and the thing the AI analysis reads when an alert came
// out of one. It is informational only — never a notification, never a badge,
// never an entry in the Alerts tab.
//
// LEARNING 3 names the fields in prose rather than as a schema, so the two
// spellings each one could plausibly have are both accepted and everything
// degrades to an empty list or a zero rather than to "undefined" on screen.
// See shell/README.md "Receipts" for which spellings are the primary ones.

// A list of names out of entries that may be plain strings or objects. The key
// order is the order the daemon is most likely to have used for that field.
function namedList(value, keys) {
  var list = Array.isArray(value) ? value : []
  var wanted = Array.isArray(keys) ? keys : ["name"]
  var out = []
  for (var i = 0; i < list.length; i++) {
    var entry = list[i]
    if (entry === undefined || entry === null) continue
    if (typeof entry !== "object") {
      var text = String(entry).trim()
      if (text) out.push(text)
      continue
    }
    for (var k = 0; k < wanted.length; k++) {
      var v = entry[wanted[k]]
      if (v === undefined || v === null || String(v).trim() === "") continue
      out.push(String(v).trim())
      break
    }
  }
  return out
}

// persistence_writes[] is the one list whose entries carry more than a name:
// LEARNING 3's own example renders ".husky/pre-commit (alerted, low)", i.e. the
// path plus whether it also raised an alert and at what severity.
function normalizePersistenceWrite(value) {
  if (value === undefined || value === null) return null
  if (typeof value !== "object") {
    var text = String(value).trim()
    return text ? { path: text, alerted: false, severity: "", text: text } : null
  }
  var w = value
  var path = String(w.path || w.file || w.name || "").trim()
  if (!path) return null
  var alerted = w.alerted === true || !!w.alert_id || !!w.alert
  var severity = String(w.severity || "").toLowerCase()
  var suffix = ""
  if (alerted) suffix = " (alerted" + (severityRank(severity) >= 0 ? ", " + severity : "") + ")"
  return { path: path, alerted: alerted, severity: severity, text: path + suffix }
}

function normalizeReceipt(record, fallbackIndex) {
  var outer = record && typeof record === "object" ? record : {}
  // In alerts.jsonl a receipt is wrapped: {"v":1,"receipt":{...}} (LEARNING 9).
  // The `receipts` socket command answers with the same objects UNWRAPPED, in a
  // `receipts` array, so accept either rather than silently normalizing an
  // entry from the socket into an empty receipt.
  var r = outer.receipt && typeof outer.receipt === "object" ? outer.receipt
        : (outer.root_exe !== undefined || outer.root_args !== undefined ? outer : {})

  var rootExe = String(r.root_exe || r.exe || r.root || "")
  var rootArgs = String(r.root_args || r.args || "")
  // LEARNING 3 says "cwd/project" — one place, two names for it. Whichever the
  // daemon sends is the project directory the install ran in.
  var cwd = String(r.cwd || r.project || r.dir || "")
  var started = String(r.started || r.start_ts || r.ts || outer.ts || "")
  var exit = r.exit === undefined || r.exit === null ? null : Number(r.exit)

  var persistence = []
  var rawPersistence = Array.isArray(r.persistence_writes) ? r.persistence_writes : []
  for (var i = 0; i < rawPersistence.length; i++) {
    var write = normalizePersistenceWrite(rawPersistence[i])
    if (write) persistence.push(write)
  }

  var id = String(outer.id || r.id || "")
  return {
    kind: "receipt",
    id: id,
    // Timeline rows are keyed rather than indexed, because the list re-sorts on
    // every append. A receipt without an id still needs a stable key.
    key: id || ("receipt:" + started + ":" + rootExe + ":" + Number(fallbackIndex || 0)),
    ts: started,
    root_exe: rootExe,
    root_args: rootArgs,
    cwd: cwd,
    project: String(r.project || cwd),
    started: started,
    duration_s: Number(r.duration_s || 0) || 0,
    exit: exit === null || !isFinite(exit) ? null : exit,
    postinstall_scripts: namedList(r.postinstall_scripts, ["name", "package", "script", "path"]),
    writes_outside_project: namedList(r.writes_outside_project, ["path", "dir", "file"]),
    network: namedList(r.network, ["host", "domain", "name", "ip"]),
    credential_reads: namedList(r.credential_reads, ["path", "file", "kind", "name"]),
    persistence_writes: persistence,
    execs_from_tree: Number(r.execs_from_tree || 0) || 0,
    execs_from_tmp: Number(r.execs_from_tmp || 0) || 0
  }
}

// Every receipt in a set of parsed records, newest first.
function foldReceipts(records) {
  var list = Array.isArray(records) ? records : []
  var out = []
  for (var i = 0; i < list.length; i++) {
    if (!isReceipt(list[i])) continue
    out.push(normalizeReceipt(list[i], out.length))
  }
  out.sort(compareReceiptsNewestFirst)
  return out
}

function compareReceiptsNewestFirst(a, b) {
  var at = Date.parse(String(a.ts || ""))
  var bt = Date.parse(String(b.ts || ""))
  if (isFinite(at) && isFinite(bt) && at !== bt) return bt - at
  if (a.id !== b.id) return a.id < b.id ? 1 : -1
  return a.key < b.key ? 1 : (a.key > b.key ? -1 : 0)
}

function receiptsFromText(text) {
  return foldReceipts(parseText(text))
}

// LEARNING 7's `{"cmd":"receipts","last":N}` answers with
// {"ok":true,"receipts":[...],"rendered":[...]} — the same receipts as the log
// carries, without the {"receipt":{...}} wrapper. The plugin normally reads
// them out of alerts.jsonl (which is how "receipts never notify" stays true by
// construction), so this is the fallback for a session whose log is unreadable.
function receiptsFromResponse(raw) {
  var value = raw
  if (typeof raw === "string") {
    try { value = JSON.parse(String(raw || "").trim() || "{}") } catch (e) { return [] }
  }
  var v = value && typeof value === "object" ? value : {}
  var list = Array.isArray(v.receipts) ? v.receipts : (Array.isArray(v) ? v : [])
  var out = []
  for (var i = 0; i < list.length; i++) out.push(normalizeReceipt(list[i], out.length))
  out.sort(compareReceiptsNewestFirst)
  return out
}

// "npm install" — what ran, as it would have been typed. Falls back to the
// executable alone when the daemon recorded no args.
function receiptCommand(receipt) {
  var r = receipt || {}
  var name = basename(r.root_exe) || String(r.root_exe || "")
  var args = String(r.root_args || "").trim()
  if (!name) return args
  return args ? name + " " + args : name
}

function plural(n, word) {
  return n + " " + word + (n === 1 ? "" : "s")
}

// The one-line timeline row:
// "npm install in ~/Projects/app · 41 s · 3 postinstall · 3 hosts".
function receiptSummary(receipt) {
  var r = receipt || {}
  var bits = []
  var head = receiptCommand(r)
  if (r.cwd) head = (head ? head + " in " : "") + r.cwd
  if (head) bits.push(head)
  if (r.duration_s > 0) bits.push(r.duration_s + " s")
  if (r.postinstall_scripts.length > 0) bits.push(r.postinstall_scripts.length + " postinstall")
  if (r.network.length > 0) bits.push(plural(r.network.length, "host"))
  // A non-zero exit is the one thing about a receipt that is not routine, so it
  // rides the collapsed row rather than waiting inside the expansion.
  if (r.exit !== null && r.exit !== 0) bits.push("exit " + r.exit)
  return bits.join(" · ")
}

function listOrNone(items) {
  var list = Array.isArray(items) ? items : []
  return list.length > 0 ? list.join(", ") : "none"
}

// The expanded block, exactly the shape LEARNING 3 prints: a headline plus five
// indented lines. Returned as { headline, lines } so the panel renders the
// headline at body weight and the rest as the detail under it.
function receiptBlock(receipt) {
  var r = receipt || {}
  var head = receiptCommand(r)
  if (r.cwd) head = (head ? head + " in " : "") + r.cwd
  var meta = []
  if (r.duration_s > 0) meta.push(r.duration_s + " s")
  if (r.exit !== null) meta.push("exit " + r.exit)
  if (meta.length > 0) head = head + " (" + meta.join(", ") + ")"

  var postinstall = r.postinstall_scripts.length > 0
    ? r.postinstall_scripts.length + " (" + r.postinstall_scripts.join(", ") + ")"
    : "none"

  var writes = []
  for (var i = 0; i < r.persistence_writes.length; i++) writes.push(r.persistence_writes[i].text)

  return {
    headline: head,
    lines: [
      "postinstall scripts: " + postinstall,
      "wrote outside the project: " + listOrNone(r.writes_outside_project),
      "network: " + listOrNone(r.network),
      "credential reads: " + listOrNone(r.credential_reads)
        + " · persistence writes: " + listOrNone(writes),
      "binaries executed from the tree: " + r.execs_from_tree
        + " · from /tmp: " + r.execs_from_tmp
    ]
  }
}

// --------------------------------------------------------------------- store
//
// FileView hands back the whole file on every change, so the store rebuilds
// the fold from scratch each time and its only real job is remembering which
// ids it has already seen. Two things depend on that memory:
//
//   * notifications: only ids that are new SINCE a previous ingest may notify,
//     and the very first ingest never notifies at all (`primed`), so a login
//     does not replay every alert in the log as a toast.
//   * rotation: moatd renames alerts.jsonl to alerts.1.jsonl at 20 MB and
//     starts a fresh file. The new file is shorter than what we last read, so
//     a shrink is the rotation signal — re-fold from the new content and keep
//     `seen`, because an id that rotated out is still not new.

//   * notification cooldown: one open window per rule, plus the summaries a
//     window still owes the user (BASELINE 5, notifyDecision below).

function createStore() {
  return {
    seen: {}, seenOrder: [], lastLength: -1, primed: false,
    // rule -> { rule, title, windowStart, windowMs, toasted, suppressedCount }
    notifyWindows: {},
    // Summaries owed for windows that were rolled over by a new alert before
    // the flush timer got to them: [{ rule, title, count }].
    notifyPending: []
  }
}

// Cap on remembered ids. Large enough that a rotation's worth of alerts stays
// suppressed, small enough that a long-lived shell does not grow without
// bound. Ids age out oldest-first.
var SEEN_LIMIT = 4096

function rememberSeen(store, id) {
  if (store.seen[id]) return
  store.seen[id] = true
  store.seenOrder.push(id)
  while (store.seenOrder.length > SEEN_LIMIT) {
    var dropped = store.seenOrder.shift()
    delete store.seen[dropped]
  }
}

// Ingest the current full text of alerts.jsonl.
//
// Returns { alerts, receipts, newIds, initialLoad, reloaded, unacked }:
//   alerts      folded, newest first, with surface/visible/demoted stamped on
//   receipts    install receipts from the same file, newest first (LEARNING 3)
//   newIds      ids to notify for — always empty on the initial load
//   initialLoad true only for the first ingest into this store
//   reloaded    the file shrank, i.e. it rotated or was truncated
//
// options: { demotedRules: [...], showSuppressed: bool } from `status`.
function ingestText(store, text, options) {
  var body = String(text || "")
  var reloaded = store.lastLength >= 0 && body.length < store.lastLength
  store.lastLength = body.length

  // One parse, two products: the folded alerts and the install receipts that
  // share the file with them (LEARNING 3). Receipts take no part in newIds, so
  // they cannot notify, and foldRecords drops them, so they cannot count.
  var records = parseText(body)
  var alerts = decorateAlerts(foldRecords(records), options)
  var receipts = foldReceipts(records)
  var initialLoad = !store.primed
  var newIds = []

  for (var i = 0; i < alerts.length; i++) {
    var id = alerts[i].id
    if (!store.seen[id] && !initialLoad) newIds.push(id)
    rememberSeen(store, id)
  }
  store.primed = true

  // alerts is newest first; notify oldest first so a burst reads in order.
  newIds.reverse()

  return {
    alerts: alerts,
    receipts: receipts,
    newIds: newIds,
    initialLoad: initialLoad,
    reloaded: reloaded,
    unacked: unackedCounts(alerts, options)
  }
}

// ------------------------------------------------------------------ surfacing
//
// BASELINE 5 is the whole surfacing policy in one table:
//
//   critical  notify (urgency critical), badge, Alerts tab
//   high      notify,                    badge, Alerts tab
//   medium    no notify,                 no badge, Timeline tab
//   low       no notify,                 no badge, Timeline tab
//   demoted   no notify,                 no badge, Timeline tab, grouped
//
// plus BASELINE 8: a suppressed alert is still appended to alerts.jsonl so the
// timeline can show it greyed out, and the plugin hides it by default.
//
// Two derived values carry that: `surface` ("alerts" | "timeline") says WHICH
// tab an alert belongs to, `visible` says whether it is shown at all. They are
// computed rather than stored so that flipping "show suppressed" or a rule
// being demoted mid-session re-sorts what is already folded, with no re-read.

var SURFACE_ALERTS = "alerts"
var SURFACE_TIMELINE = "timeline"

// `status.demoted_rules` is an array of rule ids (BASELINE 4). Turn it into a
// set once per pass rather than a linear scan per alert.
function demotedSet(demotedRules) {
  var set = {}
  var list = Array.isArray(demotedRules) ? demotedRules : []
  for (var i = 0; i < list.length; i++) {
    var id = String(list[i] === undefined || list[i] === null ? "" : list[i]).trim()
    if (id) set[id] = true
  }
  return set
}

function isDemotedRule(rule, demotedRules) {
  if (!rule) return false
  // Accept either the raw array or an already-built set, so a caller in a loop
  // can hoist the set out of it.
  var set = Array.isArray(demotedRules) ? demotedSet(demotedRules) : (demotedRules || {})
  return set[String(rule)] === true
}

// Which tab an alert belongs on. Suppression and demotion both win over
// severity: BASELINE 4 keeps a demoted rule's alerts logged and grouped in the
// timeline "regardless of severity", which is the entire point of demoting a
// rule rather than deleting it.
function alertSurface(alert, demotedRules) {
  if (!alert) return SURFACE_TIMELINE
  if (alert.suppressed_by) return SURFACE_TIMELINE
  if (isDemotedRule(alert.rule, demotedRules)) return SURFACE_TIMELINE
  return severityAtLeast(alert.severity, "high") ? SURFACE_ALERTS : SURFACE_TIMELINE
}

// Suppressed alerts are hidden unless the user turns "show suppressed" on.
// Nothing else is ever hidden: a quiet timeline row is still the record that
// moat saw something.
//
// BASELINE 8 lists "demoted:moat-..." among the possible suppressed_by values,
// but BASELINE 5 puts a demoted rule's alerts in the timeline, grouped — quiet,
// not hidden. So a demotion marker is explicitly NOT a suppression here; if it
// were, demoting a rule would erase it from the panel as well as the badge and
// the user would have no way to see what the noise guard silenced.
function isDemotionMarker(suppressedBy) {
  return String(suppressedBy || "").indexOf("demoted:") === 0
}

function alertVisible(alert, showSuppressed) {
  if (!alert) return false
  if (alert.suppressed_by && !isDemotionMarker(alert.suppressed_by)) return showSuppressed === true
  return true
}

// Stamp `demoted`, `surface` and `visible` onto every alert in place. The
// alerts are the model's own objects (foldRecords built them), so the panel's
// delegates can read alert.surface directly.
//
// options: { demotedRules: [...], showSuppressed: bool }
function decorateAlerts(alerts, options) {
  var o = options || {}
  var set = demotedSet(o.demotedRules)
  var show = o.showSuppressed === true
  var list = Array.isArray(alerts) ? alerts : []
  for (var i = 0; i < list.length; i++) {
    var alert = list[i]
    if (!alert) continue
    // Demotion arrives two ways: status.demoted_rules[] (the live list) and the
    // alert's own "demoted:<rule>" marker (BASELINE 8), which survives in the
    // log after the demotion has cleared. Either one makes the alert demoted.
    alert.demoted = isDemotedRule(alert.rule, set) || isDemotionMarker(alert.suppressed_by)
    alert.surface = alertSurface(alert, set)
    alert.visible = alertVisible(alert, show)
  }
  return list
}

// The visible alerts for one tab. The Alerts tab puts unacked first (they are
// the ones still asking for a decision); within each half, newest first. The
// timeline stays purely chronological — it is a log, not a queue.
function surfaceAlerts(alerts, surface, options) {
  var wanted = String(surface || SURFACE_ALERTS)
  var list = decorateAlerts(alerts, options)
  var out = []
  for (var i = 0; i < list.length; i++) {
    if (list[i].visible && list[i].surface === wanted) out.push(list[i])
  }
  out.sort(wanted === SURFACE_ALERTS ? compareAlertsUnackedFirst : compareAlertsNewestFirst)
  return out
}

function compareAlertsUnackedFirst(a, b) {
  if ((a.acked === true) !== (b.acked === true)) return a.acked === true ? 1 : -1
  return compareAlertsNewestFirst(a, b)
}

// The timeline groups by (rule, actor exe) so "a thousand identical events read
// as one row with a count" (BASELINE 5). The actor exe is the script when an
// interpreter is carrying one — BASELINE 1 makes the script the actor, so
// /tmp/a.sh and /tmp/b.sh under the same /usr/bin/bash are two rows, not one.
//
// Each group carries the summed event count (dedupe already folded repeats into
// alert.count), the latest timestamp, the strongest severity in it, and the
// individual alerts newest first so a row can expand into them.
function timelineGroups(alerts, options) {
  var list = surfaceAlerts(alerts, SURFACE_TIMELINE, options)
  var byKey = {}
  var order = []

  for (var i = 0; i < list.length; i++) {
    var alert = list[i]
    var exe = alert.actor && alert.actor.script ? alert.actor.script : alert.process.exe
    var key = alert.rule + "\u0000" + exe
    var group = byKey[key]
    if (!group) {
      group = {
        key: key,
        rule: alert.rule,
        exe: exe,
        exeName: basename(exe),
        title: alert.title,
        severity: alert.severity,
        count: 0,
        latestTs: alert.ts,
        latestId: alert.id,
        demoted: false,
        suppressed: true,     // only while every member is suppressed
        alerts: []
      }
      byKey[key] = group
      order.push(key)
    }
    group.alerts.push(alert)
    group.count += alert.count > 0 ? alert.count : 1
    if (severityRank(alert.severity) > severityRank(group.severity)) {
      group.severity = alert.severity
      group.title = alert.title
    }
    if (alert.id > group.latestId) { group.latestId = alert.id; group.latestTs = alert.ts }
    if (alert.demoted) group.demoted = true
    // A demotion marker is not a suppression, so it must not grey the row out.
    if (!alert.suppressed_by || isDemotionMarker(alert.suppressed_by)) group.suppressed = false
  }

  var groups = []
  for (var g = 0; g < order.length; g++) groups.push(byKey[order[g]])
  // list was newest first, so the first group seen is the newest one; sorting
  // by latest id keeps that true after a group's older members arrive.
  groups.sort(function(a, b) { return a.latestId < b.latestId ? 1 : (a.latestId > b.latestId ? -1 : 0) })
  return groups
}

// What the Timeline tab actually renders: the alert groups above, interleaved
// with the install receipts (LEARNING 3), newest first.
//
// Two row kinds share one list rather than two stacked lists because the point
// of the timeline is chronology — "what has this machine been doing" reads
// wrong if the install that produced an alert is filed in a separate panel from
// the alert. Every row carries `kind` so the delegate can switch on it.
//
// The sort is by timestamp, not by id: an alert id is a ULID and a receipt id
// need not be from the same space, so comparing them lexicographically would
// order the two kinds against each other arbitrarily. Ids only break ties.
function timelineRows(alerts, receipts, options) {
  var rows = []
  var groups = timelineGroups(alerts, options)
  for (var g = 0; g < groups.length; g++) {
    rows.push({ kind: "group", key: "g:" + groups[g].key, ts: groups[g].latestTs,
                id: groups[g].latestId, group: groups[g], receipt: null })
  }
  var list = Array.isArray(receipts) ? receipts : []
  for (var r = 0; r < list.length; r++) {
    rows.push({ kind: "receipt", key: "r:" + list[r].key, ts: list[r].ts,
                id: list[r].id, group: null, receipt: list[r] })
  }
  rows.sort(function(a, b) {
    var at = Date.parse(String(a.ts || ""))
    var bt = Date.parse(String(b.ts || ""))
    var aOk = isFinite(at)
    var bOk = isFinite(bt)
    // An unparseable timestamp sorts last rather than to the top: a row with no
    // time is the one thing that must not push a live alert off the fold.
    if (aOk !== bOk) return aOk ? -1 : 1
    if (aOk && at !== bt) return bt - at
    if (a.id !== b.id) return a.id < b.id ? 1 : -1
    return a.key < b.key ? 1 : (a.key > b.key ? -1 : 0)
  })
  return rows
}

// ------------------------------------------------------------------- counting

// Per-severity unacked counts for the status strip and the shield.
//
// Suppressed alerts and alerts of a demoted rule are NOT counted: BASELINE 4
// and 5 both say a demoted rule is "not counted in the badge", and a suppressed
// alert was hidden on purpose. Counting them would put a number on the shield
// for something the panel deliberately does not show.
//
// options: { demotedRules: [...] }
function unackedCounts(alerts, options) {
  var counts = { critical: 0, high: 0, medium: 0, low: 0, total: 0, badge: 0 }
  var set = demotedSet(options && options.demotedRules)
  var list = Array.isArray(alerts) ? alerts : []
  for (var i = 0; i < list.length; i++) {
    var alert = list[i]
    if (!alert || alert.acked === true) continue
    if (alert.suppressed_by) continue
    if (isDemotedRule(alert.rule, set)) continue
    var severity = String(alert.severity || "").toLowerCase()
    if (counts[severity] === undefined || severity === "total" || severity === "badge") continue
    counts[severity]++
    counts.total++
  }
  // What the shield's number means: alerts on the Alerts surface still waiting
  // for a decision. Precomputed here so the badge never has to re-scan.
  counts.badge = counts.critical + counts.high
  return counts
}

// The number on the shield. Prefers the `badge` unackedCounts computed (which
// already excluded demoted and suppressed alerts); falls back to critical+high
// for the daemon's own `status.unacked`, which has no such field and is only
// used when the log is unreadable.
function badgeCount(unacked) {
  var u = unacked || {}
  if (u.badge !== undefined && u.badge !== null) return Number(u.badge) || 0
  return (u.critical || 0) + (u.high || 0)
}

// ------------------------------------------------------- notification policy

// The noise guard's own alert (BASELINE 4.2). It is raised at medium, which
// by BASELINE 5 would never notify — but see NOISY_RULE_NOTIFIES below.
var NOISY_RULE_ALERT = "moat-x-noisy-rule"

// Whether a freshly-folded alert should raise a desktop notification.
// `initialLoad` is the load that primed the store: alerts that already existed
// when the shell started are history, not events, and must never toast.
//
// options: { demotedRules: [...] } from `status`.
function shouldNotify(alert, minSeverity, initialLoad, options) {
  if (initialLoad) return false
  if (!alert || !alert.id) return false
  if (alert.acked === true) return false

  // A suppressed alert was written to the log purely so the timeline can show
  // it greyed out (BASELINE 8). Toasting it would defeat the suppression.
  if (alert.suppressed_by) return false

  // A demoted rule "still logged, never notifies" (BASELINE 4.1). Checked
  // before the noisy-rule exception below so that a noise-guard alert which
  // itself started flooding can still be demoted into silence.
  if (isDemotedRule(alert.rule, options && options.demotedRules)) return false

  // NOISY_RULE_NOTIFIES — the one deliberate exception to the severity table.
  //
  // moat-x-noisy-rule is medium, so BASELINE 5 says "no notify". But this alert
  // is the noise guard announcing that it just stopped a rule from notifying:
  // it is the single thing the guard exists to put in front of the user, and if
  // it stays in the timeline the user never learns a detection went quiet. It
  // therefore bypasses minNotifySeverity — and only that. Ack, suppression and
  // demotion still silence it, and the store's seen-set means each such alert
  // still toasts exactly once, never per repeat.
  if (String(alert.rule || "") === NOISY_RULE_ALERT) return true

  return severityAtLeast(alert.severity, minSeverity)
}

// ------------------------------------------------- cooldown, burst collapse
//
// BASELINE 5: at most one toast per rule per `notifyCooldownMinutes`. Further
// alerts of that rule inside the window are counted, and when the window ends a
// single toast says "N more from <title>, see panel" — so a burst of one rule
// costs two toasts, never 173 (which is what the first live run actually did).
//
// The state lives on the store and every function here is pure over it, so the
// whole policy is testable without a timer: notifyDecision() is called for each
// new alert, flushCollapsed() is called on a clock (Service.qml, every 30 s).

var DEFAULT_NOTIFY_COOLDOWN_MINUTES = 10
var MIN_NOTIFY_COOLDOWN_MINUTES = 1
var MAX_NOTIFY_COOLDOWN_MINUTES = 120

// The manifest declares an integer 1-120; a missing, garbled or out-of-range
// value falls back to the default rather than to "no cooldown at all", because
// the failure mode of a broken setting must not be a popup storm.
function notifyCooldownMinutes(value) {
  var n = Math.round(Number(value))
  if (!isFinite(n)) return DEFAULT_NOTIFY_COOLDOWN_MINUTES
  if (n < MIN_NOTIFY_COOLDOWN_MINUTES) return MIN_NOTIFY_COOLDOWN_MINUTES
  if (n > MAX_NOTIFY_COOLDOWN_MINUTES) return MAX_NOTIFY_COOLDOWN_MINUTES
  return n
}

function notifyCooldownMs(options) {
  return notifyCooldownMinutes(options && options.notifyCooldownMinutes) * 60000
}

// Critical + first_seen is the one severity-based bypass (BASELINE 5). Critical
// alone is not enough: a critical rule that fires in a loop is exactly the
// storm the cooldown exists for. "First time this has ever happened here" is
// what makes an interruption worth it.
function bypassesCooldown(alert) {
  if (!alert) return false
  if (String(alert.severity || "").toLowerCase() !== "critical") return false
  return normalizeRarity(alert.rarity) === "first_seen"
}

function notifyWindowState(store, rule) {
  if (!store || !store.notifyWindows) return null
  return store.notifyWindows[String(rule || "")] || null
}

function _notifyStore(store) {
  if (!store.notifyWindows) store.notifyWindows = {}
  if (!store.notifyPending) store.notifyPending = []
  return store
}

// A window whose time is up owes a summary if it collapsed anything. Move that
// debt to the pending queue so flushCollapsed() still emits it even though the
// window itself is being replaced right now.
function _retireWindow(store, window) {
  if (!window) return
  delete store.notifyWindows[window.rule]
  if (window.suppressedCount > 0)
    store.notifyPending.push({ rule: window.rule, title: window.title, count: window.suppressedCount })
}

function _expired(window, nowMs) {
  // A clock that jumped backwards (suspend, NTP step) reads as expired rather
  // than as a window that never ends.
  return nowMs < window.windowStart || (nowMs - window.windowStart) >= window.windowMs
}

// Should this alert toast right now?
//
//   { toast: bool, collapsed: n, reason: string }
//
// `collapsed` is how many alerts of this rule the open window has swallowed so
// far (0 whenever the answer is "toast"). `reason` is why, for the log and the
// tests: "filtered" | "noisy-rule" | "first" | "critical-first-seen" |
// "window-reset" | "cooldown".
//
// options: { minNotifySeverity, initialLoad, demotedRules, notifyCooldownMinutes }.
function notifyDecision(store, alert, nowMs, options) {
  var opts = options || {}
  var now = Number(nowMs)
  if (!isFinite(now)) now = 0

  // Everything BASELINE 5's table already silences stays silent, and a silent
  // alert never opens a window or counts toward one: it was never a toast.
  if (!shouldNotify(alert, opts.minNotifySeverity, opts.initialLoad === true, opts))
    return { toast: false, collapsed: 0, reason: "filtered" }

  _notifyStore(store)
  var rule = String(alert.rule || "")

  // The noise guard's own alert keeps the one-shot exception it already had:
  // each moat-x-noisy-rule alert toasts exactly once (the store's seen-set
  // guarantees "once"), and it is the alert that explains why a rule just went
  // quiet — collapsing it into "N more" would hide the explanation.
  if (rule === NOISY_RULE_ALERT) return { toast: true, collapsed: 0, reason: "noisy-rule" }

  var window = store.notifyWindows[rule]
  var reset = false
  if (window && _expired(window, now)) {
    _retireWindow(store, window)
    window = null
    reset = true
  }

  if (!window || window.toasted !== true) {
    if (!window) {
      window = {
        rule: rule,
        title: String(alert.title || rule || "Moat alert"),
        windowStart: now,
        windowMs: notifyCooldownMs(opts),
        toasted: true,
        suppressedCount: 0
      }
      store.notifyWindows[rule] = window
    } else {
      window.toasted = true
    }
    return { toast: true, collapsed: 0, reason: reset ? "window-reset" : "first" }
  }

  if (bypassesCooldown(alert)) {
    // Toasted on its own merit; it does not consume or extend the window, and
    // it is not counted into the summary the window will emit.
    return { toast: true, collapsed: window.suppressedCount, reason: "critical-first-seen" }
  }

  window.suppressedCount++
  return { toast: false, collapsed: window.suppressedCount, reason: "cooldown" }
}

// Every summary now due: the debts left by rolled-over windows, then the
// windows whose time is up with a non-zero count. Windows that ended empty are
// simply dropped — nothing to say. Returns [{ rule, title, count }] and clears
// what it returns, so calling it twice does not toast the same summary twice.
function flushCollapsed(store, nowMs) {
  if (!store) return []
  _notifyStore(store)
  var now = Number(nowMs)
  if (!isFinite(now)) now = 0

  var out = store.notifyPending
  store.notifyPending = []

  var due = []
  for (var rule in store.notifyWindows) {
    var window = store.notifyWindows[rule]
    if (window && _expired(window, now)) due.push(window)
  }
  // Oldest window first, then by rule, so a flush that ends several windows at
  // once reads in a stable order.
  due.sort(function (a, b) {
    if (a.windowStart !== b.windowStart) return a.windowStart - b.windowStart
    return a.rule < b.rule ? -1 : (a.rule > b.rule ? 1 : 0)
  })
  for (var i = 0; i < due.length; i++) {
    delete store.notifyWindows[due[i].rule]
    if (due[i].suppressedCount > 0)
      out.push({ rule: due[i].rule, title: due[i].title, count: due[i].suppressedCount })
  }
  return out
}

// The one line the collapse toast says. "see panel" and not "see the timeline"
// because the click lands on the Timeline tab and the sentence should still be
// true if that ever changes.
function collapsedSummaryText(summary) {
  var s = summary || {}
  var count = Number(s.count) || 0
  var title = String(s.title || s.rule || "this rule")
  return count + " more from " + title + ", see panel"
}

// The actions CONTRACT 7 asks a toast to offer. The omarchy-shell notification
// server renders exactly ONE click action per toast (see shell/README.md), so
// this list is what the PANEL offers for the alert the toast opens; the toast
// itself carries a single click that opens the panel on that alert.
function offeredActions(alert) {
  var a = alert || {}
  var declared = Array.isArray(a.actions) ? a.actions : []
  var out = []
  var wanted = ["kill", "quarantine", "ignore"]
  for (var i = 0; i < wanted.length; i++) {
    if (declared.indexOf(wanted[i]) !== -1) out.push(wanted[i])
  }
  return out
}

// Nerd Font glyphs, all verified present in JetBrainsMono Nerd Font's cmap.
var GLYPH_SHIELD = "󰒃"        // U+F0483 md-shield
var GLYPH_SHIELD_CHECK = "󰕥"  // U+F0565 md-shield-check
var GLYPH_SHIELD_ALERT = "󰻌"  // U+F0ECC md-shield-alert
var GLYPH_SHIELD_OFF = "󰦝"    // U+F099D md-shield-off

function notifyGlyphFor(severity) {
  switch (String(severity || "").toLowerCase()) {
  case "critical":
  case "high":
    return GLYPH_SHIELD_ALERT
  default:
    return GLYPH_SHIELD
  }
}

// Shield glyph for a widget state from widgetState().
function widgetGlyph(state) {
  switch (String(state || "")) {
  case "grey": return GLYPH_SHIELD_OFF
  case "green": return GLYPH_SHIELD_CHECK
  default: return GLYPH_SHIELD_ALERT
  }
}

// ---------------------------------------------------------- rotate guidance
//
// CONTRACT 3 lets a policy annotate which secret kinds a detection exposed.
// The plugin turns each kind into the concrete thing the user has to go do;
// a rotate hint with no guidance text is worse than none, because it tells
// someone a secret leaked and then stops.

// The authoritative vocabulary is what policies/*.yaml actually annotate. At
// integration time this table and the daemon's rotate_advice() had diverged
// from it AND from each other (the plugin knew 6 of the 20 kinds the shipped
// policies emit); every kind below the divider is one a real policy uses.
// shell/tests/tst_wire.qml asserts none of them falls through to the generic
// text. The extra keys are kept as aliases for hand-written policies.
var ROTATE_GUIDANCE = {
  // --- kinds the shipped policies emit ---------------------------------------
  "ssh-key": "Generate a new key (ssh-keygen -t ed25519) and remove the old public key from GitHub, GitLab, and every server's authorized_keys.",
  "github-token": "Revoke the token at github.com/settings/tokens, issue a replacement, and update anything that stored it (gh auth login, CI secrets, ~/.netrc).",
  "git-credentials": "Every line of ~/.git-credentials is a forge password or token in cleartext. Rotate each one at its forge and move to a credential helper that does not store plaintext.",
  "npm-token": "Revoke the token at npmjs.com/settings/~/tokens, run npm login for a fresh one, and check ~/.npmrc and CI for stale copies.",
  "pypi-token": "Revoke the token at pypi.org/manage/account/token, issue a new one, and update ~/.pypirc and CI.",
  "cargo-token": "Revoke the token at crates.io/settings/tokens and run cargo login with a fresh one; the old value is in ~/.cargo/credentials.toml.",
  "docker-token": "Revoke the access token in Docker Hub security settings, then docker login again. ~/.docker/config.json holds the old one.",
  "aws-key": "Deactivate then delete the access key in IAM, create a new one, and run aws configure. Review CloudTrail for use of the old key.",
  "gcp-token": "Run gcloud auth revoke --all, delete ~/.config/gcloud/application_default_credentials.json, and rotate any service-account key it named.",
  "azure-token": "Run az logout && az account clear to drop the cached MSAL token, sign in again, and rotate any service-principal secret that was cached.",
  "kubeconfig": "Rotate the cluster credential (client cert or token) and redistribute the kubeconfig; every context in ~/.kube/config and $KUBECONFIG is compromised.",
  "gpg-key": "Revoke the affected subkey (gpg --gen-revoke), publish the revocation, and re-encrypt anything the key protected.",
  "keyring": "The login keyring was read. Change the account passwords it held and re-add them.",
  "browser-passwords": "Change every password saved in that browser profile, starting with any you reused. The login database is decryptable with the keyring that process could reach.",
  "browser-cookies": "Sign out of every session in that browser profile (this invalidates the stolen cookies) and change passwords for anything without 2FA.",
  "session-cookies": "Sign out everywhere on the affected accounts: a stolen session cookie is accepted without your password and without 2FA until it is invalidated.",
  "local-password": "/etc/shadow was read, so every local account hash is offline-crackable. Run passwd for each account and treat any reused password as public.",
  "anthropic-token": "Revoke the key at console.anthropic.com/settings/keys and issue a replacement; log the Claude CLI out and back in.",
  "openai-token": "Revoke the key at platform.openai.com/api-keys, issue a replacement, and clear OPENAI_API_KEY from ~/.codex and your shell rc files.",
  "google-token": "Revoke the key at aistudio.google.com/apikey and sign the Gemini CLI out; ~/.gemini may still hold the cached credential.",

  // --- aliases ---------------------------------------------------------------
  "gh": "Run gh auth logout && gh auth login. The old OAuth token in ~/.config/gh/hosts.yml should be revoked at github.com/settings/applications.",
  "aws": "Deactivate then delete the access key in IAM, create a new one, and run aws configure. Review CloudTrail for use of the old key.",
  "gpg": "Revoke the affected subkey, publish the revocation, and re-encrypt anything the key protected.",
  "gnupg": "Revoke the affected subkey, publish the revocation, and re-encrypt anything the key protected.",
  "claude": "Log out of the Claude CLI (claude logout) and sign in again. Revoke any API key from ~/.claude that was in use at console.anthropic.com.",
  "codex": "Sign out of the Codex CLI and sign in again; revoke any API key stored under ~/.codex.",
  "gemini": "Sign out of the Gemini CLI and revoke the key at aistudio.google.com/apikey.",
  "openai": "Revoke the key at platform.openai.com/api-keys and issue a replacement.",
  "anthropic": "Revoke the key at console.anthropic.com/settings/keys and issue a replacement.",
  "pypi": "Revoke the token at pypi.org/manage/account/token, issue a new one, and update ~/.pypirc and CI.",
  "cargo": "Revoke the token at crates.io/settings/tokens and run cargo login with a fresh one.",
  "docker": "Revoke the access token in Docker Hub security settings, then docker login again. ~/.docker/config.json holds the old one.",
  "kube": "Rotate the cluster credential (client cert or token) and redistribute the kubeconfig; the old context in ~/.kube/config is compromised.",
  "netrc": "Every credential in ~/.netrc should be treated as leaked. Rotate each host's password or token.",
  "password-store": "Your pass store was read. Rotate the entries the process could reach, starting with anything reused elsewhere.",
  "1password": "Sign out of the 1Password CLI, revoke the session/service-account token, and review the account's sign-in history.",
  "op": "Sign out of the 1Password CLI, revoke the session/service-account token, and review the account's sign-in history."
}

function rotateGuidance(kind) {
  var key = String(kind || "").toLowerCase().trim()
  if (!key) return ""
  if (ROTATE_GUIDANCE[key]) return ROTATE_GUIDANCE[key]
  return "Rotate this credential and revoke the old one at its issuer."
}

// The alert's `rotate` list as label/guidance pairs, ready to render.
function rotateItems(alert) {
  var kinds = alert && Array.isArray(alert.rotate) ? alert.rotate : []
  var out = []
  for (var i = 0; i < kinds.length; i++) {
    var kind = String(kinds[i] || "").trim()
    if (!kind) continue
    out.push({ kind: kind, guidance: rotateGuidance(kind) })
  }
  return out
}

// ----------------------------------------------------------------- formatting

function basename(path) {
  var text = String(path || "")
  if (!text) return ""
  var cut = text.lastIndexOf("/")
  return cut < 0 ? text : text.slice(cut + 1)
}

function ancestryChain(alert) {
  var chain = []
  var process = alert && alert.process ? alert.process : {}
  chain.push(basename(process.exe) || "?")
  var ancestry = Array.isArray(process.ancestry) ? process.ancestry : []
  for (var i = 0; i < ancestry.length; i++) {
    chain.push(basename(ancestry[i] && ancestry[i].exe) || "?")
  }
  // ancestry is nearest-parent-first, so reversing gives oldest -> newest,
  // which is how the summary field in CONTRACT 4 reads it out.
  return chain.reverse().join(" → ")
}

// ------------------------------------------------- baseline lines for the UI
//
// Three one-liners the detail pane puts under WHAT HAPPENED. Each returns ""
// when the alert has nothing to say, so the panel binds `visible: text !== ""`
// and an alert from an older daemon simply renders one fewer line.

// "context: interactive · actor: official (package hyprland 0.53-1)"
function actorLine(alert) {
  if (!alert) return ""
  var actor = alert.actor ? alert.actor : normalizeActor(null)
  var detail = []
  if (actor.package) detail.push("package " + actor.package)
  // The script an interpreter was running: BASELINE 1 says that, not
  // /usr/bin/bash, is the actor whose provenance was classified.
  if (actor.script) detail.push("script " + actor.script)
  return "context: " + (alert.context || "unknown") +
         " · actor: " + actor.provenance +
         (detail.length ? " (" + detail.join(", ") + ")" : "")
}

// "severity high → medium: actor is official (package hyprland)".
// Empty when nothing adjusted the severity, which is the common case.
function severityChangeLine(alert) {
  if (!alert) return ""
  var base = String(alert.severity_base || "")
  var now = String(alert.severity || "")
  if (!base || base === now) return ""
  var line = "severity " + base + " → " + now
  return alert.severity_reason ? line + ": " + alert.severity_reason : line
}

// "suppressed by baseline.toml#3" — shown on the greyed-out timeline rows so a
// suppression is never invisible, only quiet (BASELINE 6).
function suppressedLine(alert) {
  if (!alert || !alert.suppressed_by) return ""
  var by = String(alert.suppressed_by)
  // "demoted:<rule>" is the noise guard's marker, not an allowlist line.
  if (by.indexOf("demoted:") === 0) return "demoted rule " + by.slice(8)
  return "suppressed by " + by
}

// Compact relative time. `nowMs` is injectable so tests do not depend on the
// wall clock.
function relativeTime(iso, nowMs) {
  var then = Date.parse(String(iso || ""))
  if (!isFinite(then)) return ""
  var now = nowMs === undefined || nowMs === null ? Date.now() : Number(nowMs)
  var seconds = Math.round((now - then) / 1000)
  if (seconds < 0) seconds = 0
  if (seconds < 45) return "now"
  // Minutes floor and hours/days round: "59m ago" should never become
  // "60m ago" one second before it is allowed to say "1h ago".
  if (seconds < 3600) return Math.floor(seconds / 60) + "m ago"
  if (seconds < 172800) return Math.round(seconds / 3600) + "h ago"
  return Math.round(seconds / 86400) + "d ago"
}

// -------------------------------------------------------------------- status

// Normalize the `moatctl status --json` response (CONTRACT 5). Anything
// missing degrades to a state the UI can render honestly rather than to a
// confident-looking default.
// BASELINE 3/4 state, as `status.baseline`:
//   { learning: bool, learning_ends: iso, proposals: n, learned: n, demoted: [...] }
// Absent (older daemon) reads as "not learning, nothing proposed, nothing
// demoted", which is exactly how the plugin behaved before baselining existed.
function normalizeBaseline(value) {
  var b = value && typeof value === "object" ? value : {}
  return {
    learning: b.learning === true,
    learning_ends: String(b.learning_ends || ""),
    proposals: Number(b.proposals || 0),
    learned: Number(b.learned || 0),
    demoted: stringList(b.demoted)
  }
}

// BASELINE 3: a proposal is the (rule, actor exe, parent exe, file dir) tuple
// that kept recurring after the learning window closed, its counts, and the
// exact TOML that accepting it would write to baseline.toml. `id` is the handle
// `moatctl baseline accept|dismiss <id>` takes.
//
// BASELINE.md does not fix the JSON field names for a proposal, so the obvious
// spellings are each accepted and anything missing degrades to an empty string
// rather than to "undefined" on screen. The one field that must be right is
// `id`; without it the row renders but cannot be acted on, and the panel says
// so instead of sending a blank id to the daemon.
function normalizeProposal(value, fallbackIndex) {
  var p = value && typeof value === "object" ? value : {}
  var id = p.id === undefined || p.id === null ? "" : String(p.id)
  return {
    id: id,
    index: Number(fallbackIndex || 0),
    rule: String(p.rule || p.name || ""),
    exe: String(p.exe || ""),
    parent: String(p.parent || p.parent_exe || ""),
    dir: String(p.dir || p.file_dir || p.path || ""),
    count: Number(p.count || p.hits || 0),
    days: Number(p.days || p.distinct_days || 0),
    first_seen: String(p.first_seen || ""),
    last_seen: String(p.last_seen || ""),
    // The exact block accepting would append, shown verbatim the same way the
    // ignore flow shows its block: the user approves the bytes.
    toml: String(p.toml || p.line || p.block || ""),
    comment: String(p.comment || ""),
    actionable: id !== ""
  }
}

// "exe → parent, files under dir" for the proposal row's second line.
function proposalDetail(proposal) {
  var p = proposal || {}
  var bits = []
  if (p.exe) bits.push("exe " + p.exe)
  if (p.parent) bits.push("parent " + p.parent)
  if (p.dir) bits.push("files " + p.dir)
  if (p.count) bits.push(p.count + (p.count === 1 ? " alert" : " alerts"))
  if (p.days) bits.push("on " + p.days + (p.days === 1 ? " day" : " distinct days"))
  return bits.join("  ·  ")
}

// Whole days from now until an ISO stamp, or null when it is unparseable.
// Rounded up: with 4 h 1 min left it still says "1 day left", because saying
// "0 days" while learning is still running would be a lie.
function daysUntil(iso, nowMs) {
  var then = Date.parse(String(iso || ""))
  if (!isFinite(then)) return null
  var now = nowMs === undefined || nowMs === null ? Date.now() : Number(nowMs)
  return Math.ceil((then - now) / 86400000)
}

// The status strip's learning cell (BASELINE 3): "learning, 5 days left" while
// the window is open, "baseline active · 3 proposals" after it closes.
function learningSummary(status, nowMs) {
  var s = status && status.baseline ? status : normalizeStatus(status)
  var b = s.baseline
  if (b.learning) {
    var days = daysUntil(b.learning_ends, nowMs)
    if (days === null) return "learning"
    if (days <= 0) return "learning, ends today"
    return "learning, " + days + (days === 1 ? " day left" : " days left")
  }
  var n = b.proposals
  if (n > 0) return "baseline active · " + n + (n === 1 ? " proposal" : " proposals")
  return "baseline active"
}

function normalizeStatus(raw) {
  var value = raw
  if (typeof raw === "string") {
    try { value = JSON.parse(raw) } catch (e) { value = null }
  }
  var s = value && typeof value === "object" ? value : {}
  var feeds = s.feeds && typeof s.feeds === "object" ? s.feeds : {}

  var baseline = normalizeBaseline(s.baseline)
  var proposals = []
  var rawProposals = Array.isArray(s.proposals) ? s.proposals : []
  for (var i = 0; i < rawProposals.length; i++) proposals.push(normalizeProposal(rawProposals[i], i))
  // The count and the list must agree on screen; the list is the thing the user
  // can actually act on, so when it is present it wins.
  if (proposals.length > 0) baseline.proposals = proposals.length

  // Demoted rule ids. `status.demoted_rules` is the top-level array the panel
  // was specified against; `status.baseline.demoted` is the same list nested
  // inside the baseline block in BASELINE 4's own shape. Accept either, and
  // mirror whichever arrived into both so nothing downstream has to ask twice.
  var demoted = Array.isArray(s.demoted_rules) ? stringList(s.demoted_rules) : baseline.demoted
  baseline.demoted = demoted

  return {
    ok: s.ok === true,
    version: String(s.version || ""),
    mode: String(s.mode || "unknown"),
    tetragon: String(s.tetragon || "unknown"),
    policies: Number(s.policies || 0),
    // How many of those the kernel is actually running. null when moatd could
    // not read bpffs, which is "cannot tell", not "none".
    sensorsLoaded: (s.sensors_loaded === null || s.sensors_loaded === undefined)
      ? null : Number(s.sensors_loaded),
    sensorUnhealthy: s.sensor_unhealthy === true,
    policies_failed: Array.isArray(s.policies_failed) ? s.policies_failed.slice() : [],
    feeds: {
      updated: String(feeds.updated || ""),
      hashes: Number(feeds.hashes || 0),
      domains: Number(feeds.domains || 0),
      urls: Number(feeds.urls || 0)
    },
    unacked: s.unacked && typeof s.unacked === "object" ? s.unacked : null,
    sandbox: s.sandbox === true,
    // CONTRACT 5's example status carries `group_ok`; the daemon ships
    // `socket_group` instead and argues (correctly) that "is the CALLER in the
    // group" is unanswerable from the daemon side — a client that could not
    // reach the socket could not have got this response at all. So group_ok
    // stays optional and defaults to true, the shell's own `id -nG` probe is
    // authoritative, and the group NAME is carried through for the setup
    // screen so it never has to hardcode "moat".
    group_ok: s.group_ok !== false,
    socket_group: String(s.socket_group || "moat"),
    // --- BASELINE 3 and 4 ---------------------------------------------------
    baseline: baseline,
    proposals: proposals,
    demoted_rules: demoted,
    error: String(s.error || "")
  }
}

function statusSummary(status, unacked, nowMs) {
  var s = normalizeStatus(status)
  if (!s.ok) return "Moat: daemon not reachable"
  var parts = []
  parts.push("mode " + s.mode)
  parts.push("tetragon " + s.tetragon)
  parts.push(s.policies + " policies")
  var age = relativeTime(s.feeds.updated, nowMs)
  parts.push("feeds " + (age || "never"))
  var u = unacked || {}
  parts.push((u.total || 0) + " unacked")
  return "Moat: " + parts.join(", ")
}

// Free-form-safe scope value for the ignore action. An unrecognized scope
// becomes the narrowest one that always applies rather than the broadest —
// a typo must never widen an allowlist entry.
function normalizeIgnoreScope(scope) {
  var value = String(scope || "").toLowerCase()
  return isIgnoreScope(value) ? value : "exe"
}

// ----------------------------------------------------------------- allowlist
//
// CONTRACT 5's `allowlist` response lists the [[rule]] blocks in
// /etc/moat/allowlist.d/user.toml with their index and comment, and
// `unignore` removes the n-th one. The index is the only handle, so it is
// carried verbatim: renumbering client-side would remove the wrong block.
// The daemon spells three of these differently from the obvious guess, and the
// contract does not fix the field names, so both spellings are accepted here
// rather than churning the socket:
//
//   rule.path  is the TOML rule's `file =` glob (rule.file is the *source file*
//              the rule was read from, which is why it could not be reused)
//   rule.toml  is the rendered [[rule]] block
//   user_file  is the path `unignore` edits
//
// `sourceFile` keeps the daemon's per-rule `file` (which allowlist.d fragment a
// rule came from), because a rule from default.toml has a null index and cannot
// be removed — the panel has to be able to say why.
//
// BASELINE 3 adds a second origin: entries the learning window wrote itself to
// /etc/moat/allowlist.d/baseline.toml. They are listed alongside the user's own
// with a "learned" tag, because a suppression the machine chose for you is
// exactly the one you most need to be able to see and remove.
function normalizeAllowlistRule(value, fallbackIndex) {
  if (typeof value === "string") {
    return { index: fallbackIndex, comment: "", name: "", scope: "", line: value,
             detail: "", sourceFile: "", removable: false, learned: false }
  }
  var r = value && typeof value === "object" ? value : {}
  var hasIndex = !(r.index === undefined || r.index === null)
  var index = hasIndex ? Number(r.index) : fallbackIndex
  // The rule's own matcher fields. `path` is the daemon's name for the `file`
  // glob; prefer it and fall back to `file` only when there is no `path` key at
  // all, so the source-file path can never be shown as a match target.
  var matchFile = r.path === undefined ? r.file : r.path
  var detail = []
  var fields = [["exe", r.exe], ["file", matchFile], ["parent", r.parent],
                ["args", r.args], ["cwd", r.cwd], ["uid", r.uid]]
  for (var i = 0; i < fields.length; i++) {
    var v = fields[i][1]
    if (v === undefined || v === null || v === "") continue
    detail.push(fields[i][0] + " = " + String(v))
  }
  // BASELINE 8: every entry now names the fragment it came from (`file`) and
  // its origin (`source`: user | learned | shipped). `source` is a WORD, not a
  // path, so it is never a fallback for the file name — reading it as one put
  // the string "shipped" where the panel prints a path.
  var origin = String(r.source || r.origin || "").toLowerCase()
  var sourceFile = String(r.file !== undefined && r.path !== undefined ? r.file
                          : (r.source_file || r.sourceFile || ""))
  var learned = r.learned === true || origin === "learned"
                || (origin === "" && /(^|\/)baseline\.toml$/.test(sourceFile))
  // A shipped entry belongs to the package: it is replaced on upgrade, and
  // `unignore` refuses it. It is still listed, because a suppression the user
  // cannot see is the thing this project promises not to do.
  var shipped = origin === "shipped"
  // BASELINE 8 pins `removable`, and the daemon is the authority: shipped
  // entries carry a per-file index like every other entry, so "it has an index"
  // is no longer the same question as "it can be removed". Believing the index
  // put a Remove button on omarchy-default.toml rows that would have called
  // `unignore` with a user.toml index.
  var removable = typeof r.removable === "boolean" ? r.removable : hasIndex
  return {
    index: isFinite(index) ? index : fallbackIndex,
    comment: String(r.comment || ""),
    name: String(r.name || r.rule || ""),
    scope: isIgnoreScope(r.scope) ? String(r.scope).toLowerCase() : "",
    // The exact TOML block, shown verbatim the same way explain does it.
    line: String(r.toml || r.line || ""),
    detail: detail.join("  "),
    sourceFile: sourceFile,
    // The bare file name is what `moatctl unignore --file` takes: the index is
    // per-FILE (BASELINE 8), so an index without the file it belongs to would
    // remove whatever happens to sit at that position in user.toml.
    sourceName: basename(sourceFile),
    source: origin || (learned ? "learned" : "user"),
    learned: learned,
    shipped: shipped,
    // CONTRACT 5: an entry can only be removed with `unignore` if the daemon
    // gave it an index — that index is the handle, and there is no other — and
    // only if the daemon says it is removable at all.
    removable: removable && hasIndex
  }
}

function parseAllowlist(raw) {
  var value = raw
  if (typeof raw === "string") {
    try { value = JSON.parse(String(raw || "").trim() || "{}") } catch (e) { return { ok: false, error: "unparseable allowlist response", rules: [] } }
  }
  var v = value && typeof value === "object" ? value : {}
  var list = Array.isArray(v.rules) ? v.rules : (Array.isArray(v) ? v : [])
  var rules = []
  for (var i = 0; i < list.length; i++) rules.push(normalizeAllowlistRule(list[i], i))
  var errors = Array.isArray(v.errors) ? stringList(v.errors) : []
  return {
    ok: Array.isArray(v) ? true : v.ok === true,
    error: String(v.error || errors.join("; ")),
    file: String(v.user_file || v.file || "/etc/moat/allowlist.d/user.toml"),
    dir: String(v.dir || "/etc/moat/allowlist.d"),
    rules: rules
  }
}

// The Allowlist tab renders the three origins as three sections: what the user
// asked for, what the learning window decided on their behalf, and what the
// package ships (LEARNING 8's reviewed baseline, which cannot be removed here).
function allowlistSections(rules) {
  var list = Array.isArray(rules) ? rules : []
  var user = []
  var learned = []
  var shipped = []
  for (var i = 0; i < list.length; i++) {
    var rule = list[i]
    if (!rule) continue
    if (rule.shipped) shipped.push(rule)
    else if (rule.learned) learned.push(rule)
    else user.push(rule)
  }
  return { user: user, learned: learned, shipped: shipped }
}

// The `explain` socket command returns the alert with its full explain block,
// for the case where the log line was written by an older moatd (or
// truncated). Merge only the explain block: the rest of the alert on disk is
// what the sensor saw and stays authoritative.
function mergeExplainResponse(alert, raw) {
  if (!alert) return null
  var value = raw
  if (typeof raw === "string") {
    try { value = JSON.parse(String(raw || "").trim() || "{}") } catch (e) { return alert }
  }
  var v = value && typeof value === "object" ? value : {}
  var source = v.explain ? v.explain : (v.alert && v.alert.explain ? v.alert.explain : null)
  if (!source) return alert
  alert.explain = normalizeExplain(source)
  return alert
}

// ------------------------------------------------------------- AI analysis
//
// LEARNING 2. The panel's button hands the alert to whatever agent the user has
// already chosen, and `omarchy default agent` is the only place that answer
// lives. The plugin builds no prompt and reads no bundle: `moatctl analyze <id>`
// asks the daemon to write /var/lib/moat/incidents/<id>/bundle.md and then
// launches `omarchy-agent --prompt <preamble + path>` itself.
//
// That split is deliberate and it is a security property, not a layering
// preference. The bundle wraps everything that came out of a process in DATA
// fences because an alert about a malicious postinstall must not become a
// prompt-injection channel into the agent analyzing it (the s1ngularity attack
// drove the victim's own AI CLIs). A plugin that assembled the prompt from
// alert fields would be exactly that channel.

// `omarchy default agent` prints the agent name and nothing else, but a shell
// wrapper can add a trailing newline, a "no default agent set" line, or an
// error on stdout. Accept only something that looks like a command name.
function normalizeAgentName(text) {
  var first = String(text === undefined || text === null ? "" : text)
    .split("\n")[0].trim()
  if (!first) return ""
  // Anything with whitespace or a shell metacharacter in it is a message, not a
  // name — and it would end up in a button label either way, so refuse it.
  if (!/^[A-Za-z0-9._-]{1,64}$/.test(first)) return ""
  if (first.toLowerCase() === "none" || first.toLowerCase() === "unset") return ""
  return first
}

function analyzeLabel(agent) {
  var name = normalizeAgentName(agent)
  return name ? "Analyze with " + name : ""
}

// Shown in place of the button when no default agent is set. Naming the exact
// command is the difference between a disabled control and a next step.
var ANALYZE_HINT = "Set a default agent: omarchy default agent claude"

// LEARNING 7: {"cmd":"bundle","id":...} "writes bundle.md, returns its path".
// The field name for that path is not fixed, so the obvious spellings are all
// accepted; anything that is not an absolute path is refused rather than being
// handed to wl-copy, because the only thing this value is ever used for is to
// be pasted into a terminal.
function parseBundleResponse(raw) {
  var value = raw
  if (typeof raw === "string") {
    var text = String(raw || "").trim()
    if (!text) return { ok: false, path: "", error: "moatctl bundle returned nothing" }
    try { value = JSON.parse(text) } catch (e) {
      // A daemon that just prints the path is fine too.
      return text.charAt(0) === "/"
        ? { ok: true, path: text.split("\n")[0].trim(), error: "" }
        : { ok: false, path: "", error: "unparseable bundle response" }
    }
  }
  var v = value && typeof value === "object" ? value : {}
  var path = String(v.path || v.bundle || v.bundle_path || v.file || "").trim()
  if (v.ok === false) return { ok: false, path: "", error: String(v.error || "moatctl bundle failed") }
  if (!path || path.charAt(0) !== "/")
    return { ok: false, path: "", error: "moatctl bundle returned no path" }
  return { ok: true, path: path, error: "" }
}

function normalizeMode(mode) {
  return String(mode || "").toLowerCase() === "enforce" ? "enforce" : "monitor"
}

// The setup steps CONTRACT 2 tells the user to run, as (label, command) pairs.
// `needsPackage` and `needsGroup` decide which ones are still outstanding.
function setupSteps(needsPackage, needsGroup, group) {
  var name = String(group || "moat")
  var steps = []
  if (needsPackage) {
    steps.push({
      label: "Build and install the package",
      command: "cd pkg/ && makepkg -si"
    })
    steps.push({
      label: "Enable the services",
      command: "sudo systemctl enable --now tetragon moatd moat-feeds.timer"
    })
  }
  if (needsGroup) {
    steps.push({
      label: "Join the " + name + " group",
      command: "sudo usermod -aG " + name + " $USER"
    })
    steps.push({
      label: "Then log out and back in",
      command: "# group membership is only picked up by a new session"
    })
  }
  return steps
}
