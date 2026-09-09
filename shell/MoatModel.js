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
.import "MoatCopy.js" as Copy

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

// ------------------------------------------------------------------- triage
//
// LEARNING 2c: the unattended agent verdict. Advisory in the strongest sense —
// it may explain, it may propose, and on `outcome: "demoted"` it moves an alert
// from the badge to the timeline. It never changes acked, severity or
// suppressed_by, and the panel must never let it look like it did.
//
// Absent on every alert until auto-triage has looked at one, and absent forever
// when [analysis] auto_triage = "off", so null is the normal case and every
// consumer binds `visible: !!alert.triage`.

var TRIAGE_VERDICTS = ["benign", "suspicious", "malicious", "unclear"]
var TRIAGE_CONFIDENCE = ["low", "medium", "high"]

function oneOf(value, allowed, fallback) {
  var v = String(value || "").toLowerCase()
  return allowed.indexOf(v) >= 0 ? v : fallback
}

// An unrecognized verdict or confidence becomes "unclear" / "low" rather than
// being rendered raw: this string came from a language model reading hostile
// input, so the panel treats it as an enum it either knows or does not.
function normalizeTriage(value) {
  var v = value && typeof value === "object" && !Array.isArray(value) ? value : null
  if (!v) return null
  var summary = String(v.summary || "").trim()
  var reasoning = String(v.reasoning || "").trim()
  // A verdict with nothing said is not a verdict.
  if (!summary && !reasoning) return null
  var raw = Array.isArray(v.recommend) ? v.recommend : []
  var recommend = []
  for (var i = 0; i < raw.length && recommend.length < 6; i++) {
    var line = String(raw[i] || "").trim()
    if (line) recommend.push(line)
  }
  var outcome = String(v.outcome || "annotated").trim()
  return {
    agent: String(v.agent || "").trim(),
    at: String(v.at || "").trim(),
    verdict: oneOf(v.verdict, TRIAGE_VERDICTS, "unclear"),
    confidence: oneOf(v.confidence, TRIAGE_CONFIDENCE, "low"),
    summary: summary,
    reasoning: reasoning,
    // Kept as text and shown as text. The plugin has no verb that writes an
    // allowlist file from a string, and this is the one string on the alert
    // that a model wrote, so it is exactly the string that must not get one.
    proposed_allowlist: String(v.proposed_allowlist || "").trim(),
    recommend: recommend,
    outcome: outcome,
    demoted: outcome === "demoted",
    // "withheld: <reason>" is the interesting case: a benign verdict the
    // ceiling refused to act on. Showing the reason is what stops that reading
    // as the panel ignoring the agent.
    withheld: outcome.indexOf("withheld:") === 0
              ? outcome.slice("withheld:".length).trim() : ""
  }
}

// The chip beside an alert. Confidence rides along on the verdict because
// "benign" and "benign, but the agent was not sure" are different claims.
function triageChip(alert) {
  var t = alert && alert.triage
  if (!t) return ""
  return t.verdict + " \u00b7 " + t.confidence
}

// What the agent's answer actually did, in words, for the detail block.
function triageOutcomeText(alert) {
  var t = alert && alert.triage
  if (!t) return ""
  if (t.demoted) return "Moved to the timeline; it is no longer in the badge count."
  // The safe-direction counterpart of demote: the agent judged this worse than
  // it was scored and pushed it onto the badge. Without this it hit the
  // catch-all and read "Nothing was changed" -- the opposite of the truth.
  if (t.outcome === "raised") return "Raised to the badge: the agent judged this needs you."
  if (t.withheld) return "Left in the badge count: " + t.withheld + "."
  return "Recorded against this alert. Nothing was changed."
}

// Human sizes for the incident file list. -1 means the daemon did not say.
function formatBytes(bytes) {
  var n = Number(bytes)
  if (!isFinite(n) || n < 0) return ""
  if (n < 1024) return n + " B"
  if (n < 1024 * 1024) return (n / 1024).toFixed(n < 10240 ? 1 : 0) + " KB"
  return (n / (1024 * 1024)).toFixed(n < 10485760 ? 1 : 0) + " MB"
}

// =========================================================================
//  CONTRACT 4 -- "Chains": the sequence an alert turned out to be a step of
// =========================================================================
//
// A chain is the daemon's statement that several alerts sharing one process
// tree, crossing two or more detection families inside a window, are one
// story. It rides on EVERY member (`alert.chain`) so a reader that opened one
// alert can draw the whole of design 2b without joining anything -- and it
// arrives as an `update` line, because the event that makes a sequence visible
// happens after its earlier steps are already on disk.
//
// Three of the contract's reader obligations are implemented HERE, in the
// normalizer, rather than in a view -- a view is not where a rule survives:
//
//   * A malformed chain is IGNORED, never merged. "A chain only ever grows",
//     so letting a bad line through would blank a sequence already recorded.
//   * An unrecognized `role` degrades to `trigger`. `context` is the claim
//     that the user had already allowed this step, and inventing that claim
//     out of a string nobody recognises shows an accusation as a permission.
//   * The severity is only ever read back out beside its reason (see
//     `chainSeverityLine`): the daemon never escalates silently, and the panel
//     must not either.

function normalizeChainStep(value) {
  var s = value && typeof value === "object" && !Array.isArray(value) ? value : null
  if (!s) return null
  // A step is an alert id and what that alert was. Without the id there is
  // nothing to join to, nothing to ack and nothing to point the user at.
  var id = String(s.alert || "")
  if (!id) return null
  var severity = String(s.severity || "").toLowerCase()
  return {
    alert: id,
    ts: String(s.ts || ""),
    family: String(s.family || ""),
    rule: String(s.rule || ""),
    // Unrecognized severities become "" rather than being rendered raw; the
    // string has been near a process like everything else on this record.
    severity: severityRank(severity) >= 0 ? severity : "",
    title: String(s.title || s.rule || ""),
    pid: Number(s.pid) || 0,
    exe: String(s.exe || ""),
    role: s.role === "context" ? "context" : "trigger"
  }
}

function normalizeChain(value) {
  var c = value && typeof value === "object" && !Array.isArray(value) ? value : null
  if (!c) return null
  var id = String(c.id || "")
  if (!id) return null

  var raw = Array.isArray(c.steps) ? c.steps : []
  var steps = []
  for (var i = 0; i < raw.length; i++) {
    var step = normalizeChainStep(raw[i])
    if (step) steps.push(step)
  }
  // Two is the daemon's own floor: a chain is "two or more alerts sharing a
  // process tree". One step is not a sequence, and drawing 2b's rail for it
  // would put a story on the screen that never happened.
  if (steps.length < 2) return null

  var severity = String(c.severity || "").toLowerCase()
  var base = String(c.severity_base || "").toLowerCase()
  var ancestor = c.ancestor && typeof c.ancestor === "object" ? c.ancestor : {}
  var total = Number(c.steps_total)
  if (!isFinite(total) || total < steps.length) total = steps.length

  return {
    v: c.v === undefined ? 1 : c.v,
    id: id,
    // What every step is under. The tree root is the subject of the story:
    // "2 things happened under node", not "node did two things".
    ancestor: { pid: Number(ancestor.pid) || 0, exe: String(ancestor.exe || "") },
    families: stringList(c.families),
    severity: severityRank(severity) >= 0 ? severity : "",
    severity_base: severityRank(base) >= 0 ? base : "",
    severity_reason: String(c.severity_reason || ""),
    first_ts: String(c.first_ts || ""),
    last_ts: String(c.last_ts || ""),
    span_secs: Number(c.span_secs) || 0,
    steps: steps,
    steps_total: total,
    truncated: c.truncated === true || total > steps.length,
    summary: String(c.summary || "")
  }
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
    // Who answered it. Empty for anything acked before the daemon recorded it.
    acked_by: String(r.acked_by || ""),
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
    // LEARNING 2c. null until an unattended agent pass has looked at this one.
    triage: normalizeTriage(r.triage),
    // CONTRACT 4 "Chains". null until this alert turns out to be one step of a
    // sequence, which is almost always an `update` line rather than the alert
    // itself -- so `UPDATABLE` carries it too, and the two must agree.
    chain: normalizeChain(r.chain),

    // Filled in by decorateAlerts() once the demoted-rule list from `status` is
    // known. Defaults are what a lone alert with no status looks like.
    demoted: isDemotionMarker(r.suppressed_by),
    // The daemon stamps `surface` when it raises the alert (CONTRACT 4) and it
    // is the authority: it knew the noise-guard state at that moment. Keeping
    // its value here is what stops `decorateAlerts` re-deciding history from
    // whatever the demotion list happens to say now. The computed value is only
    // for a record written before the field existed.
    surface: (r.surface === SURFACE_ALERTS || r.surface === SURFACE_TIMELINE)
      ? r.surface
      : (severityAtLeast(severity, "high") && !r.suppressed_by ? SURFACE_ALERTS : SURFACE_TIMELINE),
    // Whether the value above is the DAEMON's word or this file's guess. The
    // two are not the same authority: `alertSurface` may stand in for a
    // missing stamp with the live demotion list, but it must never overrule a
    // stamp the daemon made knowing everything the list says and more.
    surfaceStamped: r.surface === SURFACE_ALERTS || r.surface === SURFACE_TIMELINE,
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

// ----------------------------------------------------------------- incidents
//
// The redesign's central move (docs/design/README.md 1c): alerts collapse by
// (rule, program) into ONE incident carrying a count and a first/last time.
// The old panel showed the same detection 68 times as 68 identical rows, which
// is what made every screen a wall of red.
//
// Grouped here rather than in the daemon for now. Stage 4 of docs/design/PLAN.md
// moves it down, behind exactly this API, so the views built on it do not get
// rewritten when it does.

/// The program an incident is about, as a person would name it.
///
/// An interpreter running a script is the script, not the interpreter -- the
/// daemon already worked that out for provenance, so "python3" never becomes
/// the subject of a sentence about a package's postinstall.
function incidentProgram(alert) {
  if (!alert) return ""
  var script = alert.actor && alert.actor.script ? String(alert.actor.script) : ""
  var exe = alert.process ? String(alert.process.exe || "") : ""
  return basename(script || exe)
}

/// What collapses into one incident.
///
/// Normally (rule, program): 68 records of one detection by one program are one
/// thing to decide about, not 68 rows (1c).
///
/// A chain outranks that, and it is the whole premise of 3a: "four alerts in
/// nine minutes sharing a process tree are one incident". Members of a chain
/// key on the CHAIN, so a `.git/config` write and a credential read one second
/// apart in one process stop being two unrelated rows the user reads in
/// whatever order the list sorted them. `chain.id` is a member's alert id and
/// every member carries the same one, so the key is stable as the chain grows.
function incidentKey(alert) {
  var chain = alert && alert.chain ? alert.chain : null
  if (chain && chain.id) return "chain\u0000" + chain.id
  return String(alert && alert.rule ? alert.rule : "") + "\u0000" + incidentProgram(alert)
}

/// Which of the five states an alert is in.
///
/// This is the redesign replacing severity, and the point is that each state
/// says what is wanted from the USER, not how bad the thing is:
///   expected  -- a rule covers it, nobody needs to look
///   explained -- Moat read it and decided, you may look
///   contained -- you already acted
///   closed    -- you have seen it
///   needsYou  -- everything else
///
/// Order matters. `contained` and `closed` are facts about what already
/// happened and outrank any opinion; `expected` (a rule the user wrote) outranks
/// `explained` (a verdict the model wrote), because a rule is the user's own
/// decision and the model must never be able to overrule it.
function alertState(alert, demotedRules) {
  if (!alert) return "closed"
  if (alert.acked) return "closed"
  // A restored quarantine is the user UNDOING an action, not moat acting -- it
  // reads as reviewed/closed, never "you stopped it".
  if (alert.action_taken === "restored") return "closed"
  if (alert.action_taken && alert.action_taken !== "none") return "contained"
  // Suppression is a per-alert fact the daemon wrote. The rule-wide demotion
  // list is NOT consulted here: `alertSurface` below is the one place that
  // decides what a demotion means for an alert, and it reads the daemon's
  // stamp. (This line used to test the list too, and silenced a chain the
  // daemon had deliberately re-surfaced.)
  if (alert.suppressed_by) return "expected"
  // A verdict is checked before the surface, because "Moat read this and
  // decided" is a more informative thing to tell the user than "a rule covers
  // it" -- and a triage demotion is what put it on the timeline in that case.
  // ONLY a demotion the daemon actually performed counts. `verdict ===
  // "benign"` used to be enough on its own, which let the agent's opinion
  // silence an alert the daemon had deliberately refused to act on: the triage
  // ceiling withholds a demotion for a chain member, a first_seen tuple, a
  // NEVER_DEMOTE rule or anything above `demote_max`, and this line handed back
  // exactly what the ceiling had just denied. On 2026-09-04 that turned the
  // real C2 chain -- which the ceiling correctly declined to demote -- into
  // "explained" and dropped it out of Now on a `benign` verdict alone.
  //
  // The verdict is still SHOWN either way; the agent explains, and at most
  // demotes. Being read is not the same as being dismissed.
  var t = alert.triage
  if (t && t.demoted) return "explained"
  // An alert the daemon put on the timeline is not asking the user for
  // anything -- that is what the timeline means. Deciding "needs you" from
  // severity here, independently of `alertSurface`, was the fourth copy of
  // this decision in the model and the one the bar counted: on 2026-09-04 the
  // shield read 51 while the daemon had surfaced 8, because 251 timelined
  // alerts still came back "needsYou" from this function.
  if (alertSurface(alert, demotedRules) !== SURFACE_ALERTS) return "expected"
  if (t && t.verdict === "unclear") return "needsYou"
  return "needsYou"
}

var INCIDENT_RANK = {
  needsYou: 0, contained: 1, explained: 2, expected: 3, closed: 4
}

/// How unsure Moat is about an incident, 0 (settled) to 1 (no idea).
///
/// 3c orders the needs-you queue by THIS, not by severity: "a HIGH it is sure
/// about matters less than a MEDIUM it can't place". Without a number for
/// uncertainty the queue silently falls back to severity and the ordering rule
/// in the design becomes decoration.
function incidentUncertainty(alert) {
  if (!alert) return 1
  var t = alert.triage
  if (!t) return 0.8                       // nobody has looked yet
  if (t.verdict === "unclear") return 1
  var byConfidence = { high: 0.1, medium: 0.45, low: 0.75 }
  var base = byConfidence[t.confidence] === undefined ? 0.6 : byConfidence[t.confidence]
  if (t.verdict === "malicious" || t.verdict === "suspicious") return Math.min(1, base + 0.2)
  return base
}

/// Collapse alerts into incidents, newest activity first.
///
/// options: { demotedRules, showSuppressed, rawDetail }
///
/// `rawDetail` is the Advanced setting and it reaches exactly two lines of this
/// function -- the title and the stake. It is deliberately NOT read by
/// `alertVisible`, `alertState` or anything that decides a surface: how an
/// incident is worded and whether it needs you are different questions, and
/// letting a rendering flag near the second one is how a display setting turns
/// into a security setting.
function buildIncidents(alerts, options) {
  var o = options || {}
  var raw = o.rawDetail === true
  var set = demotedSet(o.demotedRules)
  var list = Array.isArray(alerts) ? alerts : []
  var byKey = {}
  var order = []
  for (var i = 0; i < list.length; i++) {
    var a = list[i]
    if (!a) continue
    if (!alertVisible(a, o.showSuppressed === true)) continue
    var key = incidentKey(a)
    var inc = byKey[key]
    if (!inc) {
      inc = {
        key: key,
        id: a.id,
        rule: a.rule,
        family: a.family,
        program: incidentProgram(a),
        alerts: [],
        count: 0,
        firstSeen: a.ts,
        lastSeen: a.ts,
        severity: a.severity
      }
      byKey[key] = inc
      order.push(inc)
    }
    inc.alerts.push(a)
    // The daemon already folds identical repeats into one record with a count,
    // so an incident's count is the sum of those, not the number of records.
    inc.count += (a.count === undefined ? 1 : Number(a.count)) || 1
    if (a.ts < inc.firstSeen) inc.firstSeen = a.ts
    if (a.ts > inc.lastSeen) { inc.lastSeen = a.ts; inc.id = a.id }
    if (severityRank(a.severity) > severityRank(inc.severity)) inc.severity = a.severity
  }
  for (var j = 0; j < order.length; j++) {
    var g = order[j]
    // The newest member carries the incident: actions name an alert id, and the
    // most recent one is the only member guaranteed to still have a live process.
    g.alerts.sort(compareAlertsNewestFirst)
    var head = g.alerts[0]
    g.head = head

    // ------------------------------------------------------------- 3a
    //
    // The chain, if this incident is one. Every member carries a copy and the
    // largest is the current one ("a chain only ever grows"), so the incident
    // is never described by whichever member happened to be folded last.
    g.chain = null
    for (var c = 0; c < g.alerts.length; c++) {
      var cc = g.alerts[c].chain
      if (!cc) continue
      if (!g.chain || cc.steps_total > g.chain.steps_total) g.chain = cc
    }

    if (g.chain) {
      // The verdict is written about the SEQUENCE, so the title and the stake
      // are too, and the severity is the daemon's chain severity rather than
      // the loudest member -- CONTRACT 4: "a reader that shows a chain must
      // show `chain.severity`, not the maximum of its members." Nothing here
      // computes a severity: an empty or unrecognized one falls back to what
      // the members already said, it never invents an escalation.
      g.title = Copy.chainTitle(g.chain, raw)
      g.stake = Copy.chainStake(g.chain, raw)
      if (g.chain.severity) g.severity = g.chain.severity
      // The subject of the story is the tree root every step ran under, not
      // whichever member sorted first.
      g.program = basename(g.chain.ancestor.exe) || g.program
      // 2b's rail, ready for the view, joined against the member alerts this
      // incident already holds so a step can say what was done about it.
      g.story = chainStory(g.chain, { alerts: g.alerts, currentId: head.id, rawDetail: raw })
    } else {
      g.title = Copy.titleFor(head, raw)
      g.stake = Copy.stakeFor(head, raw)
      g.story = []
    }
    // The most recent verdict among the members, NOT the verdict of the most
    // recent member. Triage works oldest-first, so on any incident that has
    // repeated, the newest member is exactly the one not looked at yet --
    // taking `head.triage` meant a repeating incident showed no analysis at all
    // while carrying several verdicts, which is how AI analysis came to look
    // like it had never run.
    g.verdict = null
    for (var v = 0; v < g.alerts.length; v++) {
      if (g.alerts[v].triage) { g.verdict = g.alerts[v].triage; break }
    }
    // Whether anything in the incident is still waiting, so the card can say
    // "reading the evidence" beside a verdict it already has.
    g.awaitingVerdict = false
    for (var w = 0; w < g.alerts.length; w++) {
      if (!g.alerts[w].triage) { g.awaitingVerdict = true; break }
    }
    // An incident needs you if ANY member does. One resolved repeat out of 68
    // does not close the incident.
    var state = "closed"
    var worst = 5
    for (var k = 0; k < g.alerts.length; k++) {
      var st = alertState(g.alerts[k], set)
      var rank = INCIDENT_RANK[st] === undefined ? 4 : INCIDENT_RANK[st]
      if (rank < worst) { worst = rank; state = st }
    }
    g.state = state
    g.uncertainty = incidentUncertainty(head)
    // WHOSE decision made this quiet, for 1d's inline note. `suppressed_by`
    // covers an allowlist entry; a demoted rule is quiet because of the noise
    // guard and carries no marker on the alert at all, so it is resolved here
    // against the same demoted set the state was computed from -- otherwise
    // half the covered rows in History say "covered" and explain nothing.
    g.coveredBy = String(head.suppressed_by || "")
    // A label, not a decision: it explains a row the state already calls
    // "expected", and is never written onto a row that is waiting on you.
    if (!g.coveredBy && state === "expected" && isDemotedRule(head.rule, set))
      g.coveredBy = "demoted:" + head.rule
  }
  order.sort(compareIncidentsNewestFirst)
  return order
}

function compareIncidentsNewestFirst(a, b) {
  if (a.lastSeen === b.lastSeen) return a.key < b.key ? 1 : -1
  return a.lastSeen < b.lastSeen ? 1 : -1
}

/// The needs-you queue (3c): ordered by what Moat is LEAST sure about.
function needsYouIncidents(incidents) {
  var list = Array.isArray(incidents) ? incidents : []
  var out = []
  for (var i = 0; i < list.length; i++) {
    if (list[i].state === "needsYou") out.push(list[i])
  }
  out.sort(function (a, b) {
    if (b.uncertainty !== a.uncertainty) return b.uncertainty - a.uncertainty
    return a.lastSeen < b.lastSeen ? 1 : -1
  })
  return out
}

// ------------------------------------------------------------- the verdict
//
// 3g: the top line has exactly four forms and the state is DERIVED, never set.

/// `quiet | needsYou | chain | gap`.
///
/// The sensor gate is the important one. A blind sensor and a quiet machine
/// look identical from the panel, so 2f's rule is that no calm claim is made
/// unless the sensor can prove it was watching -- `gap` outranks `quiet` even
/// with nothing waiting.
function verdictState(incidents, status) {
  var needs = needsYouIncidents(incidents)
  // 3a outranks 1b/3c: a sequence is the case the product exists for, and it
  // gets the loudest form of the line whatever else is waiting.
  //
  // This condition used to read `needs[i].chain.length > 1`, which was wrong
  // twice over -- `buildIncidents` never set `chain`, and the daemon's field is
  // an OBJECT with a `steps` array, not an array. So the state was unreachable:
  // a correlated chain drew 1b, one row, no sequence.
  for (var i = 0; i < needs.length; i++) {
    var chain = needs[i].chain
    if (chain && Number(chain.steps_total) > 1) return Copy.VERDICT_CHAIN
  }
  if (needs.length > 0) return Copy.VERDICT_NEEDS
  // A blind sensor outranks a completed intervention: everything else on this
  // page is only as trustworthy as the thing feeding it.
  if (!sensorHealthy(status)) return Copy.VERDICT_GAP
  // Moat acted and nobody has said they saw it. "Nothing needs you" over a
  // card that says a process was killed is the panel contradicting itself in
  // the space of two lines -- and the kill is the more important half.
  if (stoppedIncidents(incidents).length > 0) return Copy.VERDICT_STOPPED
  return Copy.VERDICT_QUIET
}

/// Incidents where Moat itself intervened and nobody has acknowledged it.
///
/// `contained` covers anything with an `action_taken`; this is narrower on
/// purpose -- a quarantine the user asked for is not news, a kill or a refused
/// connection they have not seen yet is.
function stoppedIncidents(incidents) {
  var list = Array.isArray(incidents) ? incidents : []
  var out = []
  for (var i = 0; i < list.length; i++) {
    var members = list[i] && Array.isArray(list[i].alerts) ? list[i].alerts : []
    // EVERY member, the way `buildIncidents` computes `state`: an incident is
    // "contained" if any member was acted on, so an incident is "stopped" if
    // any member was stopped and not yet acknowledged. This used to read only
    // `head` -- the newest member -- and disagreed with the state on the row:
    // a chain whose first step was killed and whose last step was acked by
    // hand read "you stopped it" in History while Now said "Nothing needs
    // you" and drew no apology for the kill nobody had seen.
    for (var m = 0; m < members.length; m++) {
      if (alertStopped(members[m])) { out.push(list[i]); break }
    }
  }
  return out
}

/// Did Moat stop this, and has nobody said they saw it? The per-alert half of
/// `stoppedIncidents`, kept separate so the incident-level answer is exactly
/// "any member says yes" and nothing else.
function alertStopped(alert) {
  if (!alert || alert.acked) return false
  // Containment is its OWN mechanism, independent of enforce mode: moatd
  // writes a narrow deny policy and refuses the connection on its own
  // judgement even while the daemon is in monitor. So a contained alert is
  // "stopped" regardless of `mode` -- and it MUST be, or it falls through
  // every Now list: `alertState` calls it "contained" (so it is not
  // "needsYou") and this used to not recognise it (so it was not "stopped"
  // either), leaving a critical contained chain visible in History and
  // nowhere in Now. 2026-09-06.
  if (alert.action_taken === "contained") return true
  // `mode` is the mode THIS rule was raised under, so a kill the user asked
  // for with `moatctl kill` is not news and does not get an apology.
  if (alert.mode !== "enforce") return false
  return alert.action_taken === "killed" || alert.action_taken === "blocked"
}

/// Is the sensor provably watching? (2f)
///
/// Counted from the kernel, not from the daemon saying so: `sensor_unhealthy`
/// and `sensors_loaded` exist because on 2026-09-03 tetragon was dead for 25
/// minutes and every surface still read "running".
/// Both spellings on purpose. The daemon sends snake_case (`sensor_unhealthy`,
/// `sensors_loaded`) and `normalizeStatus` renames them to camelCase, so the
/// raw response and the normalized object are two different shapes -- and the
/// live panel only ever passes the normalized one. Reading just the snake_case
/// names meant the gate never fired on a real machine while every test that
/// hand-wrote a raw status passed.
function sensorHealthy(status) {
  if (!status) return false
  if (status.sensor_unhealthy === true || status.sensorUnhealthy === true) return false
  if (status.tetragon && status.tetragon !== "running") return false
  var loaded = Number(status.sensors_loaded === undefined || status.sensors_loaded === null
                      ? status.sensorsLoaded : status.sensors_loaded)
  var total = Number(status.policies)
  if (isFinite(loaded) && isFinite(total) && total > 0 && loaded < total) return false
  return true
}

/// The four verdict-line inputs, ready for the view.
///
/// `chain` is the sequence the `chain` state is about, so the sub-line under
/// the headline can be 3a's ("Four things happened in nine minutes and they
/// were all the same program") rather than the generic count. null in the
/// other three states.
function verdict(incidents, status) {
  var state = verdictState(incidents, status)
  var needs = needsYouIncidents(incidents)
  var chain = null
  if (state === Copy.VERDICT_CHAIN) {
    for (var i = 0; i < needs.length; i++) {
      var c = needs[i].chain
      if (c && Number(c.steps_total) > 1) { chain = c; break }
    }
  }
  var count = state === Copy.VERDICT_STOPPED
    ? stoppedIncidents(incidents).length
    : needs.length
  return {
    state: state,
    count: count,
    chain: chain,
    line: Copy.verdictLine(state, count),
    tone: Copy.verdictTone(state)
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
// `chain` is on this list for the same reason, and it is the only way a chain
// EVER reaches the panel: correlation needs the second alert, so by the time
// moatd knows a sequence exists its first step has been on disk for a while.
// It is written back onto every member as an update line, and a reader that
// only honoured the fields above saw the field go past and dropped it -- which
// is exactly how the panel came to show one lonely row for a chain the daemon
// had correlated correctly.
// `triage` is here for the third instance of the same story. A verdict is
// ALWAYS an update: the pass runs on a timer, minutes to hours after the alert
// was written, and appends `{"update":{"triage":{...}}}` onto the existing id.
// With the field missing from this list the reader saw 161 such lines go past
// and dropped every one, so `alert.triage` was null for every alert the log
// reader produced and the panel showed no analysis at all -- while `moatctl
// explain` on the same id printed the verdict, because the socket carried it
// and the log did not. That divergence between the two readers is the same
// fault `incident` and `chain` were added here to fix.
// `acked_by` rides with `acked`: the daemon stamps who answered an alert, and a
// field this list forgets is a field that vanishes in silence -- which is how
// `chain`, `triage` and `surface` went missing from here once already.
var UPDATABLE = ["acked", "acked_by", "action_taken", "count", "mode", "rotate", "actions", "ts",
                 "incident", "chain", "triage", "surface"]

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
    case "surface":
      // The daemon restamps this when correlation concludes a chain is worth
      // interrupting for: `surface` was decided by a rule that had seen one
      // event, and the chain is the thing that knows better. Only the two
      // known values are honoured -- an unrecognised string is not a licence
      // to invent a third state.
      if (value === SURFACE_ALERTS || value === SURFACE_TIMELINE) {
        target.surface = value
        target.surfaceStamped = true
      }
      break
    case "triage":
      // Never blank a verdict already recorded: a re-triage that failed to
      // produce one is not an instruction to forget the one we have. Same
      // reasoning as `incident` below.
      var triage = normalizeTriage(value)
      if (triage) target.triage = triage
      break
    case "incident":
      var incident = normalizeIncident(value)
      // Never null out a snapshot that is already recorded: an update that
      // failed to carry one is not an instruction to forget it.
      if (incident) target.incident = incident
      break
    case "chain":
      // CONTRACT 4: "a chain only ever grows, so a malformed one must be
      // ignored rather than allowed to blank a sequence already recorded".
      // Same reasoning covers a well-formed one that got SMALLER -- the daemon
      // does not shrink a chain, so a shorter story is a line to disbelieve
      // rather than a retraction to honour.
      var chain = normalizeChain(value)
      if (chain && (!target.chain || chain.steps_total >= target.chain.steps_total)) {
        target.chain = chain
      }
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
// The command an install ran, as ONE line. `root_args` is argv: it can carry
// newlines and it can be kilobytes long -- the triage pass invokes an agent CLI
// with a multi-kilobyte prompt as a single argument, and moatd records that
// invocation like any other. Rendered raw it turns a row into a page.
function receiptCommand(receipt) {
  var r = receipt || {}
  var name = basename(r.root_exe) || String(r.root_exe || "")
  var args = Copy.oneLine(r.root_args, 90)
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
  return Copy.oneLine(bits.join(" · "), 200)
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
// FileView hands back the whole file on every change, so the store carries the
// running fold plus a memory of which ids it has already seen. Three things
// depend on that memory:
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
    // The rotated half of the log, alerts.1.jsonl, held here rather than
    // re-supplied on every ingest: see setLogPrefix().
    prefix: "",
    // The running fold: see createFold(). Rebuilt from scratch whenever the
    // file is not a strict append onto what we already folded.
    fold: null,
    // rule -> { rule, title, windowStart, windowMs, toasted, suppressedCount }
    notifyWindows: {},
    // Summaries owed for windows that were rolled over by a new alert before
    // the flush timer got to them: [{ rule, title, count }].
    notifyPending: []
  }
}

// ---------------------------------------------------------------- the fold
//
// PERFORMANCE, and it is the whole reason this exists. FileView hands back the
// WHOLE file on every change and moatd appends to it every couple of seconds.
// Re-parsing from the top cost ~250 ms of the GUI thread per append on a 19 MB
// / 18k-line log — several dropped frames every two seconds, which is what the
// panel's janky scrolling actually was. Only the bytes appended since the last
// ingest are parsed now; the folded alerts, the parked updates and the
// receipts live here between calls.
//
// The incremental path is taken ONLY for a strict append: same bytes where we
// already folded, and more of them. A shorter file (rotation, truncation) or a
// prefix that no longer matches falls back to folding the whole body, which is
// exactly what every ingest used to do. `guard` is the tail of the region
// already folded and is what makes "same prefix" cheap to check without
// comparing 19 MB.
var FOLD_GUARD_CHARS = 64

function createFold() {
  return {
    // id -> alert, plus the first-seen order, so the sort below is total and
    // stable across re-reads exactly as foldRecords' was.
    byId: {}, order: [], pending: {},
    // LEARNING 3's install receipts, folded from the same lines.
    receipts: [], receiptCount: 0,
    // Characters of the body already folded, and the tail of them.
    consumed: 0, guard: "",
    // The folded result, newest first. Held rather than rebuilt so that a
    // re-read that adds nothing (FileView fires more than once per append)
    // hands back the SAME array and changes no binding downstream.
    alerts: []
  }
}

// The body the fold runs over is `prefix + live` -- the rotated file and then
// the live one, the order moatd folds them in (`AlertStore::load`) -- but the
// two are never concatenated. That concatenation used to happen on every
// reload: 20 MB of alerts.1.jsonl copied in front of the live file so that
// ~100 appended bytes could be folded, and the flattened 30 MB string it
// produced was the largest single allocation the panel made, twice a second.
// `bodySlice` reads a range out of the two halves instead.
function bodySlice(prefix, live, start, end) {
  var cut = prefix.length
  if (end <= cut) return prefix.slice(start, end)
  if (start >= cut) return live.slice(start - cut, end - cut)
  return prefix.slice(start) + live.slice(0, end - cut)
}

/// Is `prefix + live` the body we already folded, with more appended to the end?
function foldIsAppendOf(fold, prefix, live) {
  if (!fold) return false
  if (fold.consumed === 0) return true
  if (prefix.length + live.length < fold.consumed) return false
  return bodySlice(prefix, live, fold.consumed - fold.guard.length, fold.consumed) === fold.guard
}

// Fold one chunk of whole lines onto the running fold. The rules are
// foldRecords': a receipt is not an alert, an update merges onto its base, and
// an update whose base has not arrived is parked until it does.
//
// Returns the number of records that changed the fold, so a chunk of blank
// lines does not churn the alerts array.
function foldChunk(fold, chunk) {
  var records = parseText(chunk)
  var changed = 0
  for (var i = 0; i < records.length; i++) {
    var record = records[i]
    if (isReceipt(record)) {
      // normalizeReceipt's fallback key numbers receipts in file order, which
      // is what a running count is; foldReceipts used `out.length` for the same
      // thing when it saw the whole file at once.
      fold.receipts.push(normalizeReceipt(record, fold.receiptCount))
      fold.receiptCount++
      changed++
      continue
    }
    if (!record || !record.id) continue
    var id = String(record.id)

    if (isUpdate(record)) {
      if (fold.byId[id]) applyUpdate(fold.byId[id], record.update)
      else {
        // Later updates win over earlier ones for the same key, so merging
        // into one parked patch preserves the append-order semantics.
        fold.pending[id] = fold.pending[id] || {}
        applyUpdate(fold.pending[id], record.update)
      }
      changed++
      continue
    }

    if (!fold.byId[id]) fold.order.push(id)
    fold.byId[id] = normalizeAlert(record)
    if (fold.pending[id]) {
      applyUpdate(fold.byId[id], fold.pending[id])
      delete fold.pending[id]
    }
    changed++
  }
  return changed
}

// Cap on remembered ids BEYOND the ones still in the fold. Every folded id is
// always remembered -- that is the whole job -- and on top of those, this many
// rotated-out ids stay suppressed so a re-fold cannot bring one back as new.
// Ids age out oldest-first.
//
// The cap used to apply to the total. With more alerts folded than the cap
// (4,620 once the rotated half was folded too; the cap was 4,096) the
// oldest-first walk in ingestText evicted, on every pass, exactly the ids it
// was about to visit: remembering the oldest id dropped the (cap+1)th, which
// was the next one walked, which was then "new", and so on through the whole
// list. Measured on 2026-09-05: every one of 4,620 alerts came back in
// `newIds` on every ingest, twice a second, and the notifier's linear lookups
// over them were ~500 ms of the GUI thread per reload -- the single largest
// cost in the panel.
var SEEN_LIMIT = 4096

function rememberSeen(store, id, folded) {
  if (store.seen[id]) return
  store.seen[id] = true
  store.seenOrder.push(id)
  var limit = SEEN_LIMIT + (folded > 0 ? folded : 0)
  while (store.seenOrder.length > limit) {
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
  var live = String(text || "")
  var prefix = store.prefix || ""
  var length = prefix.length + live.length
  var reloaded = store.lastLength >= 0 && length < store.lastLength
  store.lastLength = length

  // Anything that is not a strict append re-folds the whole body.
  if (!store.fold || reloaded || !foldIsAppendOf(store.fold, prefix, live)) store.fold = createFold()
  var fold = store.fold

  // Only WHOLE lines are folded. moatd appends "<json>\n", so a body ending
  // mid-line is a read that caught a write in progress: the whole-file parse
  // dropped that line too (parseLine refuses invalid JSON) and picked it up on
  // the next read. Leaving it unconsumed does the same thing without the risk
  // of folding half a record. The prefix always ends in a newline (setLogPrefix
  // sees to it), so a live half with no newline yet ends the body there.
  var newline = live.lastIndexOf("\n")
  var end = newline >= 0 ? prefix.length + newline + 1 : prefix.length
  if (end < fold.consumed) end = fold.consumed

  // One parse, two products: the folded alerts and the install receipts that
  // share the file with them (LEARNING 3). Receipts take no part in newIds, so
  // they cannot notify, and foldChunk keeps them out of `byId`, so they cannot
  // count.
  if (end > fold.consumed) {
    var changed = foldChunk(fold, bodySlice(prefix, live, fold.consumed, end))
    fold.consumed = end
    fold.guard = bodySlice(prefix, live, end > FOLD_GUARD_CHARS ? end - FOLD_GUARD_CHARS : 0, end)
    if (changed > 0) {
      fold.alerts = []
      for (var j = 0; j < fold.order.length; j++) fold.alerts.push(fold.byId[fold.order[j]])
      fold.alerts.sort(compareAlertsNewestFirst)
      fold.receipts.sort(compareReceiptsNewestFirst)
    }
  }

  var alerts = decorateAlerts(fold.alerts, options)
  var initialLoad = !store.primed
  var newIds = []

  // Walk OLDEST first. `alerts` is newest-first, and `rememberSeen` evicts from
  // the front of its queue once SEEN_LIMIT is reached -- so walking forwards
  // remembered the newest id first and then threw it away first. Past 4096
  // folded alerts (this machine reaches ~3,500 between rotations) the most
  // recent ids aged out of `seen` and re-notified as if they were new, which is
  // the exact noise this set exists to prevent.
  //
  // Walking backwards also builds `newIds` oldest-first, which is the order the
  // notifier wants, so the reverse afterwards is no longer needed.
  for (var i = alerts.length - 1; i >= 0; i--) {
    var id = alerts[i].id
    if (!store.seen[id] && !initialLoad) newIds.push(id)
    rememberSeen(store, id, alerts.length)
  }
  store.primed = true

  return {
    alerts: alerts,
    // id -> alert, the fold's own index, so a caller with an id in hand (the
    // notifier, for every id in newIds) does not scan `alerts` for it.
    byId: fold.byId,
    receipts: fold.receipts,
    newIds: newIds,
    initialLoad: initialLoad,
    reloaded: reloaded,
    unacked: unackedCounts(alerts, options)
  }
}

/// The same result as `ingestText`, from alerts moatd has ALREADY folded.
///
/// This is the live path. `ingestText` folds raw JSONL and remains for the
/// tests and as the fallback when the socket is unavailable, but the panel no
/// longer reads the log: quickshell's `FileView` has no read-from-offset, so
/// every append had it re-read the whole file into a JS string and prefix-
/// compare it on the UI thread. On a 9.7 MB log that locked the panel for
/// seconds every time an incident was closed -- and closing appends one line
/// per member, so the biggest cards were the slowest.
///
/// Deliberately returns the identical shape, so everything downstream --
/// decoration, the badge counts, `newIds` and the notifier -- is unchanged and
/// the two paths cannot drift.
function ingestFeed(store, payload, options) {
  var raw = (payload && payload.alerts) || []
  var receipts = (payload && payload.receipts) || []

  // moatd folds; this side only decorates. `byId` is rebuilt here because the
  // notifier looks ids up in it and there is no fold to borrow one from.
  var alerts = decorateAlerts(raw.slice().reverse(), options)
  var byId = {}
  for (var b = 0; b < alerts.length; b++) byId[alerts[b].id] = alerts[b]

  var initialLoad = !store.primed
  var newIds = []
  // Oldest first, for the same reason ingestText walks backwards: rememberSeen
  // evicts from the front, so walking newest-first would remember the newest id
  // and then be the first to forget it.
  for (var i = alerts.length - 1; i >= 0; i--) {
    var id = alerts[i].id
    if (!store.seen[id] && !initialLoad) newIds.push(id)
    rememberSeen(store, id, alerts.length)
  }
  store.primed = true

  return {
    alerts: alerts,
    byId: byId,
    receipts: receipts,
    newIds: newIds,
    initialLoad: initialLoad,
    // A socket read is never a partial file, so there is no rotation to detect.
    reloaded: false,
    unacked: unackedCounts(alerts, options)
  }
}

/// Hand the store the rotated half of the log, alerts.1.jsonl, once. From then
/// on ingestText takes the LIVE file alone and folds it as if it were appended
/// to this text -- which is what it is: an update in the live file lands on a
/// record that was rotated out, exactly as in `AlertStore::load`. A panel
/// folding only the live file disagreed with `moatctl status` about what was
/// outstanding after every rotation.
///
/// A prefix that differs from the one held (a rotation, or the file appearing
/// or vanishing) drops the fold; the next ingest rebuilds it over the new
/// body. Returns whether anything changed.
function setLogPrefix(store, text) {
  var prefix = String(text || "")
  if (prefix && prefix.charAt(prefix.length - 1) !== "\n") prefix += "\n"
  if (prefix === (store.prefix || "")) return false
  store.prefix = prefix
  store.fold = null
  return true
}

/// The whole alert log, the way moatd reads it back: the rotated file first,
/// then the live one (`AlertStore::load` folds `[rotated, path]` in that
/// order). An update in the live file -- an ack, a chain written back onto
/// its first step -- then lands on a record that was rotated out, exactly as
/// it does in the daemon. A panel folding only the live file disagreed with
/// `moatctl status` about what was outstanding after every rotation.
function logBody(rotated, current) {
  var a = String(rotated || "")
  var b = String(current || "")
  if (!a) return b
  return (a.charAt(a.length - 1) === "\n" ? a : a + "\n") + b
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
//
// Demotion now arrives THREE ways, and the third is per-alert rather than
// per-rule: the noise guard's live `status.demoted_rules[]`, an alert's own
// "demoted:<rule>" marker, and LEARNING 2c's agent verdict on this one alert.
// Deriving the tab from rule and severity alone would have silently discarded
// the third — the daemon sets `surface: "timeline"` on a triage demotion and
// this function never read `alert.surface`, so an auto-triaged alert would have
// stayed in the badge and the feature would have done nothing visible.
// =====================================================================
// ONE DECISION, ONE FUNCTION.
//
// "Does this alert want something from the user?" is answered by
// `alertSurface` and by nothing else. Everything downstream -- the badge
// (`unackedCounts`), the tab (`surfaceAlerts`), incidents (`alertState`, and
// through it the bar glyph and `shouldNotify`) -- calls it rather than
// re-deriving from severity.
//
// This is written down because it was learned the expensive way. On
// 2026-09-04 there were FOUR copies of that derivation in this file, each with
// slightly different inputs. They disagreed: the shield read 51, the daemon
// had surfaced 8, and a live supply-chain exec was buried under 251 alerts the
// daemon had deliberately put on the timeline. Every copy was individually
// reasonable; the bug was that there were four.
//
// The daemon is upstream of all of it -- it stamps `surface` when it raises an
// alert, knowing the noise-guard state at that instant. The panel's job is to
// read that, not to re-litigate it from whatever the global state says now.
//
// If you need this decision somewhere new: call `alertSurface`. Do not write
// `severityAtLeast(..., "high")` next to a demotion check again.
// =====================================================================
function alertSurface(alert, demotedRules) {
  if (!alert) return SURFACE_TIMELINE
  if (alert.suppressed_by) return SURFACE_TIMELINE
  if (alert.triage && alert.triage.demoted) return SURFACE_TIMELINE

  // `status.demoted_rules` is deliberately NOT read here any more.
  //
  // It used to be: "a demotion in force NOW applies retroactively". But that
  // list is the one a PERSON wants -- every rule quietened in any way, a rule
  // with one noisy pattern included -- while the daemon's own demotion is
  // per pattern, and the daemon re-surfaces a demoted rule's alert on purpose
  // when a chain that reaches `high` needs it on the badge. Applying the
  // rule-wide list here overruled both: on 2026-09-05 a 64-step chain the
  // daemon had raised to `high` and stamped `surface: "alerts"` on read
  // "expected" in the panel, because its rules were in that list. The same
  // shape hid a live AUR attack the day before, from the other side.
  //
  // The daemon now quietens the backlog itself when the noise guard demotes
  // (it restamps `surface` on the alerts the demotion covers, and only those),
  // so retroactivity no longer needs a second implementation here. What is
  // left is the rule this file already states: the daemon stamped `surface`
  // knowing everything, and the panel reads it.
  //
  // The reverse stays asymmetric: an alert the daemon put on the timeline
  // STAYS there — clearing a demotion means "watch this rule again", which is
  // a statement about future alerts, not an instruction to resurrect a
  // backlog. On 2026-09-04 the symmetric version re-surfaced 251 alerts,
  // turned 8 real incidents into 51, and buried a live supply-chain exec.
  if (alert.surfaceStamped === true) {
    return alert.surface === SURFACE_ALERTS ? SURFACE_ALERTS : SURFACE_TIMELINE
  }
  // No stamp: a record from before the daemon wrote `surface`. Only here does
  // the live list stand in for the stamp the daemon would have made, and only
  // here does severity.
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
    alert.demoted = isDemotedRule(alert.rule, set)
                    || isDemotionMarker(alert.suppressed_by)
                    || (alert.triage && alert.triage.demoted === true)
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
    // ONE predicate for "is this waiting on the user": unacked, and on the
    // Alerts surface as `alertSurface` decides it (which already covers
    // suppression, a triage demotion and the daemon's own stamp). The
    // per-severity counts used to be taken BEFORE that check, so `high` and
    // `total` counted timelined alerts the badge did not -- `widgetState`
    // went red over a badge of 0, and "N unacked" in the status line was a
    // different N from the shield. Every number here is now the same set,
    // split by severity; `total` and `badge` are one number.
    if (alertSurface(alert, set) !== SURFACE_ALERTS) continue
    var severity = String(alert.severity || "").toLowerCase()
    if (counts[severity] === undefined || severity === "total" || severity === "badge") continue
    counts[severity]++
    counts.total++
    counts.badge++
  }
  return counts
}

/// Do two unacked-count objects say the same thing?
///
/// `unackedCounts` allocates a fresh object every ingest, and a `var` property
/// assignment fires its change signal on identity, not on value — so writing an
/// equal-but-new object re-ran the shield glyph, the badge and the status
/// summary on every re-read of a file that had not changed. Compared by field
/// rather than by JSON so it stays cheap and does not depend on key order.
function sameCounts(a, b) {
  if (a === b) return true
  if (!a || !b) return false
  return a.critical === b.critical && a.high === b.high && a.medium === b.medium
    && a.low === b.low && a.total === b.total && a.badge === b.badge
}

// The number on the shield. Prefers the `badge` unackedCounts computed (which
// already excluded demoted and suppressed alerts); falls back to critical+high
// for the daemon's own `status.unacked`, which has no such field and is only
// used when the log is unreadable.
/// The number on the shield, from the two things that can answer it.
///
/// DECISIONS when the alert log is readable -- `needsYouIncidents` is what
/// `NowView` renders, and a chain puts every trigger member on the badge, so
/// counting rows counted one story once per step. Measured 2026-09-08: 77
/// badge rows held 28 members of 15 chains, and the honest answer was 64. The
/// daemon has always agreed with the cards (`store::ledger` counts `needs you`
/// by `incident_key`); only the shield disagreed.
///
/// ROWS when it is not: there are no incidents to group without the log, and
/// the daemon's own `status.unacked` is then the best answer available. A
/// number that is slightly wrong beats a shield that reads "all clear" because
/// it could not see anything.
///
/// Lives here rather than in Service.qml because Service imports Quickshell and
/// cannot be instantiated by qmltestrunner -- a decision made there is a
/// decision no test can reach.
function shieldCount(needsYou, unacked, logReadable) {
  if (logReadable) return Array.isArray(needsYou) ? needsYou.length : 0
  return badgeCount(unacked)
}

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

  // 1f's third answer to "when should Moat interrupt you?". It is checked
  // FIRST and it is checked here, ahead of every exception below -- including
  // the noise guard's -- because "never" that has exceptions is not never.
  if (options && options.notifyMuted === true) return false

  // A suppressed alert was written to the log purely so the timeline can show
  // it greyed out (BASELINE 8). Toasting it would defeat the suppression.
  if (alert.suppressed_by) return false

  // A demoted rule "still logged, never notifies" (BASELINE 4.1). That is a
  // fact about the alert's SURFACE, which the daemon stamped and `alertState`
  // below reads; it is no longer re-derived from the rule-wide list here,
  // because that list silenced a chain the daemon had deliberately raised.
  // The one thing the list still decides is whether the noise guard's OWN
  // announcement has been demoted into silence: that alert is medium and so
  // always on the timeline, so the surface cannot carry that fact for it.
  if (String(alert.rule || "") === NOISY_RULE_ALERT
      && isDemotedRule(alert.rule, options && options.demotedRules)) return false

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

  // 2h: three notification shapes, and ONLY needs-you may interrupt. An alert
  // an unattended agent pass has already read and called benign is `explained`
  // -- Moat decided, the user may look -- and interrupting for a decision that
  // has already been made is how someone learns to dismiss the toast that
  // matters. It is still in the panel, still counted, still in History.
  //
  // Checked after the noise guard so its own announcement keeps its exception,
  // and after the demotion checks so the cautious answers still win.
  if (alertState(alert, options && options.demotedRules) !== "needsYou") return false

  // Effective severity is the max of the alert's OWN severity and the
  // severity of the chain it belongs to. A cred read (medium) and a first
  // contact (low) that together form a high exfil chain each stay quiet on
  // their own account -- but the sequence they make is high, and the whole
  // point of a chain is that the sequence is the thing worth interrupting for.
  // Gating only on the member severity meant moat detected the exfil, put a
  // high chain on the badge, and never told the user (2026-09-06 reportkit
  // test). `notifyDecision` collapses the members to one toast per chain.
  var eff = alert.severity
  if (alert.chain && severityRank(alert.chain.severity) > severityRank(eff))
    eff = alert.chain.severity
  return severityAtLeast(eff, minSeverity)
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
    store.notifyPending.push({ rule: window.rule, title: window.title,
                               program: window.program, count: window.suppressedCount })
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

  // One toast per chain, not one per member. The members of a high chain are
  // eligible via the effective-severity rule in `shouldNotify`; without this a
  // two-member exfil chain would toast twice (once for the cred rule, once for
  // the net rule). Keyed on the chain id in the store's seen-set, so a chain
  // that grows and republishes still interrupts exactly once.
  var chainId = alert.chain && alert.chain.id ? String(alert.chain.id) : ""
  if (chainId && severityRank(alert.chain.severity) > severityRank(alert.severity)) {
    if (!store.notifiedChains) store.notifiedChains = {}
    if (store.notifiedChains[chainId])
      return { toast: false, collapsed: 0, reason: "chain-already-toasted" }
    store.notifiedChains[chainId] = true
    return { toast: true, collapsed: 0, reason: "chain" }
  }

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
        // 2h's burst title names the PROGRAM, not the rule id: "Claude tripped
        // the same detection 40 more times".
        program: incidentProgram(alert),
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
      out.push({ rule: due[i].rule, title: due[i].title,
                 program: due[i].program, count: due[i].suppressedCount })
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
  // Leads with the exposure and a PROPORTIONATE first step. "Change every
  // password saved in that browser profile" is true, is what a thorough
  // response looks like, and is an instruction essentially nobody carries out
  // -- so as the opening words it reads as noise and costs the whole block its
  // credibility. The reused ones are where the actual risk is.
  "browser-passwords": "That profile's saved logins were readable: the database is decryptable with the keyring that process could reach. Change any you reused elsewhere first, then the rest as you get to them.",
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

// ------------------------------------------------------------ Advanced mode
//
// The `rawDetail` setting: the panel in the detection's own words, for a reader
// who would rather see what the sensor recorded than what Moat made of it.
//
// Everything below is PRESENTATION. None of it is read by `alertSurface`,
// `alertState`, `shouldNotify` or `unackedCounts`, and none of it changes what
// the daemon does -- the state words still decide the surface, and Advanced
// only decides how much of the record is printed beside them.

/// The parent chain as one line per process, full paths and pids, oldest first.
///
/// `ancestryChain` collapses the same data to basenames joined by arrows, which
/// is the right thing in the default voice and the wrong thing here: two
/// different /usr/bin/python3 are the same word in that rendering.
function ancestryLines(alert) {
  var process = alert && alert.process ? alert.process : {}
  var ancestry = Array.isArray(process.ancestry) ? process.ancestry : []
  var out = []
  // ancestry is nearest-parent-first, so walk it backwards for oldest -> newest.
  for (var i = ancestry.length - 1; i >= 0; i--) {
    var a = ancestry[i] || {}
    out.push(String(a.pid === undefined ? "?" : a.pid) + "  " + String(a.exe || "?"))
  }
  if (process.exe || process.pid) {
    out.push(String(process.pid === undefined ? "?" : process.pid) + "  " + String(process.exe || "?"))
  }
  return out
}

/// The label/value pairs Advanced adds, flattened so one Repeater fills a
/// two-column Grid -- the same shape `EvidenceBlock.facts()` already uses.
///
/// Only fields the daemon actually sends (CONTRACT 4). The hook that fired and
/// the policy name are not structured fields on the record: moatd writes them
/// into `explain.evidence[]` as its own sentences, which is why Advanced opens
/// the evidence rather than trying to reconstruct them.
function rawFacts(alert) {
  var a = alert
  if (!a) return []
  var out = []
  function add(label, value) {
    var text = String(value === undefined || value === null ? "" : value)
    if (text) { out.push(label); out.push(text) }
  }
  add("id", a.id)
  add("ts", a.ts)
  add("rule", a.rule)
  add("family", a.family)
  add("severity", rawSeverityLine(a))
  add("surface", a.surface)
  add("mode", a.mode)
  add("action_taken", a.action_taken)
  add("count", a.count)
  var p = a.process || {}
  add("exe", p.exe)
  add("pid", p.pid > 0 ? p.pid : "")
  // uid 0 is root and is the single most interesting uid there is, so this
  // tests against the -1 that normalizeAlert uses for "not recorded".
  add("uid", p.uid >= 0 ? p.uid : "")
  add("args", p.args)
  add("cwd", p.cwd)
  add("start_ts", p.start_ts)
  add("ancestry", ancestryLines(a).join("\n"))
  if (a.file) {
    add("file", a.file.path)
    add("sha256", a.file.sha256)
  }
  if (a.net) {
    add("dst", String(a.net.dst_ip || "") + (a.net.dst_port ? ":" + a.net.dst_port : ""))
    add("domain", a.net.domain)
  }
  add("rarity", a.rarity)
  add("rarity_text", a.rarity_text)
  add("actor", a.actor ? a.actor.provenance : "")
  add("package", a.actor ? a.actor.package : "")
  add("script", a.actor ? a.actor.script : "")
  add("context", a.context)
  add("suppressed_by", a.suppressed_by)
  if (a.incident && a.incident.dir) add("incident_dir", a.incident.dir)
  return out
}

/// "high  (base medium — <reason>)", or just the severity when nothing moved
/// it. Advanced shows severity AS severity: `severityChangeLine` is written for
/// the default voice and says nothing at all when base and current agree, which
/// is the common case and exactly the case an engineer still wants printed.
function rawSeverityLine(alert) {
  if (!alert) return ""
  var now = String(alert.severity || "")
  var base = String(alert.severity_base || "")
  var reason = String(alert.severity_reason || "")
  if (!base || base === now) return reason ? now + "  (" + reason + ")" : now
  return now + "  (base " + base + (reason ? " — " + reason : "") + ")"
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
    // Why this is being offered. Empty is the ordinary route -- a recurring,
    // official, medium/low pattern the baseline is confident about. Non-empty
    // means Moat is NOT vouching for it, and the card must say so: the TOML
    // block looks identical either way, and accepting one writes a permanent
    // allowlist entry. Whitelisted here explicitly, because a field this
    // function forgets is a field that vanishes in silence -- which is how
    // `chain`, `triage` and `surface` went missing from UPDATABLE.
    reason: String(p.reason || ""),
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

/// The rules that can be armed, as the daemon reports them.
///
/// Normalised the same way every other daemon list is: unknown shapes are
/// dropped rather than rendered, and `enforce` is an enum the panel either
/// knows or discards -- a row whose consequence line the panel cannot write is
/// a switch whose effect it cannot state, and that must never be offered.
/// What moatd is refusing on its own judgement right now.
///
/// A containment is the one thing moat does without being asked rule by rule,
/// so the panel has to be able to show it and undo it. A row the panel cannot
/// describe -- no chain to release, no destination to name -- is dropped rather
/// than drawn as a mystery the user cannot act on.
/// `{policy: [exe, ...]}` from the daemon, flattened into rows the panel can
/// draw and undo one at a time.
/// `moat-cred-etc-shadow-read` -> `cred-etc-shadow-read`. For labels that have
/// to name a rule without spending a whole line on the prefix every rule has.
function shortRule(rule) {
  return String(rule || "").replace(/^moat-/, "")
}

function normalizeExclusions(raw) {
  var out = []
  if (!raw || typeof raw !== "object") return out
  for (var rule in raw) {
    var bins = raw[rule]
    if (!Array.isArray(bins)) continue
    for (var i = 0; i < bins.length; i++) {
      var exe = String(bins[i] || "").trim()
      if (rule && exe) out.push({ rule: String(rule), exe: exe })
    }
  }
  return out
}

function normalizeContained(raw) {
  var list = Array.isArray(raw) ? raw : []
  var out = []
  for (var i = 0; i < list.length; i++) {
    var c = list[i]
    if (!c || typeof c !== "object") continue
    var chain = String(c.chain || "")
    var dests = []
    var raw2 = Array.isArray(c.dests) ? c.dests : []
    for (var j = 0; j < raw2.length; j++) {
      var d = String(raw2[j] || "").trim()
      if (d) dests.push(d)
    }
    if (!chain || dests.length === 0) continue
    out.push({
      chain: chain,
      exe: String(c.exe || ""),
      dests: dests,
      expires: Number(c.expires) || 0
    })
  }
  return out
}

function normalizeEnforceable(raw) {
  var list = Array.isArray(raw) ? raw : []
  var out = []
  for (var i = 0; i < list.length; i++) {
    var r = list[i]
    if (!r || typeof r !== "object") continue
    var rule = String(r.rule || "")
    var kind = String(r.enforce || "")
    if (!rule || (kind !== "kill" && kind !== "deny")) continue
    out.push({
      rule: rule,
      enforce: kind,
      title: String(r.title || rule),
      severity: String(r.severity || ""),
      armed: r.armed === true
    })
  }
  return out
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
    // Whitelisted like everything else here, which is why it has to be added
    // explicitly: `normalizeStatus` builds a NEW object, so a field nobody
    // lists is dropped in silence. That is the same fault that swallowed
    // `chain`, `triage` and `surface` in `UPDATABLE` -- the section that reads
    // this rendered empty and looked like a layout bug.
    enforceable: normalizeEnforceable(s.enforceable),
    // Whitelisted explicitly, like everything else that crosses this function.
    containEnabled: s.contain_enabled === true,
    // Whitelisted too -- this is the field that says whether moatd may end a
    // process tree, and a field this function drops reads as its default
    // everywhere downstream. An unknown value falls back to "log", which is
    // the safe direction: it can only under-report what moatd will do.
    containKill: (s.contain_kill === "off" || s.contain_kill === "kill")
      ? s.contain_kill : "log",
    contained: normalizeContained(s.contain),
    // Whitelisted like everything else that crosses this function. A rule with
    // a binary excluded from it has a hole in it, and a hole nobody can see is
    // the thing to avoid: it lives inside a rendered policy in /run/moat that
    // no one will ever open.
    exclusions: normalizeExclusions(s.kernel_exclusions),
    // How many of those the kernel is actually running. null when moatd could
    // not read bpffs, which is "cannot tell", not "none".
    // LEARNING 2c: `off` | `annotate` | `demote`, and how many surfaced alerts
    // have not been looked at yet. The panel uses these to say "reading the
    // evidence…" rather than showing an incident with a silently empty verdict.
    autoTriage: String(s.auto_triage || "off"),
    triagePending: Number(s.triage_pending) || 0,
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
    // When moatd first ran here. It is what turns "learning ends on Thursday"
    // into "day 2 of 9" -- the design's learning card is a progress bar, and a
    // progress bar needs both ends of the window (1g).
    installed_at: String(s.installed_at || ""),
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
  // `script` is in this list since 2026-09-07. It is the matcher that says
  // what an INTERPRETER was running, and an entry that has one and no `exe`
  // (the shape `moatctl allow --script` writes) rendered as a rule with no
  // matcher lines at all -- a grant the panel showed as covering everything.
  var fields = [["exe", r.exe], ["script", r.script], ["file", matchFile],
                ["parent", r.parent],
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
    // The matcher fields themselves, not just the rendered `detail` line. 1e
    // groups by the PROGRAM a rule is about and 2e joins on (rule, exe), and
    // neither can be done by parsing "exe = /usr/bin/ssh" back out of a string
    // that was built for display.
    exe: String(r.exe === undefined || r.exe === null ? "" : r.exe),
    path: String(matchFile === undefined || matchFile === null ? "" : matchFile),
    parent: String(r.parent === undefined || r.parent === null ? "" : r.parent),
    script: String(r.script === undefined || r.script === null ? "" : r.script),
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

// The label never carries the agent's own name.
//
// Two reasons, and the second is the load-bearing one. It is the wrong noun:
// `omarchy default agent` may be claude, codex, opencode or anything else, and
// Moat has no business putting one vendor's name on its own button. And it is
// the wrong promise: the design's "Ask Moat" (2a) is a thread INSIDE the panel,
// which the daemon has no endpoint for -- what this actually does is hand the
// evidence bundle to `omarchy-agent`, which opens a terminal. The label says
// that, so nobody presses it expecting a conversation in the panel.
//
// The specific agent belongs in the tooltip, which is evidence, not a promise.
function analyzeLabel(agent) {
  return normalizeAgentName(agent) ? "Open in the Omarchy agent" : ""
}

/// The tooltip: which agent, and that it leaves the panel.
function analyzeTooltip(agent) {
  var name = normalizeAgentName(agent)
  if (!name) return ANALYZE_HINT
  return "Writes the evidence bundle and opens it in " + name +
         ", in a terminal window. This panel closes."
}

// Shown in place of the button when no default agent is set. Naming the exact
// command is the difference between a disabled control and a next step.
var ANALYZE_HINT = "Set a default agent: omarchy default agent <name>"

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

// ==========================================================================
//  1c -- the silence choice
// ==========================================================================
//
// The scopes come from the DAEMON: `explain.if_expected.options[]` is the list
// of scopes it is prepared to write for this alert, each with the exact TOML it
// would append. Nothing here invents one, and nothing here composes a rule --
// an action still names an alert id and a scope the daemon offered, which is
// the whole reason `Service._argvFor` can stay four verbs wide.

/// The parent program, as a person would name it: the nearest ancestor's
/// basename. Used for the "anything makepkg starts" chip.
function parentProgram(alert) {
  var ancestry = alert && alert.process && Array.isArray(alert.process.ancestry)
    ? alert.process.ancestry : []
  if (ancestry.length === 0) return ""
  return basename(ancestry[0] && ancestry[0].exe)
}

/// The chips for 1c, in the order they are drawn: the recommendation first,
/// then narrowest to broadest, and the machine-wide one ALWAYS last however the
/// daemon ordered or recommended them. It is the one choice whose consequences
/// the user cannot see from this screen, so it never gets the first position
/// and it never arrives pre-selected.
function silenceScopes(alert, count) {
  var options = ignoreOptions(alert)
  var program = incidentProgram(alert)
  var parent = parentProgram(alert)
  var out = []
  for (var i = 0; i < options.length; i++) {
    var o = options[i]
    var broadest = Copy.scopeIsBroadest(o.scope)
    out.push({
      scope: o.scope,
      line: o.line,
      cmd: o.cmd,
      recommended: o.recommended && !broadest,
      broadest: broadest,
      label: Copy.scopeChipLabel(o.scope, program, parent),
      consequence: Copy.scopeConsequence(o.scope, program, parent, count)
    })
  }
  out.sort(function (a, b) {
    if (a.broadest !== b.broadest) return a.broadest ? 1 : -1
    if (a.recommended !== b.recommended) return a.recommended ? -1 : 1
    return IGNORE_SCOPES.indexOf(a.scope) - IGNORE_SCOPES.indexOf(b.scope)
  })
  return out
}

// ==========================================================================
//  1d -- History
// ==========================================================================
//
// Severity stops being a pill on every row and becomes a 3px tick plus the
// brightness of the title, so a page of history carries at most one red mark.
// The counts a person actually scans for move into the day header.

var HISTORY_FILTERS = ["everything", "needsYou", "covered"]

function historyFilterLabel(filter) {
  switch (String(filter || "")) {
  case "needsYou": return "Needed you"
  case "covered": return "Silenced by a rule"
  default: return "Everything"
  }
}

function filterHistory(incidents, filter) {
  var list = Array.isArray(incidents) ? incidents : []
  var want = String(filter || "everything")
  var out = []
  for (var i = 0; i < list.length; i++) {
    var state = list[i] ? list[i].state : ""
    if (want === "needsYou") {
      if (state === "needsYou" || state === "contained") out.push(list[i])
    } else if (want === "covered") {
      if (state === "expected") out.push(list[i])
    } else {
      out.push(list[i])
    }
  }
  return out
}

/// Local calendar day of an ISO stamp, as "YYYY-MM-DD". Local, not UTC: a
/// person's "today" ends when they go to bed, not at 00:00Z.
function dayKeyOf(iso) {
  var ms = Date.parse(String(iso || ""))
  if (!isFinite(ms)) return ""
  return dayKeyOfMs(ms)
}

function dayKeyOfMs(ms) {
  var d = new Date(Number(ms))
  var m = d.getMonth() + 1
  var day = d.getDate()
  return d.getFullYear() + "-" + (m < 10 ? "0" + m : m) + "-" + (day < 10 ? "0" + day : day)
}

var WEEKDAYS = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"]
var MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
              "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]

/// "Today" / "Yesterday" / "Friday" / "22 Aug" -- the way a person names a day
/// they are trying to remember: by how recent it was, then by its weekday, and
/// only by a date once the weekday has stopped being useful.
function dayLabelFor(iso, nowMs) {
  var ms = Date.parse(String(iso || ""))
  if (!isFinite(ms)) return "Earlier"
  var now = nowMs === undefined || nowMs === null ? Date.now() : Number(nowMs)
  var key = dayKeyOfMs(ms)
  if (key === dayKeyOfMs(now)) return "Today"
  if (key === dayKeyOfMs(now - 86400000)) return "Yesterday"
  var d = new Date(ms)
  if (now - ms < 7 * 86400000) return WEEKDAYS[d.getDay()]
  return d.getDate() + " " + MONTHS[d.getMonth()]
}

/// The day header's counts. Incidents, never events -- the whole redesign is
/// that a number in this panel is a number of decisions.
function daySummary(counts) {
  var c = counts || {}
  var parts = []
  if (c.needed > 0) parts.push(c.needed + " needed you")
  else parts.push("nothing needed you")
  if (c.contained > 0) parts.push(c.contained + " you stopped")
  if (c.explained > 0) parts.push(c.explained + " explained")
  if (c.covered > 0) parts.push(c.covered + (c.covered === 1 ? " covered by a rule"
                                                             : " covered by rules"))
  if (c.closed > 0) parts.push(c.closed + " closed")
  return parts.join("  ·  ")
}

/// Incidents grouped into day sections, newest day first.
function historyDays(incidents, nowMs) {
  var list = Array.isArray(incidents) ? incidents : []
  var byKey = {}
  var order = []
  for (var i = 0; i < list.length; i++) {
    var inc = list[i]
    if (!inc) continue
    var key = dayKeyOf(inc.lastSeen) || "unknown"
    var group = byKey[key]
    if (!group) {
      group = {
        key: key,
        label: dayLabelFor(inc.lastSeen, nowMs),
        incidents: [],
        needed: 0, explained: 0, covered: 0, contained: 0, closed: 0
      }
      byKey[key] = group
      order.push(group)
    }
    group.incidents.push(inc)
    // One bucket per state, and NOTHING falls through to "explained". The
    // catch-all `else` this used to end with counted every `closed` incident
    // -- an alert the user acked with no verdict on it -- as "explained", so
    // the day header said "3 explained" over three rows whose state word was
    // "closed" and whose card had never been read by anything. The header and
    // the rows classify with the same `state`; they must bucket it the same.
    if (inc.state === "needsYou") group.needed++
    else if (inc.state === "contained") group.contained++
    else if (inc.state === "expected") group.covered++
    else if (inc.state === "explained") group.explained++
    else group.closed++
  }
  for (var j = 0; j < order.length; j++) order[j].summary = daySummary(order[j])
  order.sort(function (a, b) { return a.key < b.key ? 1 : (a.key > b.key ? -1 : 0) })
  return order
}

/// How many events Moat looked at TODAY -- the number under the verdict line.
///
/// "Today" is decided by the same `dayKeyOf(lastSeen)` that files an incident
/// under History's "Today" header, so the two screens count the same rows.
/// The Now page used to sum `count` over every incident in the log and print
/// it after the word "today": on a log that spans a rotation window that is
/// several days of events under a one-day label, and at 00:01 it is all of
/// yesterday.
function seenToday(incidents, nowMs) {
  var now = nowMs === undefined || nowMs === null ? Date.now() : Number(nowMs)
  var today = dayKeyOfMs(now)
  var list = Array.isArray(incidents) ? incidents : []
  var seen = 0
  for (var i = 0; i < list.length; i++) {
    var inc = list[i]
    if (!inc || dayKeyOf(inc.lastSeen) !== today) continue
    seen += Number(inc.count) || 0
  }
  return seen
}

/// What gets appended to a history row's title in a dimmer colour: how many
/// times, and whose decision silenced it.
function historyNote(incident) {
  var inc = incident || {}
  var bits = []
  // 3a's marker, in the place a repeat count occupies: a chain row is not "one
  // thing that happened twice", it is several different things Moat put
  // together, and a History row that does not say so reads as a single alert.
  if (inc.chain) bits.push("a sequence of " + (Number(inc.chain.steps_total) || inc.chain.steps.length))
  var repeat = Copy.repeatPhrase(inc.family, inc.count)
  if (repeat && !inc.chain) bits.push(repeat)
  var phrase = Copy.coveredByPhrase(inc.coveredBy)
  if (phrase) bits.push(phrase)
  return bits.length ? "·  " + bits.join("  ·  ") : ""
}

// ==========================================================================
//  1e -- Rules
// ==========================================================================

/// The program a rule is about, as a person would name it.
/// The program an allowlist entry actually grants.
///
/// `script` before `exe`, because for an entry written against an interpreter
/// `exe` is `/usr/bin/python3.14` and the program the user meant is
/// `gcloud.py`. A `script`-only entry (the shape `moatctl allow --script`
/// writes) has no `exe` at all, and before 2026-09-07 rendered as an empty
/// program name in the Rules tab -- a grant with nothing readable next to it.
function ruleProgram(rule) {
  var r = rule || {}
  var s = String(r.script || "").replace(/\*+$/, "")
  if (s) {
    return basename(s)
  }
  return basename(String(r.exe || "").replace(/\*+$/, ""))
}

/// The detection family a rule id belongs to: `moat-<family>-<what>`.
function ruleFamily(name) {
  var m = /^moat-([a-z0-9]+)-/.exec(String(name || ""))
  return m ? m[1] : "other"
}

/// /home/dan/.config -> ~/.config. The model has no $HOME and does not need
/// one: every path moatd reports for a user's own files is under /home/<name>.
function shortenHome(path) {
  return String(path || "").replace(/^\/home\/[^\/]+/, "~").replace(/^\/root/, "~")
}

/// The verb a detection family grants, split from the place it grants it over.
///
/// `prefix` is present only for the families whose permission is ABOUT a
/// directory; `none` is what the family says when there is no directory to name
/// (and, for the others, the whole sentence). Kept apart from `ruleScopeWords`
/// so a program with eight learned directories can say the verb once and count
/// the places, instead of printing the verb eight times -- see `scopePhrase`.
function ruleScopeVerb(name) {
  switch (ruleFamily(name)) {
  case "cred": return { none: "reading your keys" }
  case "persist": return { prefix: "writing under", none: "writing where things start at login" }
  case "pkg": return { none: "running during package installs" }
  case "exec": return { prefix: "running from", none: "running from unusual places" }
  case "net": return { none: "connecting out" }
  case "priv": return { none: "asking for more access" }
  case "rootkit": return { none: "touching the kernel" }
  case "ransom": return { none: "destroying files or snapshots" }
  case "shell": return { none: "opening a shell" }
  case "ai": return { none: "running during package installs" }
  default: return { prefix: "touching", none: "what it was flagged for" }
  }
}

/// The deepest directory every path in `dirs` sits under, or "" when they share
/// nothing worth naming. "/" and "~" alone are treated as nothing: "5 places
/// under /" tells a reader less than "5 places" does, and costs them a word.
function commonParentDir(dirs) {
  var list = []
  for (var i = 0; i < (dirs || []).length; i++) {
    if (dirs[i]) list.push(String(dirs[i]))
  }
  if (list.length === 0) return ""
  var parts = list[0].split("/")
  for (var j = 1; j < list.length; j++) {
    var other = list[j].split("/")
    var n = 0
    while (n < parts.length && n < other.length && parts[n] === other[n]) n++
    parts = parts.slice(0, n)
  }
  var joined = parts.join("/")
  if (joined === "" || joined === "/" || joined === "~") return ""
  return joined
}

/// One family's permission for one program, as a sentence.
///
/// The tuple-per-line version printed the verb once per directory and then ran
/// out of row: "running from /tmp/moat-sandbox-test.*/home/proj, running from
/// /tmp/moat-sandbox-test.LKurquBA/home/proj, a…" -- three quarters of the cell
/// spent re-reading "running from", and the paths cut off just before the part
/// where they differed. Two or more places are counted and placed instead.
function scopePhrase(entry) {
  var e = entry || {}
  var dirs = e.dirs || []
  if (!e.prefix || dirs.length === 0) return e.none
  if (dirs.length === 1) return e.prefix + " " + dirs[0]
  var parent = commonParentDir(dirs)
  return e.prefix + " " + dirs.length + " places" + (parent ? " in " + parent : "")
}

/// What a rule lets a program do, in plain words. This is the "trusted for"
/// column in 2e and half the title in 1e, and it is derived from the detection
/// family and the path the rule matches rather than printed as a matcher.
function ruleScopeWords(name, path) {
  var dir = shortenHome(String(path || "").replace(/\/?\*+$/, ""))
  var verb = ruleScopeVerb(name)
  return verb.prefix && dir ? verb.prefix + " " + dir : verb.none
}

/// "you added this on 2026-09-03" -- the provenance line under a rule in 1e,
/// parsed out of the comment moatd writes into the TOML.
///
/// A comment it cannot parse is a HAND-WRITTEN one, so it is shown as-is: that
/// is the user's own sentence about their own rule. A machine-written one it
/// cannot parse is dropped rather than printed, because those are the ones that
/// carry alert ids and file paths.
function ruleProvenance(rule) {
  var r = rule || {}
  var comment = String(r.comment || "")
  var added = /^added\s+(\d{4}-\d{2}-\d{2})/.exec(comment)
  if (added) return "you added this on " + added[1]
  var learned = /^learned\s+(\d{4}-\d{2}-\d{2}):\s*seen\s+(\d+)\s+times?/.exec(comment)
  if (learned) {
    return "Moat learned this on " + learned[1] + ", after " + learned[2] + " alerts"
  }
  if (/^(added|learned)\b/.test(comment)) return ""
  return comment
}

/// Per (rule, exe) alert counts out of a baseline export, for the
/// silenced-since column.
function silencedCounts(tuples) {
  var list = Array.isArray(tuples) ? tuples : []
  var out = {}
  for (var i = 0; i < list.length; i++) {
    var t = list[i]
    if (!t) continue
    var key = String(t.rule || "") + " " + String(t.exe || "")
    out[key] = (out[key] || 0) + (Number(t.count) || 0)
  }
  return out
}

/// The "Yours" section of 1e: the rules the user's own decisions wrote, each
/// with the count of what it has actually silenced since.
///
/// That count is the honest measure of whether a rule was a good idea, and it is
/// the ONLY way a user can tell. It comes from the baseline's own per-tuple
/// counters (`moatctl baseline export`), which keep counting a tuple after an
/// allowlist entry starts hiding it -- which is exactly what makes them the
/// right number to put here.
function userRuleRows(rules, tuples) {
  var list = Array.isArray(rules) ? rules : []
  var counts = silencedCounts(tuples)
  var out = []
  for (var i = 0; i < list.length; i++) {
    var r = list[i]
    if (!r || r.shipped) continue
    var program = ruleProgram(r)
    var silenced = counts[String(r.name || "") + " " + String(r.exe || "")]
    out.push({
      index: r.index,
      file: r.sourceName,
      sourceFile: r.sourceFile,
      removable: r.removable,
      learned: r.learned,
      program: program,
      label: (program || "A program") + ", " + ruleScopeWords(r.name, r.path || r.file),
      provenance: ruleProvenance(r),
      binary: String(r.exe || ""),
      // -1, not 0: "the daemon is not counting this one" and "it has silenced
      // nothing" are different answers, and the view says them differently.
      silenced: silenced === undefined ? -1 : silenced,
      line: r.line,
      rule: String(r.name || "")
    })
  }
  return out
}

/// The "Came with Moat" section: sixteen near-identical cards become about five
/// lines, grouped by the programs they cover rather than by detection.
function shippedRuleGroups(rules) {
  var list = Array.isArray(rules) ? rules : []
  var byKey = {}
  var order = []
  for (var i = 0; i < list.length; i++) {
    var r = list[i]
    if (!r || !r.shipped) continue
    var group = Copy.programGroup(ruleProgram(r))
    var g = byKey[group.key]
    if (!g) {
      g = { key: group.key, label: group.label, reason: group.reason, count: 0, rules: [] }
      byKey[group.key] = g
      order.push(g)
    }
    g.count++
    g.rules.push(r)
  }
  order.sort(function (a, b) {
    if (a.key === "other") return 1
    if (b.key === "other") return -1
    if (a.count !== b.count) return b.count - a.count
    return a.label < b.label ? -1 : 1
  })
  return order
}

// ==========================================================================
//  2e -- Programs Moat knows
// ==========================================================================
//
// The positive mirror of Rules: not what has been silenced, but what is
// considered normal. `moatctl baseline export --json` is the source -- the
// daemon's own per-(rule, exe, parent, dir) counters, with `learned` marking the
// ones the learning window wrote a rule for and `suppressed` the ones an
// allowlist entry is already hiding.

function normalizeBaselineTuple(value) {
  var t = value && typeof value === "object" ? value : {}
  return {
    rule: String(t.rule || ""),
    exe: String(t.exe || ""),
    program: basename(t.exe),
    provenance: normalizeActor({ provenance: t.provenance }).provenance,
    pkg: String(t.package === null || t.package === undefined ? "" : t.package),
    parent: String(t.parent === null || t.parent === undefined ? "" : t.parent),
    dir: String(t.dir === null || t.dir === undefined ? "" : t.dir),
    context: normalizeContext(t.context),
    severity: String(t.severity || "low").toLowerCase(),
    count: Number(t.count || 0),
    days: Number(t.days || 0),
    firstSeen: String(t.first_seen || ""),
    lastSeen: String(t.last_seen || ""),
    rarity: normalizeRarity(t.rarity),
    suppressed: t.suppressed === true,
    demoted: t.demoted === true,
    learned: t.learned === true,
    eligible: t.eligible === true
  }
}

function parseBaselineExport(raw) {
  var value = raw
  if (typeof raw === "string") {
    try { value = JSON.parse(String(raw || "").trim() || "{}") } catch (e) {
      return { ok: false, error: "unparseable baseline export", tuples: [] }
    }
  }
  var v = value && typeof value === "object" ? value : {}
  var list = Array.isArray(v.tuples) ? v.tuples : (Array.isArray(v) ? v : [])
  var tuples = []
  for (var i = 0; i < list.length; i++) tuples.push(normalizeBaselineTuple(list[i]))
  return {
    ok: !v.error,
    error: String(v.error || ""),
    generated: String(v.generated || ""),
    tuples: tuples
  }
}

/// The 2e table. One row per program, with what it is trusted FOR stated as
/// permissions in plain words, when it was last seen, and how many alerts that
/// trust has silenced.
///
/// A program with an incident waiting on the user is listed too, with an empty
/// scope and a line saying so -- the design highlights it, because "this is not
/// trusted for anything yet" is the most useful row on the screen.
function trustedPrograms(tuples, incidents) {
  var list = Array.isArray(tuples) ? tuples : []
  var byProgram = {}
  var order = []

  function rowFor(name) {
    if (!name) return null
    var row = byProgram[name]
    if (!row) {
      row = { program: name, exes: [], scopes: ({}), scopeKeys: [],
              lastSeen: "", silenced: 0, open: false, rules: [] }
      byProgram[name] = row
      order.push(row)
    }
    return row
  }

  for (var i = 0; i < list.length; i++) {
    var t = list[i]
    // Trusted means a rule covers it: one the learning window wrote, or one the
    // user's own "this was me" wrote. A tuple that has merely been observed is
    // not trust, and listing it here would turn this screen back into a log.
    if (!t || !(t.learned || t.suppressed)) continue
    var row = rowFor(t.program)
    if (!row) continue
    if (row.exes.indexOf(t.exe) === -1) row.exes.push(t.exe)
    if (row.rules.indexOf(t.rule) === -1) row.rules.push(t.rule)
    // Collected by (verb, has-a-place) rather than by finished sentence, so
    // eight learned directories under one verb stay ONE permission instead of
    // eight near-identical ones.
    var verb = ruleScopeVerb(t.rule)
    var dir = shortenHome(String(t.dir || "").replace(/\/?\*+$/, ""))
    var placed = !!(verb.prefix && dir)
    var key = placed ? "at:" + verb.prefix : "is:" + verb.none
    var entry = row.scopes[key]
    if (!entry) {
      entry = { prefix: verb.prefix, none: verb.none, dirs: [] }
      row.scopes[key] = entry
      row.scopeKeys.push(key)
    }
    if (placed && entry.dirs.indexOf(dir) === -1) entry.dirs.push(dir)
    row.silenced += Number(t.count) || 0
    if (t.lastSeen > row.lastSeen) row.lastSeen = t.lastSeen
  }

  // An open incident MARKS a row; it never creates one.
  //
  // This is the one place the handoff is wrong for this codebase. 2e draws a
  // `flea` row reading "nothing yet — one incident waiting on you", as one line
  // among fourteen trusted programs. On a real machine with nine things waiting
  // that inverts the screen: eight of fifteen rows under the heading "programs
  // Moat treats as yours" were programs it trusts for nothing, which makes the
  // heading a lie and turns the positive mirror of Rules into a second copy of
  // Now. A program with no trust at all is an incident, and incidents live on
  // Now -- so it stays out, and a program that IS trusted and also has
  // something waiting keeps the highlight and says so next to its permissions.
  var open = Array.isArray(incidents) ? incidents : []
  for (var j = 0; j < open.length; j++) {
    if (!open[j] || open[j].state !== "needsYou") continue
    var waiting = byProgram[open[j].program]
    if (!waiting) continue
    waiting.open = true
    if (open[j].lastSeen > waiting.lastSeen) waiting.lastSeen = open[j].lastSeen
  }

  for (var k = 0; k < order.length; k++) {
    var out = order[k]
    var phrases = []
    for (var p = 0; p < out.scopeKeys.length; p++) {
      var phrase = scopePhrase(out.scopes[out.scopeKeys[p]])
      if (phrase && phrases.indexOf(phrase) === -1) phrases.push(phrase)
    }
    out.trusted = phrases.length > 0
    // Three permissions is as much as a row can say. Past that it is a list,
    // and a list belongs behind the row rather than inside it.
    var words = phrases.length > 3
      ? phrases.slice(0, 3).join(", ") + ", and " + (phrases.length - 3) + " more"
      : phrases.join(", ")
    if (out.open) words += " — and one thing waiting on you"
    out.scope = Copy.oneLine(words, 140)
  }
  // Open incidents first (they are the reason to look), then busiest.
  order.sort(function (a, b) {
    if (a.open !== b.open) return a.open ? -1 : 1
    if (a.silenced !== b.silenced) return b.silenced - a.silenced
    return a.program < b.program ? -1 : 1
  })
  return order
}

// ==========================================================================
//  2b / 3a -- the sequence
// ==========================================================================
//
// Two different things are called a chain in this file, and they are NOT the
// same thing:
//
//   `chainSteps`  -- 2b's ancestry: what started what, out of one alert's own
//                    `process.ancestry`. Present on every alert.
//   `chainStory`  -- the daemon's correlated SEQUENCE (CONTRACT 4 "Chains"):
//                    several alerts, in one process tree, crossing detection
//                    families. Present only when moatd found one.
//
// Both are drawn with 2b's rail-and-dot layout because both are "what led
// here" told with times. The second is what 3a is about.

/// The chain an alert is a step of, or null.
function chainOf(alert) {
  return alert && alert.chain && alert.chain.steps ? alert.chain : null
}

/// Which step of the chain this alert is, 1-based. 0 when it is not listed --
/// possible on a truncated chain, where the steps kept are not all of them.
function chainPosition(alert) {
  var c = chainOf(alert)
  if (!c) return 0
  var id = String(alert.id || "")
  for (var i = 0; i < c.steps.length; i++) {
    if (c.steps[i].alert === id) return i + 1
  }
  return 0
}

/// The line that tells a reader looking at ONE alert that it belongs to a
/// sequence, and where in it (3a).
///
/// This is the answer to landing on the `.git/config` row and never learning
/// that the same process read a credential a second later. It is deliberately
/// the first thing said about such an alert, the way `moatctl explain` puts
/// "THIS IS PART OF A SEQUENCE" above the rule's own reasoning: the rule
/// explains one event, the chain is why that event matters.
function chainMarker(alert) {
  var c = chainOf(alert)
  if (!c) return ""
  var at = chainPosition(alert)
  var total = Number(c.steps_total) || c.steps.length
  if (at > 0) return "Part of a sequence — step " + at + " of " + total
  return "Part of a sequence of " + total
}

/// A chain's severity, and NEVER without the daemon's reason for it.
///
/// CONTRACT 4: "Never show a chain severity without `severity_reason`." The
/// reason is the whole guarantee that moatd's escalation is written down
/// rather than silent, so this returns "" when there is no reason to print --
/// showing the number alone is the one thing the obligation forbids. Every
/// place the panel prints a chain severity goes through here.
function chainSeverityLine(chain) {
  var c = chain || {}
  if (!c.severity || !c.severity_reason) return ""
  return c.severity + " — " + c.severity_reason
}

/// The clock time of a step, "21:18:36", in the reader's own timezone.
///
/// Not `relativeTime`: a chain spans seconds to minutes, so every step would
/// read the same age ("2 minutes ago") and the sequence -- the entire point of
/// the screen -- would be invisible. 2b and 3a print clock times for exactly
/// this reason.
function clockTime(iso) {
  var text = String(iso || "")
  if (!text) return ""
  var d = new Date(text)
  if (isNaN(d.getTime())) return ""
  function two(n) { return n < 10 ? "0" + n : String(n) }
  return two(d.getHours()) + ":" + two(d.getMinutes()) + ":" + two(d.getSeconds())
}

/// The day a sequence happened, stated once.
///
/// Steps print clock times only, and for good reason: a chain spans seconds,
/// so a date on every row is the same string repeated and the sequence -- the
/// point of the screen -- gets harder to read. The cost was that the timeline
/// carried no date at all. "20:06:10" is unreadable a day later, and a security
/// timeline that cannot tell you WHICH 20:06:10 is not a timeline.
///
/// Written in full, including the year: this is a record someone may read back
/// months later, or paste into a ticket, and an ambiguous stamp there is worse
/// than a long one.
function chainDay(chain) {
  var c = chain || {}
  var iso = c.first_ts || (c.steps && c.steps.length ? c.steps[0].ts : "")
  return dayStamp(iso)
}

function dayStamp(iso) {
  var text = String(iso || "")
  if (!text) return ""
  var d = new Date(text)
  if (isNaN(d.getTime())) return ""
  var days = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"]
  var months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
                "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
  return days[d.getDay()] + " " + d.getDate() + " " + months[d.getMonth()]
         + " " + d.getFullYear()
}

/// 3a's status column: what has already happened to this step.
///
/// A `context` step is one the user had allowed or the noise guard had demoted
/// (CONTRACT 4, and those two are the ONLY sources). It is shown -- that is
/// what makes the story readable -- but it is not shown as an accusation, or
/// the panel reverses a decision the user made.
function chainStepStatus(step, member) {
  var s = step || {}
  var m = member || null
  if (m && m.action_taken && m.action_taken !== "none") {
    var label = "Moat stopped it"
    if (m.action_taken === "quarantined") label = "Moat held it"
    // A refusal is not a kill and must not read as one: the program is still
    // running and saw its call fail. Saying "stopped it" would have the user
    // looking for a process that never died.
    else if (m.action_taken === "blocked") label = "Moat refused it"
    return { label: label, tone: "accent" }
  }
  if (s.role === "context") return { label: "you had allowed this", tone: "calm" }
  if (m && m.acked === true) return { label: "closed", tone: "quiet" }
  return { label: "happened", tone: "quiet" }
}

/// The sequence, as rows for 2b's rail.
///
/// options: { alerts: [...the members this reader has...], currentId, rawDetail }
///
/// The daemon's step carries the id, the time, the family, the rule and its own
/// title; everything else in a row is either the panel's copy for that rule or
/// a fact joined from the member alert. A step whose alert this reader has not
/// folded yet still renders -- the chain is the authority on what happened, and
/// waiting for the log to catch up would show a shorter story than moatd has.
/// The concrete one-liner for a chain step: the acting program and the file it
/// touched or the host it reached. Built from the member alert when present
/// (it carries the path and the destination); falls back to the step's own exe.
function chainStepDetail(step, member) {
  var exe = basename(String((step && step.exe) || (member && member.process && member.process.exe) || ""))
  if (!exe) return ""
  var m = member || {}
  if (m.file && m.file.path) return exe + "  \u00b7  " + shortenHome(String(m.file.path))
  if (m.net && m.net.dst_ip) {
    var port = m.net.dst_port ? ":" + m.net.dst_port : ""
    return exe + "  \u00b7  \u2192 " + m.net.dst_ip + port
  }
  var args = m.process && m.process.args ? String(m.process.args) : ""
  return args ? exe + "  \u00b7  " + args : exe
}

function chainStory(chain, options) {
  var c = chain || {}
  var steps = Array.isArray(c.steps) ? c.steps : []
  var o = options || {}
  var raw = o.rawDetail === true
  var current = String(o.currentId || "")

  var byId = {}
  var members = Array.isArray(o.alerts) ? o.alerts : []
  for (var i = 0; i < members.length; i++) {
    if (members[i] && members[i].id) byId[String(members[i].id)] = members[i]
  }

  var rows = []
  for (var j = 0; j < steps.length; j++) {
    var s = steps[j]
    var member = byId[s.alert] || null
    // The step's own fields are what a copy lookup needs, so a step renders in
    // the panel's voice with no member alert present at all.
    var asAlert = { rule: s.rule, title: s.title, summary: "", severity: s.severity }
    rows.push({
      alert: s.alert,
      position: j + 1,
      ts: s.ts,
      time: clockTime(s.ts),
      family: s.family,
      rule: s.rule,
      severity: s.severity,
      title: Copy.titleFor(asAlert, raw),
      // Advanced asks for the detection's own words: the rule id and the
      // severity it fired at. The default voice gets what it costs you.
      note: raw ? (s.rule + (s.severity ? "  ·  " + s.severity : ""))
                : Copy.stakeFor(asAlert, false),
      status: chainStepStatus(s, member),
      role: s.role,
      isContext: s.role === "context",
      isCurrent: current !== "" && s.alert === current,
      // The concrete thing this step DID: which program, and the file it read
      // or the host it reached. The step alone carries only the rule title; the
      // member alert carries the specifics, and a contained chain is exactly
      // where the user wants "python3 read ~/.aws/credentials", not just
      // "a credential file was read".
      detail: chainStepDetail(s, member)
    })
  }
  return rows
}

// ==========================================================================
//  2b -- what led here
// ==========================================================================
//
// The old panel had this data as one line -- kernel, systemd, herdr, bash, flea
// -- with no times and no other events, which answers a question nobody asks.
// As a chain with what is known about each step, the interesting fact (what
// started what, and how long before) becomes visible.
//
// Only what the alert actually carries. moatd records an ancestry of
// {pid, exe} with no per-step timestamp, so the steps above the alert carry no
// time and this does not invent one.
function chainSteps(alert) {
  if (!alert) return []
  var process = alert.process || {}
  var ancestry = Array.isArray(process.ancestry) ? process.ancestry.slice() : []
  ancestry.reverse()                       // oldest first
  var steps = []
  for (var i = 0; i < ancestry.length; i++) {
    var a = ancestry[i] || {}
    steps.push({
      name: basename(a.exe) || "?",
      path: shortenHome(String(a.exe || "")),
      note: i === 0 ? "the oldest step Moat still has a record of"
                    : "started by the step above it",
      ts: "",
      isAlert: false
    })
  }
  steps.push({
    name: basename(process.exe) || "?",
    path: shortenHome(String(process.exe || "")),
    note: String(process.args || ""),
    cwd: shortenHome(String(process.cwd || "")),
    ts: String(alert.ts || ""),
    startedAt: String(process.start_ts || ""),
    isAlert: true
  })
  return steps
}

// ==========================================================================
//  3e -- the bar glyph
// ==========================================================================
//
// Exactly three states, matching the verdict line, so the bar and the panel can
// never disagree. No event counter, no rule name, no severity palette: the old
// widget had five colours and a count of records, which is four more colours and
// one more number than the top of the panel has.
function barState(verdictState, needsCount) {
  switch (String(verdictState || "")) {
  case Copy.VERDICT_CHAIN:
  case Copy.VERDICT_NEEDS:
    return { state: "needsYou", tone: "alarm",
             label: String(Number(needsCount) || 0),
             glyph: GLYPH_SHIELD_ALERT }
  case Copy.VERDICT_GAP:
    return { state: "gap", tone: "accent", label: "gap", glyph: GLYPH_SHIELD_OFF }
  // The verdict line grew a fifth form after the bar's "exactly three states"
  // was written, and this switch never learned it: `stopped` fell through to
  // `default`, so the bar drew the calm shield while the headline beneath it
  // read "Moat stopped one thing" in the accent colour. The bar takes its
  // tone from the same table the headline does -- `Copy.verdictTone` -- so the
  // two cannot drift apart again.
  case Copy.VERDICT_STOPPED:
    return { state: "stopped", tone: Copy.verdictTone(Copy.VERDICT_STOPPED), label: "",
             glyph: GLYPH_SHIELD_CHECK }
  default:
    return { state: "quiet", tone: "quiet", label: "", glyph: GLYPH_SHIELD }
  }
}

/// The tooltip, and only for the two loud states (3e). A tooltip on the quiet
/// state is a tooltip nobody ever needed.
function barTooltip(verdictState, incidents, nowMs) {
  var state = String(verdictState || "")
  if (state === Copy.VERDICT_GAP) {
    return "Moat cannot prove it was watching the whole time · click to open"
  }
  if (state !== Copy.VERDICT_NEEDS && state !== Copy.VERDICT_CHAIN) return ""
  var queue = needsYouIncidents(incidents)
  if (queue.length === 0) return ""
  var age = relativeTime(queue[0].lastSeen, nowMs)
  return queue[0].title + (age ? " · " + age : "") +
         "\nclick to open · right-click to refresh"
}

// ==========================================================================
//  1g -- the first week
// ==========================================================================
//
// Learning is a finite job with an end, and the design's point is that it says
// so: a progress bar, a day count, and what it has learned so far. Nine silent
// days are indistinguishable from nine broken ones.
function learningCard(status, nowMs) {
  var s = status && status.baseline ? status : normalizeStatus(status)
  var b = s.baseline
  if (!b.learning) return null
  var now = nowMs === undefined || nowMs === null ? Date.now() : Number(nowMs)
  var ends = Date.parse(b.learning_ends)
  var started = Date.parse(s.installed_at)
  if (!isFinite(ends)) return null
  var left = Math.max(0, daysUntil(b.learning_ends, now))
  var total = isFinite(started) ? Math.round((ends - started) / 86400000) : 0
  if (total <= 0) total = left > 0 ? left : 1
  var index = Math.min(total, Math.max(1, total - left + 1))
  return {
    dayIndex: index,
    dayTotal: total,
    daysLeft: left,
    fraction: Math.max(0, Math.min(1, index / total)),
    learned: Number(b.learned) || 0,
    proposals: Number(b.proposals) || 0
  }
}

/// The day-9 card: shown for the two days after the window closes, because that
/// is the only moment the enforce question can be asked honestly.
function learningDoneCard(status, nowMs) {
  var s = status && status.baseline ? status : normalizeStatus(status)
  var b = s.baseline
  if (b.learning) return null
  var ends = Date.parse(b.learning_ends)
  if (!isFinite(ends)) return null
  var now = nowMs === undefined || nowMs === null ? Date.now() : Number(nowMs)
  var age = now - ends
  // Two days: long enough that someone who was away for a weekend still sees
  // it, short enough that it is not a permanent banner.
  if (age < 0 || age > 2 * 86400000) return null
  return {
    learned: Number(b.learned) || 0,
    proposals: Number(b.proposals) || 0,
    demoted: b.demoted.length,
    enforcing: s.mode === "enforce"
  }
}

// ==========================================================================
//  3d -- after Moat blocked something
// ==========================================================================
//
// Enforce mode's real UI is the apology, not the switch. A kernel-level block
// shows up in the user's terminal as a program dying for no reason, so the panel
// owes them the explanation after the fact.
function blockedIncidents(incidents) {
  // The SAME question as `stoppedIncidents`, so it gets the same answer.
  //
  // These were two functions deciding "is this still outstanding" and they
  // disagreed: this one never looked at `acked`, so after the user allowed a
  // killed program the headline correctly read "Nothing needs you" while the
  // apology card for that very program still sat underneath it. Two consumers
  // re-deriving one decision is the bug this codebase produces most often; the
  // fix is always to have one of them ask the other.
  return stoppedIncidents(incidents)
}


/// The terminal transcript 3d shows back to the user: what they saw when the
/// kernel killed it. Reconstructed from the recorded command line only -- Moat
/// does not capture terminal output, and this does not pretend it does.
function blockTranscript(alert) {
  var process = alert && alert.process ? alert.process : {}
  var command = String(process.args || process.exe || "")
  // What the shell actually printed. A kill shows the shell's own "Killed";
  // a refusal never reaches the shell at all -- the program stayed up and got
  // EPERM from connect(), so inventing a "Killed" line here would be a lie
  // about something the user can scroll back and check.
  // A kill shows the shell's "Killed"; a refusal never reaches the shell --
  // the program stayed up and got EPERM from connect(). Both `blocked` (a
  // kernel deny in enforce mode) and `contained` (moatd's own network cut for
  // a correlated sequence) are refusals, not kills, so neither may claim a
  // "Killed" line the user could scroll back and disprove.
  var act = alert ? alert.action_taken : ""
  var refused = act === "blocked" || act === "contained"
  return {
    command: "$ " + (command || basename(process.exe)),
    killed: refused ? "connect: Permission denied" : "Killed",
    cwd: shortenHome(String(process.cwd || ""))
  }
}

// ----------------------------------------------------------- copy an alert
//
// The panel could not be selected with a mouse, so there was no way to get an
// alert OUT of it: not into a bug report, not into a message, not into an
// agent you are already talking to. Mouse selection is the obvious answer and
// the wrong one here -- this is a Quickshell popup, a click-drag across it is
// as likely to dismiss it as to select anything, and a half-selected card
// pastes as a soup of labels and values with no structure.
//
// So: copy the WHOLE record, shaped the way `moatctl explain` shapes it. That
// is the text a person already recognises, it survives being pasted anywhere,
// and it is the same thing whether it came from the terminal or the panel.
// Nothing is summarised away -- the evidence lines are what make an alert
// arguable, and an alert you cannot argue with is one you can only obey.
function alertAsText(a) {
    if (!a || !a.id)
        return "";
    var L = [];
    var ex = a.explain || {};
    var p = a.process || {};

    L.push(String(a.title || a.rule || "moat alert"));
    L.push(new Array(String(a.title || a.rule || "moat alert").length + 1).join("="));
    L.push(String(a.rule || "") + " (" + String(a.severity || "") + ")   "
           + String(a.ts || "") + "   alert " + String(a.id));
    L.push("");

    if (ex.what) {
        L.push("WHAT HAPPENED");
        L.push("  " + String(ex.what));
    }
    if (p.exe)
        L.push("  process: " + String(p.exe)
               + (p.pid ? " (pid " + p.pid + (p.uid !== undefined ? ", uid " + p.uid : "") + ")" : ""));
    if (p.args)
        L.push("  args:    " + String(p.args));
    if (p.cwd)
        L.push("  cwd:     " + String(p.cwd));
    var anc = p.ancestry;
    if (anc && anc.length)
        L.push("  parents: " + anc.map(function (x) {
            return typeof x === "string" ? x : String(x.exe || "");
        }).join(" -> "));
    if (a.mode || a.action_taken)
        L.push("  mode:    " + String(a.mode || "") + "   action taken: " + String(a.action_taken || "none"));

    if (a.chain) {
        L.push("");
        L.push("THIS IS PART OF A SEQUENCE");
        L.push("  " + String(a.chain.summary || ""));
        if (a.chain.severity_reason)
            L.push("  " + String(a.chain.severity_reason));
    }

    if (ex.why) {
        L.push("");
        L.push("WHY IT WAS FLAGGED");
        L.push("  " + String(ex.why));
    }

    var ev = ex.evidence;
    if (ev && ev.length) {
        L.push("");
        L.push("EVIDENCE");
        for (var i = 0; i < ev.length; i++)
            L.push("  - " + String(ev[i]));
    }

    // `if_expected` is NOT prose -- it is {hint, options:[{scope, cmd, line}]}.
    // Stringifying it printed "[object Object]", which is what the very first
    // copied alert showed. The prose lives in `expected`; these are the
    // commands, and they are the most useful lines in the whole record to have
    // on a clipboard, because they are the thing you actually go and run.
    var expectedProse = ex.expected ? String(ex.expected) : "";
    var ie = ex.if_expected || {};
    var opts = ie.options || [];
    if (expectedProse || opts.length) {
        L.push("");
        L.push("IF THIS IS EXPECTED");
        if (expectedProse)
            L.push("  " + expectedProse);
        if (ie.hint)
            L.push("  (recommended scope: " + String(ie.hint) + ")");
        for (var k = 0; k < opts.length; k++) {
            var o = opts[k] || {};
            if (!o.cmd)
                continue;
            L.push("");
            L.push("  * " + String(o.cmd));
            var line = String(o.line || "").replace(/\n+$/, "");
            if (line) {
                var parts = line.split("\n");
                for (var q = 0; q < parts.length; q++)
                    L.push("      " + parts[q]);
            }
        }
    }

    // The suppression and the answer are part of the record: a reader who is
    // told "this fired" and not "and a rule you wrote silenced it" has been
    // given half the story.
    if (a.suppressed_by)
        L.push("", "suppressed by: " + String(a.suppressed_by));
    if (a.acked)
        L.push("answered: yes");

    return L.join("\n") + "\n";
}
