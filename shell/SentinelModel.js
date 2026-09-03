// Pure logic behind the Sentinel plugin. No QML types, no I/O: every function
// here takes plain values and returns plain values so shell/tests/tst_model.qml
// can exercise the folding, severity and notification rules without a running
// shell, a running daemon, or a real /var/lib/sentinel.
//
// The wire format is CONTRACT.md section 4: one JSON object per line in
// /var/lib/sentinel/alerts.jsonl. A line is either a full alert record or an
// update line `{"v":1,"id":"<same id>","update":{...}}` that readers fold onto
// the alert with the matching id. sentineld never rewrites in place, so the
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
  var unacked = v.unacked || {}
  if ((unacked.critical || 0) > 0 || (unacked.high || 0) > 0) return "red"
  if ((unacked.medium || 0) > 0) return "amber"
  return "green"
}

// ------------------------------------------------------------------- parsing

function parseLine(line) {
  var text = String(line || "").replace(/^﻿/, "").trim()
  if (!text) return null
  try {
    var value = JSON.parse(text)
    if (!value || typeof value !== "object" || Array.isArray(value)) return null
    if (!value.id) return null
    return value
  } catch (e) {
    // A torn final line (sentineld appended a partial record between our read
    // and its fsync) or a corrupted byte range. Skip the line, keep the rest;
    // the next FileView change re-reads the whole file anyway.
    return null
  }
}

function isUpdate(record) {
  return !!(record && record.update && typeof record.update === "object")
}

// One alert with defaults filled in, so every consumer can read
// alert.actions.length or alert.process.exe without guarding.
function normalizeAlert(record) {
  var r = record || {}
  var process = r.process && typeof r.process === "object" ? r.process : {}
  return {
    v: r.v === undefined ? 1 : r.v,
    id: String(r.id || ""),
    ts: String(r.ts || ""),
    severity: String(r.severity || "low").toLowerCase(),
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
    count: r.count === undefined ? 1 : Number(r.count)
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

function normalizeIfExpected(value) {
  var v = value && typeof value === "object" ? value : {}
  var hint = String(v.hint || "").toLowerCase()
  var options = []
  var raw = Array.isArray(v.options) ? v.options : []
  for (var i = 0; i < raw.length; i++) {
    var option = normalizeIfExpectedOption(raw[i])
    if (!option) continue
    // A duplicate scope would render two identical buttons.
    var seen = false
    for (var j = 0; j < options.length; j++) if (options[j].scope === option.scope) seen = true
    if (!seen) options.push(option)
  }
  return {
    hint: isIgnoreScope(hint) ? hint : "",
    options: options,
    file: String(v.file || "/etc/sentinel/allowlist.d/user.toml")
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
// `ts` is here because sentineld's dedupe update carries it: when the same
// rule+exe+file repeats inside the 60 s window it appends
// {"count":N,"ts":"<latest>"} rather than a second alert, and a panel that kept
// the FIRST occurrence's time would show "8m ago" for something still
// happening. `severity` is deliberately NOT here even though the daemon's own
// fold() honors it — an update line must never be able to escalate an alert
// into a critical toast, and no shipped code path emits one.
var UPDATABLE = ["acked", "action_taken", "count", "mode", "rotate", "actions", "ts"]

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

// --------------------------------------------------------------------- store
//
// FileView hands back the whole file on every change, so the store rebuilds
// the fold from scratch each time and its only real job is remembering which
// ids it has already seen. Two things depend on that memory:
//
//   * notifications: only ids that are new SINCE a previous ingest may notify,
//     and the very first ingest never notifies at all (`primed`), so a login
//     does not replay every alert in the log as a toast.
//   * rotation: sentineld renames alerts.jsonl to alerts.1.jsonl at 20 MB and
//     starts a fresh file. The new file is shorter than what we last read, so
//     a shrink is the rotation signal — re-fold from the new content and keep
//     `seen`, because an id that rotated out is still not new.

function createStore() {
  return { seen: {}, seenOrder: [], lastLength: -1, primed: false }
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
// Returns { alerts, newIds, initialLoad, reloaded, unacked }:
//   alerts      folded, newest first
//   newIds      ids to notify for — always empty on the initial load
//   initialLoad true only for the first ingest into this store
//   reloaded    the file shrank, i.e. it rotated or was truncated
function ingestText(store, text) {
  var body = String(text || "")
  var reloaded = store.lastLength >= 0 && body.length < store.lastLength
  store.lastLength = body.length

  var alerts = foldText(body)
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
    newIds: newIds,
    initialLoad: initialLoad,
    reloaded: reloaded,
    unacked: unackedCounts(alerts)
  }
}

// ------------------------------------------------------------------- counting

function unackedCounts(alerts) {
  var counts = { critical: 0, high: 0, medium: 0, low: 0, total: 0 }
  var list = Array.isArray(alerts) ? alerts : []
  for (var i = 0; i < list.length; i++) {
    var alert = list[i]
    if (!alert || alert.acked === true) continue
    var severity = String(alert.severity || "").toLowerCase()
    if (counts[severity] === undefined) continue
    counts[severity]++
    counts.total++
  }
  return counts
}

function badgeCount(unacked) {
  var u = unacked || {}
  return (u.critical || 0) + (u.high || 0)
}

// ------------------------------------------------------- notification policy

// Whether a freshly-folded alert should raise a desktop notification.
// `initialLoad` is the load that primed the store: alerts that already existed
// when the shell started are history, not events, and must never toast.
function shouldNotify(alert, minSeverity, initialLoad) {
  if (initialLoad) return false
  if (!alert || !alert.id) return false
  if (alert.acked === true) return false
  return severityAtLeast(alert.severity, minSeverity)
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

// Normalize the `sentinelctl status --json` response (CONTRACT 5). Anything
// missing degrades to a state the UI can render honestly rather than to a
// confident-looking default.
function normalizeStatus(raw) {
  var value = raw
  if (typeof raw === "string") {
    try { value = JSON.parse(raw) } catch (e) { value = null }
  }
  var s = value && typeof value === "object" ? value : {}
  var feeds = s.feeds && typeof s.feeds === "object" ? s.feeds : {}
  return {
    ok: s.ok === true,
    version: String(s.version || ""),
    mode: String(s.mode || "unknown"),
    tetragon: String(s.tetragon || "unknown"),
    policies: Number(s.policies || 0),
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
    // screen so it never has to hardcode "sentinel".
    group_ok: s.group_ok !== false,
    socket_group: String(s.socket_group || "sentinel"),
    error: String(s.error || "")
  }
}

function statusSummary(status, unacked, nowMs) {
  var s = normalizeStatus(status)
  if (!s.ok) return "Sentinel: daemon not reachable"
  var parts = []
  parts.push("mode " + s.mode)
  parts.push("tetragon " + s.tetragon)
  parts.push(s.policies + " policies")
  var age = relativeTime(s.feeds.updated, nowMs)
  parts.push("feeds " + (age || "never"))
  var u = unacked || {}
  parts.push((u.total || 0) + " unacked")
  return "Sentinel: " + parts.join(", ")
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
// /etc/sentinel/allowlist.d/user.toml with their index and comment, and
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
function normalizeAllowlistRule(value, fallbackIndex) {
  if (typeof value === "string") {
    return { index: fallbackIndex, comment: "", name: "", scope: "", line: value,
             detail: "", sourceFile: "", removable: false }
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
  return {
    index: isFinite(index) ? index : fallbackIndex,
    comment: String(r.comment || ""),
    name: String(r.name || r.rule || ""),
    scope: isIgnoreScope(r.scope) ? String(r.scope).toLowerCase() : "",
    // The exact TOML block, shown verbatim the same way explain does it.
    line: String(r.toml || r.line || ""),
    detail: detail.join("  "),
    sourceFile: String(r.file && r.path !== undefined ? r.file : (r.source || "")),
    // CONTRACT 5: only user.toml entries carry an index, and only they can be
    // removed with `unignore`.
    removable: hasIndex
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
    file: String(v.user_file || v.file || "/etc/sentinel/allowlist.d/user.toml"),
    dir: String(v.dir || "/etc/sentinel/allowlist.d"),
    rules: rules
  }
}

// The `explain` socket command returns the alert with its full explain block,
// for the case where the log line was written by an older sentineld (or
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

function normalizeMode(mode) {
  return String(mode || "").toLowerCase() === "enforce" ? "enforce" : "monitor"
}

// The setup steps CONTRACT 2 tells the user to run, as (label, command) pairs.
// `needsPackage` and `needsGroup` decide which ones are still outstanding.
function setupSteps(needsPackage, needsGroup, group) {
  var name = String(group || "sentinel")
  var steps = []
  if (needsPackage) {
    steps.push({
      label: "Build and install the package",
      command: "cd pkg/ && makepkg -si"
    })
    steps.push({
      label: "Enable the services",
      command: "sudo systemctl enable --now tetragon sentineld sentinel-feeds.timer"
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
