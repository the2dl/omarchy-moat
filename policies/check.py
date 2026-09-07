#!/usr/bin/env python3
"""Structural validator for the omarchy-moat Tetragon policy templates.

Nothing here talks to the kernel: it checks the templates against the grammar
verified in docs/TETRAGON-NOTES.md (Tetragon v1.7.1) so that a policy that
would be rejected at daemon start is caught at build time instead.

Usage:  python3 policies/check.py [policy-dir]
Exit:   0 = all templates valid, 1 = at least one problem, 2 = cannot run.
"""

import os
import re
import sys

try:
    import yaml
except ImportError:
    sys.stderr.write(
        "check.py needs PyYAML.\n"
        "  verify with:  python3 -c 'import yaml'\n"
        "  install with: sudo pacman -S python-yaml   (or: python3 -m pip install --user PyYAML)\n"
    )
    sys.exit(2)

HOME = "/home/test"

# List placeholders that `moatd render-policies` fills from the [telemetry]
# section of moat.toml (moatd/src/render.rs). They stand in for a whole
# sequence, so the representative values below are what the grammar checks see:
# a scope entry has to be a directory Prefix and a suffix entry a Postfix, and
# both are subject to Tetragon's length caps like any other literal.
LIST_PLACEHOLDERS = {
    "{{FILE_SCOPE}}": ["/usr/bin/", HOME + "/.local/bin/"],
    "{{FILE_SUFFIXES}}": [".sh", ".js", ".mjs"],
}

# ---------------------------------------------------------------------------
# Verified enums and limits (docs/TETRAGON-NOTES.md sections 1, 2, 3, 10)
# ---------------------------------------------------------------------------

API_VERSION = "cilium.io/v1alpha1"
KIND = "TracingPolicy"
NAME_PREFIX = "moat-"
FAMILIES = {"cred", "pkg", "persist", "shell", "rootkit", "priv", "ai", "net", "exec",
            # `ransom`: files or recovery points destroyed. Two policies, one a
            # plain detection (snapshot-destroy) and one a `signal` feed for the
            # counting rule of the same name (file-churn).
            "ransom",
            # `telemetry` is not a detection family. A moat-telemetry-* policy
            # is a record: moatd routes it past rule evaluation entirely
            # (engine::handle_line) and it can never raise an alert. It is
            # checked here like any other policy because a malformed one still
            # takes the whole daemon down at load time.
            "telemetry"}
TELEMETRY_FAMILY = "telemetry"

# notes section 1: spec keys accepted by the CRD (parsed strictly).
SPEC_KEYS = {
    "kprobes", "tracepoints", "lsmhooks", "uprobes", "usdts", "fentries",
    "loader", "lists", "enforcers", "options", "selectorsMacros",
    "podSelector", "containerSelector", "hostSelector",
}
HOOK_KEYS = {"kprobes", "tracepoints", "lsmhooks", "uprobes", "usdts", "fentries"}

# notes section 2: matchArgs operator enum (CRD).
ARG_OPERATORS = {
    "Equal", "NotEqual", "Prefix", "NotPrefix", "Postfix", "NotPostfix",
    "GreaterThan", "LessThan", "GT", "LT", "Mask", "SPort", "NotSPort",
    "SPortPriv", "NotSportPriv", "DPort", "NotDPort", "DPortPriv",
    "NotDPortPriv", "SAddr", "NotSAddr", "DAddr", "NotDAddr", "Protocol",
    "Family", "State", "InMap", "NotInMap", "CapabilitiesGained", "InRange",
    "NotInRange", "SubString", "SubStringIgnCase", "CelExpr", "FileType",
    "NotFileType",
}

# notes section 2: action enum.
ACTIONS = {
    "Post", "FollowFD", "UnfollowFD", "Sigkill", "CopyFD", "Override",
    "GetUrl", "DnsLookup", "NoPost", "Signal", "TrackSock", "UntrackSock",
    "NotifyEnforcer", "CleanupEnforcerNotification", "Set",
}
DEPRECATED_ACTIONS = {"FollowFD", "UnfollowFD", "CopyFD"}

BINARY_OPERATORS = {"In", "NotIn", "Prefix", "NotPrefix", "Postfix", "NotPostfix"}
PID_OPERATORS = {"In", "NotIn"}

# notes section 1: KProbeArg types.
ARG_TYPES = {
    "int", "int8", "int16", "int32", "int64", "uint8", "uint16", "uint32",
    "uint64", "size_t", "long", "ulong", "string", "char_buf", "char_iovec",
    "fd", "file", "filename", "path", "dentry", "linux_binprm", "sock",
    "socket", "sockaddr", "sockaddr_un", "skb", "nop", "bpf_attr", "bpf_cmd",
    "bpf_map", "bpf_prog", "perf_event", "capability", "kernel_cap_t", "cred",
    "user_namespace", "kiocb", "iov_iter", "load_info", "module", "syscall64",
    "data_loc", "net_device", "const_buf", "auto",
}

# notes section 2: operators the parser accepts per argument type.
INT_TYPES = {
    "int", "int8", "int16", "int32", "int64", "uint8", "uint16", "uint32",
    "uint64", "size_t", "long", "ulong",
}
PATHY_TYPES = {"file", "path", "fd", "dentry", "linux_binprm", "filename"}
STRING_TYPES = {"string", "char_buf"}
SOCK_TYPES = {"sock", "socket", "skb"}

INT_OPS = {"Equal", "NotEqual", "GT", "LT", "GreaterThan", "LessThan", "Mask",
           "InRange", "NotInRange", "InMap", "NotInMap"}
PATH_OPS = {"Equal", "NotEqual", "Prefix", "Postfix"}
FILETYPE_OPS = {"FileType", "NotFileType"}
STRING_OPS = {"Equal", "NotEqual", "Prefix", "Postfix", "SubString", "SubStringIgnCase"}
SOCK_OPS = {"SAddr", "NotSAddr", "DAddr", "NotDAddr", "SPort", "NotSPort",
            "DPort", "NotDPort", "SPortPriv", "NotSportPriv", "DPortPriv",
            "NotDPortPriv", "Protocol", "Family", "State"}
SOCKADDR_OPS = {"SAddr", "NotSAddr", "SPort", "NotSPort", "SPortPriv", "Family"}
PORT_OPS = {"SPort", "NotSPort", "DPort", "NotDPort"}

# notes section 2 / 10: hard limits.
MAX_SELECTORS = 5
MAX_MATCHARGS = 5
MAX_ACTIONS_PER_SELECTOR = 2
MAX_NUMERIC_VALUES = 4
MAX_BINARY_SELECTOR_ENTRIES = 1
# notes section 3: the BPF trampoline behind an LSM hook takes BPF_MAX_TRAMP_LINKS = 38
# programs, and Tetragon attaches two per policy (generic_lsm_event and
# generic_lsm_output), so the 20th policy on one hook fails to load with E2BIG
# ("argument list too long") and takes the whole daemon down with it. Kprobes are
# not attached through a trampoline and have no such cap.
BPF_MAX_TRAMP_LINKS = 38
PROGS_PER_LSM_POLICY = 2
MAX_POLICIES_PER_LSM_HOOK = BPF_MAX_TRAMP_LINKS // PROGS_PER_LSM_POLICY
MAX_MESSAGE = 256
MAX_TAGS = 16
LEN_CAPS = {"Prefix": 256, "NotPrefix": 256, "Postfix": 127, "NotPostfix": 127,
            "SubString": 100, "SubStringIgnCase": 100}

RATE_LIMIT_RE = re.compile(r"^\d+[smh]?$")
RATE_LIMIT_SCOPES = {"thread", "process", "global"}
DNS1123 = re.compile(r"^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$")

REQUIRED_ANNOTATIONS = [
    "moat.omarchy/severity",
    "moat.omarchy/title",
    "moat.omarchy/enforce",
    "moat.omarchy/actions",
    "moat.omarchy/why",
    "moat.omarchy/expected",
    "moat.omarchy/fp-hint",
]
OPTIONAL_ANNOTATIONS = ["moat.omarchy/rotate", "moat.omarchy/telemetry-class",
                        "moat.omarchy/tier"]
# BASELINE section 4. Absent means "detection": a policy that says nothing is a
# detection, because the failure mode of a forgotten annotation must be "keeps
# asking" and never "went quiet". moatd applies the same default, and rejects an
# unknown value the same way -- this is where a typo should be caught.
TIERS = {"detection", "signal"}
TELEMETRY_CLASSES = {"process", "network", "file"}
SEVERITIES = {"critical", "high", "medium", "low"}
ENFORCE = {"kill", "deny", "none"}
FP_HINTS = {"exe", "exe+file", "rule", "parent"}
UI_ACTIONS = {"kill", "quarantine", "ignore"}


class Problems(list):
    def add(self, where, msg):
        self.append("%s: %s" % (where, msg))


def check_matchargs(p, where, margs, argtypes):
    if len(margs) > MAX_MATCHARGS:
        p.add(where, "%d matchArgs, limit is %d" % (len(margs), MAX_MATCHARGS))
    for i, f in enumerate(margs):
        w = "%s.matchArgs[%d]" % (where, i)
        op = f.get("operator")
        if op not in ARG_OPERATORS:
            p.add(w, "operator %r not in the verified enum" % (op,))
            continue
        values = f.get("values", [])
        if not values:
            p.add(w, "no values")
        idx = f.get("index")
        t = argtypes.get(idx)
        if idx is None and "args" not in f:
            p.add(w, "neither index nor args given")
        elif t is None and "args" not in f:
            p.add(w, "index %r has no matching spec arg" % (idx,))
        else:
            if t in INT_TYPES:
                allowed = INT_OPS
            elif t in PATHY_TYPES:
                allowed = PATH_OPS | (FILETYPE_OPS if t in ("file", "path") else set())
            elif t in STRING_TYPES:
                allowed = STRING_OPS
            elif t in SOCK_TYPES:
                allowed = SOCK_OPS
            elif t == "sockaddr":
                allowed = SOCKADDR_OPS
            elif t == "sockaddr_un":
                allowed = {"Equal", "NotEqual", "Prefix", "NotPrefix", "Family"}
            elif t == "syscall64":
                allowed = {"InMap", "NotInMap"}
            else:
                allowed = ARG_OPERATORS
            if op not in allowed:
                p.add(w, "operator %s is not accepted for arg type %s" % (op, t))
            if t in INT_TYPES and op not in ("InMap", "NotInMap") and len(values) > MAX_NUMERIC_VALUES:
                p.add(w, "%d numeric values, limit is %d (use InMap)" % (len(values), MAX_NUMERIC_VALUES))
        if op in PORT_OPS and len(values) > MAX_NUMERIC_VALUES:
            p.add(w, "%d port values, limit is %d" % (len(values), MAX_NUMERIC_VALUES))
        cap = LEN_CAPS.get(op)
        for v in values:
            if not isinstance(v, str):
                continue
            if cap and len(v) > cap:
                p.add(w, "value %r is %d bytes, %s cap is %d" % (v[:40], len(v), op, cap))
        # Two filters on the same index is only a documented risk for the
        # path/string/int arg types (notes section 2, selector_arg_offset).
        # Several filters on one sock/sockaddr arg is the verified upstream
        # shape (notes section 5), so it is allowed here.
        if idx is not None and t not in SOCK_TYPES and t != "sockaddr":
            same = [g for g in margs if g.get("index") == idx and g is not f]
            if same:
                p.add(w, "index %s is filtered twice in one selector (UNVERIFIED at "
                         "runtime, notes section 2)" % (idx,))


def check_selector(p, where, sel):
    known = {"matchArgs", "matchData", "matchReturnArgs", "matchPIDs",
             "matchBinaries", "matchParentBinaries", "matchNamespaces",
             "matchNamespaceChanges", "matchCapabilities",
             "matchCapabilityChanges", "matchActions", "matchReturnActions",
             "macros"}
    for k in sel:
        if k not in known:
            p.add(where, "unknown selector field %r (matchAncestors does not exist)" % (k,))
    for key in ("matchBinaries", "matchParentBinaries"):
        entries = sel.get(key, [])
        if len(entries) > MAX_BINARY_SELECTOR_ENTRIES:
            p.add(where, "%s has %d entries, limit is 1" % (key, len(entries)))
        for e in entries:
            if e.get("operator") not in BINARY_OPERATORS:
                p.add(where, "%s operator %r not in %s" % (key, e.get("operator"), sorted(BINARY_OPERATORS)))
            if not e.get("values"):
                p.add(where, "%s has no values" % key)
            if e.get("followChildren") and e.get("operator") not in ("In", "NotIn"):
                p.add(where, "%s followChildren needs operator In or NotIn" % key)
            for v in e.get("values", []):
                if e.get("operator") in ("Postfix", "NotPostfix") and len(v) > 127:
                    p.add(where, "%s Postfix value %r exceeds 127 bytes" % (key, v))
                if e.get("operator") in ("In", "NotIn") and not v.startswith("/"):
                    p.add(where, "%s In/NotIn value %r is not an absolute path" % (key, v))
    for e in sel.get("matchPIDs", []):
        if e.get("operator") not in PID_OPERATORS:
            p.add(where, "matchPIDs operator %r not in In|NotIn" % (e.get("operator"),))
    acts = sel.get("matchActions", [])
    if len(acts) > MAX_ACTIONS_PER_SELECTOR:
        p.add(where, "%d actions, BPF supports %d per selector" % (len(acts), MAX_ACTIONS_PER_SELECTOR))
    for i, a in enumerate(acts):
        w = "%s.matchActions[%d]" % (where, i)
        act = a.get("action")
        if act not in ACTIONS:
            p.add(w, "action %r not in the verified enum" % (act,))
        if act in DEPRECATED_ACTIONS:
            p.add(w, "action %s is deprecated upstream (unsafe)" % act)
        if "rateLimit" in a:
            if act != "Post":
                p.add(w, "rateLimit only applies to Post")
            if not RATE_LIMIT_RE.match(str(a["rateLimit"])):
                p.add(w, "rateLimit %r is not N|Ns|Nm|Nh" % (a["rateLimit"],))
        if "rateLimitScope" in a and a["rateLimitScope"] not in RATE_LIMIT_SCOPES:
            p.add(w, "rateLimitScope %r not in %s" % (a["rateLimitScope"], sorted(RATE_LIMIT_SCOPES)))
        for bad in ("ratelimit", "rate_limit", "rateLimitSeconds"):
            if bad in a:
                p.add(w, "misspelled %r: the verified spelling is rateLimit" % bad)


def check_hook(p, where, kind, hook):
    if kind == "kprobes":
        if not hook.get("call"):
            p.add(where, "kprobe without call")
        if "syscall" not in hook:
            p.add(where, "syscall is not set; the CRD default is true, write syscall: false")
    elif kind == "lsmhooks":
        if not hook.get("hook"):
            p.add(where, "lsm hook without hook name")
        if str(hook.get("hook", "")).startswith("security_"):
            p.add(where, "lsm hook name must not carry the security_ prefix")
        for f in ("return", "returnArg", "returnArgAction"):
            if f in hook:
                p.add(where, "LsmHookSpec has no %s field" % f)
    msg = hook.get("message")
    if msg is None:
        p.add(where, "no message (it is exported and drives the alert text)")
    elif len(msg) > MAX_MESSAGE:
        p.add(where, "message is %d bytes, cap is %d" % (len(msg), MAX_MESSAGE))
    if len(hook.get("tags", [])) > MAX_TAGS:
        p.add(where, "more than %d tags" % MAX_TAGS)

    argtypes = {}
    for i, a in enumerate(hook.get("args", [])):
        if a.get("type") not in ARG_TYPES:
            p.add("%s.args[%d]" % (where, i), "type %r not in the verified type list" % (a.get("type"),))
        if a.get("index") is None:
            p.add("%s.args[%d]" % (where, i), "no index")
        argtypes[a.get("index")] = a.get("type")

    sels = hook.get("selectors", [])
    if not sels:
        p.add(where, "no selectors: this hook would fire unfiltered")
    if len(sels) > MAX_SELECTORS:
        p.add(where, "%d selectors, limit is %d" % (len(sels), MAX_SELECTORS))
    for i, sel in enumerate(sels):
        w = "%s.selectors[%d]" % (where, i)
        check_selector(p, w, sel)
        check_matchargs(p, w, sel.get("matchArgs", []), argtypes)


def check_policy(path, text):
    p = Problems()
    rendered = text.replace("{{HOME}}", HOME)
    for placeholder, values in LIST_PLACEHOLDERS.items():
        if placeholder not in rendered:
            continue
        # The placeholder is always a whole sequence item. Expanding it inline
        # as a flow sequence keeps the surrounding indentation valid whatever
        # the item is nested under.
        rendered = re.sub(
            r"^(\s*)-\s*[\"']?" + re.escape(placeholder) + r"[\"']?\s*$",
            lambda m, v=values: "\n".join("%s- %r" % (m.group(1), x) for x in v),
            rendered,
            flags=re.M,
        )
    for m in re.finditer(r"\{\{(\w+)\}\}", rendered):
        p.add(path, "unknown template placeholder {{%s}} (only {{HOME}} is rendered)" % m.group(1))
    try:
        doc = yaml.safe_load(rendered)
    except Exception as exc:  # noqa: BLE001
        p.add(path, "YAML does not parse after rendering: %s" % exc)
        return None, p

    if doc.get("apiVersion") != API_VERSION:
        p.add(path, "apiVersion is %r, expected %r" % (doc.get("apiVersion"), API_VERSION))
    if doc.get("kind") != KIND:
        p.add(path, "kind is %r, expected %r" % (doc.get("kind"), KIND))

    md = doc.get("metadata") or {}
    name = md.get("name", "")
    if not name.startswith(NAME_PREFIX):
        p.add(path, "metadata.name %r does not start with %r" % (name, NAME_PREFIX))
    if not DNS1123.match(name or ""):
        p.add(path, "metadata.name %r is not DNS-1123" % (name,))
    expect = "moat-" + os.path.basename(path)[: -len(".yaml")]
    if name != expect:
        p.add(path, "metadata.name %r does not match the file name (expected %r)" % (name, expect))
    family = name[len(NAME_PREFIX):].split("-")[0]
    if family not in FAMILIES:
        p.add(path, "family %r is not one of %s" % (family, sorted(FAMILIES)))
    ann = md.get("annotations") or {}
    for key in REQUIRED_ANNOTATIONS:
        if not str(ann.get(key, "")).strip():
            p.add(path, "missing required annotation %s" % key)
    for key in ann:
        if key not in REQUIRED_ANNOTATIONS + OPTIONAL_ANNOTATIONS:
            p.add(path, "unexpected annotation %s" % key)
    if family == TELEMETRY_FAMILY:
        cls = ann.get("moat.omarchy/telemetry-class")
        if cls not in TELEMETRY_CLASSES:
            p.add(path, "telemetry policy needs moat.omarchy/telemetry-class in %s, got %r"
                        % (sorted(TELEMETRY_CLASSES), cls))
        # A telemetry policy observes and never acts. Enforcement here would be
        # a log line that kills things.
        for sel_action in re.findall(r"action:\s*(\w+)", text):
            if sel_action in ("Sigkill", "Signal", "Override", "NotifyEnforcer", "Set"):
                p.add(path, "telemetry policy carries the %s action; telemetry observes "
                            "and never acts" % sel_action)
        if ann.get("moat.omarchy/enforce") != "none":
            p.add(path, "telemetry policy must declare moat.omarchy/enforce: none")
    elif ann.get("moat.omarchy/telemetry-class"):
        p.add(path, "moat.omarchy/telemetry-class on a non-telemetry policy")
    sev = ann.get("moat.omarchy/severity")
    if sev not in SEVERITIES:
        p.add(path, "severity %r not in %s" % (sev, sorted(SEVERITIES)))
    enf = ann.get("moat.omarchy/enforce")
    if enf not in ENFORCE:
        p.add(path, "enforce %r not in %s" % (enf, sorted(ENFORCE)))
    tier = ann.get("moat.omarchy/tier", "detection")
    if tier not in TIERS:
        p.add(path, "tier %r not in %s (omit it for a detection)" % (tier, sorted(TIERS)))
    # A rule that ends a process is not a building block. `signal` says "weak
    # alone, correlate on me"; an enforcing action says "act on me by yourself".
    # A policy claiming both would kill on evidence it has declared too weak to
    # put on the badge.
    if tier == "signal" and ann.get("moat.omarchy/enforce") in ("kill", "deny"):
        p.add(path, "tier signal with enforce %r: a building block must not act on its own"
                    % (ann.get("moat.omarchy/enforce"),))
    if family == TELEMETRY_FAMILY and tier != "detection":
        p.add(path, "telemetry policy carries a tier; telemetry is not a detection at all")
    if ann.get("moat.omarchy/fp-hint") not in FP_HINTS:
        p.add(path, "fp-hint %r not in %s" % (ann.get("moat.omarchy/fp-hint"), sorted(FP_HINTS)))
    for a in str(ann.get("moat.omarchy/actions", "")).split(","):
        if a.strip() and a.strip() not in UI_ACTIONS:
            p.add(path, "actions entry %r not in %s" % (a.strip(), sorted(UI_ACTIONS)))

    spec = doc.get("spec") or {}
    for k in spec:
        if k not in SPEC_KEYS:
            p.add(path, "spec key %r is not in the verified set %s" % (k, sorted(SPEC_KEYS)))
    if "lsmHooks" in spec:
        p.add(path, "spec.lsmHooks must be spelled lsmhooks")
    opts = {o.get("name"): o.get("value") for o in spec.get("options", [])}
    if opts.get("policy-mode") != "monitor":
        p.add(path, "spec.options policy-mode must default to monitor, got %r" % (opts.get("policy-mode"),))

    hooks = []
    for kind in HOOK_KEYS:
        for i, h in enumerate(spec.get(kind, []) or []):
            hooks.append((kind, h))
            check_hook(p, "%s.spec.%s[%d]" % (path, kind, i), kind, h)
    if not hooks:
        p.add(path, "no hooks")

    # enforce annotation must agree with the actions actually in the policy
    kills = set()
    for _, h in hooks:
        for sel in h.get("selectors", []):
            for a in sel.get("matchActions", []):
                if a.get("action") in ("Sigkill", "Signal", "Override", "NotifyEnforcer"):
                    kills.add(a["action"])
    # Sigkill ends the process; Override refuses the operation and lets it live.
    # Those are different promises to the user and the annotation has to say
    # which one, because it is what the panel prints and what `moatctl` reports.
    wants = set()
    for a in kills:
        wants.add("deny" if a == "Override" else "kill")
    if len(wants) > 1:
        p.add(path, "policy mixes %s: a rule either ends the process or refuses "
                    "the operation, not both" % sorted(kills))
    elif wants and enf not in wants:
        p.add(path, "policy carries %s so annotation enforce must be %r, got %r"
                    % (sorted(kills), sorted(wants)[0], enf))
    if not kills and enf in ("kill", "deny"):
        p.add(path, "annotation enforce is %r but no enforcing action is present" % enf)

    row = {
        "name": name,
        "family": family,
        "severity": sev or "?",
        "hook": ", ".join(sorted({h.get("call") or h.get("hook") or kind for kind, h in hooks})),
        "kind": ", ".join(sorted({kind for kind, _ in hooks})),
        "enforce": enf or "?",
        "tier": tier,
        "sels": sum(len(h.get("selectors", [])) for _, h in hooks),
        "attaches": [(kind, h.get("call") or h.get("hook") or kind) for kind, h in hooks],
    }
    return row, p


def main():
    d = sys.argv[1] if len(sys.argv) > 1 else os.path.dirname(os.path.abspath(__file__))
    files = sorted(f for f in os.listdir(d) if f.endswith(".yaml"))
    if not files:
        sys.stderr.write("no .yaml templates in %s\n" % d)
        return 2
    rows, problems = [], []
    for f in files:
        row, p = check_policy(f, open(os.path.join(d, f)).read())
        if row:
            rows.append(row)
        problems.extend(p)

    per_lsm_hook = {}
    for r in rows:
        for kind, hook in r["attaches"]:
            if kind == "lsmhooks":
                per_lsm_hook.setdefault(hook, []).append(r["name"])
    for hook, names in sorted(per_lsm_hook.items()):
        if len(names) > MAX_POLICIES_PER_LSM_HOOK:
            problems.append(
                "LSM hook %s: %d policies, limit is %d (%d BPF trampoline links, "
                "cap %d). Tetragon fails to load the %dth with E2BIG and exits. "
                "Move the surplus to a kprobe on security_%s, which needs no "
                "trampoline: %s"
                % (hook, len(names), MAX_POLICIES_PER_LSM_HOOK,
                   len(names) * PROGS_PER_LSM_POLICY, BPF_MAX_TRAMP_LINKS,
                   MAX_POLICIES_PER_LSM_HOOK + 1, hook,
                   ", ".join(sorted(names)[MAX_POLICIES_PER_LSM_HOOK:])))

    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "?": 4}
    rows.sort(key=lambda r: (r["family"], order[r["severity"]], r["name"]))
    w = [max(len(r[k]) if isinstance(r[k], str) else 4 for r in rows + [{k: k}]) for k in
         ("name", "severity", "kind", "hook", "enforce", "tier")]
    hdr = "%-*s  %-*s  %-*s  %-*s  %-*s  %-*s  %s" % (
        w[0], "POLICY", w[1], "SEVERITY", w[2], "KIND", w[3], "HOOK", w[4], "ENFORCE",
        w[5], "TIER", "SEL")
    print(hdr)
    print("-" * len(hdr))
    for r in rows:
        print("%-*s  %-*s  %-*s  %-*s  %-*s  %-*s  %d" % (
            w[0], r["name"], w[1], r["severity"], w[2], r["kind"],
            w[3], r["hook"], w[4], r["enforce"], w[5], r["tier"], r["sels"]))
    print("-" * len(hdr))
    per_sev = {s: sum(1 for r in rows if r["severity"] == s) for s in ("critical", "high", "medium", "low")}
    print("%d policies: %s" % (len(rows), ", ".join("%s %d" % (k, v) for k, v in per_sev.items())))
    # Two kinds of enforcement, counted apart: ending the process and refusing
    # the operation are different promises, and a single number hid the fact
    # that every armed rule was a kill.
    print("%d kill (Sigkill), %d deny (Override -EPERM), %d monitor-only" % (
        sum(1 for r in rows if r["enforce"] == "kill"),
        sum(1 for r in rows if r["enforce"] == "deny"),
        sum(1 for r in rows if r["enforce"] not in ("kill", "deny"))))
    # BASELINE section 4. A signal policy is recorded, is a full chain step, and
    # never reaches the badge on its own; a detection is what a person is asked
    # about. Counted apart because "how many of these can interrupt me" is the
    # first question anyone asks of a rule set this size.
    alerting = [r for r in rows if r["family"] != TELEMETRY_FAMILY]
    print("%d detection, %d signal (building blocks, timeline only), of %d alerting policies" % (
        sum(1 for r in alerting if r["tier"] == "detection"),
        sum(1 for r in alerting if r["tier"] == "signal"),
        len(alerting)))

    if problems:
        print("\n%d problem(s):" % len(problems))
        for msg in problems:
            print("  " + msg)
        return 1
    print("\nOK: every template parses, renders and matches the verified v1.7.1 grammar.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
