//! `/etc/moat/allowlist.d/*.toml`.
//!
//! This is the half of allowlisting Tetragon cannot do: ancestry, and anything
//! that needs a glob (`matchBinaries` has no wildcards at all). CONTRACT §6.3
//! fixes the shape — every field is optional except `name`, globs are allowed,
//! and *every field present must match*:
//!
//! ```toml
//! # added 2026-09-03 from alert 01J8ZK...: Private SSH key read
//! [[rule]]
//! name   = "moat-cred-ssh-private-key-read"   # or "moat-cred-*"
//! exe    = "/home/dan/.local/share/mise/installs/node/*/bin/node"
//! file   = "/home/dan/.ssh/id_rsa"
//! parent = "/usr/bin/restic"
//!
//! # added 2026-09-11 from alert 01M28F...: a sinkhole I visit on purpose
//! [[rule]]
//! name   = "moat-x-net-domain-ioc"
//! domain = "sinkhole.example"            # or "*.sinkhole.example"
//! ```
//!
//! Comments matter: `moatctl allowlist` shows them, so an entry added six
//! months ago still explains itself.

use std::path::{Path, PathBuf};

use globset::{Glob, GlobMatcher};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize, Default, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RuleSpec {
    pub name: String,
    pub exe: Option<String>,
    pub file: Option<String>,
    pub parent: Option<String>,
    /// The SCRIPT an interpreter was handed, when `exe` is an interpreter.
    ///
    /// 2026-09-07: `gcloud iam service-accounts list` reads its own
    /// `~/.config/gcloud/credentials.db` and then calls Google -- cred read
    /// followed by egress, which is the exfil shape exactly, so the chain went
    /// high and moat CONTAINED it mid-command. There was no way to allow it:
    /// gcloud is a python script, so `exe` is `/usr/bin/python3.14`, and
    /// allowing THAT would let any python script on the machine read your cloud
    /// credentials. The kernel cannot help either -- `matchBinaries` sees the
    /// interpreter too (see `util::interpreter_of`).
    ///
    /// moatd already resolves this: the alert prints "an interpreter takes the
    /// provenance of its script, /opt/google-cloud-cli/lib/gcloud.py" and
    /// `Actor::script` carries it. The allowlist simply could not match on it.
    /// Now it can, so the entry says the true thing -- *gcloud* reading
    /// *gcloud's own store* -- rather than blessing an interpreter.
    pub script: Option<String>,
    /// The hostname behind the connection, when the alert has one.
    ///
    /// 2026-09-11: the domain feed arrived with 47,755 entries and no way to
    /// disagree with any of them. A false positive -- a sinkholed domain the
    /// user visits on purpose, a shared host a fed name also used, a
    /// compromised site they are the one cleaning up -- could only be answered
    /// by allowing the PROGRAM for the whole rule (`firefox` never flags any
    /// bad domain again) or switching the rule off. Neither is the thing
    /// anybody meant.
    ///
    /// It matters more than it looks because a domain match sets `ioc`, and
    /// `scoring::never_lowered` holds an IOC finding at its base severity
    /// whatever the provenance or context says -- so the normal noise
    /// machinery cannot quieten one, and a `high` net step can carry a chain
    /// to the threshold where `maybe_contain` cuts the connection.
    ///
    /// Matched against BOTH the resolved name and the feed entry that fired,
    /// like `parent` is matched against every ancestor: the user types what
    /// the alert showed them, and the alert shows both.
    pub domain: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RuleFile {
    #[serde(default)]
    rule: Vec<RuleSpec>,
}

#[derive(Debug, Clone)]
pub struct Rule {
    pub spec: RuleSpec,
    /// The `#` lines directly above the `[[rule]]` header.
    pub comment: String,
    pub source: PathBuf,
    /// Position within its own file, 1-based. `unignore` takes this number.
    pub index: usize,
    name_m: GlobMatcher,
    exe_m: Option<GlobMatcher>,
    file_m: Option<GlobMatcher>,
    parent_m: Option<GlobMatcher>,
    script_m: Option<GlobMatcher>,
    domain_m: Option<GlobMatcher>,
}

/// The names a `domain` entry may be written against, narrowest last.
///
/// ONE function, called by both places that build a `Candidate`: the live
/// evaluator in `engine::emit` and the blast-radius preview in
/// `control::would_match`, whose whole promise is that it agrees with the
/// evaluator. Two copies of this would be two copies that drift, and the
/// direction they drift in is "the preview said it was narrower than it is".
pub fn domain_candidates(resolved: Option<&str>, ioc_matched: Option<&str>) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(n) = resolved {
        if !n.is_empty() {
            out.push(n.to_string());
        }
    }
    if let Some(m) = ioc_matched.and_then(|m| m.strip_prefix("domain:")) {
        if !m.is_empty() && !out.iter().any(|x| x == m) {
            out.push(m.to_string());
        }
    }
    out
}

/// What an event offers the allowlist.
#[derive(Debug, Default, Clone)]
pub struct Candidate<'a> {
    pub rule: &'a str,
    pub exe: &'a str,
    pub file: Option<&'a str>,
    pub parents: Vec<String>,
    /// `Actor::script`: what the interpreter was actually running.
    pub script: Option<&'a str>,
    /// The resolved name and the feed entry that matched it, in that order.
    /// Empty when the event has no name -- a rule naming a domain then cannot
    /// match, the same way one naming a file cannot match an event without one.
    pub domains: Vec<String>,
}

#[derive(Debug, Default)]
pub struct Allowlist {
    pub rules: Vec<Rule>,
    pub failed: Vec<String>,
}

/// Collapse `.` and `..` without touching the filesystem.
///
/// Component-wise, so a file honestly named `..config` or a directory `a..b` is
/// left alone -- only a whole `..` component walks up. A leading `..` on a
/// relative path is kept: there is nothing above it to remove, and inventing
/// one would change which file the string names.
///
/// Deliberately NOT `Path::canonicalize`: this runs on attacker-chosen paths on
/// the alert path, and canonicalising would follow symlinks and stat the disk
/// for every candidate.
fn normalize_lexical(path: &str) -> String {
    let absolute = path.starts_with('/');
    let mut out: Vec<&str> = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => match out.last() {
                Some(&last) if last != ".." => {
                    out.pop();
                }
                // Above the root there is nothing; above a relative start, keep it.
                _ => {
                    if !absolute {
                        out.push("..");
                    }
                }
            },
            p => out.push(p),
        }
    }
    let joined = out.join("/");
    if absolute {
        format!("/{}", joined)
    } else if joined.is_empty() {
        ".".to_string()
    } else {
        joined
    }
}

fn compile(pattern: &str) -> Result<GlobMatcher, String> {
    Glob::new(pattern)
        .map(|g| g.compile_matcher())
        .map_err(|e| format!("bad glob {:?}: {}", pattern, e))
}

impl Allowlist {
    /// Merge every `*.toml` under `dir`, in file-name order.
    pub fn load(dir: &Path) -> Allowlist {
        let mut out = Allowlist::default();
        let Ok(rd) = std::fs::read_dir(dir) else {
            return out;
        };
        let mut files: Vec<PathBuf> = rd
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.extension().map(|e| e == "toml").unwrap_or(false))
            .collect();
        files.sort();
        for f in files {
            match Self::load_file(&f) {
                Ok(mut rules) => out.rules.append(&mut rules),
                Err(e) => {
                    log::warn!("allowlist {}: {}", f.display(), e);
                    out.failed.push(format!("{}: {}", f.display(), e));
                }
            }
        }
        out
    }

    pub fn load_file(path: &Path) -> Result<Vec<Rule>, String> {
        let text = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
        Self::parse(&text, path)
    }

    pub fn parse(text: &str, source: &Path) -> Result<Vec<Rule>, String> {
        let parsed: RuleFile = toml::from_str(text).map_err(|e| e.to_string())?;
        let blocks = split_blocks(text).1;
        let mut out = Vec::new();
        for (i, spec) in parsed.rule.into_iter().enumerate() {
            let comment = blocks
                .get(i)
                .map(|b| b.comment.clone())
                .unwrap_or_default();
            out.push(Rule {
                name_m: compile(&spec.name)?,
                exe_m: spec.exe.as_deref().map(compile).transpose()?,
                file_m: spec.file.as_deref().map(compile).transpose()?,
                parent_m: spec.parent.as_deref().map(compile).transpose()?,
                script_m: spec.script.as_deref().map(compile).transpose()?,
                domain_m: spec.domain.as_deref().map(compile).transpose()?,
                spec,
                comment,
                source: source.to_path_buf(),
                index: i + 1,
            });
        }
        Ok(out)
    }

    /// First matching rule, or `None`.
    pub fn find(&self, c: &Candidate) -> Option<&Rule> {
        // Matched on the NORMALISED path, always.
        //
        // These globs are lexical and `*` crosses `/`, so
        // `/usr/lib/python*/site-packages/...` also matched
        // `/usr/lib/python3.14/../../../tmp/site-packages/...`: a string that
        // satisfies a root-owned anchor and resolves under /tmp. Anchoring the
        // root is the entire mechanism keeping these entries out of attacker
        // reach, and traversal walks straight past it.
        //
        // Normalising rather than refusing, because `..` here is not by itself
        // suspicious: `script_arg` absolutises a relative script against cwd
        // without collapsing it, so `python ../../opt/google-cloud-cli/lib/
        // gcloud.py` legitimately arrives as `/usr/bin/../../opt/...`. Refusing
        // those would make gcloud alert on its own store. Collapsing keeps that
        // working and closes the bypass in the same move.
        //
        // Lexical, never `canonicalize`: this runs on attacker-chosen paths in
        // the alert path, and resolving through the filesystem would follow
        // symlinks and touch disk on every candidate.
        let (exe, file, script) = (
            normalize_lexical(c.exe),
            c.file.map(normalize_lexical),
            c.script.map(normalize_lexical),
        );
        let c = Candidate {
            rule: c.rule,
            exe: &exe,
            file: file.as_deref(),
            parents: c.parents.clone(),
            script: script.as_deref(),
            // Not normalised: a hostname has no `..` to collapse, and running a
            // path normaliser over one could only mangle it.
            domains: c.domains.clone(),
        };
        self.rules.iter().find(|r| r.matches(&c))
    }

    pub fn len(&self) -> usize {
        self.rules.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }
}

impl Rule {
    pub fn matches(&self, c: &Candidate) -> bool {
        if !self.name_m.is_match(c.rule) {
            return false;
        }
        if let Some(m) = &self.exe_m {
            if !m.is_match(c.exe) {
                return false;
            }
        }
        if let Some(m) = &self.file_m {
            match c.file {
                Some(f) if m.is_match(f) => {}
                // A rule that names a file cannot match an event without one.
                _ => return false,
            }
        }
        if let Some(m) = &self.parent_m {
            if !c.parents.iter().any(|p| m.is_match(p)) {
                return false;
            }
        }
        if let Some(m) = &self.domain_m {
            // Any of them, like `parent`: the alert shows the resolved name and
            // the entry that fired, and either is a reasonable thing to type.
            if !c.domains.iter().any(|d| m.is_match(d)) {
                return false;
            }
        }
        if let Some(m) = &self.script_m {
            match c.script {
                Some(s) if m.is_match(s) => {}
                // A rule that names a script cannot match an event that was not
                // an interpreter running one. This is what keeps the entry from
                // widening into "any python".
                _ => return false,
            }
        }
        true
    }

    /// The exact TOML this rule would be written as.
    pub fn to_toml(&self) -> String {
        render_block(&self.spec)
    }

    /// Does this rule's `name` glob cover `rule`?
    ///
    /// Split out because the *name* alone decides two refusals that have to be
    /// answered before anything is written: a pattern that reaches a
    /// `NEVER_SILENCE` rule, and a pattern that reaches a rule armed in the
    /// kernel. `matches` cannot answer either — it needs an exe and a file it
    /// does not have yet.
    pub fn name_matches(&self, rule: &str) -> bool {
        self.name_m.is_match(rule)
    }
}

/// Compile a spec into a matchable `Rule` without writing a file first.
///
/// 2026-09-07: `moatctl allow` and its `--dry-run` both have to answer "what
/// would this actually match" BEFORE the entry exists, and the only honest
/// answer is the one the live evaluator gives. Going through the same
/// `compile`/`matches` pair the loader uses means the preview cannot drift
/// from the verdict — a second implementation of glob matching next to this
/// one would eventually disagree, and the direction it disagrees in is
/// "the preview said it was narrow".
///
/// `source` and `index` are the identity the entry WOULD have; nothing is
/// written here.
pub fn rule_from_spec(spec: RuleSpec, source: &Path, index: usize) -> Result<Rule, String> {
    Ok(Rule {
        name_m: compile(&spec.name)?,
        exe_m: spec.exe.as_deref().map(compile).transpose()?,
        file_m: spec.file.as_deref().map(compile).transpose()?,
        parent_m: spec.parent.as_deref().map(compile).transpose()?,
        script_m: spec.script.as_deref().map(compile).transpose()?,
        domain_m: spec.domain.as_deref().map(compile).transpose()?,
        spec,
        comment: String::new(),
        source: source.to_path_buf(),
        index,
    })
}

/// Render a `[[rule]]` block exactly the way `ignore` writes it. Kept in one
/// place so the block shown in `explain` and the block appended to `user.toml`
/// can never drift apart.
pub fn render_block(spec: &RuleSpec) -> String {
    let mut s = String::from("[[rule]]\n");
    s.push_str(&format!("name = {}\n", toml_str(&spec.name)));
    if let Some(v) = &spec.exe {
        s.push_str(&format!("exe = {}\n", toml_str(v)));
    }
    if let Some(v) = &spec.file {
        s.push_str(&format!("file = {}\n", toml_str(v)));
    }
    if let Some(v) = &spec.parent {
        s.push_str(&format!("parent = {}\n", toml_str(v)));
    }
    if let Some(v) = &spec.script {
        s.push_str(&format!("script = {}\n", toml_str(v)));
    }
    if let Some(v) = &spec.domain {
        s.push_str(&format!("domain = {}\n", toml_str(v)));
    }
    s
}

fn toml_str(s: &str) -> String {
    // Control characters too, not just `\` and `"`.
    //
    // A TOML basic string may not contain a raw newline, and a path may: a
    // filename with a `\n` in it produced a `user.toml` that failed to parse,
    // and `Allowlist::load` drops EVERY rule in a file it cannot read -- so one
    // crafted filename, run past the user once and clicked "This was me",
    // silently emptied their whole allowlist. It fails noisy rather than blind,
    // but the user's next reflex is to allow more things, which is the wrong
    // direction to be pushed in by an attacker.
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 || c == '\u{7f}' => {
                out.push_str(&format!("\\u{:04X}", c as u32))
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// A `[[rule]]` block together with the comment lines above it.
#[derive(Debug, Clone, PartialEq)]
pub struct Block {
    pub comment: String,
    /// Full text of the block, comment included, newline-terminated.
    pub text: String,
}

/// Split a TOML allowlist into `(preamble, blocks)`. The preamble is the file
/// header — comments that are not attached to any rule.
pub fn split_blocks(text: &str) -> (String, Vec<Block>) {
    let lines: Vec<&str> = text.lines().collect();
    let mut starts: Vec<usize> = Vec::new();
    for (i, l) in lines.iter().enumerate() {
        if l.trim() == "[[rule]]" {
            // Absorb the contiguous comment run directly above.
            let mut s = i;
            while s > 0 && lines[s - 1].trim_start().starts_with('#') {
                s -= 1;
            }
            starts.push(s);
        }
    }
    let preamble_end = starts.first().copied().unwrap_or(lines.len());
    let preamble = join(&lines[..preamble_end]);
    let mut blocks = Vec::new();
    for (n, &s) in starts.iter().enumerate() {
        let e = starts.get(n + 1).copied().unwrap_or(lines.len());
        let seg = &lines[s..e];
        let comment = seg
            .iter()
            .take_while(|l| l.trim_start().starts_with('#'))
            .map(|l| l.trim_start().trim_start_matches('#').trim())
            .collect::<Vec<_>>()
            .join(" ");
        blocks.push(Block {
            comment,
            text: join(seg),
        });
    }
    (preamble, blocks)
}

fn join(lines: &[&str]) -> String {
    if lines.is_empty() {
        String::new()
    } else {
        format!("{}\n", lines.join("\n"))
    }
}

/// Append a block to `user.toml`, creating it with a header if missing.
/// Returns the exact text appended.
pub fn append_rule(path: &Path, comment: &str, spec: &RuleSpec) -> std::io::Result<String> {
    use std::io::Write;
    if let Some(p) = path.parent() {
        std::fs::create_dir_all(p)?;
    }
    let fresh = !path.exists();
    let mut block = String::new();
    if fresh {
        block.push_str(
            "# Written by `moatctl ignore`. Hand edits are kept; see\n\
             # /etc/moat/allowlist.d/default.toml for the field reference.\n",
        );
    }
    block.push('\n');
    block.push_str(&format!("# {}\n", comment));
    block.push_str(&render_block(spec));
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    f.write_all(block.as_bytes())?;
    f.sync_all()?;
    Ok(block)
}

/// Where an allowlist entry came from, for the panel's Allowlist tab
/// (BASELINE §8 "Resolved shapes").
///
/// * `user` — `user.toml`, written by `moatctl ignore`
/// * `learned` — `baseline.toml`, written by the learning window or by accepting
///   a proposal
/// * `shipped` — anything else (`default.toml`, `omarchy-default.toml`), which
///   belongs to the package and is not removable from the UI
pub fn source_label(file: &Path) -> &'static str {
    match file.file_name().and_then(|n| n.to_str()) {
        Some("user.toml") => "user",
        Some("baseline.toml") => "learned",
        _ => "shipped",
    }
}

pub fn is_removable(file: &Path) -> bool {
    matches!(source_label(file), "user" | "learned")
}

/// Comment out the `index`-th `[[rule]]` block in place, keeping it visible with
/// a reason above it. Used when a learned entry's actor stops being official:
/// deleting it would hide the fact that moat ever trusted it (LEARNING §1).
///
/// Returns the disabled text.
pub fn disable_rule(path: &Path, index: usize, reason: &str) -> Result<String, String> {
    let text = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    let (preamble, blocks) = split_blocks(&text);
    if index == 0 || index > blocks.len() {
        return Err(format!(
            "no rule {} in {} ({} rules)",
            index,
            path.display(),
            blocks.len()
        ));
    }
    let mut out = preamble;
    let mut disabled = String::new();
    for (i, b) in blocks.iter().enumerate() {
        if i + 1 == index {
            disabled.push_str(&format!("# DISABLED {}: {}\n", crate::util::now_rfc3339(), reason));
            for line in b.text.lines() {
                if line.trim().is_empty() {
                    disabled.push('\n');
                } else if line.trim_start().starts_with('#') {
                    disabled.push_str(line);
                    disabled.push('\n');
                } else {
                    disabled.push_str(&format!("# {}\n", line));
                }
            }
            out.push_str(&disabled);
        } else {
            out.push_str(&b.text);
        }
    }
    crate::util::atomic_write(path, out.as_bytes(), 0o644).map_err(|e| e.to_string())?;
    Ok(disabled)
}

/// Index of the first `[[rule]]` block in `path` matching `spec`, 1-based.
/// `load_file` for callers outside this module (the baseline's approval
/// backfill needs a rule's COMMENT, which `find_index` does not return).
pub fn load_file_pub(path: &Path) -> Result<Vec<Rule>, String> {
    Allowlist::load_file(path)
}

/// Three answers, not two.
///
/// `Ok(Some(i))` found it; `Ok(None)` read the file and it is not there;
/// `Err(why)` could not read or parse the file at all, so nothing is known
/// either way.
///
/// This used to return `Option<usize>` and fold the last two together. The
/// caller that matters is the baseline revoke path, which reads "no block" as
/// "nothing is granting anything, so the entry is safe to mark withdrawn" --
/// correct for `Ok(None)` and exactly backwards for a corrupt file, where the
/// grant may still be live and live grants are what this is trying to remove.
/// It is the same shape as the failed-write case the code beside it already
/// guards, reached by a different route.
pub fn find_index(path: &Path, spec: &RuleSpec) -> Result<Option<usize>, String> {
    // A file that is not there grants nothing, which is a real answer and not
    // a failure to get one. Only a file that EXISTS and cannot be read or
    // parsed leaves the question open -- collapsing those two was the first
    // version of this fix, and it stopped a legitimate withdrawal.
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.to_string()),
    };
    let rules = Allowlist::parse(&text, path)?;
    Ok(rules
        .iter()
        .position(|r| &r.spec == spec)
        .map(|i| i + 1))
}

/// Remove the `index`-th (1-based) `[[rule]]` block from `path`.
/// Returns the removed text.
pub fn remove_rule(path: &Path, index: usize) -> Result<String, String> {
    let text = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    let (preamble, blocks) = split_blocks(&text);
    if index == 0 || index > blocks.len() {
        return Err(format!(
            "no rule {} in {} ({} rules)",
            index,
            path.display(),
            blocks.len()
        ));
    }
    let removed = blocks[index - 1].text.clone();
    let mut out = preamble;
    for (i, b) in blocks.iter().enumerate() {
        if i + 1 != index {
            out.push_str(&b.text);
        }
    }
    crate::util::atomic_write(path, out.as_bytes(), 0o644).map_err(|e| e.to_string())?;
    Ok(removed)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"# header comment, belongs to nobody

# added 2026-09-03 from alert 01AAA: ssh key read
[[rule]]
name = "moat-cred-ssh-private-key-read"
exe = "/usr/bin/restic"

# allow the whole cred family for gnome-keyring
[[rule]]
name = "moat-cred-*"
exe = "/usr/bin/gnome-keyring-daemon"
"#;

    fn al(text: &str) -> Allowlist {
        Allowlist {
            rules: Allowlist::parse(text, Path::new("/etc/moat/allowlist.d/user.toml")).unwrap(),
            failed: vec![],
        }
    }

    #[test]
    fn comments_attach_to_their_block() {
        let a = al(SAMPLE);
        assert_eq!(a.len(), 2);
        assert!(a.rules[0].comment.contains("01AAA"));
        assert_eq!(a.rules[0].index, 1);
        assert_eq!(a.rules[1].index, 2);
        let (pre, blocks) = split_blocks(SAMPLE);
        assert!(pre.contains("belongs to nobody"));
        assert_eq!(blocks.len(), 2);
    }

    // --- the domain dimension ---------------------------------------------

    const DOMAIN_SAMPLE: &str = r#"
# a sinkhole I visit on purpose
[[rule]]
name   = "moat-x-net-domain-ioc"
domain = "sinkhole.example"
"#;

    fn net_cand<'a>(rule: &'a str, exe: &'a str, resolved: &'a str, entry: &'a str) -> Candidate<'a> {
        Candidate {
            rule,
            exe,
            file: None,
            parents: vec![],
            script: None,
            domains: domain_candidates(Some(resolved), Some(&format!("domain:{}", entry))),
        }
    }

    #[test]
    fn a_domain_entry_allows_one_name_and_nothing_else() {
        let a = al(DOMAIN_SAMPLE);
        // The whole point: the program is NOT blessed. Before this field
        // existed the only answer to a false positive was `exe`, which stops
        // the browser ever flagging any fed domain again.
        assert!(a
            .find(&net_cand("moat-x-net-domain-ioc", "/usr/bin/firefox", "sinkhole.example", "sinkhole.example"))
            .is_some());
        assert!(
            a.find(&net_cand("moat-x-net-domain-ioc", "/usr/bin/firefox", "evil.example", "evil.example"))
                .is_none(),
            "the same program reaching a different fed domain still alerts"
        );
    }

    #[test]
    fn a_domain_entry_matches_the_entry_that_fired_as_well_as_the_resolved_name() {
        let a = al(DOMAIN_SAMPLE);
        // The alert shows both -- `cdn.sinkhole.example` resolved, entry
        // `sinkhole.example` fired -- and either is a reasonable thing to type.
        assert!(a
            .find(&net_cand(
                "moat-x-net-domain-ioc",
                "/usr/bin/curl",
                "cdn.sinkhole.example",
                "sinkhole.example",
            ))
            .is_some());
    }

    #[test]
    fn a_rule_naming_a_domain_cannot_match_an_event_without_one() {
        let a = al(DOMAIN_SAMPLE);
        // Same guarantee `file` gives. Otherwise an entry written to quieten
        // one hostname would quietly cover every nameless event of that rule.
        assert!(a
            .find(&Candidate {
                rule: "moat-x-net-domain-ioc",
                exe: "/usr/bin/curl",
                file: None,
                parents: vec![],
                script: None,
                domains: vec![],
            })
            .is_none());
    }

    #[test]
    fn a_domain_glob_covers_a_campaign_and_stops_at_the_label_boundary() {
        let a = al("[[rule]]\nname = \"moat-x-net-domain-ioc\"\ndomain = \"*.lab.example\"\n");
        assert!(a
            .find(&net_cand("moat-x-net-domain-ioc", "/usr/bin/curl", "a.lab.example", "lab.example"))
            .is_some());
        assert!(
            a.find(&net_cand("moat-x-net-domain-ioc", "/usr/bin/curl", "notlab.example", "notlab.example"))
                .is_none()
        );
    }

    #[test]
    fn the_domain_candidates_are_the_name_then_the_entry_without_duplicates() {
        assert_eq!(
            domain_candidates(Some("cdn.evil.example"), Some("domain:evil.example")),
            vec!["cdn.evil.example".to_string(), "evil.example".to_string()]
        );
        // The common case: the resolved name IS the entry.
        assert_eq!(
            domain_candidates(Some("evil.example"), Some("domain:evil.example")),
            vec!["evil.example".to_string()]
        );
        // A hash IOC is not a domain and must not become one.
        assert_eq!(domain_candidates(None, Some("sha256:abc")), Vec::<String>::new());
        assert_eq!(domain_candidates(None, None), Vec::<String>::new());
    }

    #[test]
    fn a_domain_entry_round_trips_through_toml() {
        let a = al(DOMAIN_SAMPLE);
        let toml = a.rules[0].to_toml();
        assert!(toml.contains("domain = \"sinkhole.example\""), "{}", toml);
        // And parses back to the same matcher.
        let again = Allowlist::parse(&toml, Path::new("x.toml")).unwrap();
        assert_eq!(again[0].spec.domain.as_deref(), Some("sinkhole.example"));
    }

    #[test]
    fn every_present_field_must_match() {
        let a = al(SAMPLE);
        let hit = a.find(&Candidate {
            rule: "moat-cred-ssh-private-key-read",
            exe: "/usr/bin/restic",
            file: Some("/home/dan/.ssh/id_rsa"),
            parents: vec![],
                script: None,
            domains: vec![],
            });
        assert!(hit.is_some());

        let miss = a.find(&Candidate {
            rule: "moat-cred-ssh-private-key-read",
            exe: "/usr/bin/node",
            file: None,
            parents: vec![],
                script: None,
            domains: vec![],
            });
        assert!(miss.is_none(), "exe must match");
    }

    #[test]
    fn name_globs_cover_a_family() {
        let a = al(SAMPLE);
        assert!(a
            .find(&Candidate {
                rule: "moat-cred-cloud-credential-read",
                exe: "/usr/bin/gnome-keyring-daemon",
                file: None,
                parents: vec![],
                script: None,
            domains: vec![],
            })
            .is_some());
        // A rule id that EXISTS and is outside the glob's family. It read
        // `moat-net-reverse-shell` until 2026-09-05, and no such rule has ever
        // existed — a synthetic id in a test about matching real rule names is
        // one anybody can grep for and not find.
        assert!(a
            .find(&Candidate {
                rule: "moat-shell-reverse-shell-connect",
                exe: "/usr/bin/gnome-keyring-daemon",
                file: None,
                parents: vec![],
                script: None,
            domains: vec![],
            })
            .is_none());
    }

    #[test]
    fn a_file_rule_never_matches_an_event_without_a_file() {
        let a = al("[[rule]]\nname = \"r\"\nfile = \"/home/dan/.ssh/*\"\n");
        assert!(a
            .find(&Candidate {
                rule: "r",
                exe: "/x",
                file: Some("/home/dan/.ssh/id_rsa"),
                parents: vec![],
                script: None,
            domains: vec![],
            })
            .is_some());
        assert!(a
            .find(&Candidate {
                rule: "r",
                exe: "/x",
                file: None,
                parents: vec![],
                script: None,
            domains: vec![],
            })
            .is_none());
    }

    #[test]
    fn parent_matches_any_ancestor() {
        let a = al("[[rule]]\nname = \"r\"\nparent = \"/usr/bin/restic\"\n");
        assert!(a
            .find(&Candidate {
                rule: "r",
                exe: "/usr/bin/sh",
                file: None,
                parents: vec!["/usr/bin/sh".into(), "/usr/bin/restic".into()],
                script: None,
            domains: vec![],
            })
            .is_some());
        assert!(a
            .find(&Candidate {
                rule: "r",
                exe: "/usr/bin/sh",
                file: None,
                parents: vec!["/usr/bin/npm".into()],
                script: None,
            domains: vec![],
            })
            .is_none());
    }

    #[test]
    fn version_glob_in_an_exe_path() {
        let a = al(
            "[[rule]]\nname = \"moat-cred-*\"\nexe = \"/home/dan/.local/share/mise/installs/node/*/bin/node\"\n",
        );
        assert!(a
            .find(&Candidate {
                rule: "moat-cred-ssh-private-key-read",
                exe: "/home/dan/.local/share/mise/installs/node/26.5.0/bin/node",
                file: None,
                parents: vec![],
                script: None,
            domains: vec![],
            })
            .is_some());
    }

    #[test]
    fn append_then_remove_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("user.toml");
        let spec = RuleSpec {
            name: "moat-cred-ssh-private-key-read".into(),
            exe: Some("/usr/bin/restic".into()),
            ..Default::default()
        };
        let written = append_rule(&p, "added 2026-09-03 from alert 01AAA: test", &spec).unwrap();
        assert!(written.contains("[[rule]]"));
        let rules = Allowlist::load_file(&p).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].spec, spec);
        assert!(rules[0].comment.contains("01AAA"));

        let spec2 = RuleSpec {
            name: "moat-net-*".into(),
            ..Default::default()
        };
        append_rule(&p, "second", &spec2).unwrap();
        assert_eq!(Allowlist::load_file(&p).unwrap().len(), 2);

        let removed = remove_rule(&p, 1).unwrap();
        assert!(removed.contains("restic"));
        let left = Allowlist::load_file(&p).unwrap();
        assert_eq!(left.len(), 1);
        assert_eq!(left[0].spec.name, "moat-net-*");
        assert!(remove_rule(&p, 9).is_err());
    }

    #[test]
    fn a_quote_in_a_path_survives_the_round_trip() {
        let spec = RuleSpec {
            name: "r".into(),
            exe: Some("/home/a\"b/x".into()),
            ..Default::default()
        };
        let text = render_block(&spec);
        let back = Allowlist::parse(&text, Path::new("x")).unwrap();
        assert_eq!(back[0].spec.exe.as_deref(), Some("/home/a\"b/x"));
    }

    #[test]
    fn unknown_field_is_rejected_loudly() {
        assert!(Allowlist::parse("[[rule]]\nname=\"r\"\nexes=\"/x\"\n", Path::new("x")).is_err());
    }

    #[test]
    fn a_learned_entry_is_disabled_in_place_with_its_reason() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("baseline.toml");
        append_rule(
            &p,
            "learned 2026-09-03: seen 9 times on 3 distinct days",
            &RuleSpec {
                name: "moat-persist-hypr-config-write".into(),
                exe: Some("/usr/bin/hyprctl".into()),
                ..Default::default()
            },
        )
        .unwrap();
        append_rule(&p, "second", &RuleSpec { name: "moat-net-*".into(), ..Default::default() }).unwrap();
        assert_eq!(Allowlist::load_file(&p).unwrap().len(), 2);

        let text = disable_rule(&p, 1, "the owning package is no longer official").unwrap();
        assert!(text.contains("# DISABLED"));
        assert!(text.contains("no longer official"));
        // The entry stops matching, the other one is untouched, and the record
        // of what moat once trusted is still readable in the file.
        let left = Allowlist::load_file(&p).unwrap();
        assert_eq!(left.len(), 1);
        assert_eq!(left[0].spec.name, "moat-net-*");
        let on_disk = std::fs::read_to_string(&p).unwrap();
        assert!(on_disk.contains("# exe = \"/usr/bin/hyprctl\""), "{}", on_disk);
        assert!(disable_rule(&p, 9, "x").is_err());
    }

    #[test]
    fn entries_are_labelled_by_the_file_they_came_from() {
        assert_eq!(source_label(Path::new("/etc/moat/allowlist.d/user.toml")), "user");
        assert_eq!(source_label(Path::new("/etc/moat/allowlist.d/baseline.toml")), "learned");
        assert_eq!(source_label(Path::new("/etc/moat/allowlist.d/omarchy-default.toml")), "shipped");
        assert!(is_removable(Path::new("/x/user.toml")));
        assert!(is_removable(Path::new("/x/baseline.toml")));
        assert!(!is_removable(Path::new("/x/default.toml")));
    }

    /// Three answers, and the difference between two of them is a live grant.
    ///
    /// The baseline revoke path reads "not there" as "nothing is granting
    /// anything, so mark the entry withdrawn". For a file that will not parse
    /// that is exactly backwards: the grant may still be live, and
    /// `mark_revoked` drops the entry from `learned_entries` so the next
    /// re-check never retries it. A corrupt file would have quietly become a
    /// permanent grant that moat's own records described as withdrawn.
    #[test]
    fn a_file_that_will_not_parse_is_not_the_same_as_a_rule_that_is_not_there() {
        let dir = tempfile::tempdir().unwrap();
        let spec = RuleSpec {
            name: "moat-cred-ssh-private-key-read".into(),
            exe: Some("/usr/bin/restic".into()),
            ..Default::default()
        };

        // Control: a real file that really does hold the block. Without this
        // the negatives below could pass with `find_index` always failing.
        let good = dir.path().join("good.toml");
        std::fs::write(&good, SAMPLE).unwrap();
        assert_eq!(find_index(&good, &spec), Ok(Some(1)), "the block is there");

        // Absent file: a real answer. Nothing grants anything.
        let gone = dir.path().join("not-created.toml");
        assert_eq!(
            find_index(&gone, &spec),
            Ok(None),
            "a file that does not exist grants nothing"
        );

        // Present and unparseable: no answer at all.
        let bad = dir.path().join("bad.toml");
        std::fs::write(&bad, "[[rule]]\nname = \"unterminated").unwrap();
        assert!(
            find_index(&bad, &spec).is_err(),
            "a corrupt file must not answer 'not there'"
        );
    }

    #[test]
    fn find_index_locates_a_block_by_its_spec() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("baseline.toml");
        let a = RuleSpec { name: "r-a".into(), exe: Some("/x".into()), ..Default::default() };
        let b = RuleSpec { name: "r-b".into(), ..Default::default() };
        append_rule(&p, "a", &a).unwrap();
        append_rule(&p, "b", &b).unwrap();
        assert_eq!(find_index(&p, &a), Ok(Some(1)));
        assert_eq!(find_index(&p, &b), Ok(Some(2)));
        assert_eq!(
            find_index(&p, &RuleSpec { name: "nope".into(), ..Default::default() }),
            Ok(None),
            "parsed, and genuinely not there"
        );
    }

    /// An interpreter's SCRIPT is what an allowlist entry may name, so a grant
    /// can be "gcloud reading gcloud's own store" rather than "python may read
    /// your cloud credentials".
    ///
    /// 2026-09-07, live: gcloud was CONTAINED mid-command because there was no
    /// way to express the narrow grant.
    #[test]
    fn an_entry_may_name_the_script_an_interpreter_was_handed() {
        let toml = r#"
# gcloud, reading its own store.
[[rule]]
name   = "moat-cred-cloud-credentials-read"
script = "*/google-cloud-cli/lib/gcloud.py"
file   = "*/.config/gcloud/*"
"#;
        let rules = Allowlist::parse(toml, Path::new("t.toml")).expect("parses");
        let a = Allowlist { rules, failed: vec![] };

        let gcloud = Candidate {
            rule: "moat-cred-cloud-credentials-read",
            exe: "/usr/bin/python3.14",
            file: Some("/home/dan/.config/gcloud/credentials.db"),
            parents: vec![],
            script: Some("/usr/bin/../../opt/google-cloud-cli/lib/gcloud.py"),
            domains: vec![],
        };
        assert!(a.find(&gcloud).is_some(), "gcloud reading its own store is allowed");

        // The whole point: the grant does NOT extend to any other python.
        let other = Candidate {
            script: Some("/tmp/steal.py"),
            ..gcloud.clone()
        };
        assert!(
            a.find(&other).is_none(),
            "a different script must still fire -- otherwise this is just allowing python"
        );

        // Nor to a process that is not an interpreter running a script at all.
        let no_script = Candidate { script: None, ..gcloud.clone() };
        assert!(
            a.find(&no_script).is_none(),
            "a rule that names a script cannot match an event without one"
        );

        // And it round-trips through the TOML writer, or `moatctl ignore`
        // would silently drop the field that makes it narrow.
        assert!(
            render_block(&a.rules[0].spec).contains("script = "),
            "render_block must write the script back: {}",
            render_block(&a.rules[0].spec)
        );
    }

    #[test]
    fn shipped_defaults_parse() {
        for name in ["default.toml", "omarchy-default.toml"] {
            let p = Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("etc/allowlist.d")
                .join(name);
            let rules = Allowlist::load_file(&p).unwrap_or_else(|e| panic!("{}: {}", name, e));
            assert!(!rules.is_empty(), "{} has no rules", name);
            for r in &rules {
                assert!(!r.comment.is_empty(), "{}: every rule explains itself", name);
                assert_eq!(source_label(&r.source), "shipped");
                assert!(!is_removable(&r.source), "{} must not be removable", name);
            }
        }
    }

    /// BASELINE §5: moat's own build and tests are not incidents — and the
    /// entry that says so must be as narrow as the paragraph promises.
    #[test]
    fn the_shipped_baseline_covers_moats_own_test_suite_and_nothing_wider() {
        let p =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("etc/allowlist.d/omarchy-default.toml");
        let al = Allowlist {
            rules: Allowlist::load_file(&p).unwrap(),
            ..Default::default()
        };
        assert_eq!(
            al.len(),
            2,
            "the omarchy-shell plugin exec entry and the agent-usage credential \
             read — nothing else. The twelve moat-test-suite entries moved to \
             moat-dev.toml.example on 2026-09-09: every one matched a path an \
             moat-test-suite entries moved to moat-dev.toml.example on 2026-09-09: \
             every one matched a path an attacker can create (/tmp/.tmp*/nc, \
             */target/*/deps/moatd-*), and they were shipped to everyone to protect \
             a case only moat's own developers hit, which additionally needs \
             `contain.enabled` -- off by default. Moat's own \
             triage pass has NO entry: see the note at the end of \
             omarchy-default.toml"
        );

        // omarchy-shell running its own plugins' helper scripts. Scoped to that
        // actor and that tree: everything else executing from there still fires,
        // and quickshell executing from anywhere else still fires.
        let plugin = "/home/dan/.config/omarchy/plugins/io.github.x.thing/scripts/config";
        let under_shell = vec![
            "/usr/bin/python3.14".to_string(),
            "/usr/bin/quickshell".to_string(),
            "/usr/bin/Hyprland".to_string(),
        ];
        // Scoped by ancestry, because the helper is as often run through an
        // interpreter as by the shell directly: both must be covered.
        for exe in ["/usr/bin/quickshell", "/usr/bin/python3.14", "/usr/bin/bash"] {
            assert!(
                al.find(&Candidate {
                    rule: "moat-exec-untrusted-home",
                    exe,
                    file: Some(plugin),
                    parents: under_shell.clone(),
                script: None,
            domains: vec![],
            })
                .is_some(),
                "{} running a plugin helper under the shell",
                exe
            );
        }
        // Nothing wider. Not descended from the shell, or not the plugins tree.
        let no_shell = vec!["/usr/bin/bash".to_string(), "/usr/bin/sshd".to_string()];
        for (file, parents) in [
            (plugin, no_shell.clone()),
            ("/home/dan/.cache/evil", under_shell.clone()),
            ("/tmp/evil", under_shell.clone()),
            ("/home/dan/.config/omarchy-plugins-evil/x", under_shell.clone()),
        ] {
            assert!(
                al.find(&Candidate {
                    rule: "moat-exec-untrusted-home",
                    exe: "/usr/bin/python3.14",
                    file: Some(file),
                    parents,
                script: None,
            domains: vec![],
            })
                .is_none(),
                "must still alert: executing {}",
                file
            );
        }

        // The bar's agent-usage widget reading the Claude credentials file.
        assert!(
            al.find(&Candidate {
                rule: "moat-cred-ai-credentials-read",
                exe: "/usr/share/omarchy/bin/omarchy-agent-usage-claude",
                file: Some("/home/dan/.claude/.credentials.json"),
                parents: under_shell.clone(),
                script: None,
            domains: vec![],
            })
            .is_some()
        );
        // Any other reader of that file, and that reader against any other file.
        for (exe, file) in [
            ("/usr/bin/curl", "/home/dan/.claude/.credentials.json"),
            ("/usr/share/omarchy/bin/omarchy-agent-usage-other", "/home/dan/.claude/.credentials.json"),
            ("/usr/share/omarchy/bin/omarchy-agent-usage-claude", "/home/dan/.aws/credentials"),
        ] {
            assert!(
                al.find(&Candidate {
                    rule: "moat-cred-ai-credentials-read",
                    exe,
                    file: Some(file),
                    parents: under_shell.clone(),
                script: None,
            domains: vec![],
            })
                .is_none(),
                "must still alert: {} reading {}",
                exe,
                file
            );
        }

    }

    /// The shipped entries must be written against the fields `engine::emit`
    /// actually fills in, or they are decoration.
    ///
    /// On 2026-09-05 the two tmpfs entries named `exe = "/tmp/.tmp*/nc"` and
    /// `exe = "/tmp/.tmp*/moat-*"`. For a `bprm_check_security` finding the
    /// actor is the CALLER — the cargo test binary — and the executed path is
    /// `file`, so those two entries could never match anything: 50 of 50 such
    /// alerts were unsuppressed. The candidates below are copied from real
    /// alerts, field for field, so an entry that reads plausibly but cannot
    /// fire is caught here instead of on the badge.
    /// `/proc/self/exe` is a name every process can wear.
    ///
    /// The Spotify entry allowed it so Chromium's utility subprocesses -- which
    /// re-exec themselves through that path -- could read Spotify's own cache
    /// without raising a cookie-jar theft. With only `exe` and `file`, that
    /// read "anything that re-execs itself may read Spotify's session token",
    /// and re-execing yourself is one line of code. Handoff item 4.
    #[test]
    fn re_execing_yourself_does_not_make_you_spotify() {
        let p = Path::new(env!("CARGO_MANIFEST_DIR")).join("etc/allowlist.d/default.toml");
        let al = Allowlist {
            rules: Allowlist::load_file(&p).unwrap(),
            ..Default::default()
        };
        let jar = "/home/dan/.cache/spotify/Cookies";
        let cand = |parents: Vec<String>| Candidate {
            rule: "moat-cred-browser-secrets-read",
            exe: "/proc/self/exe",
            file: Some(jar),
            parents,
            script: None,
            domains: vec![],
        };

        // Control: the case the entry exists for still works. If this stops
        // matching, the negative below proves nothing -- it would just mean
        // the entry never matches anything.
        assert!(
            al.find(&cand(vec![
                "/opt/spotify/spotify".into(),
                "/usr/bin/bash".into()
            ]))
            .is_some(),
            "a subprocess of the real Spotify is still excused"
        );

        // The hole: any process at all, re-exec'd through /proc/self/exe.
        assert!(
            al.find(&cand(vec!["/usr/bin/bash".into(), "/usr/bin/sshd".into()]))
                .is_none(),
            "a self-re-exec with no Spotify above it must not be excused"
        );
        assert!(
            al.find(&cand(vec![])).is_none(),
            "and neither must one with no ancestry at all"
        );
    }

    #[test]
    fn the_shipped_entries_match_the_candidates_the_engine_really_builds() {
        let p =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("etc/allowlist.d/omarchy-default.toml");
        let al = Allowlist {
            rules: Allowlist::load_file(&p).unwrap(),
            ..Default::default()
        };
        let runner = "/home/dan/Projects/omarchy-moat/moatd/target/release/deps/moatd-decac2790eaa7887";
        let shim = "/home/dan/Projects/omarchy-moat/pkg/src/omarchy-moat-tree/sandbox/shims/cargo";

        // The `cargo test` tempdir case moved to moat-dev.toml.example on
        // 2026-09-09 and is asserted there
        // (`dev_example::the_dev_example_still_covers_moats_own_test_suite`).
        // What matters HERE is that the shipped file no longer covers it: a
        // /tmp path an attacker can create must not be excused on everyone's
        // machine to spare moat's own developers a test failure.
        assert!(
            al.find(&Candidate {
                rule: "moat-exec-untrusted-tmpfs",
                exe: runner,
                file: Some("/tmp/.tmpFIBj5s/nc"),
                parents: vec![runner.into(), "/usr/bin/cargo".into(), "/usr/bin/bash".into()],
                script: None,
            domains: vec![],
            })
            .is_none(),
            "the shipped file must no longer excuse an attacker-creatable /tmp path"
        );

        // The shim half of the same move. `parent = "*/sandbox/shims/*"` is a
        // path an attacker can create too, so it left with the runner entry --
        // and the variable for it outlived its assertion, which is how a gap
        // this shape goes unnoticed.
        assert!(
            al.find(&Candidate {
                rule: "moat-exec-untrusted-tmpfs",
                exe: shim,
                file: Some("/tmp/moat-shim-test.aBcD/nc"),
                parents: vec![shim.into(), "/usr/bin/bash".into()],
                script: None,
            domains: vec![],
            })
            .is_none(),
            "the shipped file must no longer excuse a shim-parented /tmp path"
        );


        // The incident writer chmodding its own fixtures also moved to the dev
        // example: its actor glob was `*/target/*/deps/moatd-*`, which matches
        // any project with a target/ directory, not just moat's.
        assert!(
            al.find(&Candidate {
                rule: "moat-priv-setuid-chmod",
                exe: runner,
                file: Some("/tmp/.tmpgdwbQe/incidents/01M1SR6NRX4JVX1R993SAX2XYX/.pkg.json.663928.tmp"),
                parents: vec!["/usr/bin/cargo".into(), "/usr/bin/bash".into()],
                script: None,
            domains: vec![],
            })
            .is_none(),
            "the setuid entry moved to moat-dev.toml.example"
        );

        // And the shape this file exists to keep alerting on: a payload dropped
        // in /tmp by an install script. No moat runner, no shim, no prefix.
        for rule in [
            "moat-exec-untrusted-tmpfs",
            "moat-pkg-subtree-netcat-exec",
            "moat-priv-setuid-chmod",
        ] {
            assert!(
                al.find(&Candidate {
                    rule,
                    exe: "/usr/bin/bash",
                    file: Some("/tmp/x/payload"),
                    parents: vec!["/usr/bin/makepkg".into(), "/usr/bin/bash".into()],
                script: None,
            domains: vec![],
            })
                .is_none(),
                "a dropper must still alert: {}",
                rule
            );
        }
    }
}


#[cfg(test)]
mod shipped_shape {
    use super::*;

    /// A shipped `script` or `exe` glob may not begin with a wildcard.
    ///
    /// A leading `*` on the path of the code being trusted is
    /// attacker-selectable: `script = "*/google-cloud-sdk/lib/gcloud.py"` is
    /// inherited by anyone who can create that directory shape in /tmp, and
    /// creating a directory is not a privilege. `file` globs are exempt --
    /// they name the TARGET, which is usually under an unknown home, and
    /// matching one is not by itself a grant to the actor.
    #[test]
    fn no_shipped_actor_glob_starts_with_a_wildcard() {
        // Both shipped files, since 2026-09-09. `omarchy-default.toml` was
        // exempt because its `*/target/*/deps/moatd-*` entries prevented a
        // recorded incident -- a `cargo test` of moat reaching critical and
        // quarantining the repo's own moatctl. But that incident needs
        // `contain.enabled`, which is off by default, so the population at risk
        // is people who build moat AND turned containment on; they can install
        // moat-dev.toml.example. Shipping an attacker-creatable /tmp glob to
        // everyone to spare that group a test failure was the wrong trade.
        for name in ["default.toml", "omarchy-default.toml"] {
            let p = Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("etc/allowlist.d")
                .join(name);
            for r in Allowlist::load_file(&p).unwrap() {
                // `parent` too: an ancestry glob is an actor pattern like any
                // other, and `parent = "*/sandbox/shims/*"` sat in the shipped
                // set for a day after this test was written because the field
                // list did not name it.
                for (field, val) in [
                    ("script", &r.spec.script),
                    ("exe", &r.spec.exe),
                    ("parent", &r.spec.parent),
                ] {
                    let Some(v) = val else { continue };
                    assert!(
                        !v.starts_with('*'),
                        "{}: {} {:?} on rule {:?} starts with a wildcard, so any writable \
                         directory can be shaped to match it",
                        name,
                        field,
                        v,
                        r.spec.name
                    );
                }
            }
        }
    }
}

#[cfg(test)]
mod dev_example {
    use super::*;

    /// The moat-test-suite entries still WORK -- they are just not shipped.
    ///
    /// They moved out of omarchy-default.toml on 2026-09-09 because every one
    /// matched a path an attacker can create, and they only ever helped people
    /// building moat with `contain.enabled` on. This keeps the coverage that
    /// proved they match what the suite actually does, against the file that
    /// now holds them.
    #[test]
    fn the_dev_example_still_covers_moats_own_test_suite() {
        let p = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("etc/allowlist.d/moat-dev.toml.example");
        let al = Allowlist {
            rules: Allowlist::parse(&std::fs::read_to_string(&p).unwrap(), &p).unwrap(),
            ..Default::default()
        };
        let shim = "/home/dan/Projects/omarchy-moat/pkg/src/omarchy-moat-tree/sandbox/shims/cargo";
        // The scanner suites: bash execs the fake toolchain the shim built, and
        // the shim script itself is what identifies the run in the ancestry.
        for file in [
            "/tmp/moat-shim-test.n_b42zuu/bin/moat-scan-npm",
            "/tmp/moat-build-shim-test.2o96mi62/bin/moat-scan-cargo",
            "/tmp/moat-sandbox-test.FkzONpNE/bin/moat-shim-probe",
        ] {
            assert!(
                al.find(&Candidate {
                    rule: "moat-exec-untrusted-tmpfs",
                    exe: "/usr/bin/bash",
                    file: Some(file),
                    parents: vec![
                        "/usr/bin/bash".into(),
                        shim.into(),
                        "/usr/bin/python3".into(),
                        "/usr/bin/makepkg".into(),
                    ],
                script: None,
            domains: vec![],
            })
                .is_some(),
                "the shim-suite case: {}",
                file
            );
        }

        let parent = "/home/dan/Projects/omarchy-moat/moatd/target/debug/deps/moatd-16a3beb0";
        // The netcat rule is a userland rule whose actor IS the copied binary,
        // so there the executed path arrives as `exe`.
        for exe in ["/tmp/.tmpAbC123/nc", "/tmp/.tmpAbC123/moat-helper"] {
            assert!(
                al.find(&Candidate {
                    rule: "moat-pkg-subtree-netcat-exec",
                    exe,
                    file: None,
                    parents: vec![parent.to_string()],
                script: None,
            domains: vec![],
            })
                .is_some(),
                "moat-pkg-subtree-netcat-exec {} is the test suite",
                exe
            );
        }
        // The tmpfs rule hangs off `bprm_check_security`, where the actor is the
        // test binary and the executed path arrives as `file`.
        for file in ["/tmp/.tmpAbC123/nc", "/tmp/.tmpAbC123/moat-helper"] {
            assert!(
                al.find(&Candidate {
                    rule: "moat-exec-untrusted-tmpfs",
                    exe: parent,
                    file: Some(file),
                    parents: vec![parent.to_string()],
                script: None,
            domains: vec![],
            })
                .is_some(),
                "moat-exec-untrusted-tmpfs {} is the test suite",
                file
            );
        }
        // Nothing wider: a real dropper, the same binary from a shell, another
        // rule, or a plain /tmp path all still alert.
        for (rule, exe, parents) in [
            ("moat-exec-untrusted-tmpfs", "/tmp/.tmpAbC123/nc", vec!["/usr/bin/bash"]),
            ("moat-exec-untrusted-tmpfs", "/tmp/nc", vec![parent]),
            ("moat-exec-untrusted-tmpfs", "/tmp/.tmpAbC123/evil", vec![parent]),
            ("moat-cred-ssh-private-key-read", "/tmp/.tmpAbC123/nc", vec![parent]),
            ("moat-exec-untrusted-tmpfs", "/home/dan/.cache/nc", vec![parent]),
        ] {
            assert!(
                al.find(&Candidate {
                    rule,
                    exe: parent,
                    file: Some(exe),
                    parents: parents.iter().map(|s| s.to_string()).collect(),
                script: None,
            domains: vec![],
            })
                .is_none(),
                "{} {} must still alert",
                rule,
                exe
            );
        }
    }
}

#[cfg(test)]
mod cloud_cli_paths {
    use super::*;

    fn shipped() -> Allowlist {
        let p = Path::new(env!("CARGO_MANIFEST_DIR")).join("etc/allowlist.d/default.toml");
        Allowlist { rules: Allowlist::load_file(&p).unwrap(), ..Default::default() }
    }

    fn matches(script: &str, file: &str) -> bool {
        shipped()
            .find(&Candidate {
                rule: "moat-cred-cloud-credentials-read",
                exe: "/usr/bin/python3.14",
                file: Some(file),
                parents: vec![],
                script: Some(script),
            domains: vec![],
            })
            .is_some()
    }

    /// An entry that cannot match is not a safe entry, it is a wrong one.
    ///
    /// The first anchored version used `/opt/azure/cli/__main__.py`, which is
    /// not where any distro puts it: Arch ships
    /// `/opt/azure-cli/lib/python3.14/site-packages/azure/cli/__main__.py`.
    /// It failed safe -- and would have gone on alerting forever while looking
    /// like it had been handled.
    #[test]
    fn the_real_cloud_cli_layouts_match() {
        // No azure assertion: there is no azure entry, on purpose. Its launcher
        // re-execs python with `-m azure.cli`, and `script_arg` returns None for
        // `-m`, so no `script =` entry can match the real invocation however
        // well its path is spelled. Two anchored attempts were wrong before
        // that was noticed; the reasoning is recorded in default.toml.
        assert!(
            !matches(
                "/opt/azure-cli/lib/python3.14/site-packages/azure/cli/__main__.py",
                "/home/dan/.azure/config"
            ),
            "an azure entry is back; check it can actually fire before keeping it"
        );
        assert!(
            matches("/opt/google-cloud-cli/lib/gcloud.py", "/home/dan/.config/gcloud/creds.db"),
            "Arch's google-cloud-cli layout"
        );
    }

    /// And the anchoring still holds: a writable root must not match.
    #[test]
    fn an_attacker_shaped_tree_does_not_match() {
        for script in [
            "/tmp/x/azure/cli/__main__.py",
            "/home/dan/azure-cli/lib/python3.14/site-packages/azure/cli/__main__.py",
            "/tmp/google-cloud-cli/lib/gcloud.py",
            "/home/dan/.local/google-cloud-sdk/lib/gcloud.py",
        ] {
            assert!(
                !matches(script, "/home/dan/.azure/config")
                    && !matches(script, "/home/dan/.config/gcloud/creds.db"),
                "a writable root matched: {}",
                script
            );
        }
    }
}

#[cfg(test)]
mod traversal {
    use super::*;

    #[test]
    fn dot_dot_is_collapsed_component_wise() {
        assert_eq!(normalize_lexical("/usr/bin/../../opt/x/y.py"), "/opt/x/y.py");
        assert_eq!(
            normalize_lexical("/usr/lib/python3.14/../../../tmp/site-packages/a/b.py"),
            "/tmp/site-packages/a/b.py"
        );
        assert_eq!(normalize_lexical("/a/./b//c"), "/a/b/c");
        // Above the root there is nothing to remove.
        assert_eq!(normalize_lexical("/../../etc/passwd"), "/etc/passwd");
        // A name that merely CONTAINS dots is not traversal.
        assert_eq!(normalize_lexical("/home/dan/..config/a..b"), "/home/dan/..config/a..b");
        // A relative path keeps what it cannot resolve.
        assert_eq!(normalize_lexical("../x"), "../x");
    }

    /// The bypass: a root-owned anchor satisfied by a string that resolves
    /// somewhere else entirely.
    #[test]
    fn traversal_cannot_walk_past_an_anchored_root() {
        let toml = "# t\n[[rule]]\nname = \"moat-cred-cloud-credentials-read\"\n\
                    script = \"/usr/lib/python*/site-packages/azure/cli/__main__.py\"\n\
                    file = \"*/.azure/*\"\n";
        let a = Allowlist {
            rules: Allowlist::parse(toml, Path::new("t.toml")).unwrap(),
            failed: vec![],
        };
        let cand = |script: &'static str| Candidate {
            rule: "moat-cred-cloud-credentials-read",
            exe: "/usr/bin/python3.14",
            file: Some("/home/dan/.azure/config"),
            parents: vec![],
            script: Some(script),
            domains: vec![],
        };
        assert!(
            a.find(&cand("/usr/lib/python3.14/site-packages/azure/cli/__main__.py")).is_some(),
            "the real path still matches"
        );
        assert!(
            a.find(&cand(
                "/usr/lib/python3.14/../../../tmp/site-packages/azure/cli/__main__.py"
            ))
            .is_none(),
            "a path that resolves under /tmp must not inherit a /usr/lib grant"
        );
    }
}
