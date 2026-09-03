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
}

/// What an event offers the allowlist.
#[derive(Debug, Default, Clone)]
pub struct Candidate<'a> {
    pub rule: &'a str,
    pub exe: &'a str,
    pub file: Option<&'a str>,
    pub parents: Vec<String>,
}

#[derive(Debug, Default)]
pub struct Allowlist {
    pub rules: Vec<Rule>,
    pub failed: Vec<String>,
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
        self.rules.iter().find(|r| r.matches(c))
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
        true
    }

    /// The exact TOML this rule would be written as.
    pub fn to_toml(&self) -> String {
        render_block(&self.spec)
    }
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
    s
}

fn toml_str(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
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
pub fn find_index(path: &Path, spec: &RuleSpec) -> Option<usize> {
    let rules = Allowlist::load_file(path).ok()?;
    rules.iter().position(|r| &r.spec == spec).map(|i| i + 1)
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

    #[test]
    fn every_present_field_must_match() {
        let a = al(SAMPLE);
        let hit = a.find(&Candidate {
            rule: "moat-cred-ssh-private-key-read",
            exe: "/usr/bin/restic",
            file: Some("/home/dan/.ssh/id_rsa"),
            parents: vec![],
        });
        assert!(hit.is_some());

        let miss = a.find(&Candidate {
            rule: "moat-cred-ssh-private-key-read",
            exe: "/usr/bin/node",
            file: None,
            parents: vec![],
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
            })
            .is_some());
        assert!(a
            .find(&Candidate {
                rule: "moat-net-reverse-shell",
                exe: "/usr/bin/gnome-keyring-daemon",
                file: None,
                parents: vec![],
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
            })
            .is_some());
        assert!(a
            .find(&Candidate {
                rule: "r",
                exe: "/x",
                file: None,
                parents: vec![],
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
            })
            .is_some());
        assert!(a
            .find(&Candidate {
                rule: "r",
                exe: "/usr/bin/sh",
                file: None,
                parents: vec!["/usr/bin/npm".into()],
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

    #[test]
    fn find_index_locates_a_block_by_its_spec() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("baseline.toml");
        let a = RuleSpec { name: "r-a".into(), exe: Some("/x".into()), ..Default::default() };
        let b = RuleSpec { name: "r-b".into(), ..Default::default() };
        append_rule(&p, "a", &a).unwrap();
        append_rule(&p, "b", &b).unwrap();
        assert_eq!(find_index(&p, &a), Some(1));
        assert_eq!(find_index(&p, &b), Some(2));
        assert_eq!(find_index(&p, &RuleSpec { name: "nope".into(), ..Default::default() }), None);
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
            5,
            "two test-suite rules x two exe globs, plus the omarchy-shell plugin \
             exec entry — nothing else"
        );

        // omarchy-shell running its own plugins' helper scripts. Scoped to that
        // actor and that tree: everything else executing from there still fires,
        // and quickshell executing from anywhere else still fires.
        let plugin = "/home/dan/.config/omarchy/plugins/io.github.x.thing/scripts/config";
        assert!(
            al.find(&Candidate {
                rule: "moat-exec-untrusted-home",
                exe: "/usr/bin/quickshell",
                file: Some(plugin),
                parents: vec!["/usr/bin/quickshell".to_string()],
            })
            .is_some(),
            "the shell running its own plugin helper"
        );
        for (exe, file) in [
            // Someone else executing out of the plugins tree is the actual threat.
            ("/usr/bin/bash", plugin),
            ("/home/dan/.cache/dropper", plugin),
            // The shell executing something outside the plugins tree.
            ("/usr/bin/quickshell", "/home/dan/.cache/evil"),
            ("/usr/bin/quickshell", "/tmp/evil"),
            // Adjacent path that only looks like the plugins tree.
            ("/usr/bin/quickshell", "/home/dan/.config/omarchy-plugins-evil/x"),
        ] {
            assert!(
                al.find(&Candidate {
                    rule: "moat-exec-untrusted-home",
                    exe,
                    file: Some(file),
                    parents: vec!["/usr/bin/quickshell".to_string()],
                })
                .is_none(),
                "must still alert: {} executing {}",
                exe,
                file
            );
        }

        let parent = "/home/dan/Projects/omarchy-moat/moatd/target/debug/deps/moatd-16a3beb0";
        // The two rules the paragraph names, for both globs.
        for rule in ["moat-exec-untrusted-tmpfs", "moat-pkg-subtree-netcat-exec"] {
            for exe in ["/tmp/.tmpAbC123/nc", "/tmp/.tmpAbC123/moat-helper"] {
                assert!(
                    al.find(&Candidate {
                        rule,
                        exe,
                        file: None,
                        parents: vec![parent.to_string()],
                    })
                    .is_some(),
                    "{} {} is the test suite",
                    rule,
                    exe
                );
            }
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
                    exe,
                    file: None,
                    parents: parents.iter().map(|s| s.to_string()).collect(),
                })
                .is_none(),
                "{} {} must still alert",
                rule,
                exe
            );
        }
    }
}
