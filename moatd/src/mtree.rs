//! Per-file checksums from pacman's `mtree`, for asking whether a
//! package-owned file still holds the bytes the package shipped.
//!
//! `%VALIDATION%` in `desc` -- which is all `provenance.rs` had -- records how
//! the PACKAGE was validated when it was installed: a signature over the
//! tarball, checked once, years ago. It says nothing about the file on disk
//! now. A trojaned `/usr/bin/curl` in a pgp-validated coreutils install still
//! classifies as `official`, and `official` is what quiets a rule.
//!
//! `/var/lib/pacman/local/<pkg>/mtree` has the missing fact and ships with
//! every installed package: a gzipped BSD mtree listing one line per file with
//! `size=` and `sha256digest=`. It is written at install time and owned by
//! root, so it is exactly as trustworthy as the package database already has
//! to be -- an attacker who can rewrite it can rewrite `desc` too.
//!
//! The format, as pacman writes it:
//!
//! ```text
//! #mtree
//! /set type=file uid=0 gid=0 mode=644
//! ./usr/bin/base32 time=1784093337.0 size=51512 sha256digest=6ee22548...
//! /set mode=755
//! ./usr/bin/\133 time=1784093337.0 size=55600 sha256digest=6ee593fc...
//! ```
//!
//! Two details that are easy to get wrong and silently return "no digest",
//! which reads as "cannot check" and lets a modified file pass:
//!
//! * paths are relative (`./usr/bin/x`) and octal-escaped -- `\133` is `[`, and
//!   coreutils really does ship that name;
//! * `/set` lines carry defaults for the lines after them, so a bare entry can
//!   be a directory. Directories and symlinks have no `sha256digest` at all,
//!   which is why absence is never reported as a mismatch.

use std::io::BufRead;
use std::path::Path;

/// What one file's mtree line says it should be.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub sha256: String,
    pub size: u64,
}

/// The recorded digest for one absolute path inside `pkg_dir`'s package.
///
/// `None` when the package has no mtree, the path is not in it, or the entry
/// carries no digest (a directory or a symlink). All three mean "no claim",
/// never "mismatch" -- the caller must not read absence as tampering.
pub fn lookup(pkg_dir: &Path, abs_path: &str) -> Option<Entry> {
    // No traversal check needed here and one would be misleading: this asks
    // about a path the CALLER already has, and an mtree entry that walks
    // elsewhere simply fails to equal it. `entries` is the direction that
    // needs the guard, because there the mtree chooses the path.
    let want = abs_path.strip_prefix('/')?;
    let file = std::fs::File::open(pkg_dir.join("mtree")).ok()?;
    let rd = std::io::BufReader::new(flate2::read::GzDecoder::new(file));
    for line in rd.lines().map_while(Result::ok) {
        let line = line.trim_end();
        // `/set` and `/unset` carry defaults; nothing we read is inherited,
        // because a line without its own `sha256digest` has no digest at all.
        if line.is_empty() || line.starts_with('#') || line.starts_with('/') {
            continue;
        }
        let mut fields = line.split(' ');
        let Some(raw) = fields.next() else { continue };
        let Some(rel) = raw.strip_prefix("./") else {
            continue;
        };
        if unescape(rel) != want {
            continue;
        }
        let mut sha256 = None;
        let mut size = 0u64;
        for f in fields {
            if let Some(v) = f.strip_prefix("sha256digest=") {
                sha256 = Some(v.to_string());
            } else if let Some(v) = f.strip_prefix("size=") {
                size = v.parse().unwrap_or(0);
            }
        }
        // Found the path. Whatever it says is the answer; a later line cannot
        // describe the same file.
        return sha256.map(|sha256| Entry { sha256, size });
    }
    None
}

/// Every path in a package's mtree that carries a digest, absolute.
///
/// One decompression for the whole package. `lookup` opens and decompresses
/// the mtree per call, which is right for a single question and wrong for a
/// sweep: asking it about 8,615 files would decompress a thousand mtrees
/// thousands of times over.
pub fn entries(pkg_dir: &Path) -> Vec<(String, Entry)> {
    let Ok(file) = std::fs::File::open(pkg_dir.join("mtree")) else {
        return Vec::new();
    };
    let rd = std::io::BufReader::new(flate2::read::GzDecoder::new(file));
    let mut out = Vec::new();
    for line in rd.lines().map_while(Result::ok) {
        let line = line.trim_end();
        if line.is_empty() || line.starts_with('#') || line.starts_with('/') {
            continue;
        }
        let mut fields = line.split(' ');
        let Some(raw) = fields.next() else { continue };
        let Some(rel) = raw.strip_prefix("./") else {
            continue;
        };
        let mut sha256 = None;
        let mut size = 0u64;
        for f in fields {
            if let Some(v) = f.strip_prefix("sha256digest=") {
                sha256 = Some(v.to_string());
            } else if let Some(v) = f.strip_prefix("size=") {
                size = v.parse().unwrap_or(0);
            }
        }
        if let Some(sha256) = sha256 {
            let path = format!("/{}", unescape(rel));
            // An mtree describes ONE package's files, and every one of them is
            // under `/`. A `..` component would make it describe someone
            // else's -- and the sweep would then read, hash and raise an alert
            // about a file the package never owned, on the package's say-so.
            // A hostile AUR package writes its own mtree, so this is not a
            // hypothetical the root ownership of the file rules out.
            if !path_stays_put(&path) {
                log::warn!(
                    "mtree in {}: ignoring {:?}, which walks out of the filesystem it \
                     describes",
                    pkg_dir.display(),
                    path
                );
                continue;
            }
            out.push((path, Entry { sha256, size }));
        }
    }
    out
}

/// Does this path name what it appears to name, without walking anywhere?
///
/// `..` is the whole question. `.` and empty components are harmless noise but
/// are refused too, because a path that needs normalising before it can be
/// compared is a path two pieces of code will normalise differently.
fn path_stays_put(path: &str) -> bool {
    use std::path::Component;
    std::path::Path::new(path)
        .components()
        .all(|c| matches!(c, Component::RootDir | Component::Normal(_)))
}

/// `\133` -> `[`, `\\` -> `\`. Anything else after a backslash is left as
/// written, so an unrecognised escape can never turn one path into another.
fn unescape(s: &str) -> String {
    if !s.contains('\\') {
        return s.to_string();
    }
    // Byte level: a path is bytes, and an octal escape names one byte.
    let b = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\' {
            if i + 1 < b.len() && b[i + 1] == b'\\' {
                out.push(b'\\');
                i += 2;
                continue;
            }
            if i + 4 <= b.len() {
                let d = &b[i + 1..i + 4];
                if d.iter().all(|c| (b'0'..=b'7').contains(c)) {
                    // Three octal digits reach 0o777 = 511, which is not a
                    // byte. Out of range is not an escape.
                    let n = (d[0] - b'0') as u16 * 64
                        + (d[1] - b'0') as u16 * 8
                        + (d[2] - b'0') as u16;
                    if n <= 255 {
                        out.push(n as u8);
                        i += 4;
                        continue;
                    }
                }
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// sha256 of a file on disk, hex, or `None` when it cannot be read.
///
/// Streams: a package-owned binary can be hundreds of megabytes and this runs
/// in the daemon.
pub fn sha256_file(path: &str) -> Option<String> {
    use sha2::{Digest, Sha256};
    let mut f = std::fs::File::open(path).ok()?;
    let mut h = Sha256::new();
    std::io::copy(&mut f, &mut h).ok()?;
    Some(format!("{:x}", h.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Octal escapes, against the name that forced them to exist.
    ///
    /// coreutils ships `/usr/bin/[`, written `./usr/bin/\133`. Getting this
    /// wrong does not throw: the path simply never matches, `lookup` returns
    /// `None`, and "no digest" reads as "cannot check" -- so a decoding bug
    /// silently excuses the file instead of failing loudly.
    #[test]
    fn octal_escapes_decode_to_the_byte_they_name() {
        assert_eq!(unescape("usr/bin/\\133"), "usr/bin/[");
        assert_eq!(unescape("a\\040b"), "a b");
        assert_eq!(unescape("back\\\\slash"), "back\\slash");
        assert_eq!(unescape("plain/path"), "plain/path");
        // Not escapes: too few digits, a non-octal digit, and out of range.
        assert_eq!(unescape("a\\13"), "a\\13");
        assert_eq!(unescape("a\\19b"), "a\\19b");
        assert_eq!(unescape("a\\777b"), "a\\777b");
    }

    /// A package describes its own files. An mtree that walks out of them
    /// would make the sweep read, hash and raise an alert about a file the
    /// package never owned -- on that package's say-so.
    ///
    /// Not ruled out by the file being root-owned: a hostile AUR package
    /// writes its own mtree, and `%VALIDATION%` says nothing about content.
    #[test]
    fn an_mtree_cannot_describe_files_outside_the_package() {
        use std::io::Write;
        let dir = tempfile::tempdir().unwrap();
        let body = [
            "#mtree",
            "/set type=file uid=0 gid=0 mode=755",
            "./usr/bin/mine time=1.0 size=4 sha256digest=aa",
            "./../../etc/shadow time=1.0 size=4 sha256digest=bb",
            "./usr/../../root/.ssh/id_rsa time=1.0 size=4 sha256digest=cc",
        ]
        .join("\n");
        let f = std::fs::File::create(dir.path().join("mtree")).unwrap();
        let mut gz = flate2::write::GzEncoder::new(f, flate2::Compression::fast());
        gz.write_all(body.as_bytes()).unwrap();
        gz.finish().unwrap();

        let got = entries(dir.path());
        let paths: Vec<&str> = got.iter().map(|(p, _)| p.as_str()).collect();
        // Control: the honest entry is still returned, so the refusals below
        // are the guard and not a parser that stopped working.
        assert!(paths.contains(&"/usr/bin/mine"), "{paths:?}");
        assert_eq!(paths.len(), 1, "and nothing that walks out: {paths:?}");
        assert!(
            !paths.iter().any(|p| p.contains("shadow") || p.contains("id_rsa")),
            "{paths:?}"
        );

        assert!(path_stays_put("/usr/bin/curl"));
        assert!(!path_stays_put("/usr/../etc/shadow"));
        assert!(!path_stays_put("/../etc/shadow"));
    }

    /// The parser against the real pacman database, if this machine has one.
    ///
    /// A fixture would prove the parser reads the format this test's author
    /// believed in. Only the installed database proves it reads the one pacman
    /// writes -- and this is the file a security decision now rests on.
    #[test]
    fn the_real_mtree_yields_the_digest_of_a_file_that_is_really_there() {
        let local = std::path::Path::new("/var/lib/pacman/local");
        if !local.is_dir() {
            return;
        }
        let Some(dir) = std::fs::read_dir(local)
            .unwrap()
            .flatten()
            .map(|e| e.path())
            .find(|p| {
                p.file_name()
                    .map(|n| n.to_string_lossy().starts_with("coreutils-"))
                    .unwrap_or(false)
            })
        else {
            return;
        };

        // A file every coreutils has, whose bytes are on this disk right now.
        let e = lookup(&dir, "/usr/bin/base32").expect("coreutils ships /usr/bin/base32");
        assert_eq!(e.sha256.len(), 64, "a sha256 is 64 hex characters");
        assert!(e.size > 0);
        assert_eq!(
            sha256_file("/usr/bin/base32").as_deref(),
            Some(e.sha256.as_str()),
            "the installed file must still match what the package recorded"
        );
        assert_eq!(
            std::fs::metadata("/usr/bin/base32").unwrap().len(),
            e.size,
            "and be the size it recorded"
        );

        // The escaped name, end to end through the real file.
        let br = lookup(&dir, "/usr/bin/[").expect("coreutils ships /usr/bin/[ as \\133");
        assert_eq!(
            sha256_file("/usr/bin/[").as_deref(),
            Some(br.sha256.as_str())
        );

        // Absence is not mismatch: a directory has no digest, and a path the
        // package does not own is not in the file at all.
        assert!(lookup(&dir, "/usr/bin").is_none(), "a directory has no digest");
        assert!(lookup(&dir, "/usr/bin/definitely-not-in-coreutils").is_none());
    }

    /// A changed byte must be caught. The real file, one bit different.
    #[test]
    fn a_modified_copy_does_not_match_the_recorded_digest() {
        let src = "/usr/bin/base32";
        if !std::path::Path::new(src).exists() {
            return;
        }
        let real = sha256_file(src).expect("readable");
        let tmp = std::env::temp_dir().join(format!("moat-mtree-{}", std::process::id()));
        let mut bytes = std::fs::read(src).unwrap();
        // Control: an untouched copy still matches, so the comparison is not
        // failing for some unrelated reason like a truncated read.
        std::fs::write(&tmp, &bytes).unwrap();
        assert_eq!(
            sha256_file(&tmp.to_string_lossy()).as_deref(),
            Some(real.as_str()),
            "an identical copy must match"
        );
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        std::fs::write(&tmp, &bytes).unwrap();
        assert_ne!(
            sha256_file(&tmp.to_string_lossy()).as_deref(),
            Some(real.as_str()),
            "one flipped bit must not match"
        );
        let _ = std::fs::remove_file(&tmp);
    }
}
