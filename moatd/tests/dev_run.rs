//! End-to-end test: runs `dev-run.sh` against the freshly built binaries.
//!
//! This is the same script a developer runs by hand, so if the demo breaks, CI
//! notices. It needs no root, no Tetragon and no network: the "export file" is
//! `testdata/sample.log` copied into a scratch directory.

use std::path::PathBuf;
use std::process::Command;

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

#[test]
fn dev_run_script_completes() {
    let script = manifest_dir().join("dev-run.sh");
    assert!(script.exists(), "dev-run.sh is missing");

    let out = Command::new("bash")
        .arg(&script)
        // Reuse the binaries cargo just built for this test run.
        .env("SKIP_BUILD", "1")
        .env("MOATD_BIN", env!("CARGO_BIN_EXE_moatd"))
        .env("MOATCTL_BIN", env!("CARGO_BIN_EXE_moatctl"))
        .env("RUST_LOG", "warn")
        .output()
        .expect("failed to run dev-run.sh");

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "dev-run.sh failed ({}):\n--- stdout ---\n{}\n--- stderr ---\n{}",
        out.status,
        stdout,
        stderr
    );

    // The script walked the whole flow; check the parts that matter.
    for needle in [
        "rendered 5 policies",
        "\"policy_names\"",
        "moatd  0.1.0",
        "WHAT HAPPENED",
        "WHY IT WAS FLAGGED",
        "EVIDENCE",
        "IF THIS IS EXPECTED",
        "WHAT TO DO",
        "[[rule]]",
        "OK — dev run complete",
    ] {
        assert!(
            stdout.contains(needle),
            "dev-run output missing {:?}\n{}",
            needle,
            stdout
        );
    }
}

/// `moatctl` must fail loudly, and usefully, when the daemon is not there.
#[test]
fn moatctl_without_a_daemon_explains_itself() {
    let out = Command::new(env!("CARGO_BIN_EXE_moatctl"))
        .args(["--socket", "/nonexistent/moat.sock", "status"])
        .output()
        .expect("failed to run moatctl");
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("moatd running"), "{}", stderr);
}

/// A permission error must tell the user how to fix it (CONTRACT §5).
#[test]
fn permission_denied_names_the_group_command() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("locked/control.sock");
    std::fs::create_dir_all(sock.parent().unwrap()).unwrap();
    std::fs::write(&sock, b"").unwrap();
    // Make the containing directory unsearchable so connect() gets EACCES.
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(sock.parent().unwrap(), std::fs::Permissions::from_mode(0o000)).unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_moatctl"))
        .args(["--socket", sock.to_str().unwrap(), "status"])
        .output()
        .expect("failed to run moatctl");

    std::fs::set_permissions(sock.parent().unwrap(), std::fs::Permissions::from_mode(0o755)).unwrap();

    let stderr = String::from_utf8_lossy(&out.stderr);
    if unsafe { libc::geteuid() } == 0 {
        // root ignores directory permissions; nothing to assert.
        return;
    }
    assert!(!out.status.success());
    assert!(
        stderr.contains(sock.to_str().unwrap()),
        "the refusal must name the socket it was refused on, got: {}",
        stderr
    );
    assert!(
        stderr.contains("moat"),
        "expected group advice, got: {}",
        stderr
    );

    // The advice has to match reality. Someone already in the group who is told
    // to run `usermod -aG moat` is sent round a loop that cannot terminate: the
    // command succeeds, changes nothing, and the socket still refuses them.
    let already_a_member = std::fs::read_to_string("/etc/group")
        .unwrap_or_default()
        .lines()
        .filter(|l| l.starts_with("moat:"))
        .any(|l| {
            let user = std::env::var("USER").unwrap_or_default();
            !user.is_empty()
                && l.rsplit(':')
                    .next()
                    .unwrap_or("")
                    .split(',')
                    .any(|m| m == user)
        });
    if already_a_member {
        assert!(
            !stderr.contains("usermod -aG moat"),
            "already in the group, so usermod is the one thing that cannot help: {}",
            stderr
        );
    }
}

/// `moat-feeds` must exit 0 with no key and leave existing files alone.
#[test]
fn moat_feeds_without_a_key_is_a_no_op() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = dir.path().join("feeds.toml");
    std::fs::write(&cfg, "auth_key = \"\"\n").unwrap();
    let out_dir = dir.path().join("feeds");
    std::fs::create_dir_all(&out_dir).unwrap();
    std::fs::write(out_dir.join("hashes.txt"), "cafebabe\n").unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_moat-feeds"))
        .args(["--config", cfg.to_str().unwrap()])
        .args(["--out-dir", out_dir.to_str().unwrap()])
        .arg("--json")
        .output()
        .expect("failed to run moat-feeds");

    assert!(out.status.success(), "the timer must never fail hard");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("\"skipped\":true"), "{}", stdout);
    assert_eq!(
        std::fs::read_to_string(out_dir.join("hashes.txt")).unwrap(),
        "cafebabe\n",
        "existing feed files must survive"
    );
}

/// `render-policies` is idempotent, which matters because it is an
/// ExecStartPre that runs on every boot.
#[test]
fn render_policies_is_idempotent_from_the_cli() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("policies");
    let allow = dir.path().join("export-allowlist");
    let run = || {
        Command::new(env!("CARGO_BIN_EXE_moatd"))
            .arg("render-policies")
            .args(["--templates-dir", manifest_dir().join("testdata/templates").to_str().unwrap()])
            .args(["--out-dir", out.to_str().unwrap()])
            .args(["--export-allowlist", allow.to_str().unwrap()])
            .args(["--home", "/home/dan"])
            .arg("--json")
            .output()
            .expect("render-policies failed to run")
    };
    let first: serde_json::Value = serde_json::from_slice(&run().stdout).unwrap();
    assert_eq!(first["rendered"].as_array().unwrap().len(), 5);
    assert_eq!(first["files_changed"], 5);
    assert_eq!(first["allowlist_changed"], true);

    let second: serde_json::Value = serde_json::from_slice(&run().stdout).unwrap();
    assert_eq!(second["files_changed"], 0);
    assert_eq!(second["allowlist_changed"], false);

    let body = std::fs::read_to_string(&allow).unwrap();
    let lines: Vec<&str> = body.lines().collect();
    assert_eq!(lines[0], r#"{"event_set":["PROCESS_EXEC","PROCESS_EXIT"]}"#);
    assert!(lines[1].contains(r#""policy_names":["moat-"#));
    assert!(lines[1].starts_with(r#"{"event_set":["PROCESS_KPROBE""#));
}
