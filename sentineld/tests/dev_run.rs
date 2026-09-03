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
        .env("SENTINELD_BIN", env!("CARGO_BIN_EXE_sentineld"))
        .env("SENTINELCTL_BIN", env!("CARGO_BIN_EXE_sentinelctl"))
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
        "sentineld  0.1.0",
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

/// `sentinelctl` must fail loudly, and usefully, when the daemon is not there.
#[test]
fn sentinelctl_without_a_daemon_explains_itself() {
    let out = Command::new(env!("CARGO_BIN_EXE_sentinelctl"))
        .args(["--socket", "/nonexistent/sentinel.sock", "status"])
        .output()
        .expect("failed to run sentinelctl");
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("sentineld running"), "{}", stderr);
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

    let out = Command::new(env!("CARGO_BIN_EXE_sentinelctl"))
        .args(["--socket", sock.to_str().unwrap(), "status"])
        .output()
        .expect("failed to run sentinelctl");

    std::fs::set_permissions(sock.parent().unwrap(), std::fs::Permissions::from_mode(0o755)).unwrap();

    let stderr = String::from_utf8_lossy(&out.stderr);
    if unsafe { libc::geteuid() } == 0 {
        // root ignores directory permissions; nothing to assert.
        return;
    }
    assert!(!out.status.success());
    assert!(
        stderr.contains("usermod -aG sentinel"),
        "expected the group hint, got: {}",
        stderr
    );
}

/// `sentinel-feeds` must exit 0 with no key and leave existing files alone.
#[test]
fn sentinel_feeds_without_a_key_is_a_no_op() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = dir.path().join("feeds.toml");
    std::fs::write(&cfg, "auth_key = \"\"\n").unwrap();
    let out_dir = dir.path().join("feeds");
    std::fs::create_dir_all(&out_dir).unwrap();
    std::fs::write(out_dir.join("hashes.txt"), "cafebabe\n").unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_sentinel-feeds"))
        .args(["--config", cfg.to_str().unwrap()])
        .args(["--out-dir", out_dir.to_str().unwrap()])
        .arg("--json")
        .output()
        .expect("failed to run sentinel-feeds");

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
        Command::new(env!("CARGO_BIN_EXE_sentineld"))
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
    assert!(lines[1].contains(r#""policy_names":["sentinel-"#));
    assert!(lines[1].starts_with(r#"{"event_set":["PROCESS_KPROBE""#));
}
