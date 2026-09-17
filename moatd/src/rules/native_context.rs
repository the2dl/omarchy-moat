//! Expected native operations stay in History; identity is not a blanket exemption.
use crate::{context::Context, explain::Finding, proctable::ProcInfo};
use std::{os::unix::fs::MetadataExt, path::{Component, Path}};

pub fn host(p: &ProcInfo) -> bool {
    p.in_container == Some(false) && p.user_ns_host == Some(true)
}

/// Require a system executable and root-controlled resolved path components.
/// This checks filesystem ownership, not package authenticity.
pub fn system_executable(path: &str) -> bool {
    let Ok(real) = std::fs::canonicalize(path) else { return false };
    if !real.starts_with("/usr") && !real.starts_with("/opt") { return false; }
    let Ok(m) = std::fs::metadata(&real) else { return false };
    m.is_file() && m.mode() & 0o111 != 0 && real.ancestors().all(|p| {
        std::fs::metadata(p).is_ok_and(|m| m.uid() == 0 && m.mode() & 0o022 == 0)
    })
}

fn beneath(path: &str, root: &str) -> bool {
    Path::new(path).starts_with(root) && path != root
        && !Path::new(path).components().any(|c| matches!(c, Component::ParentDir | Component::CurDir))
}

fn own_home(p: &ProcInfo, home: &str) -> bool {
    std::fs::metadata(home).is_ok_and(|m| m.uid() == p.uid)
}

pub fn own_profile(p: &ProcInfo, ancestors: &[&ProcInfo], path: &str, homes: &[String]) -> bool {
    own_profile_with(p, ancestors, path, homes, system_executable)
}

fn own_profile_with(p: &ProcInfo, ancestors: &[&ProcInfo], path: &str, homes: &[String], trusted: impl Fn(&str) -> bool) -> bool {
    if !host(p) { return false; }
    // /proc/self/exe is meaningful only with the observed direct parent, not
    // an arbitrary same-name ancestor or a live PID lookup after the event.
    let app = if p.exe == "/proc/self/exe" {
        let Some(parent) = ancestors.first().filter(|a| a.uid == p.uid && host(a)) else { return false };
        if !p.args.split_whitespace().any(|w| w == "--utility-sub-type=network.mojom.NetworkService") { return false; }
        parent.exe.as_str()
    } else { p.exe.as_str() };
    let roots: &[&str] = match app {
        "/opt/spotify/spotify" => &[".cache/spotify", ".config/spotify"],
        "/usr/lib/slack/slack" | "/opt/slack/slack" => &[".config/Slack"],
        "/opt/google/chrome/chrome" => &[".config/google-chrome"],
        "/usr/lib/chromium/chromium" => &[".config/chromium"],
        _ => return false,
    };
    trusted(app) && homes.iter().any(|home| own_home(p, home)
        && roots.iter().any(|root| beneath(path, &format!("{home}/{root}"))))
}

pub fn docker_storage(p: &ProcInfo, path: &str) -> bool {
    docker_storage_with(p, path, system_executable)
}

fn docker_storage_with(p: &ProcInfo, path: &str, trusted: impl Fn(&str) -> bool) -> bool {
    host(p) && p.uid == 0 && p.exe == "/usr/bin/dockerd" && trusted(&p.exe)
        && ["/var/lib/docker/overlay2", "/var/lib/docker/overlayfs", "/var/lib/docker/buildkit",
            "/var/lib/docker/tmp", "/var/lib/docker/containerd/daemon/io.containerd.snapshotter.v1.overlayfs",
            "/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs"]
            .iter().any(|root| beneath(path, root))
}

/// Return a reason for expected operations. Guard response/IoC events upstream.
pub fn classify(f: &mut Finding, homes: &[String]) -> bool {
    classify_with(f, homes, system_executable)
}

fn classify_with(f: &mut Finding, homes: &[String], trusted: impl Fn(&str) -> bool) -> bool {
    if f.ioc.is_some() || f.kill_expected || f.denied || f.request_kill
        || f.actor.modified.is_some() || f.context == Context::PkgInstall || !host(&f.proc) {
        return false;
    }
    let ancestors: Vec<_> = f.ancestry.iter().collect();
    let reason = if f.rule == "moat-cred-browser-secrets-read"
        && f.file.as_ref().is_some_and(|file| own_profile_with(&f.proc, &ancestors, &file.path, homes, &trusted)) {
        "Application accessed its own profile; this is not cross-application credential access"
    } else if matches!(f.rule.as_str(), "moat-cred-project-token-read" | "moat-persist-agent-config-write")
        && f.file.as_ref().is_some_and(|file| docker_storage_with(&f.proc, &file.path, &trusted)) {
        "Docker accessed configuration inside image/build storage; no host credential access or active host persistence established"
    } else if f.rule == "moat-x-ai-cli-headless" && f.proc.args.trim() == "--chrome-native-host"
        && f.ancestry.first().is_some_and(|p| p.comm() == "chrome-native-host" && p.uid == f.proc.uid)
        && f.ancestry.iter().any(|p| p.uid == f.proc.uid && host(p)
            && p.exe == "/opt/google/chrome/chrome" && trusted(&p.exe)) {
        "Browser launched its Claude native messaging helper; headlessness alone does not establish agent abuse"
    } else if f.rule == "moat-priv-ptrace-attach"
        && f.proc.exe == "/opt/google/chrome/chrome_crashpad_handler"
        && trusted(&f.proc.exe)
        && f.proc.args.split_whitespace().any(|w| w == "--monitor-self-annotation=ptype=crashpad-handler")
        && homes.iter().any(|home| own_home(&f.proc, home)
            && f.proc.args.contains(&format!("--database={home}/.config/google-chrome/Crash Reports"))) {
        "Chrome crash collector requested ptrace; target identity is not captured, so this event alone does not establish injection or credential theft"
    } else { return false };
    f.meta.family = "context".into();
    f.meta.severity = "low".into();
    f.meta.tier = "signal".into();
    f.meta.title = "Expected native application activity".into();
    f.meta.why = reason.into();
    f.what_override = Some(reason.into());
    f.extra_evidence.push(reason.into());
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    fn finding(rule: &str, exe: &str, args: &str, uid: u32) -> Finding {
        Finding::new(rule, crate::policy::PolicyMeta::fallback(rule), ProcInfo {
            exe: exe.into(), args: args.into(), uid,
            in_container: Some(false), user_ns_host: Some(true), ..Default::default()
        })
    }

    #[test]
    fn docker_image_files_are_context_but_host_secrets_and_startup_are_not() {
        for (rule, path) in [
            ("moat-cred-project-token-read", "/var/lib/docker/overlay2/layer/merged/app/.env"),
            ("moat-persist-agent-config-write", "/var/lib/docker/buildkit/refs/abc/AGENTS.md"),
            ("moat-cred-project-token-read", "/var/lib/docker/containerd/daemon/io.containerd.snapshotter.v1.overlayfs/snapshots/123/fs/app/.env"),
        ] {
            let mut f = finding(rule, "/usr/bin/dockerd", "-H fd://", 0);
            f.file = Some(crate::alert::FileRef { path: path.into(), sha256: None });
            assert!(classify_with(&mut f, &[], |_| true));
            assert_eq!(f.meta.family, "context");
            for bad in ["/root/.aws/credentials", "/etc/systemd/system/evil.service",
                "/var/lib/docker/overlay2/../../outside/.env", "/var/lib/docker/overlay2-other/.env"] {
                f.file.as_mut().unwrap().path = bad.into();
                assert!(!classify_with(&mut f, &[], |_| true));
            }
        }
        let p = finding("unused", "/tmp/dockerd", "", 0).proc;
        assert!(!docker_storage_with(&p, "/var/lib/docker/overlay2/x/.env", |_| true));
    }

    #[test]
    fn chrome_helpers_require_operation_and_lineage_not_just_their_name() {
        let home = tempfile::tempdir().unwrap();
        let homes = vec![home.path().display().to_string()];
        let uid = unsafe { libc::geteuid() };
        let mut f = finding("moat-x-ai-cli-headless", "/home/user/claude", "--chrome-native-host", uid);
        f.ancestry.push(finding("unused", "/home/user/chrome-native-host", "", uid).proc);
        f.ancestry.push(finding("unused", "/opt/google/chrome/chrome", "", uid).proc);
        assert!(classify_with(&mut f.clone(), &homes, |_| true));
        assert!(!classify_with(&mut f.clone(), &homes, |_| false));
        f.context = Context::PkgInstall;
        assert!(!classify_with(&mut f.clone(), &homes, |_| true));
        f.context = Context::Unknown;
        f.proc.args = "--chrome-native-host --dangerously-skip-permissions -p steal".into();
        assert!(!classify_with(&mut f.clone(), &homes, |_| true));
        f.proc.args = "--chrome-native-host".into();
        f.ancestry.clear();
        assert!(!classify_with(&mut f, &homes, |_| true));

        let args = format!("--monitor-self-annotation=ptype=crashpad-handler --database={}/.config/google-chrome/Crash Reports", homes[0]);
        let mut crash = finding("moat-priv-ptrace-attach", "/opt/google/chrome/chrome_crashpad_handler", &args, uid);
        assert!(classify_with(&mut crash.clone(), &homes, |_| true));
        crash.actor.modified = Some("changed bytes".into());
        assert!(!classify_with(&mut crash.clone(), &homes, |_| true));
        crash.actor.modified = None;
        crash.proc.args = "--database=/tmp/other".into();
        assert!(!classify_with(&mut crash, &homes, |_| true));
    }

    #[test]
    fn own_profile_requires_identity_owner_namespace_and_exact_scope() {
        let home = tempfile::tempdir().unwrap();
        let homes = vec![home.path().display().to_string()];
        let p = ProcInfo { exe: "/opt/spotify/spotify".into(), uid: unsafe { libc::geteuid() },
            in_container: Some(false), user_ns_host: Some(true), ..Default::default() };
        let path = format!("{}/.cache/spotify/Browser/Cookies", homes[0]);
        assert!(own_profile_with(&p, &[], &path, &homes, |_| true));
        for bad in [format!("{}/.config/google-chrome/Default/Cookies", homes[0]),
            format!("{}/.cache/spotify-other/Cookies", homes[0]),
            format!("{}/.cache/spotify/../secret", homes[0])] {
            assert!(!own_profile_with(&p, &[], &bad, &homes, |_| true));
        }
        assert!(!own_profile_with(&p, &[], &path, &homes, |_| false));
        let mut child = p.clone(); child.exe = "/proc/self/exe".into();
        child.args = "--utility-sub-type=network.mojom.NetworkService".into();
        assert!(own_profile_with(&child, &[&p], &path, &homes, |_| true));
        assert!(!own_profile_with(&child, &[], &path, &homes, |_| true));
        child.in_container = None;
        assert!(!own_profile_with(&child, &[&p], &path, &homes, |_| true));
        let mut wrong = p.clone(); wrong.uid = p.uid + 1;
        assert!(!own_profile_with(&wrong, &[], &path, &homes, |_| true));
    }
}
