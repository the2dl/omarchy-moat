//! Native authentication is context, not a credential-theft sequence by itself.
use crate::{context::Context, explain::Finding, provenance::Provenance};
use std::os::unix::fs::MetadataExt;

pub fn classify(f: &mut Finding, homes: &[String]) {
    classify_with(f, homes, super::native_context::system_executable)
}

fn classify_with(f: &mut Finding, homes: &[String], trusted: impl Fn(&str) -> bool) {
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
                    && f.proc.exe == "/usr/lib/docker/cli-plugins/docker-buildx"
                    && file.path == format!("{home}/.docker/config.json")))
            && std::fs::metadata(home).is_ok_and(|m| m.uid() == f.proc.uid)
    });
    if !own_config { return; }
    let expected = match f.proc.exe.as_str() {
        "/usr/bin/gke-gcloud-auth-plugin" => f.ancestry.first().is_some_and(|p| p.exe == "/usr/bin/kubectl" && p.uid == f.proc.uid),
        "/usr/lib/docker/cli-plugins/docker-buildx" => {
            f.ancestry.first().is_some_and(|p| p.exe == "/usr/bin/docker" && p.uid == f.proc.uid)
                && (f.proc.args.starts_with("buildx build ") || f.proc.args.starts_with("build ")
                    || f.proc.args.starts_with("buildx imagetools inspect ")
                    || f.proc.args.starts_with("imagetools inspect ")
                    || matches!(f.proc.args.trim(), "buildx ls" | "ls")
                    || f.proc.args.starts_with("buildx ls ") || f.proc.args.starts_with("ls "))
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
        registry.meta.family = "cred".into();
        registry.file.as_mut().unwrap().path = format!("{}/.npmrc", homes[0]);
        classify(&mut registry, &homes);
        assert_eq!(registry.meta.family, "cred");
        buildx.proc.args = "buildx imagetools create registry.example/project/image:tag".into();
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
