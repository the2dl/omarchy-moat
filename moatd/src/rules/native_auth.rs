//! Native authentication is context, not a credential-theft sequence by itself.
use crate::{context::Context, explain::Finding, provenance::Provenance};
use std::os::unix::fs::MetadataExt;

pub fn classify(f: &mut Finding, homes: &[String]) {
    if f.rule != "moat-cred-cloud-credentials-read"
        || f.actor.provenance != Provenance::Official
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
        file.path == format!("{home}/.kube/config")
            && std::fs::metadata(home).is_ok_and(|m| m.uid() == f.proc.uid)
    });
    if !own_config { return; }
    let expected = match f.proc.exe.as_str() {
        "/usr/bin/gke-gcloud-auth-plugin" => f.ancestry.iter().any(|p| p.exe == "/usr/bin/kubectl"),
        "/usr/lib/docker/cli-plugins/docker-buildx" => {
            f.ancestry.first().is_some_and(|p| p.exe == "/usr/bin/docker")
                && (f.proc.args.starts_with("buildx build ") || f.proc.args.starts_with("build ")
                    || f.proc.args.starts_with("buildx imagetools inspect ")
                    || f.proc.args.starts_with("imagetools inspect "))
        }
        _ => false,
    };
    if !expected { return; }
    f.meta.family = "auth".into();
    f.meta.severity = "low".into();
    f.meta.tier = "signal".into();
    f.meta.title = "Native tool accessed its cluster configuration".into();
    f.what_override = Some("A package-verified native authentication or build tool read its user's kubeconfig in its expected launch context. Other credential files and destinations remain monitored.".into());
    f.extra_evidence.push("native authentication context: verified host executable, same-user kubeconfig and expected launcher; this is not permission for other tools".into());
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
        base.ancestry.push(crate::proctable::ProcInfo { exe: "/usr/bin/kubectl".into(), ..Default::default() });
        let mut yes = base.clone();
        classify(&mut yes, &homes);
        assert_eq!(yes.meta.family, "auth");
        let mut buildx = base.clone();
        buildx.proc.exe = "/usr/lib/docker/cli-plugins/docker-buildx".into();
        buildx.ancestry[0].exe = "/usr/bin/docker".into();
        for args in ["buildx imagetools inspect registry.example/project/image:tag", "imagetools inspect registry.example/project/image:tag"] {
            let mut inspect = buildx.clone();
            inspect.proc.args = args.into();
            classify(&mut inspect, &homes);
            assert_eq!(inspect.meta.family, "auth");
        }
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
