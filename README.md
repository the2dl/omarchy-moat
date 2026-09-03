# omarchy-sentinel

Developer-workstation EDR for Omarchy. Tetragon (eBPF, upstream, unmodified) as the
kernel sensor, a Rust companion daemon for correlation and response, prevention
shims for package managers, and an omarchy-shell plugin for notifications and a
panel.

Threat model: a hijacked package (npm, PyPI, AUR, editor extension) running as the
logged-in user, harvesting credentials from $HOME and installing persistence.
Root compromise is out of scope for enforcement; it is detected best-effort.

Layout:

    manifest.json   omarchy-shell plugin manifest (plugin id io.github.the2dl.sentinel)
    shell/          QML: Service, bar widget, panel
    pkg/            PKGBUILD for the system package `omarchy-sentinel`
    policies/       Tetragon TracingPolicy YAML (the detection rules)
    sentineld/      Rust: sentineld (daemon) + sentinelctl (client) + sentinel-feeds
    sandbox/        bubblewrap sandbox wrapper + PATH shims for npm/pip/cargo/makepkg
    scanner/        PKGBUILD / .install static scanner
    docs/           CONTRACT.md is the interface spec every component builds against

See docs/CONTRACT.md before touching anything.
