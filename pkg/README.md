# pkg/ — the `omarchy-moat` Arch package

One `pacman` package holds everything the system half of Moat needs: the
upstream Tetragon v1.7.1 sensor, our policy templates, `moatd` and its
units, the bubblewrap sandbox with its shims, and the PKGBUILD scanner. The
omarchy-shell plugin is **not** in here — see "Package vs plugin" below.

```
pkg/
├── PKGBUILD                  package recipe (version 0.1.0, x86_64)
├── omarchy-moat.install  post_install / post_upgrade / pre_remove notices
├── LICENSE.MIT               our licence, shipped as /usr/share/licenses/…/LICENSE
├── scanner-allow.conf        /etc/moat/scanner-allow.conf (commented example)
├── .gitignore                makepkg's src/, pkg/ and fetched sources
└── README.md                 this file
```

## Build

**Run `makepkg` from inside `pkg/`.** makepkg has no source type for a sibling
directory of the PKGBUILD (`../moatd` is not a valid `source=()` entry), so
`prepare()` copies the components out of the repository working tree via
`$startdir/..` — the usual pattern for a PKGBUILD that lives inside the repo it
packages. That makes the working directory load-bearing; `prepare()` aborts with
a clear message if the repository root is not where it expects.

```bash
cd pkg
makepkg -f
```

Result: `omarchy-moat-0.1.0-1-x86_64.pkg.tar.zst` (~75 MB compressed,
~284 MB installed — most of it is Tetragon's 94 CO-RE BPF objects and the two
Go binaries).

What the build does:

| phase | what runs |
|---|---|
| download | the upstream Tetragon tarball, pinned to the sha256 published next to the release as `tetragon-v1.7.1-amd64.tar.gz.sha256sum` (never `SKIP`), plus Tetragon's `LICENSE` and `bpf/LICENSE.GPL-2.0` at tag `v1.7.1` |
| `prepare()` | copy the working tree into `$srcdir`, drop any developer `target/`, `cargo fetch --locked` |
| `build()` | `cargo build --release --locked` in the copied `moatd/` (`Cargo.lock` is committed, so `--locked` is meaningful) |
| `check()` | `cargo test --release --locked` · `python3 policies/check.py policies` · `python3 -m unittest discover tests` in `scanner/` · `bash sandbox/tests/run.sh` |
| `package()` | install exactly the layout in `docs/CONTRACT.md` §2 |

`check()` runs in full — the sandbox suite uses **real** bubblewrap, and that
works because makepkg itself is unprivileged (only `package()` is `fakeroot`ed).
No `--nocheck` needed. Use `makepkg -f --nocheck` only on a machine where
unprivileged user namespaces are disabled.

Build-time requirements: `cargo`, plus `python`, `bubblewrap`, `bash` and
`shellcheck` for the check phase.

### `options=('!debug' '!lto' '!strip')`

`!debug` and `!lto` because cargo owns codegen and the release profile already
sets `strip = true`. `!strip` matters more than it looks: makepkg's tidy-install
step strips every ELF it finds, which rewrote all 94 upstream BPF objects (26
ELF sections down to 17). Tetragon is meant to ship byte-identical to upstream,
and a stripped CO-RE object is a relocation failure waiting to happen. With
`!strip` the packaged `.o` files hash identical to the ones in the release
tarball.

## Install

```bash
sudo pacman -U omarchy-moat-0.1.0-1-x86_64.pkg.tar.zst
```

pacman's own alpm hooks run `systemd-sysusers` (creating the `moat` group)
and `systemd-tmpfiles --create` (creating `/var/lib/moat`,
`/var/log/moat`, `/run/moat`, `/run/moat/policies` and the
quarantine dir), then reload the systemd manager. The `.install` file does not
duplicate any of that, and it never enables or starts a unit.

## Enable

```bash
sudo systemctl enable --now tetragon moatd moat-feeds.timer
sudo usermod -aG moat $USER
# log out and back in — a new group only reaches a fresh session
omarchy plugin add https://github.com/the2dl/omarchy-moat --enable
moatctl status
```

Moat starts in **monitor** mode: it alerts, it never kills.
`moatctl set mode enforce` switches it. The bubblewrap shims are off until
`moatctl set sandbox on` creates `/etc/moat/sandbox.enabled`; the
`/etc/profile.d` and fish snippets are no-ops until then, and they only take
effect in a new login shell.

## Uninstall

```bash
sudo systemctl disable --now tetragon moatd moat-feeds.timer
sudo pacman -Rns omarchy-moat
```

`pacman -Rns` leaves behind, on purpose:

* `/var/lib/moat` (alerts, quarantine, feeds) and `/var/log/moat` — the
  evidence trail outlives the package; delete by hand when you want it gone.
* modified `backup=()` files under `/etc/moat` and `/etc/tetragon`, saved as
  `.pacsave`.

`/run/moat` is tmpfs and disappears on reboot regardless.

## Package vs plugin

They are two halves and they install through different channels.

| | package | plugin |
|---|---|---|
| what | Tetragon, policies, `moatd`, sandbox, scanner | the omarchy-shell bar widget and panel (`shell/`, `manifest.json`) |
| installed by | `pacman -U` | `omarchy plugin add <repo-url> --enable` |
| runs as | root (`tetragon`, `moatd`) | your user, inside omarchy-shell |
| talks over | — | `/run/moat/control.sock` + `/var/lib/moat/alerts.jsonl` |

The plugin is deliberately **not** packaged: omarchy-shell manages plugins
itself, out of a git checkout, and hot-reloads them. The package is what gives
the plugin something to talk to. Without the package the plugin shows its setup
screen; without the plugin the package is fully usable from `moatctl`.

The bridge between them is group membership. Both the socket
(`/run/moat/control.sock`, 0660) and `alerts.jsonl` (0640) are
`root:moat`, so a user not in the `moat` group sees a grey shield and a
setup hint no matter how healthy the daemon is.

## The upgrade caveat

**Tetragon reads its tracing policies exactly once, at startup, and has no
hot-reload.** `policy_names` in the export allowlist has no glob and no prefix
match either. So an upgrade that adds, removes or edits a policy changes nothing
until you restart the sensor:

```bash
sudo systemctl restart tetragon moatd
```

`post_upgrade` prints this and stops there — restarting the sensor for you would
tear down every loaded BPF program mid-`pacman`, which is exactly the moment you
least want the machine unwatched. Restarting `tetragon.service` re-runs
`ExecStartPre=/usr/bin/moatd render-policies`, which re-expands `{{HOME}}`
into `/run/moat/policies` and regenerates
`/etc/tetragon/tetragon.conf.d/export-allowlist` with the exact policy names.

Two consequences worth knowing:

* `export-allowlist` is a `backup=()` file that the daemon also rewrites. It
  ships with the exact content `render-policies` generates for the 32 policies
  in this version, so normally there is no drift — but after an upgrade that
  changes the policy set, expect a `.pacnew` and ignore it: the next
  `tetragon` start overwrites the live file correctly either way.
* `moatd` loads `moat.toml`, the policy annotations and `allowlist.d`
  at start. `systemctl reload moatd` (SIGHUP) re-reads all three without
  dropping the process table; a full restart is only needed when the binary
  itself changed.
