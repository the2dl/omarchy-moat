# sentinel-scan-pkgbuild

Static review of an AUR package recipe *before* you build it. Pure Python 3
standard library, no dependencies, no network, no execution of anything it
reads.

```
sentinel-scan-pkgbuild [PATH ...]        # default: .
```

Each `PATH` may be a directory (its `PKGBUILD`, every `*.install` beside it and
every **local** file named in `source=()`) or a single file. Findings carry:

| field      | meaning                                                    |
|------------|------------------------------------------------------------|
| `id`       | stable rule id, e.g. `net.curl-pipe-shell`                  |
| `severity` | `high` \| `medium` \| `low`                                 |
| `file`     | path as given on the command line                           |
| `line`     | 1-based line of the offending statement                     |
| `evidence` | the offending line, whitespace-collapsed, ≤ 160 chars       |
| `why`      | one line: what attack this pattern is                       |
| `proceed`  | one line: how to move on if you judge it legitimate         |

## Options and exit codes

| flag | effect |
|------|--------|
| `--json` | `{"findings":[...],"summary":{"high":n,"medium":n,"low":n}}` |
| `--min-severity {low,medium,high}` | drop findings below this level (also changes the exit code) |
| `--quiet` / `-q` | print nothing; use the exit code (`--json` still prints) |
| `--allow-file PATH` | extra allow file, repeatable |
| `--no-allow` | ignore every allow file (what the tests use) |
| `--no-color` | never colorize (colour is automatic on a tty, `NO_COLOR` respected) |

| exit | meaning |
|------|---------|
| `0`  | nothing found, or only `low` findings |
| `1`  | at least one `medium`, no `high` |
| `2`  | at least one `high` |

## Rules

Severity is the default; the "adjusted to" column lists context that moves it.

| id | sev | catches | rationale / adjusted to |
|----|-----|---------|--------------------------|
| `net.curl-pipe-shell` | high | `curl`/`wget`/`aria2c` piped into `sh`/`bash`/`python`/`eval`, `bash <(curl …)`, `sh -c "$(curl …)"` | the build runs whatever the server serves at build time; nothing is checksummed |
| `obf.base64-exec` | high | `base64 -d`/`base32 -d`/`xxd -r`/`uudecode`/`openssl enc -d`/`b64decode` feeding a shell, `eval`, or a `chmod +x`'d file | the payload is unreadable in review; the only reason to encode a build step is to hide it |
| `obf.eval-var` | high | `eval` whose argument contains `$` | the command that actually runs is not in the file |
| `pkg.nested-package-manager` | high | `npm/pnpm/yarn/bun/npx install`, `pip install`, `uv pip install`, `cargo install`, `gem install`, `go install`, `poetry/composer/pipx install` | the June 2026 "Atomic Arch" shape: a second package manager fetches and runs install scripts makepkg never checksums. **medium** inside `PKGBUILD` (many electron/node packages genuinely do this and the sandbox contains it), **high** in a `.install` hook (root, at pacman time) |
| `src.host-mismatch` | medium | a `source=()` host that is not a known forge/CDN and not related to `url=`; or a forge source under a *different account* than `url=` | the July 2025 CHAOS RAT shape: a real-looking package whose payload comes from someone else's repo. **low** when the host merely looks like the same vendor (`slack.com` → `downloads.slack-edge.com`) |
| `src.suspicious-host` | high | pastebin/paste.ee/hastebin/termbin, ngrok, trycloudflare, transfer.sh, anonfiles, gofile, 0x0.st, `.onion`, Discord/Telegram webhook URLs, raw IP literals — in `source=()` **or** anywhere in the code | no legitimate package fetches sources from a paste bin, a tunnel or a bare IP |
| `src.skip-checksum` | medium | `SKIP` in `sha*sums`/`b2sums`/`md5sums` at the index of a **remote non-VCS** source | the file can change under you; `SKIP` on a `git+https://` source is correct and is *not* flagged |
| `persist.shell-rc` | high | writes to `~/.bashrc`, `.zshrc`, `.profile`, `.bash_profile`, `zshenv`, fish config, `/etc/profile*`, `/etc/bash.bashrc` outside `$pkgdir` | re-runs the payload on every login shell |
| `persist.systemd-enable` | high | `systemctl enable/start/link/preset/reenable`, or symlinks into `/etc/systemd/system/*.wants` | Arch packages must never enable or start services; the unit survives reboots. **medium** for `--global`/`--user` scope (the socket-activation idiom used by pipewire and gnome-keyring) |
| `persist.autostart` | high | writes to `~/.config/autostart`, `/etc/xdg/autostart`, `~/.config/systemd/user`, `~/.config/hypr/autostart` outside `$pkgdir` | runs on every session start and pacman does not own the file |
| `persist.cron` | high | `crontab`, writes to `/etc/cron.*`, `/etc/crontab`, `/var/spool/cron`, `systemd-run --on-calendar` outside `$pkgdir` | a recurring trigger the user never asked for |
| `persist.ld-preload` | high | `/etc/ld.so.preload`, `export LD_PRELOAD=` (**medium** for `/etc/ld.so.conf.d` writes outside `$pkgdir`) | injects code into every process started afterwards |
| `priv.suid` | high | `chmod +s`/`chmod 4755`-style, `install -m4755` | local privilege escalation. **medium** when the target is an ordinary system path (`/usr/bin/…`, as `1password-cli` legitimately does), **low** when it is under `$pkgdir` (the package merely ships a setuid file) |
| `priv.setcap` | high | `setcap` | same shape as above; **medium**/**low** by the same rule (mtr, gvfs-nfs and wireshark-cli legitimately setcap their own binaries) |
| `uni.invisible-chars` | high | zero-width, bidi, tag and filler characters: U+200B–200F, U+2028–202E, U+2060–2064, U+2066–206F, U+00AD, U+061C, U+180E, U+3164, U+FFA0, U+FE00–FE0F, U+FEFF, U+E0000–E007F, U+E0100–E01EF, plus any non-ASCII `Cc`/`Cf`/`Co`/`Cs` character | the GlassWorm technique: code a reviewer cannot see. **low** for a lone UTF-8 BOM on line 1. Evidence is printed with the invisible characters escaped (`​`) |
| `install.network` | high | any network verb in a `.install` hook: `curl`, `wget`, `git clone/pull/fetch`, `/dev/tcp/`, `nc`/`socat`, `ssh`/`scp`, remote `rsync`, `openssl s_client`, `gpg --recv-keys`, python `urllib`/`requests`, `npm`/`pip`/`cargo install` | `.install` hooks run as **root** at pacman time; fetching anything there is root-level RCE |

### Context the scanner understands (this is what keeps it quiet)

* **`$pkgdir` / `$srcdir` / `DESTDIR` staging** — a package that installs a
  cron file, a systemd unit or a `/etc/profile.d` snippet *under `$pkgdir`* is
  doing normal packaging; pacman owns those files. Persistence rules only fire
  on writes to the live system.
* **Removals** — `rm -r "$pkgdir"/etc/cron.daily/` is not persistence.
* **Message text** — a hit inside the quoted argument of `echo`/`printf`/`cat`
  is help text, not a command (`echo "run: systemctl --user enable foo"`).
* **Heredoc bodies** — passed through verbatim and never treated as commands,
  which also stops an apostrophe in prose from corrupting quote state.
* **Comments, line continuations, `name::url`, per-arch `source_x86_64` arrays
  and their matching `sha256sums_x86_64`, and `${var}` expansion** (including
  `${var^}` case modifiers) are all handled by the parser, so `url=`-relative
  source hosts resolve correctly.

## Allow file

`/etc/sentinel/scanner-allow.conf` (system) and
`~/.config/sentinel/scanner-allow.conf` (user, `$XDG_CONFIG_HOME` honoured) are
read on every run; `--allow-file PATH` and `$SENTINEL_SCANNER_ALLOW`
(colon-separated) add more. Format:

```conf
# one entry per line; keys on the same line are ANDed; '#' starts a comment
host=downloads.slack-edge.com          # trust a host (subdomains included)
rule=src.skip-checksum                 # silence a rule everywhere
rule=persist.*                         # globs work
pkg=my-electron-app                    # trust one package entirely
pkg=my-electron-app rule=pkg.nested-package-manager   # ... or just one rule of it
```

`pkg=` matches `pkgbase`/`pkgname` from the scanned `PKGBUILD`. Suppressed
findings are counted in the human output (`… hidden by allow rules`) so a
silenced rule never becomes invisible.

## How the makepkg shim calls it

`/usr/lib/sentinel/shims/makepkg` (see `sandbox/`) runs, before handing over to
the real `makepkg`:

```bash
sentinel-scan-pkgbuild .          # exit 0/1 -> continue, exit 2 -> ask
```

* exit `0` or `1`: build continues (findings were printed, nothing blocks).
* exit `2`: interactive → `gum confirm "Build anyway?"`; non-interactive →
  refuse and exit non-zero.
* `SENTINEL_SANDBOX=0` bypasses the shim entirely, scan included.

Use `--json` if you want to feed the result to something else; the schema above
is stable.

## Adding a rule

1. **Pick an id** in the existing `family.rule` style (`net`, `obf`, `pkg`,
   `src`, `persist`, `priv`, `uni`, `install`). Ids are API: the allow file and
   the plugin both key on them, so never rename one.
2. **Add it to `RULES`** in `sentinel-scan-pkgbuild` with
   `(severity, why, proceed)`. `why` is one sentence on the attack; `proceed`
   is one sentence with a concrete escape hatch and may use `{pkg}`, `{id}`,
   `{host}`.
3. **Add the pattern** near the other compiled regexes.
4. **Check it in `Scanner.scan_code`** (per logical line) or in
   `Scanner.scan_sources` (per `source=()` entry). Guard command-shaped rules
   with `live(m)` so heredocs and `echo` help text do not trigger them, and
   consider `staging` / `removing` before flagging a path write.
5. **Add a fixture** under `tests/fixtures/<name>/` — synthetic only, never
   real malware — and a test in `tests/test_scanner.py` asserting the exact id
   set and exit code.
6. **Re-check the false-positive corpus**: every `PKGBUILD` in `~/.cache/yay/*/`
   and, for `.install` rules, `/var/lib/pacman/local/*/install`. Ordinary
   packages must come out clean or `low`.

```
python3 -m unittest discover scanner/tests
```
