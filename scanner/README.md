# moat scanners

Three pre-execution static analysers, all pure Python 3 standard library, no
dependencies, no network, no execution of anything they read, sharing one
finding shape, one allow file and one exit-code contract:

| tool | reads | run by |
|------|-------|--------|
| [`moat-scan-pkgbuild`](#moat-scan-pkgbuild) | `PKGBUILD`, `*.install`, local `source=()` files | the `makepkg` shim |
| [`moat-scan-npm`](#moat-scan-npm) | `package.json`, lockfiles, `node_modules`, JS/Python source | the `npm`, `pnpm`, `yarn`, `bun` shims |
| [`moat-scan-build`](#moat-scan-build) | `build.rs`, `Cargo.toml`, `Cargo.lock`, `.cargo/config.toml`, `setup.py`, `pyproject.toml`, `*.pth`, requirements files, `go.mod`, Go source | the `cargo`, `pip`, `pip3`, `uv` and `go` shims, under the names `moat-scan-cargo`, `moat-scan-pip` and `moat-scan-go` |

The one question all three answer is the same one: **if I let this thing run
right now, what would execute?** Everything they check is somewhere an
ecosystem runs code *before the user has run anything* — a `PKGBUILD`'s
`build()`, an npm `postinstall`, a Rust `build.rs`, a Python `setup.py`, a
`.pth` file's `import` line.

---

## moat-scan-pkgbuild

Static review of an AUR package recipe *before* you build it. Pure Python 3
standard library, no dependencies, no network, no execution of anything it
reads.

```
moat-scan-pkgbuild [PATH ...]        # default: .
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

`/etc/moat/scanner-allow.conf` (system) and
`~/.config/moat/scanner-allow.conf` (user, `$XDG_CONFIG_HOME` honoured) are
read on every run; `--allow-file PATH` and `$MOAT_SCANNER_ALLOW`
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

`/usr/lib/moat/shims/makepkg` (see `sandbox/`) runs, before handing over to
the real `makepkg`:

```bash
moat-scan-pkgbuild .          # exit 0/1 -> continue, exit 2 -> ask
```

* exit `0` or `1`: build continues (findings were printed, nothing blocks).
* exit `2`: interactive → `gum confirm "Build anyway?"`; non-interactive →
  refuse and exit non-zero.
* `MOAT_SANDBOX=0` bypasses the shim entirely, scan included.

Use `--json` if you want to feed the result to something else; the schema above
is stable.

## Adding a rule

1. **Pick an id** in the existing `family.rule` style (`net`, `obf`, `pkg`,
   `src`, `persist`, `priv`, `uni`, `install`). Ids are API: the allow file and
   the plugin both key on them, so never rename one.
2. **Add it to `RULES`** in `moat-scan-pkgbuild` with
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

---

## moat-scan-npm

Static review of a JavaScript package tree *before* its install scripts run.
Same finding shape, same allow file, same exit codes as above.

```
moat-scan-npm [PATH ...]             # default: .
```

Each `PATH` may be

* a **project** (a directory with a lockfile or a `node_modules/`): its
  `package.json`, its lockfile, and the `package.json` of every package in
  `node_modules` are read, plus the files any install script actually invokes;
* a **package directory** (a `package.json`, no lockfile — an unpacked
  tarball): everything in it is read;
* a **single source file**: the obfuscation heuristics only.

The question it answers is *if I let npm run right now, what would execute?*
Everything it needs is on disk: it never contacts a registry, which would be
both slow in front of every install and a new attack surface.

### Options and exit codes

The flags and the exit codes are `moat-scan-pkgbuild`'s, plus:

| flag | effect |
|------|--------|
| `--deep` | also run the obfuscation heuristics over every `.js/.cjs/.mjs/.jsx/.ts/.py` file in the tree. Not what the shims run: ~1 s over `node_modules`, against ~50 ms for the default scan |
| `--max-per-rule N` | human output only: show at most `N` findings per rule, then a count (default 10, `0` for all). JSON always carries everything |

`--json` adds one field to each finding, `pkg`, the package the finding
belongs to — that is what the allow file's `pkg=` matches.

### The severity ladder, and why

A scanner that false-positives blocks the user's work, so the default is
**warn and continue**; only six of the fourteen rules can reach `high`, and
each of those describes something with no benign explanation inside an install
script. **Presence of a lifecycle script never refuses a build.**

| id | sev | catches | rationale / adjusted to |
|----|-----|---------|--------------------------|
| `npm.lifecycle-script` | medium | a `preinstall`/`install`/`postinstall` in a **transitive** dependency | nobody chose this package; it is the shape of every recent npm worm. **low** for a **direct** dependency (you added `sharp` *because* it builds), **low** for a recognised native-build idiom in any dependency (`node-gyp`, `node-gyp-build`, `prebuild-install`, `node-pre-gyp`, `cmake-js`, `napi`, `husky`, `patch-package`, `echo`/`exit 0`, `npm run …`). **Not reported at all** for the project's own `package.json`: you wrote it |
| `npm.script-shell-pipe` | high | an install script piping a download into a shell (`curl … \| sh`, `sh -c "$(curl …)"`, `bash <(wget …)`) | the install runs whatever that server sends today; there is no build reason for it |
| `npm.script-net-literal` | high | an install script naming a bare public IP, a paste bin, a tunnel (ngrok, trycloudflare), an exfil endpoint (`webhook.site`, `requestbin`, `0x0.st`), or a Discord/Telegram webhook | that is where stolen data goes. **medium** for an ordinary `https://` host that a fetch verb in the same script downloads from |
| `npm.script-credential-path` | high | an install script naming `~/.ssh`, `id_rsa`, `.npmrc`/`_authToken`, `.aws`, `.gnupg`, `.netrc`, `.git-credentials`, `.docker/config`, `.kube/config`, gcloud, keychains, keyrings, wallets, or `NPM_TOKEN`/`AWS_SECRET`-style names | the Shai-Hulud token-theft shape; a build step has no reason to read any of them |
| `npm.script-home-access` | medium | an install script reaching into `$HOME`/`~`/`os.homedir()` outside the build caches | native builds live in `~/.cache`, `~/.node-gyp`, `~/.npm`, `~/.electron`, `~/.cargo` and friends, all of which are allowed and silent |
| `npm.bin-outside-package` | high | a `bin` entry that is absolute or escapes the package directory with `../` | linking it puts a file the package does not own on your `PATH` |
| `lock.foreign-registry` | medium | a `resolved` URL whose host is not your configured registry | it is re-fetched on every `npm ci` and every fresh clone, which makes it persistence rather than a one-off. **high** for a paste bin/tunnel/webhook/public bare IP, **low** for a forge tarball (`codeload.github.com`, gitlab, codeberg). Not applied to `git+`, `file:`, `link:`, `workspace:`, `portal:` entries |
| `lock.missing-integrity` | medium | a registry tarball pinned with `resolved` but no `integrity` | what arrives is whatever the server serves at install time. Not applied to git/file/link entries, which legitimately have no hash |
| `obf.eval-decoded` | high | decoded data reaching `eval`, `new Function`, `vm.runIn*`, Python `exec`/`compile`, or `child_process.exec` — inline **or** through a variable assigned a decode one or two lines earlier | `new Function(decoded)()` with the decode on the line above is the exact shape this scanner was written for. The finding prints what the blob decodes to, so nobody has to run it |
| `obf.computed-require` | high | a module name assembled from string literals (`"child_" + "process"`) or decoded at runtime | done only to keep a grep from finding it. **medium** when the reconstructed name is not a sensitive core module. `require("./locale/" + lang)` and `require(path.join(…))` are ordinary and not flagged |
| `obf.charcode-chain` | medium | `String.fromCharCode` with 8+ numeric arguments | the classic dropper encoding; the finding prints the decoded string |
| `obf.long-blob` | low | a 400+ character base64 or hex string literal | usually an embedded asset. Context for a nearby `eval` finding, never a reason to stop |
| `obf.long-line` | low | a line over 5 000 characters | minified output, or code packed to defeat review. Skipped entirely under `dist/`, `build/`, `vendor/`, `*.min.js`, `*.map`, fixtures |

### Context the scanner understands (this is what keeps it quiet)

* **`prepare` is not an install script for a registry dependency.** npm runs
  `prepare` for the root project, for a git/`file:`/`link:` dependency, and
  before pack/publish — never for a package installed from a registry tarball.
  Published packages routinely ship a development `prepare` (`tshy`, `tsc`,
  `husky`), so reporting it fired **20 times on npm's own bundled dependency
  tree** and never once described something that would execute. It is reported
  only when the package is resolved from git or from disk.
* **Direct versus transitive** comes from the root `package.json` (all four
  dependency blocks) plus every workspace package's, so a monorepo's own
  packages count as chosen.
* **The project's own lifecycle scripts** are never reported for existing —
  but they are still read for content, because a repo you cloned and did not
  write is an RCE if its `preinstall` pipes `curl` into `sh`.
* **`registry.yarnpkg.com`** is the public registry under another name; yarn 1
  writes it into every lockfile regardless of `registry=`, so treating it as
  foreign would flag every yarn project alive. Your own `registry=` and
  `@scope:registry=` are read from `.npmrc` (project, user, `/etc`) and
  `$npm_config_registry` — offline, by parsing the file.
* **A private-IP registry** (`http://10.0.0.5:4873/`, Verdaccio, Artifactory)
  is a real corporate setup: `medium`, not `high`. Only a *public* bare IP is
  unambiguous.
* **`.exec()` is only a process sink when the file contains `child_process`**,
  otherwise it is `RegExp.prototype.exec`. **`String.fromCharCode` is only a
  decoder with 4+ arguments**, otherwise it is a keycode. Both of these were
  real false positives against the JavaScript on this machine.
* **Budgets**: a 64 MB lockfile cap, 4 MB per source file, 20 000 packages,
  4 000 files under `--deep`, and a capped taint set, so a hostile tree cannot
  make the scan slow.

### Lockfiles

`package-lock.json` and `npm-shrinkwrap.json` (v1, v2 and v3 — v2/v3 also give
`hasInstallScript`, which is how a transitive install script is detected on a
**fresh clone with no `node_modules` at all**), `yarn.lock` (v1 and berry) and
`pnpm-lock.yaml` (`requiresBuild`). `bun.lockb` is binary and is not read; in a
bun-only project the scan falls back to `package.json` plus `node_modules`.
A lockfile that cannot be parsed is skipped, never fatal.

### How the shims call it

`/usr/lib/moat/shims/{npm,pnpm,yarn,bun}` run, before handing over to the real
binary and only for install-shaped subcommands:

```bash
moat-scan-npm .               # exit 0/1 -> continue, exit 2 -> ask
```

This is `shim_run_scan` in `shim-common.sh`, the same contract the `makepkg`
shim established:

* exit `0` or `1`: the install continues (findings were printed, nothing blocks).
* exit `2`: interactive → `gum confirm "Continue anyway?"`; non-interactive →
  refuse and exit non-zero.
* a scanner that is missing, or that fails with any other code: warn and
  continue. It must never be able to stop an install by breaking.
* `MOAT_SANDBOX=0` bypasses the shim entirely, scan included — which is what
  both the refusal message and the scanner's own footer tell the user to do.

`npm run`, `npm test`, `npm ls`, `npm exec`, `yarn run`, bare `bun` and
`npm install -g` are **not** scanned: they unpack nothing from the current
directory, so scanning them would be startup cost for no signal. Bare `yarn`
and bare `pnpm` *are*, because they mean `install`.

### Adding a rule

Same five steps as `moat-scan-pkgbuild` (ids are API; `RULES` carries
`(severity, why, proceed)`), plus one:

6. **Re-check the false-positive corpus.** There is no npm registry available
   offline, so use what is on the machine: the bundled dependency tree of npm
   itself (`$(dirname "$(readlink -f "$(command -v npm)")")/../lib/node_modules/npm`
   — ~100 packages, 1 100 JS files) must come out **completely clean**, and
   `moat-scan-npm --deep /usr/share` must produce no `medium` or `high`.

```
python3 -m unittest discover scanner/tests
```

---

## moat-scan-build

Static review of a Rust, Python or Go project *before* its build and install
steps run. Same finding shape, same allow file, same exit codes as the two
above.

```
moat-scan-build  [PATH ...]          # default: ., ecosystems auto-detected
moat-scan-cargo  [PATH ...]          # the same file; argv[0] picks the rules
moat-scan-pip    [PATH ...]
moat-scan-go     [PATH ...]
```

### Why one tool and three names

The three ecosystems share the whole infrastructure (finding shape, allow
file, exit codes, rendering, budgets) and most of the detection vocabulary:
curl-pipe-shell, suspicious and bare-IP hosts, credential-path reads, the
base64/eval obfuscation engine and the invisible-Unicode check are the same
attack whether the file is a `PKGBUILD`, a `postinstall`, a `build.rs` or a
`setup.py`. Three separate executables would have been three copies of about
700 lines, and there is nowhere in this design to put a shared Python module:
both existing scanners are single self-contained files installed straight into
`/usr/bin`, and adding an importable library under `/usr/lib` would introduce
a new failure mode (a scanner that cannot find its library crashes, and the
shim then warns and continues — silently disabling the scan).

So there is one file, `moat-scan-build`, installed with symlinks
`moat-scan-cargo`, `moat-scan-pip` and `moat-scan-go`. `argv[0]` selects the
default ecosystem, `--for` overrides it, and no argument at all auto-detects
from the marker files present. That keeps each shim's line reading exactly
like the existing ones (`moat-scan-cargo --for cargo .`), keeps the
`MOAT_SCANNER_*` override per ecosystem, and covers a polyglot repository
correctly when it is run without `--for`.

### What each ecosystem executes, and therefore what is checked

**cargo.** `cargo build` runs `build.rs` and every `[build-dependencies]`
build script with your user's privileges; a proc-macro crate runs *inside*
rustc; `.cargo/config.toml` decides which registry every crate comes from and
which program is invoked as the linker, the compiler wrapper and the runner
for `cargo run`/`cargo test`.

**python.** `pip install .` executes `setup.py`. A PEP 517 `backend-path`
makes pip import the build backend out of the package being installed, before
anything else. A `*.pth` file's `import` line is `exec`'d by `site.py` on
every interpreter start, forever after — the best persistence trick in the
ecosystem. `setup_requires` makes setuptools fetch and run packages while
`setup.py` is still being parsed, outside pip's resolver and hashes.

**go** is the least exposed ecosystem moat scans, and this is worth saying
plainly: `go build` compiles a dependency, it never *runs* one. There is no
`build.rs`, no `postinstall`, no `setup.py`. What is left is `go generate`
(commands embedded in source that run the moment anyone types it), a module
`replace` pointing outside the tree (the code that compiles is not the code
`go.mod` names, and `go.sum` does not cover it) and `//go:linkname`.

### Options and exit codes

The flags and the exit codes are `moat-scan-pkgbuild`'s, plus:

| flag | effect |
|------|--------|
| `--for {cargo,python,go}` | scan only this ecosystem; repeatable. Default: whichever ones the directory has |
| `--deep` | also run the build-code rules over every `.rs`/`.py` file in the tree, not just the ones that run at build time. Not what the shims run |
| `--max-per-rule N` | human output only: at most `N` findings per rule (default 10, `0` for all) |

### Rules

Severity is the default; the "adjusted to" column lists context that moves it.
`net.*`, `cred.*`, `obf.*`, `uni.*` and `lock.*` are the shared vocabulary and
mean the same thing in every ecosystem, so `rule=obf.*` in the allow file
covers all three tools.

| id | sev | catches | rationale / adjusted to |
|----|-----|---------|--------------------------|
| `net.curl-pipe-shell` | high | a download piped into a shell, anywhere in a build script or a `go:generate` directive | the build runs whatever that server sends today |
| `net.suspicious-host` | high | paste bins, ngrok/trycloudflare tunnels, transfer.sh/gofile/0x0.st, webhook.site/requestbin, Discord and Telegram webhooks, `.onion`, bare public IPs — in a build script, a dependency URL, a registry override or a requirements file | no build fetches from a paste bin, a tunnel or a bare IP. A **private** IP is a real corporate mirror and is not flagged |
| `cred.build-read` | high | a build step naming `~/.ssh`, `id_rsa`, `.aws`, `.gnupg`, `.netrc`, `.pypirc`, `.cargo/credentials`, `.docker/config`, `.kube/config`, keyrings, or `GITHUB_TOKEN`/`CARGO_REGISTRY_TOKEN`/`TWINE_PASSWORD`-style names | the token-theft shape; a build has no reason to read any of them |
| `obf.eval-decoded` | high | decoded data reaching an exec sink — `eval`/`exec`/`compile`, `subprocess`, `Command::new`/`.arg`, `exec.Command` — inline or through a variable decoded a line or two earlier | the finding prints what the blob decodes to, so nobody has to run it. `.arg(`/`.args(` count as sinks only when the file actually spawns processes |
| `obf.charcode-chain` | medium | `String.fromCharCode` / `char::from_u32` / `chr` with 8+ numeric arguments | the classic dropper encoding; the finding prints the decoded string |
| `obf.long-blob` | low | a 400+ character base64 or hex literal | usually an embedded asset. Context, never a reason to stop |
| `obf.long-line` | low | a line over 5 000 characters | generated output, or code packed to defeat review. Skipped under `target/`, `dist/`, `*.pb.go`, `*_gen.go`, fixtures |
| `uni.invisible-chars` | high | zero-width, bidi, tag and filler characters in a build file | the GlassWorm technique: code a reviewer cannot see. **low** for a lone UTF-8 BOM on line 1. Evidence is printed escaped |
| `lock.foreign-registry` | medium | a `Cargo.lock` entry whose `source` is not crates.io, or a `git+` source on an unknown host | it is re-fetched on every fresh clone. **high** for a paste bin/tunnel/bare IP |
| `lock.missing-integrity` | medium | a `Cargo.lock` registry package with no `checksum` | what arrives is whatever the server serves. Not applied when the lockfile keeps checksums in a v1/v2 `[metadata]` table, and never to path or git entries |
| `exec.build-rs-network` | high | a `build.rs` (or a build script named by `build = `) opening the network: `reqwest::`/`ureq::`/`curl::easy`/`TcpStream::connect`, or spawning `curl`/`wget` | what runs on your machine is decided by a server, not the lockfile. **medium** when the only URL in the file is an ordinary host — the same ladder as `npm.script-net-literal`. Crate *names* are not matched, only call forms, so a feature string mentioning `hyper` is silent |
| `cargo.build-script-outside` | high | `build = "/abs"` or `build = "../x.rs"` in `Cargo.toml` | cargo compiles and runs code the package does not own — the `npm.bin-outside-package` shape |
| `cargo.registry-replaced` | high | `.cargo/config.toml` `[source.crates-io] replace-with` | every crate in every build silently comes from somewhere else. **medium** for a `replace-with` on another source, **low** for merely *defining* a `[source.X]` that nothing has replaced crates-io with |
| `cargo.build-runner` | high | `target.*.runner`, `[build] rustc`, `rustc-wrapper`, `rustc-workspace-wrapper`, `rustdoc` | cargo executes that program in place of, or around, the compiler — and `runner` runs instead of your binary on `cargo run`/`test`/`bench`. **medium** when the value is a recognised wrapper (`sccache`, `ccache`, `cachepot`, `mold`, `lld`, `cross`) |
| `cargo.linker-override` | medium | `target.*.linker`, or `rustflags` carrying `-C linker=` / `-C link-arg` / `-Z` | cross-compilation sets this legitimately, so it warns rather than blocks |
| `cargo.dep-outside-tree` | medium | a `path =` dependency resolving outside the scanned project | the code compiled is not in the repository you reviewed. A workspace member inside the tree is silent |
| `cargo.dep-git` | low | a `git =` dependency with no `rev` pin | its content can change under you between builds. **medium** for a git **build**-dependency (it runs at build time and no checksum covers it) or a git host that is not a known forge. A `rev`-pinned forge dependency is silent |
| `cargo.proc-macro` | low | `[lib] proc-macro = true` | it executes inside rustc while your code compiles. **medium** when the crate is not the root package. The crate's own source has already been through the obfuscation and network rules |
| `exec.setup-py-network` | high | `setup.py` or a local PEP 517 backend opening the network: `urlopen`/`urlretrieve`/`requests.get`/`httpx`/`socket.create_connection`/`pip._internal`, or spawning `curl`/`wget` | pip runs this while it builds. **medium** for an ordinary https host. A bare `pip install` in help text is deliberately **not** matched (ruamel.yaml's `setup.py` says it five times) |
| `py.setup-requires` | medium | `setup_requires=` in `setup.py` or `setup.cfg` | setuptools fetches and executes those while `setup.py` is parsed, outside pip's resolver and hashes |
| `py.startup-hook` | medium | a `*.pth` line beginning `import ` (which `site.py` `exec`s), or a `sitecustomize.py`/`usercustomize.py` in the tree | persistence, not a build step. **high** when that line also fetches, decodes, or spawns. **low** for the two idioms that legitimately do it: setuptools' `__editable___*_finder` and `distutils-precedence.pth`. A path-only `.pth` is **not reported at all** |
| `py.build-backend-path` | medium | `[build-system] backend-path` in `pyproject.toml` | pip imports the build backend out of the package being installed, so the package's own code runs first. **high** when the path escapes the package with `..` or an absolute path. The named backend module is then read with the build-code rules |
| `py.index-override` | medium | `--extra-index-url` or `--trusted-host` in a requirements file, `index-url`/`extra-index-url`/`trusted-host` in a `pip.conf`/`pip.ini` in the tree, or an index in `[tool.uv]`/`[tool.poetry.source]`/`[tool.pdm]` | `--extra-index-url` is the dependency-confusion shape: pip installs whichever index has the higher version. **low** for `--index-url`/`--find-links`, which replace the index outright — a deliberate, visible choice with no name shadowing, and the most common line in a real requirements file (`download.pytorch.org` appears eight times on this machine) |
| `py.direct-url-requirement` | medium | a requirement pinned to a URL or a VCS rather than the index | its content is whatever that server serves at install time, and its `setup.py` runs. **low** for a known forge |
| `go.generate-directive` | low | a `//go:generate` command | it does **not** run during `go build`, only when someone types `go generate`. **medium** when the directive hands a command line to a shell or an interpreter (`sh -c`, `python -c`); recognised code generators (`go`, `stringer`, `mockgen`, `protoc`, `sqlc`, `wire`, module paths, …) are silent. A directive that pipes curl into a shell, names a paste bin, or reads a credential path reports under the shared `net.*`/`cred.*` rules instead |
| `go.replace-outside-tree` | medium | a `go.mod` `replace` whose target is a path outside the module | the code that compiles is not the module `go.mod` names, and `go.sum` does not cover it. An in-tree `./internal/x` replace is silent |
| `go.linkname` | medium | `//go:linkname` | binds to a private symbol in another package or the runtime, bypassing visibility and the type system |

### What is deliberately not checked

* **Dependency build scripts in `~/.cargo/registry/src`.** `cargo build` runs
  the `build.rs` of every dependency, not just yours — but resolving which
  ones from `Cargo.lock` and walking the registry cache is a different, much
  slower tool, and the cache is populated *by* the build being scanned. What
  the lockfile can say statically (a non-crates.io source, a missing checksum)
  is checked instead. Point the scanner at an unpacked crate directly if you
  want its build script read.
* **`~/.cargo/config.toml`.** `.cargo/config.toml` is read in the project
  directory and every directory above it *up to `$HOME`*, but not `$HOME`
  itself: that file is the user's own deliberate configuration (a corporate
  mirror, a cross linker), and firing on it in front of every `cargo build`
  is exactly the false positive that gets a scanner uninstalled.
* **`#cgo` flags.** The go toolchain already validates them against
  `CGO_CFLAGS_ALLOW` and refuses `-fplugin=`-style smuggling itself.
* **The presence of `[build-dependencies]` or a plain `build.rs`.** Nearly
  every `-sys` crate has both. Presence is not signal; the content is, and it
  is read.
* **Non-standard PEP 517 backends** (`hatchling`, `poetry.core`, `pdm.backend`,
  `maturin`, …). They are ordinary published packages; only `backend-path`,
  which runs code out of the package being installed, is reported.
* **`go.sum` completeness.** Not decidable from the files on disk without
  resolving the module graph.

### Context the scanner understands (this is what keeps it quiet)

* **Comment-only lines cannot run**, so they are skipped by the network,
  credential and shell-pipe rules. A URL in a doc comment is not a fetch.
* **`String::from_utf8` is not a decoder.** Turning a child process's stdout
  into a `String` is what every `-sys` crate's `build.rs` does with `rustc
  --version`; treating it as one reported `obf.eval-decoded` against ten real
  crates on this machine (libc, serde, quote, proc-macro2, thiserror, …).
* **A string literal is not an identifier.** `.arg("--version")` next to a
  variable called `version` was the other half of that same false positive;
  literals are stripped before the taint check.
* **Budgets**: 4 MB per file, 400 manifests, 200 build scripts, 200 `.pth`
  files, 2 000 Go files, 5 000 directories walked, and a capped taint set, so
  a hostile tree cannot make the scan slow. A real project scans in ~40 ms.

### How the shims call it

`/usr/lib/moat/shims/{cargo,pip,pip3,uv,go}` run, before handing over to the
real binary and only for build-shaped subcommands:

```bash
moat-scan-cargo --for cargo .    # exit 0/1 -> continue, exit 2 -> ask
moat-scan-pip   --for python .
moat-scan-go    --for go .
```

This is `shim_run_scan` in `shim-common.sh`, the same contract the `makepkg`
shim established: exit `0`/`1` continues, exit `2` prompts when interactive and
refuses when not, and **a scanner that is missing or that fails with any other
code warns and continues** — it must never be able to stop a build by breaking.
`MOAT_SANDBOX=0` bypasses the shim, scan included.

The scan is skipped entirely when there is nothing here to read: `cargo
install ripgrep` from a directory with no `Cargo.toml`, `pip install requests`
with no `setup.py`/`pyproject.toml`/`requirements*.txt`, `go build` with no
`go.mod`. `cargo fmt`, `pip list`, `uv venv`, `uv pip list`, `go env` and
`go fmt` build nothing and are not scanned.

### Adding a rule

Same steps as the other two (ids are API; `RULES` carries
`(severity, why, proceed)`), plus:

6. **Re-check the false-positive corpus.** There is no network, so use what is
   on the machine: every crate under
   `~/.cargo/registry/src/*/*/` must come out clean or `low`
   (146 crates here), every directory on the machine holding a `setup.py`,
   `pyproject.toml`, `setup.cfg` or `requirements*.txt` must do the same, and
   `moat-scan-cargo` over this repository's own `moatd/` must print
   `clean: no findings`.

```
python3 -m unittest discover scanner/tests
```
