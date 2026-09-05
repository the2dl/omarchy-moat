# sandbox/ — `moat-sandbox` and the PATH shims

Package managers execute arbitrary code from strangers: npm lifecycle scripts,
`setup.py`, `build.rs`, a PKGBUILD's `prepare()`. This directory makes that code
run without seeing your credentials.

`moat-sandbox` wraps a command in [bubblewrap](https://github.com/containers/bubblewrap)
so that:

- the whole filesystem is **read-only**, except the project directory and the
  package caches;
- the credential directories are **not there at all** — a tmpfs over each
  denied directory, an empty file over each denied file;
- secret-looking environment variables are **unset**;
- the network is **left alone**, because installs need it.

The shims in `shims/` put that in front of `npm`, `pip`, `cargo`, `go` and
friends so
you do not have to remember to type it.

Nothing here needs root. Everything here is user-level.

## Install paths (contract section 2)

| Source | Installed as |
|---|---|
| `sandbox/moat-sandbox` | `/usr/bin/moat-sandbox` (0755) |
| `sandbox/shims/shim-common.sh` | `/usr/lib/moat/shims/shim-common.sh` (0644) |
| `sandbox/shims/{npm,npx,pnpm,yarn,bun,pip,pip3,uv,cargo,go,makepkg}` | `/usr/lib/moat/shims/<name>` (0755) |
| `sandbox/sandbox.conf` | `/etc/moat/sandbox.conf` (root:root 0644, `backup=` in the PKGBUILD) |
| `sandbox/profile.d/moat-shims.sh` | `/etc/profile.d/moat-shims.sh` (0644) |
| `sandbox/fish/conf.d/moat-shims.fish` | `/usr/share/fish/vendor_conf.d/moat-shims.fish` (0644) |

The shims are only on `PATH` while `/etc/moat/sandbox.enabled` exists. The
package does **not** create that file; `moatctl set sandbox on` (contract
section 5) does. New login shells pick it up; existing ones need a re-login or
`export PATH=/usr/lib/moat/shims:$PATH`.

`bubblewrap` is a hard runtime dependency. `gum` is an optional dependency, used
only for the `makepkg` prompt (a plain `read` prompt is the fallback).

## Usage

```
moat-sandbox [--allow PATH]... [--keep-env NAME]... [--dry-run]
                 [--force-new-session] -- cmd [args...]
```

```console
$ moat-sandbox -- npm install
[moat] sandboxed: npm install

$ moat-sandbox --dry-run -- pip install requests      # see the exact bwrap line
$ moat-sandbox --allow ~/vendor -- cargo build        # one more writable path
$ moat-sandbox --keep-env NPM_TOKEN -- npm publish    # keep one secret
$ MOAT_SANDBOX=0 npm install                          # bypass everything
$ MOAT_QUIET=1 moat-sandbox -- npm ci             # no notice line
```

The exit code is the command's own. `--dry-run` prints the `bwrap` invocation
and runs nothing.

### `--new-session` and Ctrl-C

`--new-session` calls `setsid()`, which is what stops a sandboxed process from
pushing characters back into your terminal with `TIOCSTI`. It also takes away
the controlling terminal, so **Ctrl-C in your shell no longer reaches the
process** — which you notice the first time you try to interrupt an
`npm install`.

Since Linux 6.2 that attack is gated behind `dev.tty.legacy_tiocsti`, which is
`0` by default and compiled out entirely when `CONFIG_LEGACY_TIOCSTI` is unset
(the Arch kernel does not set it). So `moat-sandbox` decides:

| `/proc/sys/dev/tty/legacy_tiocsti` | `--new-session` |
|---|---|
| reads `0` — TIOCSTI already impossible | omitted, Ctrl-C works |
| reads `1` — injection possible | passed |
| missing/unreadable — pre-6.2 kernel, always allows TIOCSTI | passed |

`--force-new-session` passes it regardless. `MOAT_TIOCSTI_FILE` overrides
the sysctl path and exists for the test suite; do not rely on it.

Check what your machine does with `sysctl dev.tty.legacy_tiocsti` and
`moat-sandbox --dry-run -- true`.

### Environment variables

| Variable | Effect |
|---|---|
| `MOAT_SANDBOX=0` | `moat-sandbox` and every shim exec the real command directly, and every shim's pre-execution scan is skipped with it — it is the single documented escape hatch, so it has to open all the way |
| `MOAT_QUIET=1` | suppress the `[moat] …` notice and warnings on stderr |
| `MOAT_SANDBOX_ACTIVE` | set to `1` **inside** the sandbox (`bwrap --setenv`). Do not set it yourself; it is how nested calls avoid a second, broken layer of bubblewrap. It deliberately does *not* skip the `makepkg` PKGBUILD scan: a nested `makepkg` is usually a different directory with a different PKGBUILD that the outer call never saw. **moatd cannot see it**: `/etc/tetragon/tetragon.conf.d/filter-environment-variables` is `LD_PRELOAD`, so the export carries no other environment variable, and pkg-family alerts raised inside a sandbox cannot be down-ranked on that basis. See docs/INTEGRATION.md |

### What the sandbox looks like inside

```
--ro-bind / /            everything readable, nothing writable
--dev /dev  --proc /proc
--unshare-pid            cannot see or signal your other processes
--die-with-parent        dies when your shell does
--new-session            only on kernels that still allow TIOCSTI (see below)
--tmpfs /tmp             (plus $TMPDIR)
--bind  <caches>         ~/.npm ~/.cache ~/.cache/pip ~/.local/share/pnpm
                         ~/.cargo/registry ~/.cargo/git ~/.rustup
                         ~/.local/share/mise ~/.local/share/uv ~/.bun ~/.yarn
--bind  $PWD             and the git toplevel of $PWD, if any
--tmpfs <denied dirs>    ~/.ssh ~/.gnupg ~/.aws … (see sandbox.conf)
--ro-bind-data <fd> <denied files>   ~/.netrc, ~/.git-credentials, …
--unsetenv <secrets>     *_TOKEN *_SECRET *_KEY AWS_* GITHUB_TOKEN NPM_TOKEN
--setenv MOAT_SANDBOX_ACTIVE 1
--chdir $PWD
```

Denied paths are applied **after** the writable binds, so a deny always wins
over a cache bind. Writable binds are sorted shortest-path-first, so a nested
bind is applied after the directory that contains it.

Paths that do not exist are skipped — the sandbox never creates a `~/.ssh` for
you. Denied *files* become empty files rather than missing ones, because tools
handle "empty `~/.netrc`" better than "`~/.netrc` disappeared".

`$PWD` is bound, never widened. If `$PWD` is somewhere under `$HOME`, only
`$PWD` becomes writable, not `$HOME`. The git toplevel is bound too, but it is
skipped with a warning if it turns out to be `$HOME` or an ancestor of it —
that is exactly what a bare dotfiles repo checked out over `$HOME` looks like,
and binding it would hand the whole home directory to an install script.

If `$PWD` is inside a denied path, `moat-sandbox` refuses to run rather
than quietly bind it:

```console
$ cd ~/.ssh && moat-sandbox -- npm install
[moat] moat-sandbox: refusing to run: the current directory /home/you/.ssh
is inside the denied path /home/you/.ssh
Either cd elsewhere, or add 'allow=/home/you/.ssh' to ~/.config/moat/sandbox.conf.
```

## Configuration

Read in order, both optional, entries accumulate:

1. `/etc/moat/sandbox.conf`
2. `$XDG_CONFIG_HOME/moat/sandbox.conf` (i.e. `~/.config/moat/sandbox.conf`)

```conf
# comments start with #
deny=~/.config/rclone      # tmpfs (directory) or empty file (file)
allow=$HOME/build/pkgdest  # writable, and removed from the deny list
keep-env=NPM_TOKEN         # do not strip this variable
```

`~/` and `$HOME/` at the start of a value expand to the invoking user's home.
Unknown keys are reported on stderr and ignored. A per-user `allow=` with a
value that exactly matches a system `deny=` removes it — that is the only way a
user can weaken the system policy, and it is deliberate: the sandbox is a
convenience for the person running the build, not a boundary against them.

The default deny list is compiled into `moat-sandbox` so it still applies
with no config file at all; `sandbox.conf` restates it so the set is visible and
so a line can be commented out or turned into an `allow=`.

## The `.npmrc` / `.pypirc` trade-off

`~/.npmrc` and `~/.pypirc` are **readable** inside the sandbox (read-only, like
the rest of `/`). They are not on the deny list.

Why: installing from a private registry means `npm` needs the `_authToken` in
`~/.npmrc`, and `pip`/`uv` need the index credentials in `~/.pypirc`. Denying
them turns "sandbox on" into "private dependencies stop resolving", and a
sandbox people switch off protects nothing.

The cost: a malicious `postinstall` script **can read your registry token** and
exfiltrate it — the network is open. That is a narrower loss than your SSH key
or your GitHub token, but it is a real one.

If you do not publish to or install from a private registry, close the hole:

```conf
# ~/.config/moat/sandbox.conf
deny=~/.npmrc
deny=~/.pypirc
```

Better still, keep registry tokens out of the file entirely and use a
short-lived one in the environment only when publishing:

```console
$ NPM_TOKEN=$(op read op://dev/npm/token) moat-sandbox --keep-env NPM_TOKEN -- npm publish
```

## The shims

`/usr/lib/moat/shims/<name>` is a small bash script that:

1. works out its own directory from `$0`;
2. removes that directory from `PATH` — every entry that *resolves* to it, so a
   symlinked shim dir goes too;
3. resolves the real binary with `command -v` under the reduced `PATH`;
4. execs `moat-sandbox -- <real> "$@"`.

Because resolution happens after step 2, mise keeps working: on a machine where
`node`/`npm` come from `~/.local/share/mise/shims`, the shim finds the mise
shim, mise re-execs the real npm inside the sandbox, and
`~/.local/share/mise` is one of the writable binds. Verified with a real
`npm install left-pad`.

A shim that resolves back to its own directory, or finds nothing, exits **127**
with a message instead of looping. Inside the sandbox `MOAT_SANDBOX_ACTIVE=1`
is set and the shims exec the real binary directly, so a package manager that
calls another package manager by name does not try to nest bubblewrap.

If `moat-sandbox` is not on `PATH`, a shim warns and runs the command
unsandboxed rather than breaking your toolchain.

### `cargo` is only sandboxed for some subcommands

Sandboxed (they fetch code, or compile and therefore run `build.rs` and proc
macros): `build` `b` `install` `add` `fetch` `update` `run` `r` `test` `t`
`check` `c` `bench` `clippy` `doc` `rustc` `miri` `publish` `package`.

Passed straight through: everything else — `fmt`, `tree`, `metadata`, `search`,
`new`, `init`, `clean`, `login`, `--version`, and any third-party subcommand.
Those either touch no foreign code, or need exactly the credential access the
sandbox removes (`cargo login` writes `~/.cargo/credentials.toml`). `+toolchain`
and leading flags are skipped when looking for the subcommand.

The trade-off is deliberate: sandboxing `cargo fmt` costs startup time, breaks
editor integrations, and protects nothing.

For the sandboxed subcommands the shim also runs `moat-scan-cargo --for cargo .`
first, when there is a `Cargo.toml` in `$PWD` — `cargo build` on an untrusted
crate is arbitrary code execution via `build.rs`, which is the whole reason
that subcommand list exists, so it is exactly the list worth scanning. See
"scans first" below for the ladder; `cargo install ripgrep` from a directory
with no manifest reads nothing local and is not scanned.

### `go` is only sandboxed for some subcommands

Same split, same reasoning. Sandboxed: `build` `install` `get` `run` `test`
`generate` `mod` `work` `vet` `bench` `fix` `tool`. Passed through: `fmt`,
`env`, `version`, `doc`, `list`, `help`, `clean` — `go env -w` in particular
writes the user config the sandbox deliberately makes read-only.

Because `GOMODCACHE` (`$GOPATH/pkg/mod`, default `~/go/pkg/mod`) and
`$GOPATH/bin` are outside every path `moat-sandbox` makes writable by default,
and a read-only module cache fails every build that needs a dependency, the
shim adds an `--allow` for each — derived from `$GOPATH`/`$GOMODCACHE`/`$GOBIN`
rather than by running `go env`, which would be a subprocess in front of every
command for a value we already know.

`moat-scan-go --for go .` runs first for `build install get run test generate
mod vet`, when there is a `go.mod` in `$PWD`. Go is the least exposed ecosystem
here — `go build` compiles a dependency, it never runs one — so the scan is
about `go generate` directives, `replace` targets outside the module and
`//go:linkname`.

### `pip`, `pip3` and `uv` scan first

`pip install`, `pip wheel` and `pip download` build from whatever is in `$PWD`
(`pip install .`, `-e .`, `-r requirements.txt`), so the shim runs
`moat-scan-pip --for python .` first. `pip list`, `pip show` and
`pip uninstall` execute nothing new and are not scanned; neither is
`pip install requests` from a directory with no `setup.py`, `setup.cfg`,
`pyproject.toml`, `pip.conf` or `requirements*.txt`.

For `uv` the scanned subcommands are `add sync lock build run export install`
and `uv pip {install,download,wheel,sync,compile}`. `uv run` is included
because on a fresh clone it installs the whole project first; `uv venv`,
`uv tool`, `uv python`, `uv cache` and `uv pip list` build nothing from this
directory.

### `makepkg` scans first

The `makepkg` shim runs `moat-scan-pkgbuild .` (scanner/, contract section 9)
before doing anything. This is the ladder every shim's scan uses, via
`shim_run_scan` in `shim-common.sh`:

| Scanner exit | Shim behaviour |
|---|---|
| 0 (clean) | build |
| 1 (medium) | print a warning, build |
| 2 (high) | interactive: `gum confirm "Continue building anyway?"` — non-interactive: refuse, exit 1 |
| other | warn that the scan failed, build |
| not installed | warn, build |

"Interactive" means both stdin and stdout are terminals. `gum` is used when
present, otherwise a `read -r -p` prompt. If there is no `PKGBUILD` in `$PWD`
the scan is skipped and `makepkg` reports the problem itself.

**`makepkg` limitations — read these before filing a bug.**

- **No root, no `sudo`.** bubblewrap sets `PR_SET_NO_NEW_PRIVS`, so setuid
  binaries do not elevate. `makepkg -s` (install dependencies) and `makepkg -i`
  (install the result) both call `pacman` through `sudo` and will fail. Install
  the dependencies first and build with `-d`/`--nodeps`, install the resulting
  package yourself afterwards, or run `MOAT_SANDBOX=0 makepkg -si`.
- **Output paths.** `$PWD` is writable, which covers the defaults: `srcdir`,
  `pkgdir`, `SRCDEST`, `PKGDEST`, `SRCPKGDEST` and `LOGDEST` all default to the
  build directory. If `makepkg.conf` points any of them elsewhere, the shim
  parses the value out of `/etc/makepkg.conf`, `/etc/makepkg.conf.d/*.conf`,
  `~/.config/pacman/makepkg.conf` and `~/.makepkg.conf` (without sourcing them)
  and adds an `--allow` for it. Values containing an unexpanded variable other
  than a leading `$HOME` are not understood and are ignored — use
  `--allow` yourself, or an absolute path in the config.
- **`BUILDDIR` under `/tmp`** would land in the sandbox tmpfs and the built
  package would vanish. The shim refuses with a hint instead of building into
  the void.
- **`makepkg` is not sandboxed against itself.** A PKGBUILD's `package()`
  writes into `$pkgdir` inside `$PWD`, which is writable. The scan is what
  catches a hostile PKGBUILD; the sandbox only limits the damage.

## Known gaps

The sandbox is damage limitation, not containment. Specifically:

- **The network is open.** By design: installs need it. Anything a build can
  read, it can exfiltrate. `moat-x-pkg-egress` (moatd, contract 6.4) is
  what watches for that, not this.
- **The project directory is writable.** A compromised dependency can backdoor
  the code you are about to run, commit, or publish. It cannot touch
  `~/.bashrc`, `~/.config/systemd`, or `~/.local/bin` — those are read-only —
  but the repo in front of you is fair game.
- **The package caches are writable and shared between projects.** A malicious
  install can poison `~/.npm/_cacache` or `~/.cargo/registry` for every other
  project on the machine.
- **`~/.npmrc` and `~/.pypirc` are readable.** See the trade-off above.
- **`~/.gitconfig` and `~/.config/git` are readable.** They hold commit
  identity, which builds need; credentials live in `~/.git-credentials`, which
  is denied. A `[credential] helper = …` line pointing at a helper the sandbox
  can still execute is a hole — check yours.
- **`~/.cache` is bound writable as a whole**, not just the package-manager
  subdirectories. Anything that keeps a token in `~/.cache` is exposed. Add a
  `deny=` for it.
- **First run creates empty cache directories.** bubblewrap requires a bind
  source to exist, so `moat-sandbox` creates any missing cache directory
  from the list above — you will see an empty `~/.bun`, `~/.yarn`, `~/.rustup`
  and `~/.cargo/{registry,git}` even if you never use those tools. Cosmetic,
  but surprising.
- **No seccomp filter, no cgroup limits.** A build can fork-bomb or fill your
  disk. `--unshare-pid` means you can kill it by killing the wrapper.
- **On a pre-6.2 kernel you lose Ctrl-C.** There `--new-session` is required
  to block `TIOCSTI` keystroke injection, and it takes the controlling
  terminal with it. `--die-with-parent` still tears the sandbox down when the
  shell exits, and killing `bwrap` kills the tree. On a current kernel
  `--new-session` is skipped and Ctrl-C behaves normally — see above.
- **Unix sockets under `/run` are read-only**, so a build cannot talk to the
  session D-Bus or the keyring. Mostly a feature; it does break the rare tool
  that expects them.
- **The shims are `PATH`-based, so they are advisory.** `/usr/bin/npm`,
  `~/.local/share/mise/shims/npm`, an absolute path, a `Makefile` with a
  hardcoded path, or anything invoked from a non-login shell that never read
  `/etc/profile.d` all bypass them. Real coverage of "npm ran and touched a
  secret" comes from the Tetragon policies, not from here.
- **A user can turn it off.** `MOAT_SANDBOX=0`, or just calling the real
  binary. This protects you from your dependencies, not from yourself.

## Tests

```console
$ ./sandbox/tests/run.sh          # add -v for command output
52 passed, 0 failed
```

Unprivileged, and they really run `bwrap`. Everything happens inside one
`mktemp -d` under `${TMPDIR:-/tmp}`, removed by an `EXIT`/`INT`/`TERM` trap; the
credential tests use a fake `HOME` with a fake key and never touch the real
`~/.ssh`. If bubblewrap cannot create a user namespace the suite prints
bwrap's exact error and exits non-zero instead of skipping.

Covered: denied directories and files (including the case where the parent is
explicitly bound writable, which isolates the deny rule from the `/tmp` tmpfs),
`$PWD` and git-toplevel writes, `$HOME/other` and the real `$HOME` staying
read-only, `/tmp` isolation in both directions, env stripping and `--keep-env`
(flag and config), `deny=` from a config file, every expected `--dry-run` flag,
the `--new-session` decision for `legacy_tiocsti` 0 / 1 / missing plus
`--force-new-session` (the sysctl path is faked, so the result does not depend
on the test machine's kernel), shim resolution with the shim dir duplicated in
`PATH`, the no-real-binary and
no-recursion paths, `cargo` pass-through vs sandboxed subcommands, all three
`makepkg` scanner outcomes, the `cargo` and `go` scan gates (including the
"no manifest here, nothing to scan" case), `MOAT_SANDBOX=0`,
`MOAT_SANDBOX_ACTIVE=1`,
exit-code propagation, the notice line, `MOAT_QUIET`, refusing a denied
`$PWD`, `$PWD == $HOME`, and mise-provided `node` running inside the sandbox.

`shellcheck -x` over every script (and `-s sh` over the profile.d snippet) runs
as part of the suite when shellcheck is installed.
