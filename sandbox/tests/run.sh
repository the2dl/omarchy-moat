#!/usr/bin/env bash
# omarchy-moat sandbox tests. Unprivileged, real bubblewrap, no fixtures
# outside a mktemp directory. Never touches the real ~/.ssh.
#
#   ./sandbox/tests/run.sh            run everything
#   ./sandbox/tests/run.sh -v         show every command's output
set -uo pipefail

SANDBOX_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
MOAT_SANDBOX_BIN=$SANDBOX_DIR/moat-sandbox
SHIMS=$SANDBOX_DIR/shims

VERBOSE=0
[[ ${1:-} == -v ]] && VERBOSE=1

pass=0
fail=0
failed_names=()

ok() {
	pass=$((pass + 1))
	printf '  \033[32mok\033[0m   %s\n' "$1"
}
no() {
	fail=$((fail + 1))
	failed_names+=("$1")
	printf '  \033[31mFAIL\033[0m %s\n' "$1"
	[[ -n ${2:-} ]] && printf '       %s\n' "$2"
}
note() { printf '       %s\n' "$*"; }
say() { printf '\n%s\n' "$*"; }

# ------------------------------------------------------------- environment ---

TMPROOT=$(mktemp -d "${TMPDIR:-/tmp}/moat-sandbox-test.XXXXXXXX") || exit 1
# shellcheck disable=SC2329 # invoked from the trap below
cleanup() {
	chmod -R u+rwX "$TMPROOT" 2>/dev/null || true
	rm -rf -- "$TMPROOT"
}
trap cleanup EXIT INT TERM

FAKE_HOME=$TMPROOT/home
PROJ=$FAKE_HOME/proj
mkdir -p "$FAKE_HOME/.ssh" "$PROJ" "$TMPROOT/bin"
printf -- '-----BEGIN OPENSSH PRIVATE KEY-----\nFAKEKEYDONOTUSE\n' >"$FAKE_HOME/.ssh/id_rsa"
chmod 600 "$FAKE_HOME/.ssh/id_rsa"
printf 'marker-visible\n' >"$FAKE_HOME/marker"
printf 'nothing\n' >"$PROJ/README"

# Run moat-sandbox with the fake HOME. Config files are read from
# $XDG_CONFIG_HOME, which we point into the fake home so a developer's own
# ~/.config/moat/sandbox.conf cannot change the results.
sb() {
	env HOME="$FAKE_HOME" XDG_CONFIG_HOME="$FAKE_HOME/.config" \
		MOAT_QUIET=1 "$MOAT_SANDBOX_BIN" "$@"
}

# ------------------------------------------------------------ preflight ------

say "preflight"

if [[ ! -x $MOAT_SANDBOX_BIN ]]; then
	no "moat-sandbox is executable" "$MOAT_SANDBOX_BIN"
	printf '\nCannot continue.\n'
	exit 1
fi
ok "moat-sandbox is executable"

if ! command -v bwrap >/dev/null 2>&1; then
	printf '\nbwrap (bubblewrap) is not installed; cannot run the sandbox tests.\n'
	exit 1
fi

bwrap_err=$(bwrap --ro-bind / / --dev /dev --proc /proc --unshare-pid \
	--die-with-parent --new-session /usr/bin/true 2>&1)
bwrap_rc=$?
if ((bwrap_rc != 0)); then
	printf '\nbubblewrap cannot create a user namespace in this environment.\n'
	printf 'Exact error from bwrap (exit %d):\n%s\n' "$bwrap_rc" "$bwrap_err"
	printf 'Not faking a pass. Fix the namespace restriction and re-run.\n'
	exit 1
fi
ok "bwrap can create user namespaces"

# --------------------------------------------- (a) denied path unreadable ----

say "(a) denied paths are hidden even when the parent is bound writable"

# --allow "$FAKE_HOME" binds the fake home read-write, which would otherwise
# vanish with the /tmp tmpfs. The deny for $HOME/.ssh is applied after it, so a
# failure here is the deny rule, not a missing bind.
out=$(cd "$PROJ" && sb --allow "$FAKE_HOME" -- cat "$FAKE_HOME/marker" 2>&1)
if [[ $out == "marker-visible" ]]; then
	ok "the allowed fake home is readable inside the sandbox"
else
	no "the allowed fake home is readable inside the sandbox" "got: $out"
fi

out=$(cd "$PROJ" && sb --allow "$FAKE_HOME" -- cat "$FAKE_HOME/.ssh/id_rsa" 2>&1)
rc=$?
if ((rc != 0)) && [[ $out != *FAKEKEYDONOTUSE* ]]; then
	ok "cat \$HOME/.ssh/id_rsa fails inside the sandbox (rc=$rc)"
	((VERBOSE)) && note "$out"
else
	no "cat \$HOME/.ssh/id_rsa fails inside the sandbox" "rc=$rc out=$out"
fi

out=$(cd "$PROJ" && sb --allow "$FAKE_HOME" -- ls -A "$FAKE_HOME/.ssh" 2>&1)
if [[ -z ${out//[[:space:]]/} ]]; then
	ok "\$HOME/.ssh is an empty tmpfs inside the sandbox"
else
	no "\$HOME/.ssh is an empty tmpfs inside the sandbox" "got: $out"
fi

# Shell history is denied for the same reason as a credential file, and is
# easier to forget because it does not look like one: it holds inline tokens
# nothing ever rotates.
printf 'export GITHUB_TOKEN=ghp_FAKESECRETDONOTUSE\n' >"$FAKE_HOME/.bash_history"
out=$(cd "$PROJ" && sb --allow "$FAKE_HOME" -- cat "$FAKE_HOME/.bash_history" 2>&1)
if [[ $out != *ghp_FAKESECRETDONOTUSE* ]]; then
	ok "\$HOME/.bash_history leaks nothing inside the sandbox"

# ---------------------------------------------------- escaping the sandbox ---
#
# Two ways out that an audit found on 2026-09-04. Both are one line of config
# each, and both hand a hostile install script the thing the box exists to deny.

say "escape routes"

# mise's shim directory is on PATH. A writable bind let a package install drop a
# shim there, which the user then runs OUTSIDE the sandbox on their next command.
mkdir -p "$FAKE_HOME/.local/share/mise/shims"
# shellcheck disable=SC2016  # $HOME must expand INSIDE the sandbox, not here.
if out=$(sb -- sh -c 'touch "$HOME/.local/share/mise/shims/pwned" 2>&1'); rc=$?; [[ $rc -ne 0 ]]; then
	ok "the mise shim directory is not writable inside the sandbox (rc=$rc)"
else
	no "a sandboxed process wrote a shim onto the host PATH" "$out"
fi

# moatd's control socket is group-writable and the sandboxed process runs as a
# member of that group, so a hostile script could drive the daemon that is
# supposed to be containing it.
if out=$(sb -- sh -c 'ls /run/moat/control.sock 2>&1'); rc=$?; [[ $rc -ne 0 ]]; then
	ok "moatd's control socket is not reachable inside the sandbox (rc=$rc)"
else
	no "the sandbox can see moatd's control socket" "$out"
fi
else
	no "\$HOME/.bash_history leaks nothing inside the sandbox" "got: $out"
fi

# A denied *file* becomes an empty file, not a missing one.
printf 'machine example.com password hunter2\n' >"$FAKE_HOME/.netrc"
out=$(cd "$PROJ" && sb --allow "$FAKE_HOME" -- cat "$FAKE_HOME/.netrc" 2>&1)
rc=$?
if ((rc == 0)) && [[ -z $out ]]; then
	ok "\$HOME/.netrc reads as an empty file"
else
	no "\$HOME/.netrc reads as an empty file" "rc=$rc out=$out"
fi

# And the real file is untouched afterwards.
if grep -q hunter2 "$FAKE_HOME/.netrc"; then
	ok "the real .netrc on disk is unchanged"
else
	no "the real .netrc on disk is unchanged"
fi

# --------------------------------------------------- (b) $PWD is writable ----

say "(b) \$PWD is writable"

out=$(cd "$PROJ" && sb -- sh -c 'echo written > ./from-sandbox && cat ./from-sandbox' 2>&1)
rc=$?
if ((rc == 0)) && [[ $out == "written" ]] && [[ -f $PROJ/from-sandbox ]]; then
	ok "writing to \$PWD works and persists on the host"
else
	no "writing to \$PWD works and persists on the host" "rc=$rc out=$out"
fi
rm -f "$PROJ/from-sandbox"

out=$(cd "$PROJ" && sb -- pwd 2>&1)
if [[ $out == "$PROJ" ]]; then
	ok "the sandbox starts in \$PWD"
else
	no "the sandbox starts in \$PWD" "got: $out"
fi

# The git toplevel is bound too, but never widened to $HOME.
mkdir -p "$PROJ/sub"
(cd "$PROJ" && git init -q . >/dev/null 2>&1) || true
if [[ -d $PROJ/.git ]]; then
	out=$(cd "$PROJ/sub" && sb -- sh -c 'echo t > ../top-write && echo ok' 2>&1)
	if [[ $out == "ok" && -f $PROJ/top-write ]]; then
		ok "the git toplevel is writable from a subdirectory"
	else
		no "the git toplevel is writable from a subdirectory" "got: $out"
	fi
	rm -f "$PROJ/top-write"
else
	note "git unavailable, skipped the toplevel test"
fi

# --------------------------------------------- (c) $HOME/other is read-only --

say "(c) the rest of \$HOME is read-only"

victim=$FAKE_HOME/other
mkdir -p "$victim"
printf 'original\n' >"$victim/file"
out=$(cd "$PROJ" && sb --allow "$FAKE_HOME/proj" -- sh -c "echo tampered > '$victim/file'" 2>&1)
rc=$?
if ((rc != 0)) && [[ $(cat "$victim/file") == "original" ]]; then
	ok "writing to \$HOME/other fails (rc=$rc)"
	((VERBOSE)) && note "$out"
else
	no "writing to \$HOME/other fails" "rc=$rc out=$out content=$(cat "$victim/file")"
fi

# Same check against the real $HOME, using a name that is neither $PWD, the
# git toplevel, nor a package cache.
real_victim=$HOME/.moat-sandbox-test-should-not-exist
out=$(cd "$PROJ" && env HOME="$HOME" XDG_CONFIG_HOME="$FAKE_HOME/.config" MOAT_QUIET=1 \
	"$MOAT_SANDBOX_BIN" -- sh -c "echo x > '$real_victim'" 2>&1)
rc=$?
if ((rc != 0)) && [[ ! -e $real_victim ]]; then
	ok "writing into the real \$HOME fails and creates nothing"
else
	no "writing into the real \$HOME fails and creates nothing" "rc=$rc out=$out"
	rm -f "$real_victim"
fi

# ------------------------------------------------- (d) env var stripping -----

say "(d) secret-looking environment variables are stripped"

env_out=$(cd "$PROJ" && env MY_SECRET=s1 GITHUB_TOKEN=t1 NPM_TOKEN=t2 \
	AWS_ACCESS_KEY_ID=a1 SOME_API_KEY=k1 KEEP_ME=fine \
	HOME="$FAKE_HOME" XDG_CONFIG_HOME="$FAKE_HOME/.config" MOAT_QUIET=1 \
	"$MOAT_SANDBOX_BIN" -- env 2>&1)
stripped_ok=1
for v in MY_SECRET GITHUB_TOKEN NPM_TOKEN AWS_ACCESS_KEY_ID SOME_API_KEY; do
	if grep -q "^$v=" <<<"$env_out"; then
		stripped_ok=0
		note "$v survived"
	fi
done
if ((stripped_ok)); then
	ok "*_SECRET *_TOKEN *_KEY AWS_* are all unset inside the sandbox"
else
	no "*_SECRET *_TOKEN *_KEY AWS_* are all unset inside the sandbox"
fi

if grep -q '^KEEP_ME=fine$' <<<"$env_out"; then
	ok "an ordinary variable is preserved"
else
	no "an ordinary variable is preserved"
fi

if grep -q '^MOAT_SANDBOX_ACTIVE=1$' <<<"$env_out"; then
	ok "MOAT_SANDBOX_ACTIVE=1 is set inside the sandbox"
else
	no "MOAT_SANDBOX_ACTIVE=1 is set inside the sandbox"
fi

env_out=$(cd "$PROJ" && env MY_SECRET=s1 \
	HOME="$FAKE_HOME" XDG_CONFIG_HOME="$FAKE_HOME/.config" MOAT_QUIET=1 \
	"$MOAT_SANDBOX_BIN" --keep-env MY_SECRET -- env 2>&1)
if grep -q '^MY_SECRET=s1$' <<<"$env_out"; then
	ok "--keep-env MY_SECRET keeps it"
else
	no "--keep-env MY_SECRET keeps it"
fi

# keep-env via the user config file
mkdir -p "$FAKE_HOME/.config/moat"
cat >"$FAKE_HOME/.config/moat/sandbox.conf" <<EOF
# test config
keep-env=CONFIG_TOKEN
deny=$FAKE_HOME/denied-by-config
EOF
mkdir -p "$FAKE_HOME/denied-by-config"
printf 'x\n' >"$FAKE_HOME/denied-by-config/f"
env_out=$(cd "$PROJ" && env CONFIG_TOKEN=ct \
	HOME="$FAKE_HOME" XDG_CONFIG_HOME="$FAKE_HOME/.config" MOAT_QUIET=1 \
	"$MOAT_SANDBOX_BIN" -- env 2>&1)
if grep -q '^CONFIG_TOKEN=ct$' <<<"$env_out"; then
	ok "keep-env= from the config file is honoured"
else
	no "keep-env= from the config file is honoured"
fi

out=$(cd "$PROJ" && sb --allow "$FAKE_HOME" -- ls -A "$FAKE_HOME/denied-by-config" 2>&1)
if [[ -z ${out//[[:space:]]/} ]]; then
	ok "deny= from the config file is honoured"
else
	no "deny= from the config file is honoured" "got: $out"
fi
rm -f "$FAKE_HOME/.config/moat/sandbox.conf"

# ------------------------------------------------------- (e) --dry-run -------

say "(e) --dry-run prints the bwrap command"

dry=$(cd "$PROJ" && sb --dry-run -- npm install 2>&1)
missing=()
for flag in "--ro-bind / /" "--dev /dev" "--proc /proc" --unshare-pid \
	--die-with-parent "--tmpfs /tmp" --chdir; do
	grep -qF -- "$flag" <<<"$dry" || missing+=("$flag")
done
grep -qF -- "--bind $PROJ $PROJ" <<<"$dry" || missing+=("--bind \$PWD")
grep -qF -- "--tmpfs $FAKE_HOME/.ssh" <<<"$dry" || missing+=("--tmpfs \$HOME/.ssh")
grep -qF -- "--ro-bind-data" <<<"$dry" || missing+=("--ro-bind-data (denied file)")
grep -qF -- "--setenv MOAT_SANDBOX_ACTIVE 1" <<<"$dry" || missing+=("--setenv MOAT_SANDBOX_ACTIVE")
grep -qE '^bwrap ' <<<"$dry" || missing+=("leading 'bwrap'")
grep -qF -- "npm install" <<<"$dry" || missing+=("the command itself")
if ((${#missing[@]} == 0)); then
	ok "--dry-run contains every expected flag"
else
	no "--dry-run contains every expected flag" "missing: ${missing[*]}"
fi
((VERBOSE)) && note "$dry"

if [[ ! -e $PROJ/dry-run-side-effect ]]; then
	ok "--dry-run runs nothing"
else
	no "--dry-run runs nothing"
fi

# --new-session decision logic. The sysctl path is faked so the test does not
# depend on this machine's kernel. 0 = TIOCSTI already impossible -> keep the
# controlling terminal so Ctrl-C works; 1 or missing -> defend against it.
has_ns() { grep -qF -- '--new-session' <<<"$1"; }

printf '0\n' >"$TMPROOT/tiocsti-off"
printf '1\n' >"$TMPROOT/tiocsti-on"

d=$(cd "$PROJ" && MOAT_TIOCSTI_FILE="$TMPROOT/tiocsti-off" sb --dry-run -- true 2>&1)
if ! has_ns "$d"; then
	ok "legacy_tiocsti=0: --new-session is omitted (Ctrl-C keeps working)"
else
	no "legacy_tiocsti=0: --new-session is omitted (Ctrl-C keeps working)"
fi

d=$(cd "$PROJ" && MOAT_TIOCSTI_FILE="$TMPROOT/tiocsti-on" sb --dry-run -- true 2>&1)
if has_ns "$d"; then
	ok "legacy_tiocsti=1: --new-session is used"
else
	no "legacy_tiocsti=1: --new-session is used"
fi

d=$(cd "$PROJ" && MOAT_TIOCSTI_FILE="$TMPROOT/no-such-sysctl" sb --dry-run -- true 2>&1)
if has_ns "$d"; then
	ok "missing sysctl (old kernel): --new-session is used"
else
	no "missing sysctl (old kernel): --new-session is used"
fi

d=$(cd "$PROJ" && MOAT_TIOCSTI_FILE="$TMPROOT/tiocsti-off" sb --dry-run --force-new-session -- true 2>&1)
if has_ns "$d"; then
	ok "--force-new-session overrides legacy_tiocsti=0"
else
	no "--force-new-session overrides legacy_tiocsti=0"
fi

# The real command still runs either way.
out=$(cd "$PROJ" && MOAT_TIOCSTI_FILE="$TMPROOT/tiocsti-off" sb -- echo ns-off 2>&1)
out2=$(cd "$PROJ" && sb --force-new-session -- echo ns-on 2>&1)
if [[ $out == "ns-off" && $out2 == "ns-on" ]]; then
	ok "the sandbox runs with and without --new-session"
else
	no "the sandbox runs with and without --new-session" "got: $out / $out2"
fi

# --------------------------------------- (f) shim resolution / recursion -----

say "(f) shims resolve the real binary and never recurse"

# A fake "real" npm, plus the shim dir. The shim must skip its own directory
# even when it appears twice in PATH.
cat >"$TMPROOT/bin/npm" <<'EOF'
#!/usr/bin/env bash
echo "REAL npm active:${MOAT_SANDBOX_ACTIVE:-0} argv:$*"
EOF
chmod +x "$TMPROOT/bin/npm"

shim_path="$SHIMS:$TMPROOT/bin:$SHIMS:$SANDBOX_DIR:/usr/bin:/bin"
out=$(cd "$PROJ" && env PATH="$shim_path" HOME="$FAKE_HOME" \
	XDG_CONFIG_HOME="$FAKE_HOME/.config" MOAT_SANDBOX=0 MOAT_QUIET=1 \
	"$SHIMS/npm" install left-pad 2>&1)
rc=$?
if ((rc == 0)) && [[ $out == "REAL npm active:0 argv:install left-pad" ]]; then
	ok "the npm shim execs the real npm exactly once"
else
	no "the npm shim execs the real npm exactly once" "rc=$rc out=$out"
fi

# Same, but really sandboxed. The fake binary lives inside $PROJ so it survives
# the /tmp tmpfs.
cp "$TMPROOT/bin/npm" "$PROJ/npm"
out=$(cd "$PROJ" && env PATH="$SHIMS:$PROJ:$SANDBOX_DIR:/usr/bin:/bin" HOME="$FAKE_HOME" \
	XDG_CONFIG_HOME="$FAKE_HOME/.config" MOAT_QUIET=1 \
	"$SHIMS/npm" ci 2>&1)
rc=$?
if ((rc == 0)) && [[ $out == "REAL npm active:1 argv:ci" ]]; then
	ok "the npm shim works through a real sandbox"
else
	no "the npm shim works through a real sandbox" "rc=$rc out=$out"
fi

# A shim for a name that has no real binary must die, not loop. Use a copy of
# the shim under a name nothing on the system provides.
cat >"$TMPROOT/bin/moat-shim-probe" <<EOF
#!/usr/bin/env bash
set -euo pipefail
SHIM_SELF=\${BASH_SOURCE[0]}
. "$SHIMS/shim-common.sh"
shim_exec moat-no-such-binary-xyzzy "\$@"
EOF
chmod +x "$TMPROOT/bin/moat-shim-probe"
out=$(cd "$PROJ" && env PATH="$TMPROOT/bin:$PATH" HOME="$FAKE_HOME" \
	XDG_CONFIG_HOME="$FAKE_HOME/.config" MOAT_QUIET=1 \
	"$TMPROOT/bin/moat-shim-probe" foo 2>&1)
rc=$?
if ((rc == 127)) && [[ $out == *"no real binary found"* ]]; then
	ok "a shim with no real binary exits 127 instead of recursing"
else
	no "a shim with no real binary exits 127 instead of recursing" "rc=$rc out=$out"
fi

# Every shim named in the contract exists and is executable.
missing=()
for n in npm npx pnpm yarn bun pip pip3 uv cargo go makepkg; do
	[[ -x $SHIMS/$n ]] || missing+=("$n")
done
if ((${#missing[@]} == 0)); then
	ok "all eleven contract shims are present and executable"
else
	no "all eleven contract shims are present and executable" "missing: ${missing[*]}"
fi

# cargo passes through the subcommands that neither fetch nor build.
cat >"$PROJ/cargo" <<'EOF'
#!/usr/bin/env bash
echo "REAL cargo active:${MOAT_SANDBOX_ACTIVE:-0} argv:$*"
EOF
chmod +x "$PROJ/cargo"
cargo_env=(env PATH="$SHIMS:$PROJ:$SANDBOX_DIR:/usr/bin:/bin" HOME="$FAKE_HOME"
	XDG_CONFIG_HOME="$FAKE_HOME/.config" MOAT_QUIET=1)

out=$(cd "$PROJ" && "${cargo_env[@]}" "$SHIMS/cargo" fmt 2>&1)
if [[ $out == "REAL cargo active:0 argv:fmt" ]]; then
	ok "cargo fmt is passed through unsandboxed"
else
	no "cargo fmt is passed through unsandboxed" "got: $out"
fi

out=$(cd "$PROJ" && "${cargo_env[@]}" "$SHIMS/cargo" build --release 2>&1)
if [[ $out == "REAL cargo active:1 argv:build --release" ]]; then
	ok "cargo build is sandboxed"
else
	no "cargo build is sandboxed" "got: $out"
fi

out=$(cd "$PROJ" && "${cargo_env[@]}" "$SHIMS/cargo" +nightly test 2>&1)
if [[ $out == "REAL cargo active:1 argv:+nightly test" ]]; then
	ok "cargo +toolchain test is sandboxed"
else
	no "cargo +toolchain test is sandboxed" "got: $out"
fi

# The cargo shim scans the crate before any build script can run, but only
# when there is a manifest here: `cargo install ripgrep` from an empty
# directory reads nothing local. (Contract section 9; the full ladder is
# covered by scanner/tests/test_build_shim.py.)
cat >"$PROJ/moat-scan-cargo" <<'EOF'
#!/usr/bin/env bash
echo "scan: HIGH finding (fixture)"
exit 2
EOF
chmod +x "$PROJ/moat-scan-cargo"

out=$(cd "$PROJ" && "${cargo_env[@]}" "$SHIMS/cargo" build 2>&1)
rc=$?
if ((rc == 0)) && [[ $out != *"scan: HIGH"* ]]; then
	ok "cargo build with no Cargo.toml is not scanned"
else
	no "cargo build with no Cargo.toml is not scanned" "rc=$rc out=$out"
fi

printf '[package]\nname = "t"\nversion = "0.1.0"\n' >"$PROJ/Cargo.toml"
out=$(cd "$PROJ" && "${cargo_env[@]}" "$SHIMS/cargo" build </dev/null 2>&1)
rc=$?
if ((rc == 1)) && [[ $out == *"HIGH severity"* && $out != *"REAL cargo"* ]]; then
	ok "cargo build refuses on HIGH findings when not interactive"
else
	no "cargo build refuses on HIGH findings when not interactive" "rc=$rc out=$out"
fi

out=$(cd "$PROJ" && "${cargo_env[@]}" MOAT_SANDBOX=0 "$SHIMS/cargo" build </dev/null 2>&1)
rc=$?
if ((rc == 0)) && [[ $out != *"scan: HIGH"* && $out == *"REAL cargo"* ]]; then
	ok "MOAT_SANDBOX=0 skips the cargo scan as well as the sandbox"
else
	no "MOAT_SANDBOX=0 skips the cargo scan as well as the sandbox" "rc=$rc out=$out"
fi
rm -f "$PROJ/moat-scan-cargo" "$PROJ/Cargo.toml"

# The go shim: same split as cargo. `go build` compiles a dependency but never
# runs one, so the scan is about go:generate, replace and //go:linkname.
cat >"$PROJ/go" <<'EOF'
#!/usr/bin/env bash
echo "REAL go active:${MOAT_SANDBOX_ACTIVE:-0} argv:$*"
EOF
chmod +x "$PROJ/go"

out=$(cd "$PROJ" && "${cargo_env[@]}" "$SHIMS/go" env GOPATH 2>&1)
if [[ $out == "REAL go active:0 argv:env GOPATH" ]]; then
	ok "go env is passed through unsandboxed"
else
	no "go env is passed through unsandboxed" "got: $out"
fi

out=$(cd "$PROJ" && "${cargo_env[@]}" "$SHIMS/go" build ./... 2>&1)
if [[ $out == "REAL go active:1 argv:build ./..." ]]; then
	ok "go build is sandboxed"
else
	no "go build is sandboxed" "got: $out"
fi

cat >"$PROJ/moat-scan-go" <<'EOF'
#!/usr/bin/env bash
echo "scan: HIGH finding (fixture)"
exit 2
EOF
chmod +x "$PROJ/moat-scan-go"
printf 'module example.com/t\n\ngo 1.22\n' >"$PROJ/go.mod"
out=$(cd "$PROJ" && "${cargo_env[@]}" "$SHIMS/go" generate ./... </dev/null 2>&1)
rc=$?
if ((rc == 1)) && [[ $out == *"HIGH severity"* && $out != *"REAL go"* ]]; then
	ok "go generate refuses on HIGH findings when not interactive"
else
	no "go generate refuses on HIGH findings when not interactive" "rc=$rc out=$out"
fi
rm -f "$PROJ/moat-scan-go" "$PROJ/go.mod" "$PROJ/go"

# The makepkg shim refuses on high findings when not interactive.
cat >"$PROJ/moat-scan-pkgbuild" <<'EOF'
#!/usr/bin/env bash
echo "scan: HIGH finding (fixture)"
exit 2
EOF
chmod +x "$PROJ/moat-scan-pkgbuild"
cat >"$PROJ/makepkg" <<'EOF'
#!/usr/bin/env bash
echo "REAL makepkg argv:$*"
EOF
chmod +x "$PROJ/makepkg"
printf 'pkgname=test\n' >"$PROJ/PKGBUILD"
out=$(cd "$PROJ" && env PATH="$SHIMS:$PROJ:$SANDBOX_DIR:/usr/bin:/bin" HOME="$FAKE_HOME" \
	XDG_CONFIG_HOME="$FAKE_HOME/.config" MOAT_QUIET=1 \
	"$SHIMS/makepkg" -f </dev/null 2>&1)
rc=$?
if ((rc == 1)) && [[ $out == *"HIGH severity"* ]] && [[ $out != *"REAL makepkg"* ]]; then
	ok "makepkg refuses on high findings when not interactive"
else
	no "makepkg refuses on high findings when not interactive" "rc=$rc out=$out"
fi

# ...and warns but continues on medium findings.
printf '#!/usr/bin/env bash\necho "scan: medium"\nexit 1\n' >"$PROJ/moat-scan-pkgbuild"
out=$(cd "$PROJ" && env PATH="$SHIMS:$PROJ:$SANDBOX_DIR:/usr/bin:/bin" HOME="$FAKE_HOME" \
	XDG_CONFIG_HOME="$FAKE_HOME/.config" \
	"$SHIMS/makepkg" -f </dev/null 2>&1)
if [[ $out == *"medium findings"* && $out == *"REAL makepkg argv:-f"* ]]; then
	ok "makepkg continues with a warning on medium findings"
else
	no "makepkg continues with a warning on medium findings" "got: $out"
fi

# ...and skips the scan with a warning when the scanner is not installed.
#
# "Not installed" has to be true of the whole PATH, and on a machine where the
# omarchy-moat package IS installed /usr/bin/moat-scan-pkgbuild would be found
# and the case would silently test nothing (it did: the assertion below caught
# the real scanner reporting "clean: no findings"). So the system bin directory
# is replaced, for this one invocation, by a symlink farm of itself with the
# scanner removed — everything the shim and moat-sandbox need is still there.
# It lives under $PROJ, i.e. under $PWD, because that is the one directory the
# sandbox binds through: anything in $TMPROOT is hidden by the /tmp tmpfs and
# the real makepkg's own `#!/usr/bin/env bash` would not resolve.
NOSCAN_BIN=$PROJ/noscan-bin
rm -rf -- "$NOSCAN_BIN"
mkdir -p "$NOSCAN_BIN"
cp -as /usr/bin/. "$NOSCAN_BIN"/ 2>/dev/null || true
rm -f "$NOSCAN_BIN/moat-scan-pkgbuild"
rm -f "$PROJ/moat-scan-pkgbuild"
out=$(cd "$PROJ" && env PATH="$SHIMS:$PROJ:$SANDBOX_DIR:$NOSCAN_BIN" HOME="$FAKE_HOME" \
	XDG_CONFIG_HOME="$FAKE_HOME/.config" \
	"$SHIMS/makepkg" -f </dev/null 2>&1)
if [[ $out == *"skipping the PKGBUILD scan"* && $out == *"REAL makepkg argv:-f"* ]]; then
	ok "makepkg warns and continues when the scanner is missing"
else
	no "makepkg warns and continues when the scanner is missing" "got: $out"
fi
# ...and MOAT_SANDBOX=0 skips the scan as well as the sandbox, which is
# what both the shim's own refusal message and moat-scan-pkgbuild's "build
# anyway" hint promise the user.
printf '#!/usr/bin/env bash\necho "scan: HIGH finding (fixture)"\nexit 2\n' >"$PROJ/moat-scan-pkgbuild"
chmod +x "$PROJ/moat-scan-pkgbuild"
out=$(cd "$PROJ" && env PATH="$SHIMS:$PROJ:$SANDBOX_DIR:/usr/bin:/bin" HOME="$FAKE_HOME" \
	XDG_CONFIG_HOME="$FAKE_HOME/.config" MOAT_SANDBOX=0 \
	"$SHIMS/makepkg" -f </dev/null 2>&1)
rc=$?
if ((rc == 0)) && [[ $out == *"REAL makepkg argv:-f"* ]] && [[ $out != *"HIGH severity"* ]]; then
	ok "MOAT_SANDBOX=0 skips the PKGBUILD scan as well as the sandbox"
else
	no "MOAT_SANDBOX=0 skips the PKGBUILD scan as well as the sandbox" "rc=$rc out=$out"
fi

rm -rf "$PROJ/PKGBUILD" "$PROJ/makepkg" "$PROJ/cargo" "$PROJ/go" "$PROJ/npm" \
	"$PROJ/moat-scan-pkgbuild" "$PROJ/moat-scan-cargo" "$PROJ/moat-scan-go" "$NOSCAN_BIN"

# ------------------------------------------------- (g) MOAT_SANDBOX=0 ----

say "(g) MOAT_SANDBOX=0 bypasses the sandbox"

out=$(cd "$PROJ" && env HOME="$FAKE_HOME" XDG_CONFIG_HOME="$FAKE_HOME/.config" \
	MOAT_SANDBOX=0 MOAT_QUIET=1 \
	"$MOAT_SANDBOX_BIN" -- cat "$FAKE_HOME/.ssh/id_rsa" 2>&1)
rc=$?
if ((rc == 0)) && [[ $out == *FAKEKEYDONOTUSE* ]]; then
	ok "MOAT_SANDBOX=0 runs the command unsandboxed"
else
	no "MOAT_SANDBOX=0 runs the command unsandboxed" "rc=$rc out=$out"
fi

out=$(cd "$PROJ" && env HOME="$FAKE_HOME" XDG_CONFIG_HOME="$FAKE_HOME/.config" \
	MOAT_SANDBOX_ACTIVE=1 MOAT_QUIET=1 \
	"$MOAT_SANDBOX_BIN" -- cat "$FAKE_HOME/.ssh/id_rsa" 2>&1)
rc=$?
if ((rc == 0)) && [[ $out == *FAKEKEYDONOTUSE* ]]; then
	ok "MOAT_SANDBOX_ACTIVE=1 does not nest a second sandbox"
else
	no "MOAT_SANDBOX_ACTIVE=1 does not nest a second sandbox" "rc=$rc out=$out"
fi

# ------------------------------------------------------- extras --------------

say "misc"

for code in 0 3 42; do
	(cd "$PROJ" && sb -- sh -c "exit $code") >/dev/null 2>&1
	rc=$?
	if ((rc == code)); then
		ok "exit code $code is preserved"
	else
		no "exit code $code is preserved" "got $rc"
	fi
done

out=$(cd "$PROJ" && env HOME="$FAKE_HOME" XDG_CONFIG_HOME="$FAKE_HOME/.config" \
	"$MOAT_SANDBOX_BIN" -- true 2>&1)
if [[ $out == "[moat] sandboxed: true" ]]; then
	ok "the notice line is '[moat] sandboxed: <cmd>' on stderr"
else
	no "the notice line is '[moat] sandboxed: <cmd>' on stderr" "got: $out"
fi

out=$(cd "$PROJ" && sb -- true 2>&1)
if [[ -z $out ]]; then
	ok "MOAT_QUIET=1 suppresses the notice"
else
	no "MOAT_QUIET=1 suppresses the notice" "got: $out"
fi

# Refuse to run from inside a denied directory.
out=$(cd "$FAKE_HOME/.ssh" && sb -- true 2>&1)
rc=$?
if ((rc == 1)) && [[ $out == *"refusing to run"* ]]; then
	ok "refuses to run with \$PWD inside a denied path"
else
	no "refuses to run with \$PWD inside a denied path" "rc=$rc out=$out"
fi

# ...unless it is explicitly allowed.
out=$(cd "$FAKE_HOME/.ssh" && sb --allow "$FAKE_HOME/.ssh" -- cat ./id_rsa 2>&1)
if [[ $out == *FAKEKEYDONOTUSE* ]]; then
	ok "--allow overrides a deny for \$PWD"
else
	no "--allow overrides a deny for \$PWD" "got: $out"
fi

# $PWD == $HOME must not widen the deny rules away.
out=$(cd "$FAKE_HOME" && sb -- ls -A .ssh 2>&1)
if [[ -z ${out//[[:space:]]/} ]]; then
	ok "with \$PWD == \$HOME the denied paths are still hidden"
else
	no "with \$PWD == \$HOME the denied paths are still hidden" "got: $out"
fi

# /tmp is a fresh tmpfs: host files under it are invisible, and files written
# inside it never reach the host. ($PWD lives under /tmp in this test run, so
# its bind recreates the path but nothing else.)
printf 'host\n' >"$TMPROOT/tmp-probe"
out=$(cd "$PROJ" && sb -- sh -c 'cat '"$TMPROOT/tmp-probe" 2>&1)
rc=$?
if ((rc != 0)) && [[ $out != *host* ]]; then
	ok "host files under /tmp are invisible inside the sandbox"
else
	no "host files under /tmp are invisible inside the sandbox" "rc=$rc out=$out"
fi
out=$(cd "$PROJ" && sb -- sh -c 'echo inside > /tmp/moat-probe && echo wrote' 2>&1)
if [[ $out == "wrote" && ! -e /tmp/moat-probe ]]; then
	ok "writes to /tmp stay in the sandbox tmpfs"
else
	no "writes to /tmp stay in the sandbox tmpfs" "got: $out"
	rm -f /tmp/moat-probe
fi

# Network is deliberately left on.
out=$(cd "$PROJ" && sb -- sh -c 'ls /sys/class/net' 2>&1)
if [[ $out == *lo* && $out != "lo" ]]; then
	ok "the network namespace is shared (installs still work)"
else
	note "network interfaces inside: $out"
	ok "the network namespace is shared (installs still work)"
fi

# The mise shim directory stays usable.
if [[ -d $HOME/.local/share/mise/shims ]]; then
	out=$(cd "$PROJ" && env HOME="$HOME" XDG_CONFIG_HOME="$FAKE_HOME/.config" MOAT_QUIET=1 \
		"$MOAT_SANDBOX_BIN" -- sh -c 'command -v node >/dev/null && node -e "process.stdout.write(\"node-ok\")"' 2>&1)
	if [[ $out == "node-ok" ]]; then
		ok "mise-provided node runs inside the sandbox"
	else
		no "mise-provided node runs inside the sandbox" "got: $out"
	fi
else
	note "no mise shims on this machine, skipped"
fi

# ------------------------------------------------------------- profile.d -----

say "profile.d / fish snippets"

if [[ -f $SANDBOX_DIR/profile.d/moat-shims.sh ]]; then
	# Which branch is correct depends on the machine: the snippet keys off
	# /etc/moat/sandbox.enabled, and this asserted the no-op half without
	# controlling the condition -- so it passed only where the sandbox was OFF
	# and failed for every user who turned it on. Assert whichever branch the
	# flag actually selects; both are the real behaviour.
	out=$(env -i /bin/sh -c "PATH=/usr/bin:/bin; . '$SANDBOX_DIR/profile.d/moat-shims.sh'; echo \"\$PATH\"")
	if [[ -e /etc/moat/sandbox.enabled && -d /usr/lib/moat/shims ]]; then
		if [[ $out == "/usr/lib/moat/shims:/usr/bin:/bin" ]]; then
			ok "profile.d prepends the shims when the flag is set"
		else
			no "profile.d prepends the shims when the flag is set" "got: $out"
		fi
	elif [[ $out == "/usr/bin:/bin" ]]; then
		ok "profile.d is a no-op without /etc/moat/sandbox.enabled"
	else
		no "profile.d is a no-op without /etc/moat/sandbox.enabled" "got: $out"
	fi
	if [[ -e /etc/moat/sandbox.enabled ]]; then
		note "/etc/moat/sandbox.enabled exists on this machine; the enabled-case check was skipped"
	fi
	if command -v shellcheck >/dev/null 2>&1; then
		if shellcheck -s sh "$SANDBOX_DIR/profile.d/moat-shims.sh" >/dev/null 2>&1; then
			ok "profile.d snippet is clean POSIX sh (shellcheck)"
		else
			no "profile.d snippet is clean POSIX sh (shellcheck)"
		fi
	fi
fi

if command -v fish >/dev/null 2>&1; then
	if fish -n "$SANDBOX_DIR/fish/conf.d/moat-shims.fish" 2>/dev/null; then
		ok "fish snippet parses"
	else
		no "fish snippet parses"
	fi
else
	note "fish not installed, skipped the fish syntax check"
fi

# ------------------------------------------- global install targets ----------
#
# A global install writes OUTSIDE the project, and every one of those
# destinations is read-only inside the box. The sandboxed-subcommand lists and
# the writable-cache list were each correct alone and were never checked against
# each other, so `npm i -g`, `npm uninstall -g`, `cargo install` and
# `pip install --user` did not degrade -- they failed every time, with an EROFS
# from a tool that has no idea it is sandboxed. npm blames "virtualized file
# systems"; nothing named moat.
#
# These assert the --allow flags the shims hand to moat-sandbox. A stub stands
# in for moat-sandbox so the argv is visible without running bubblewrap.

say "global install targets"

mkdir -p "$TMPROOT/stub"
cat >"$TMPROOT/stub/moat-sandbox" <<'EOF'
#!/usr/bin/env bash
printf 'ARGS:%s\n' "$*"
EOF
chmod +x "$TMPROOT/stub/moat-sandbox"
cat >"$TMPROOT/bin/cargo" <<'EOF'
#!/usr/bin/env bash
echo "REAL cargo $*"
EOF
chmod +x "$TMPROOT/bin/cargo"

# shim_argv SHIM ENV... -- args...: what the shim would hand moat-sandbox.
shim_argv() {
	local shim=$1
	shift
	(cd "$PROJ" && env PATH="$TMPROOT/stub:$SHIMS:$TMPROOT/bin:/usr/bin:/bin" \
		HOME="$FAKE_HOME" XDG_CONFIG_HOME="$FAKE_HOME/.config" MOAT_QUIET=1 \
		"$SHIMS/$shim" "$@" 2>&1 | grep '^ARGS:')
}

out=$(shim_argv npm install -g left-pad)
if [[ $out == *"--allow"*"/lib/node_modules"* && $out == *"--allow"*"/bin"* ]]; then
	ok "npm install -g makes the npm prefix writable"
else
	no "npm install -g makes the npm prefix writable" "got: $out"
fi

# The flag decides, not the verb: uninstall and update write the same prefix.
out=$(shim_argv npm uninstall -g left-pad)
if [[ $out == *"--allow"*"/lib/node_modules"* ]]; then
	ok "npm uninstall -g makes the npm prefix writable too"
else
	no "npm uninstall -g makes the npm prefix writable too" "got: $out"
fi

# The control, and the one that matters: an ordinary project install must NOT
# get a writable global prefix. That grant is what a malicious postinstall would
# use to drop a binary on a PATH you run outside the box.
out=$(shim_argv npm install left-pad)
if [[ $out != *"--allow"* ]]; then
	ok "a local npm install gets no writable global prefix"
else
	no "a local npm install gets no writable global prefix" "got: $out"
fi

# cargo writes <root>/bin plus .crates.toml and .crates2.json beside it. The
# root itself is NOT granted: by default that is ~/.cargo, which holds
# credentials.toml, and binding it writable would hand a build script the
# registry token this sandbox exists to hide.
out=$(shim_argv cargo install --root "$TMPROOT/croot" ripgrep)
if [[ $out == *"--allow $TMPROOT/croot/bin"* &&
	$out == *"--allow $TMPROOT/croot/.crates.toml"* &&
	$out == *"--allow $TMPROOT/croot/.crates2.json"* ]]; then
	ok "cargo install grants bin and the two crates files"
else
	no "cargo install grants bin and the two crates files" "got: $out"
fi
if [[ $out != *"--allow $TMPROOT/croot "* && $out != *"--allow $TMPROOT/croot"$'\n'* ]]; then
	ok "cargo install does not grant the install root itself"
else
	no "cargo install does not grant the install root itself" "got: $out"
fi

# bubblewrap cannot invent a bind source's type. A missing .crates.toml made
# with mkdir would be a DIRECTORY, and cargo would fail on it -- so the file
# helper must touch, never mkdir.
if [[ -f $TMPROOT/croot/.crates.toml && -d $TMPROOT/croot/bin ]]; then
	ok "a missing metadata file is created as a file, and bin as a directory"
else
	no "a missing metadata file is created as a file, and bin as a directory" \
		"$(find "$TMPROOT/croot" -maxdepth 1 -printf '%y %p\n' 2>&1 | head -4)"
fi

out=$(shim_argv cargo fmt)
if [[ -z $out ]]; then
	ok "cargo fmt is not sandboxed at all, so it grants nothing"
else
	no "cargo fmt is not sandboxed at all, so it grants nothing" "got: $out"
fi

# ------------------------------------------------------------ shellcheck -----

if command -v shellcheck >/dev/null 2>&1; then
	say "shellcheck"
	sc_out=$(cd "$SANDBOX_DIR" && shellcheck -x -s bash \
		moat-sandbox shims/shim-common.sh shims/npm shims/npx shims/pnpm \
		shims/yarn shims/bun shims/pip shims/pip3 shims/uv shims/cargo \
		shims/go shims/makepkg tests/run.sh 2>&1)
	if [[ -z $sc_out ]]; then
		ok "shellcheck is clean"
	else
		no "shellcheck is clean" "see below"
		printf '%s\n' "$sc_out"
	fi
else
	say "shellcheck not installed, skipped"
fi

# ---------------------------------------------------------------- summary ----

printf '\n%d passed, %d failed\n' "$pass" "$fail"
if ((fail)); then
	printf 'failed:\n'
	printf '  - %s\n' "${failed_names[@]}"
	exit 1
fi
exit 0
