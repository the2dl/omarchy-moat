#!/usr/bin/env bash
#
# Install omarchy-moat on this machine.
#
# Idempotent: safe to re-run, and re-running is how you upgrade.
#
# What it will NOT do, deliberately:
#   - turn on enforcement (`mode enforce`), containment, or `kill`. Those are
#     decisions about your machine, they are root-gated on purpose, and moat
#     ships in monitor mode so a bad first day is noisy rather than expensive.
#   - touch ~/.config/hypr, or run omarchy-refresh-shell (it resets shell.json).
#   - restart your shell.
#
# Usage:
#   ./install.sh                 build from this tree, install, enable, verify
#   ./install.sh --check         preflight only; changes nothing
#   ./install.sh --no-build      install the newest pkg/*.pkg.tar.zst as-is
#   ./install.sh --plugin-url U  also register the panel from git URL U
set -euo pipefail

HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
DO_BUILD=1
CHECK_ONLY=0
# The canonical plugin URL. This repository IS the plugin -- manifest.json at
# the root declares id io.github.the2dl.moat with its entry points under
# shell/ -- so `omarchy plugin add` on this URL installs the panel and keeps it
# updatable from upstream.
#
# It was empty until 2026-09-10, which meant a default install ended with "no
# panel installed ... add it by hand" and most people simply did not have the
# UI. --plugin-url still overrides, which is what a fork or a local checkout
# needs.
PLUGIN_URL="${MOAT_PLUGIN_URL:-https://github.com/the2dl/omarchy-moat.git}"

while [ $# -gt 0 ]; do
	case "$1" in
	--check) CHECK_ONLY=1 ;;
	--no-build) DO_BUILD=0 ;;
	--plugin-url) PLUGIN_URL="${2:-}"; shift ;;
	-h | --help) sed -n '2,25p' "$0" | sed 's/^# \?//'; exit 0 ;;
	*) echo "unknown option: $1 (try --help)" >&2; exit 2 ;;
	esac
	shift
done

say() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }
ok() { printf '    \033[32mok\033[0m   %s\n' "$*"; }
warn() { printf '    \033[33mwarn\033[0m %s\n' "$*"; }
die() { printf '\n\033[31mstopped:\033[0m %s\n\n' "$*" >&2; exit 1; }

# --------------------------------------------------------------- preflight
#
# Every check here is something that, if missing, produces a moat that looks
# installed and running while silently doing nothing. They are cheap; a silent
# sensor outage is not.

say "Checking this machine"

[ -f /etc/arch-release ] || die "this is an Arch package; /etc/arch-release is missing"
ok "Arch"

case "$(uname -m)" in
	x86_64|aarch64) ok "$(uname -m)" ;;
	*) die "Tetragon ships amd64 and arm64 builds only (this is $(uname -m))" ;;
esac

command -v systemctl >/dev/null || die "systemd is required"
ok "systemd"

# Tetragon needs BTF to attach anything at all. Arch ships it; a custom or
# very old kernel may not.
[ -f /sys/kernel/btf/vmlinux ] || die \
	"/sys/kernel/btf/vmlinux is missing -- this kernel has no BTF, so Tetragon cannot attach.
   Use the stock Arch kernel, or rebuild with CONFIG_DEBUG_INFO_BTF=y."
ok "BTF present"

# THE check that is easy to miss. Moat's deny policies and all of containment
# work by returning EPERM from an LSM hook (`Override`, argError -1). Without
# BPF LSM those policies load, report "enforce", and refuse nothing whatsoever.
# Arch enables it by default with no lsm= on the cmdline.
if grep -qw bpf /sys/kernel/security/lsm 2>/dev/null; then
	ok "BPF LSM enabled ($(cat /sys/kernel/security/lsm))"
else
	warn "BPF LSM is NOT enabled: $(cat /sys/kernel/security/lsm 2>/dev/null || echo unknown)"
	MOAT_NO_BPF_LSM=1
	# Two different failures wearing the same symptom, and the fix for one is
	# not the fix for the other. This used to say only "add bpf to the cmdline"
	# and "detection will work" -- both true for the first case, both wrong for
	# the second, and the second is what every Asahi and most distro arm64
	# kernels are.
	if grep -q '^CONFIG_BPF_LSM=y' "/boot/config-$(uname -r)" 2>/dev/null \
		|| { [ -r /proc/config.gz ] && zgrep -q '^CONFIG_BPF_LSM=y' /proc/config.gz 2>/dev/null; }; then
		warn "The kernel HAS BPF LSM built in, it is just not in the active list."
		warn "Detection will work. Blocking will NOT -- deny policies and containment"
		warn "will load, report enforce, and refuse nothing. To fix, add bpf to the"
		warn "kernel cmdline, keeping the modules you already run:"
		warn "  lsm=$(cat /sys/kernel/security/lsm 2>/dev/null),bpf"
	else
		warn "This kernel was BUILT WITHOUT BPF LSM (CONFIG_BPF_LSM is not set)."
		warn "No boot parameter can enable it. Moat renders its LSM policies as"
		warn "kprobes instead, so DETECTION IS INTACT -- including credentials and"
		warn "the decoy files -- but nothing can be refused in the kernel, by any"
		warn "rule, however armed it looks. moatctl status says so on every run."
		MOAT_NO_BPF_LSM=built_out
	fi
fi

if [ "$DO_BUILD" = 1 ]; then
	command -v makepkg >/dev/null || die "makepkg is required to build (pacman -S base-devel)"
	command -v cargo >/dev/null || die "cargo is required to build (pacman -S rust)"
	ok "makepkg and cargo"
fi

if pacman -Q omarchy-moat >/dev/null 2>&1; then
	ok "already installed: $(pacman -Q omarchy-moat) -- this run will upgrade it"
fi

if [ "$CHECK_ONLY" = 1 ]; then
	say "Preflight only; nothing was changed"
	exit 0
fi

# ------------------------------------------------------------------- build

if [ "$DO_BUILD" = 1 ]; then
	say "Building the package"
	# The PKGBUILD runs the full test suite in check(); a failure here means
	# do not install this, so it is deliberately not skipped.
	(cd "$HERE/pkg" && makepkg --force --syncdeps --noconfirm)
fi

# Ask makepkg where it put the package rather than guessing at the name.
#
# `--packagelist` honours PKGDEST and PKGEXT from makepkg.conf, which a glob
# cannot: a host that sets PKGDEST builds into a shared cache directory and a
# host that sets PKGEXT='.pkg.tar.xz' produces a name the pattern below never
# matches. Either way `makepkg` reports success and the install then says "no
# package found", which reads as a build failure and is not one.
PKG=""
if PKG_LIST="$(cd "$HERE/pkg" && makepkg --packagelist 2>/dev/null)"; then
	# One line per split package; this PKGBUILD produces one.
	for candidate in $PKG_LIST; do
		[ -f "$candidate" ] && PKG="$candidate" && break
	done
fi

# Fallback for an older makepkg without --packagelist. Newest by mtime,
# NUL-safe: pkgrel 9 sorts after 62 alphabetically, so this must be
# time-ordered rather than name-ordered.
if [ -z "$PKG" ]; then
	PKG="$(find "$HERE/pkg" -maxdepth 1 -name '*.pkg.tar.*' -printf '%T@ %p\n' 2>/dev/null |
		sort -rn | head -1 | cut -d' ' -f2- || true)"
fi
if [ -z "$PKG" ]; then
	die "makepkg reported success but no package file was found.
   makepkg --packagelist says it should be at:
$(cd "$HERE/pkg" && makepkg --packagelist 2>&1 | sed 's/^/     /')
   Check PKGDEST and PKGEXT in /etc/makepkg.conf and ~/.makepkg.conf."
fi
ok "package: $(basename "$PKG")"

say "Installing (needs root)"
sudo pacman -U --noconfirm "$PKG"

# ----------------------------------------------------------------- enable
#
# Order matters and is not cosmetic: moatd is Requires=+After= tetragon, and
# starting moatd against a tetragon that is still coming up leaves it reading a
# log written under the previous policy set.

say "Enabling services"
sudo systemctl enable --now tetragon
sudo systemctl enable --now moatd
sudo systemctl enable --now moat-feeds.timer
ok "tetragon, moatd, moat-feeds.timer"

# Group membership is what lets you read alerts and use moatctl without sudo.
if id -nG "$USER" | tr ' ' '\n' | grep -qx moat; then
	ok "$USER is already in the moat group"
	NEED_RELOGIN=0
else
	sudo usermod -aG moat "$USER"
	ok "added $USER to the moat group"
	NEED_RELOGIN=1
fi

# ----------------------------------------------------------------- verify
#
# "enabled and started" is not "working". On 2026-09-03 a bad policy load cost
# 25 minutes of blindness while every surface still read "running", so this
# asks the daemon what the KERNEL actually pinned.

say "Verifying"
sleep 2
if ! moatctl status >/dev/null 2>&1; then
	if [ "${NEED_RELOGIN:-0}" = 1 ]; then
		warn "moatctl cannot reach the socket yet -- that is expected until you log out"
		warn "and back in, because your shell predates the new group membership."
	else
		warn "moatctl could not reach the daemon; check: systemctl status moatd"
	fi
else
	moatctl status | sed 's/^/    /'
	LOADED="$(moatctl --json status 2>/dev/null |
		python3 -c 'import json,sys; print(json.load(sys.stdin).get("sensors_loaded", 0))' 2>/dev/null || echo 0)"
	if [ "${LOADED:-0}" -gt 0 ]; then
		ok "$LOADED policies loaded in the kernel"
	else
		warn "the daemon is up but the kernel has 0 policies pinned -- a silent sensor"
		warn "outage. Check: journalctl -u tetragon -n50"
	fi
fi

# ----------------------------------------------------------------- panel
#
# The package does not ship the shell plugin: `omarchy plugin add` takes a git
# URL, and a plugin registered from a local copy would not update with the
# package. So the URL above is the default and this stays best-effort -- a
# machine with no `omarchy` on PATH, or no network, still gets everything else.

say "Panel"
if [ -n "$PLUGIN_URL" ]; then
	if command -v omarchy >/dev/null; then
		omarchy plugin add "$PLUGIN_URL" --enable --yes ||
			warn "could not add the plugin from $PLUGIN_URL; add it by hand"
	else
		warn "omarchy is not on PATH; skipping the plugin"
	fi
elif [ -d "$HOME/.config/omarchy/plugins/io.github.the2dl.moat" ]; then
	ok "plugin already present"
else
	warn "no panel installed. It is a separate omarchy shell plugin:"
	warn "    omarchy plugin add <git-url> --enable"
	warn "or re-run this script with --plugin-url <git-url>."
	warn "Everything works without it; moatctl is the full interface."
fi

# ------------------------------------------------------------------ done

say "Installed"
cat <<EOF

  Moat is running in MONITOR mode: it alerts, it does not block. Nothing here
  turned on enforcement, containment or process killing -- those are root-gated
  decisions, and they belong to you.

  Next, in your own session (no sudo):

    systemctl --user enable --now moat-digest.timer moat-triage.timer

EOF

if [ "${NEED_RELOGIN:-0}" = 1 ]; then
	cat <<EOF
  LOG OUT AND BACK IN before anything else. Your current shell predates the
  moat group, so moatctl will be denied until you start a fresh session.

EOF
fi

if [ "${MOAT_NO_BPF_LSM:-0}" = built_out ]; then
	cat <<EOF
  REMEMBER: this kernel has no BPF LSM and cannot get one from a boot flag.
  Moat detects -- all 55 policies load, as kprobes -- and refuses nothing.
  Do not trust "enforce" on this machine. \`moatctl status\` states it plainly.

EOF
elif [ "${MOAT_NO_BPF_LSM:-0}" != 0 ]; then
	cat <<EOF
  REMEMBER: BPF LSM is off on this kernel. Moat will detect but cannot block.
  Add bpf to the kernel cmdline; until then, do not trust "enforce" here.

EOF
fi

cat <<EOF
  Then:

    moatctl status          what is running, and what the kernel actually has
    moatctl list            recent alerts
    moatctl decisions       what the kill gate would have done, and why

  Give it a few days in monitor mode before turning anything on. The intended
  order is: watch -> \`moatctl set contain on\` (a narrow network cut, nothing
  killed) -> and only then consider \`set kill kill\`, after reading a week of
  \`moatctl decisions\` and agreeing with every line.

  Docs: /usr/share/doc/omarchy-moat

EOF
