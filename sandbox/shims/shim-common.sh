# shellcheck shell=bash
# Common logic for the omarchy-moat PATH shims.
#
# Sourced by /usr/lib/moat/shims/<name>. Never executed directly.
#
# A shim must:
#   1. work out its own directory,
#   2. remove that directory from $PATH (so mise shims, ~/.local/bin and
#      /usr/bin all still resolve normally),
#   3. resolve the real binary from the reduced $PATH,
#   4. exec `moat-sandbox -- <real> "$@"`.
#
# Inside the sandbox MOAT_SANDBOX_ACTIVE=1, and shim_exec then runs the
# real binary directly: bubblewrap cannot usefully nest under an unprivileged
# user namespace, and the outer sandbox already applies.

# Extra options handed to moat-sandbox. A shim may append to this after
# sourcing this file and before calling shim_exec.
SHIM_SANDBOX_ARGS=()

shim_warn() {
	[[ ${MOAT_QUIET:-0} == 1 ]] || printf '[moat] %s\n' "$*" >&2
}

shim_die() {
	printf '[moat] %s\n' "$*" >&2
	exit 127
}

# Where the shims live when installed from the package. Used only as a
# fallback if argv[0] carries no directory (it normally does: the kernel gives
# a #! script its full path in $0).
SHIM_DIR_DEFAULT=${SHIM_DIR_DEFAULT:-/usr/lib/moat/shims}

# shim_self_dir: absolute, symlink-resolved directory holding this shim.
# The shim sets SHIM_SELF=${BASH_SOURCE[0]} before sourcing this file.
shim_self_dir() {
	local src=${SHIM_SELF:-$0} dir target
	if [[ $src != */* ]]; then
		printf '%s' "$SHIM_DIR_DEFAULT"
		return 0
	fi
	# Follow symlinks to the shim itself (a distro may symlink the shim dir).
	while [[ -L $src ]]; do
		target=$(readlink -- "$src")
		case $target in
		/*) src=$target ;;
		*) src=$(dirname -- "$src")/$target ;;
		esac
	done
	dir=$(cd -- "$(dirname -- "$src")" && pwd -P) || return 1
	printf '%s' "$dir"
}

# shim_path_without DIR: $PATH with every entry resolving to DIR removed.
shim_path_without() {
	local drop=$1 out="" entry real
	local -a parts
	IFS=: read -r -a parts <<<"${PATH:-}"
	for entry in "${parts[@]}"; do
		[[ -z $entry ]] && continue
		if [[ $entry == "$drop" ]]; then
			continue
		fi
		# Resolve so /usr/lib/moat/shims and a symlink to it both go.
		if real=$(cd -- "$entry" 2>/dev/null && pwd -P); then
			[[ $real == "$drop" ]] && continue
		fi
		out=${out:+$out:}$entry
	done
	printf '%s' "$out"
}

# shim_resolve NAME: absolute path of the real NAME, shim dir excluded.
# Sets SHIM_REAL. Dies if the only match is the shim itself.
shim_resolve() {
	local name=$1 dir reduced real
	dir=$(shim_self_dir) || shim_die "cannot determine the shim directory"
	reduced=$(shim_path_without "$dir")
	real=$(PATH=$reduced command -v -- "$name" 2>/dev/null) || real=""
	[[ -n $real ]] || shim_die "$name: no real binary found in PATH (shim dir $dir excluded)"
	# Refuse to exec ourselves under any circumstance.
	local real_dir
	real_dir=$(cd -- "$(dirname -- "$real")" 2>/dev/null && pwd -P) || real_dir=""
	if [[ $real_dir == "$dir" ]]; then
		shim_die "$name: resolved back to the shim directory, refusing to recurse"
	fi
	SHIM_REAL=$real
	SHIM_PATH_REDUCED=$reduced
}

# shim_exec NAME "$@"
# Runs the real NAME under moat-sandbox, or directly when the sandbox is
# disabled / already active. Extra moat-sandbox options come from the
# SHIM_SANDBOX_ARGS array, which a shim may set before calling; everything
# after NAME is passed through to the real binary untouched (including "--").
shim_exec() {
	local name=$1
	shift
	local -a sandbox_args=()
	if ((${#SHIM_SANDBOX_ARGS[@]})); then
		sandbox_args=("${SHIM_SANDBOX_ARGS[@]}")
	fi

	shim_resolve "$name"

	if [[ ${MOAT_SANDBOX:-1} == 0 || ${MOAT_SANDBOX_ACTIVE:-0} == 1 ]]; then
		PATH=$SHIM_PATH_REDUCED exec -- "$SHIM_REAL" "$@"
	fi

	if ! command -v moat-sandbox >/dev/null 2>&1; then
		shim_warn "moat-sandbox not found, running $name unsandboxed"
		PATH=$SHIM_PATH_REDUCED exec -- "$SHIM_REAL" "$@"
	fi

	if ((${#sandbox_args[@]})); then
		exec moat-sandbox "${sandbox_args[@]}" -- "$SHIM_REAL" "$@"
	fi
	exec moat-sandbox -- "$SHIM_REAL" "$@"
}

# shim_is_tty: true only when both stdin and stdout are terminals.
shim_is_tty() {
	[[ -t 0 && -t 1 ]]
}

# --------------------------------------------------------------- scanning ---
#
# The pre-execution scan contract, shared by every shim that runs a
# moat-scan-* tool before handing over. It is the one the makepkg shim
# established; the scanners all use the same exit codes:
#
#   0            nothing, or only low findings   -> continue silently
#   1            medium findings                 -> warn, continue
#   2            high findings                   -> ask, or refuse when there
#                                                   is no terminal to ask at
#   anything else / scanner missing              -> warn, continue
#
# The last line matters most: a scanner that crashes, or is not installed,
# must never be able to stop an install. Refusal is reserved for findings the
# scanner is sure about.
#
# MOAT_SANDBOX=0 skips the scan as well as the sandbox, because that is what
# both this refusal message and the scanner's own "install anyway" hint tell
# the user to do; scanning anyway would make both of them lie.
#
# MOAT_SANDBOX_ACTIVE=1 deliberately does NOT skip the scan: a nested install
# inside the sandbox is usually a different directory with a different tree
# that the outer invocation never saw.

# shim_run_scan LABEL SCANNER [ARG...]
shim_run_scan() {
	local label=$1 scanner=$2
	shift 2
	[[ ${MOAT_SANDBOX:-1} == 0 ]] && return 0
	# An explicit override, so a local build can be pointed at without touching
	# PATH -- and so the "scanner is absent" contract can be tested for real
	# rather than by relying on it not being installed yet.
	local var="MOAT_SCANNER_${scanner//-/_}"
	local override=${!var:-}
	[[ -n $override ]] && scanner=$override
	if ! command -v "$scanner" >/dev/null 2>&1; then
		shim_warn "$scanner not found, skipping the $label scan"
		return 0
	fi

	local rc=0
	"$scanner" "$@" || rc=$?

	case $rc in
	0) return 0 ;;
	1)
		shim_warn "$label scan: medium findings above. Continuing."
		return 0
		;;
	2) ;;
	*)
		shim_warn "$scanner failed (exit $rc), continuing without a scan"
		return 0
		;;
	esac

	# High findings.
	if ! shim_is_tty; then
		printf '[moat] %s scan found HIGH severity findings and this is not an interactive terminal. Refusing to continue.\n' "$label" >&2
		printf '[moat] Review the findings, then re-run from a terminal or set MOAT_SANDBOX=0 to bypass everything.\n' >&2
		exit 1
	fi
	if command -v gum >/dev/null 2>&1; then
		if gum confirm "Continue anyway?"; then
			shim_warn "continuing at your request despite HIGH findings"
			return 0
		fi
	else
		local reply=""
		read -r -p "[moat] HIGH findings. Continue anyway? [y/N] " reply || reply=""
		if [[ $reply == [yY]* ]]; then
			shim_warn "continuing at your request despite HIGH findings"
			return 0
		fi
	fi
	printf '[moat] aborted.\n' >&2
	exit 1
}

# shim_subcmd_n N "$@": echo the Nth (1-based) bare word of an argv, i.e. the
# subcommand and, for `uv pip install`, the one after it. Options are skipped.
shim_subcmd_n() {
	local want=$1 seen=0 arg
	shift
	for arg in "$@"; do
		case $arg in
		--) ;;
		-*) ;;
		*)
			seen=$((seen + 1))
			if ((seen == want)); then
				printf '%s' "$arg"
				return 0
			fi
			;;
		esac
	done
	return 0
}

# shim_subcmd "$@": the first bare word of an argv.
shim_subcmd() { shim_subcmd_n 1 "$@"; }

# Historical name, kept because the JS shims and their tests use it.
shim_js_subcmd() { shim_subcmd_n 1 "$@"; }

# shim_js_has_global "$@": true when the argv asks for a global install, which
# has no local package tree worth scanning.
shim_js_has_global() {
	local arg
	for arg in "$@"; do
		case $arg in
		-g | --global | --location=global) return 0 ;;
		esac
	done
	return 1
}

# shim_scan_js_tree LABEL "$@": scan the JavaScript package tree in $PWD
# before an install-shaped command runs. Silent when there is nothing here
# that npm would read, so `npm install -g` from $HOME costs nothing.
shim_scan_js_tree() {
	local label=$1
	shift
	shim_js_has_global "$@" && return 0
	[[ -f ./package.json || -f ./package-lock.json || -f ./npm-shrinkwrap.json ||
		-f ./yarn.lock || -f ./pnpm-lock.yaml ]] || return 0
	shim_run_scan "$label" moat-scan-npm .
}

# shim_scan_python_tree LABEL: scan the Python project in $PWD before pip or
# uv builds anything from it. Silent when there is nothing here that pip would
# read, so `pip install requests` from $HOME costs nothing.
shim_scan_python_tree() {
	local label=$1
	[[ -f ./setup.py || -f ./setup.cfg || -f ./pyproject.toml ||
		-f ./pip.conf || -f ./pip.ini ]] ||
		compgen -G './requirements*.txt' >/dev/null 2>&1 ||
		return 0
	shim_run_scan "$label" moat-scan-pip --for python .
}
