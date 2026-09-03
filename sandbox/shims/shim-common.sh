# shellcheck shell=bash
# Common logic for the omarchy-sentinel PATH shims.
#
# Sourced by /usr/lib/sentinel/shims/<name>. Never executed directly.
#
# A shim must:
#   1. work out its own directory,
#   2. remove that directory from $PATH (so mise shims, ~/.local/bin and
#      /usr/bin all still resolve normally),
#   3. resolve the real binary from the reduced $PATH,
#   4. exec `sentinel-sandbox -- <real> "$@"`.
#
# Inside the sandbox SENTINEL_SANDBOX_ACTIVE=1, and shim_exec then runs the
# real binary directly: bubblewrap cannot usefully nest under an unprivileged
# user namespace, and the outer sandbox already applies.

# Extra options handed to sentinel-sandbox. A shim may append to this after
# sourcing this file and before calling shim_exec.
SHIM_SANDBOX_ARGS=()

shim_warn() {
	[[ ${SENTINEL_QUIET:-0} == 1 ]] || printf '[sentinel] %s\n' "$*" >&2
}

shim_die() {
	printf '[sentinel] %s\n' "$*" >&2
	exit 127
}

# Where the shims live when installed from the package. Used only as a
# fallback if argv[0] carries no directory (it normally does: the kernel gives
# a #! script its full path in $0).
SHIM_DIR_DEFAULT=${SHIM_DIR_DEFAULT:-/usr/lib/sentinel/shims}

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
		# Resolve so /usr/lib/sentinel/shims and a symlink to it both go.
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
# Runs the real NAME under sentinel-sandbox, or directly when the sandbox is
# disabled / already active. Extra sentinel-sandbox options come from the
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

	if [[ ${SENTINEL_SANDBOX:-1} == 0 || ${SENTINEL_SANDBOX_ACTIVE:-0} == 1 ]]; then
		PATH=$SHIM_PATH_REDUCED exec -- "$SHIM_REAL" "$@"
	fi

	if ! command -v sentinel-sandbox >/dev/null 2>&1; then
		shim_warn "sentinel-sandbox not found, running $name unsandboxed"
		PATH=$SHIM_PATH_REDUCED exec -- "$SHIM_REAL" "$@"
	fi

	if ((${#sandbox_args[@]})); then
		exec sentinel-sandbox "${sandbox_args[@]}" -- "$SHIM_REAL" "$@"
	fi
	exec sentinel-sandbox -- "$SHIM_REAL" "$@"
}

# shim_is_tty: true only when both stdin and stdout are terminals.
shim_is_tty() {
	[[ -t 0 && -t 1 ]]
}
