# omarchy-sentinel: put the sandbox shims in front of PATH.
#
# Installed as /etc/profile.d/sentinel-shims.sh. Sourced by bash and zsh login
# shells (zsh reads /etc/profile via /etc/zprofile on Arch). Fish has its own
# copy in /usr/share/fish/vendor_conf.d/sentinel-shims.fish.
#
# POSIX sh only: no arrays, no [[ ]], no local. Never exits or returns a
# non-zero status, so it cannot break a login shell.

if [ -e /etc/sentinel/sandbox.enabled ] && [ -d /usr/lib/sentinel/shims ]; then
	case ":${PATH-}:" in
	:/usr/lib/sentinel/shims:*)
		# already first, nothing to do
		;;
	*)
		# shellcheck disable=SC2123 # prepending to PATH is the point
		PATH="/usr/lib/sentinel/shims${PATH:+:$PATH}"
		export PATH
		;;
	esac
fi
