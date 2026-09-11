#!/usr/bin/env bash
# Keep the installed panel in step with this repository.
#
# # Why this exists
#
# The panel is an Omarchy shell plugin, which means it is a SECOND git clone of
# this same repository living under ~/.config/omarchy/plugins/. The pacman
# package ships the daemon, the policies and the scanners; it ships no QML at
# all. So on a development machine `makepkg -si` updates everything except the
# thing you are looking at.
#
# That has now bitten twice. On 2026-09-11 the plugin clone sat eight commits
# behind for most of a day -- the process-tree work, the domain-name
# highlighting, the allowlist chips and a History rewrite were all "shipped"
# and none of them were running. It had no upstream branch set, so `git pull`
# printed a hint about --set-upstream-to and exited 0, which reads exactly like
# "already up to date".
#
# # What it does
#
# Finds every plugin clone whose `origin` is this repository and fast-forwards
# it. Fast-forward only: if somebody has been editing the plugin copy directly,
# that is a thing to look at, not a thing to overwrite.
#
#   scripts/sync-plugin.sh            fast-forward, print what moved
#   scripts/sync-plugin.sh --check    report drift and exit 1; writes nothing
#
# Run automatically from .githooks/post-commit, so the running panel is always
# some commit of this repo and never a half-finished edit. A symlink would be
# the other way to do it, and was rejected: the panel is a security surface the
# user reads every day, and pointing it at a dirty working tree means every
# mid-edit save reloads it.

set -uo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
PLUGIN_DIR=${MOAT_PLUGIN_DIR:-$HOME/.config/omarchy/plugins}

CHECK=0
[ "${1:-}" = "--check" ] && CHECK=1

say() { printf '%s\n' "$*"; }

# Does this clone's origin point at us? Compared by resolved path, so a
# symlinked or relative remote still matches.
origin_is_this_repo() {
    local dir=$1 url
    url=$(git -C "$dir" remote get-url origin 2>/dev/null) || return 1
    case "$url" in
        /*|./*|../*) [ "$(cd "$url" 2>/dev/null && pwd -P)" = "$REPO_ROOT" ] ;;
        *) return 1 ;;
    esac
}

found=0
drift=0

[ -d "$PLUGIN_DIR" ] || exit 0

for dir in "$PLUGIN_DIR"/*/; do
    [ -d "$dir/.git" ] || continue
    origin_is_this_repo "$dir" || continue
    found=$((found + 1))
    name=$(basename "$dir")

    branch=$(git -C "$dir" symbolic-ref --quiet --short HEAD 2>/dev/null)
    if [ -z "$branch" ]; then
        say "plugin $name: detached HEAD, leaving it alone"
        drift=1
        continue
    fi

    git -C "$dir" fetch --quiet origin 2>/dev/null

    local_sha=$(git -C "$dir" rev-parse HEAD 2>/dev/null)
    want_sha=$(git -C "$dir" rev-parse "origin/$branch" 2>/dev/null)
    if [ -z "$want_sha" ]; then
        say "plugin $name: no origin/$branch to follow"
        drift=1
        continue
    fi
    [ "$local_sha" = "$want_sha" ] && continue

    behind=$(git -C "$dir" rev-list --count "HEAD..origin/$branch" 2>/dev/null || echo 0)
    ahead=$(git -C "$dir" rev-list --count "origin/$branch..HEAD" 2>/dev/null || echo 0)
    drift=1

    if [ "$CHECK" = 1 ]; then
        say "plugin $name: $behind behind, $ahead ahead of origin/$branch"
        continue
    fi

    # Uncommitted work in the plugin copy is somebody editing the wrong tree.
    # Say so; do not clobber it.
    if [ -n "$(git -C "$dir" status --porcelain 2>/dev/null)" ]; then
        say "plugin $name: has uncommitted changes, refusing to touch it"
        continue
    fi
    if [ "$ahead" != "0" ]; then
        say "plugin $name: $ahead commit(s) not in this repo, refusing to fast-forward"
        continue
    fi

    if git -C "$dir" merge --ff-only "origin/$branch" --quiet 2>/dev/null; then
        # Set the upstream so a bare `git pull` in there works from now on.
        # Its absence is what made the last failure silent.
        git -C "$dir" branch --quiet --set-upstream-to="origin/$branch" "$branch" 2>/dev/null
        say "plugin $name: fast-forwarded $behind commit(s) to $(git -C "$dir" rev-parse --short HEAD)"
        drift=0
    else
        say "plugin $name: fast-forward failed"
    fi
done

if [ "$found" = 0 ]; then
    [ "$CHECK" = 1 ] && say "no plugin clone of this repo under $PLUGIN_DIR"
    exit 0
fi

[ "$CHECK" = 1 ] && [ "$drift" != 0 ] && exit 1
exit 0
