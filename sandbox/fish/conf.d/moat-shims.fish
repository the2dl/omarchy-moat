# omarchy-moat: put the sandbox shims in front of PATH (fish).
#
# Installed as /usr/share/fish/vendor_conf.d/moat-shims.fish, which fish
# sources for login and non-login shells alike. /etc/profile.d is not read by
# fish, hence this copy.

if test -e /etc/moat/sandbox.enabled
    if test -d /usr/lib/moat/shims
        if not test "$PATH[1]" = /usr/lib/moat/shims
            set -gx PATH /usr/lib/moat/shims $PATH
        end
    end
end
