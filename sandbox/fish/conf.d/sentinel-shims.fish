# omarchy-sentinel: put the sandbox shims in front of PATH (fish).
#
# Installed as /usr/share/fish/vendor_conf.d/sentinel-shims.fish, which fish
# sources for login and non-login shells alike. /etc/profile.d is not read by
# fish, hence this copy.

if test -e /etc/sentinel/sandbox.enabled
    if test -d /usr/lib/sentinel/shims
        if not test "$PATH[1]" = /usr/lib/sentinel/shims
            set -gx PATH /usr/lib/sentinel/shims $PATH
        end
    end
end
