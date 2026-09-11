# Decoy files

Every other file rule in `policies/` has the same shape: watch a real
credential, then subtract the programs allowed to read it. That subtraction is
where the false positives live. `cred-ssh-private-key-read` carries fourteen
`NotPostfix` entries — ssh, sshd, git, rsync, borg, gpg-agent and the rest — and
still needs an allowlist, because ssh keys have legitimate readers.

A decoy has none. Nothing references it, no config points at it, no program
knows its name, and it holds nothing real. So the rule is the path and nothing
else, and a hit means something walked the filesystem looking for secrets.

It is the only detection here that needs no tuning and cannot be quietened by
adding a binary to a list, because there is no binary that belongs on one.

    sudo moatctl canary --on          plant a set
    moatctl canary                    what is planted (paths need root)
    sudo moatctl canary --enforce on  refuse the read as well
    sudo moatctl canary --off         remove them

Off by default. Two switches in the panel's Settings tab: **Plant decoy files**
and **Refuse the read as well**.

## Where, and why each

| place | a read there means | mode |
|---|---|---|
| `/etc` ×2 | something searched `/etc` for credentials | 0644 |
| `/root` ×1 | something **already root** searched for credentials | 0600 |
| `$HOME` ×2 per home | something searched your home for credentials | 0600, owned by you |
| `/tmp`, `/var/tmp` ×1 each | something searched the temp directories | 0644 |

The modes are the design, not an oversight.

**`/etc` is world-readable on purpose.** A decoy only root can read cannot catch
the thing worth catching — an unprivileged process enumerating `/etc` for a way
up. A world-readable secrets file in `/etc` is itself the classic local
escalation finding, which is exactly what makes it convincing bait *and* what
makes it reachable before the escalation rather than after.

**`/root` is the mirror image.** 0600, unreadable until something already
succeeded, so a hit there means the escalation has happened.

**`/tmp` is world-readable too, and the first cut got this wrong.** They were
0600 owned by the directory's owner — root — so `cat /tmp/db-dump.sql` was
Permission denied for the person who planted them, and would have been for every
attacker running as a user. A decoy the threat model cannot open is furniture.

## The names differ on every machine

Drawn per machine from a table of plausible shapes — `rsync.secrets`,
`ansible-vault-pass`, `.pgpass`, `.env.production`, `wallet.dat` — and recorded
in `/var/lib/moat/canaries.json`, `0600 root:root`, which is the only place they
exist.

A fixed set would be a fingerprint: read one file, learn the names of all the
others, step around them on every machine that runs this.

That is also why **`moatctl canary` does not show the paths without root**. The
threat model is a package running as you, and you are in the `moat` group — so
is anyone with a shell as you. Serving the list over a group-readable socket
would let them type one command and avoid all seven, which is the whole
detection. The counts, which places are covered, how many have gone missing and
whether reads are refused all stay visible without sudo: "is this working" has
to be answerable without being handed a map. Knowing decoys exist without
knowing where is most of the deterrent.

## Three things it refuses to do

**Never overwrites.** A canary that clobbers a real `/etc/rsync.secrets` would
be moat destroying the machine it protects. A taken name is skipped.

**Never deletes anything without its own marker.** Every decoy starts with a
`moat-canary:` comment, and removal re-reads the file and refuses anything that
is not still ours — so `canary --off` cannot be the command that deletes a real
file somebody put at that path afterwards. That marker is also there so a person
who finds one can tell what it is: files appearing in `/etc` with no package
behind them is the shape of an intrusion, and a decoy that cannot explain itself
gets reported as malware by its own owner.

**Never renders a policy with an empty path list.** `matchArgs` with no values
matches *nothing*, while the policy still loads, still counts toward `policies`,
and still reports armed — a detection whose silence means nothing, wearing the
face of one whose silence means everything. With no decoys planted the template
is skipped entirely and the stale file swept.

## Partial coverage is not success

`--on` plants into five places and any of them can fail: `/root` may not exist,
`/var/tmp` may be read-only, a name may be taken. One unwritable directory is
not a reason to abandon the rest — but it *is* a reason to say so.

The first cut only logged those failures. On 2026-09-10 it planted two files in
`/tmp`, failed five times with `EROFS`, and printed "2 decoy file(s) planted" as
a success: a security feature reporting it was watching `/etc` and `/root` while
watching neither. `--on` now lists every place it could not cover, and
`moatctl canary` names which of etc/root/home/tmp are **NOT COVERED** rather
than printing a count nobody can interpret.

The same applies to decoys that vanish later. A `/tmp` sweep deleting one leaves
the rule loaded, counted and reporting armed with nothing to match, so the
manifest is checked against the disk and `canaries_missing` is reported
separately from `canaries` — the panel turns the count red. Silence from this
rule is supposed to mean nothing went looking; if the file is gone it means
nothing at all, and only that second number tells the two apart.

## Enforcement denies the read, it does not kill

With `--enforce on` the policy is armed and `file_post_open` returns `-EACCES`,
so the open fails and the decoy's contents never reach the caller.

Not `Sigkill`, deliberately — the same trade `cred-ssh-private-key-read`
documents at length. A canary read is close to certain malice, which is an
argument for killing; but the one false positive this rule has is a backup or a
full-disk search, and restic skipping a file and reporting it is a better
outcome than restic killed halfway through a run. Denying costs the attacker the
bytes either way and leaves the process alive to be looked at, which is the
point of having caught it.

The exclusion list is short and every entry reads the whole disk for a living —
restic, borg, rsync, tar, clamscan and friends. They are there because they read
*every* file, not because they have business with these.

## What this does not cover

**Exfiltration after the fact.** The rule fires when a decoy is read on this
machine. If the file is copied off and opened somewhere else next month, nothing
here knows. That is what a Canarytoken-style network callback would add, and it
is deliberately not built: it means a unique per-machine token beaconing to
infrastructure we run, and moat currently sends nothing anywhere.

**A patient attacker.** Someone who reads nothing, or who knows this feature and
checks `sudo moatctl canary` first, walks past all of it. The value is against
automated credential stealers that glob for `.env`, `wallet.dat` and
`.aws/credentials` — which is what the package-hijack threat model actually
looks like.

**Anything outside the planted set.** Five places, seven files. A real secret in
a sixth place is protected by the `cred-*` rules or by nothing.
