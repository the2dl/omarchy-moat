# The kernel sees the interpreter, not the script

This is the one thing that makes moat tuning different from tuning an ordinary
log-based tool, and it is the single most common cause of **tuning that appears
to work and does nothing**.

## The mechanism

A Tetragon tracing policy's `matchBinaries` selector is evaluated **in the
kernel**, against the binary the kernel loaded for that process. When you run:

```
$ /usr/bin/ssh-copy-id -i ~/.ssh/id_ed25519.pub host
```

`ssh-copy-id` starts with `#!/bin/sh`. The kernel does not execute
`ssh-copy-id`. It executes `/bin/sh` and hands it the script as an argument.
So:

```
$ readlink /proc/$PID/exe
/usr/bin/bash          # /bin/sh is bash on Arch
```

`matchBinaries` sees `/usr/bin/bash`. There is no kernel mechanism that can see
`ssh-copy-id`, because from the kernel's point of view it never ran. The same
is true of every `#!` script: python, perl, ruby, node, bash, awk — and of
anything launched through `/usr/bin/env`.

Userspace is different. `moatd` reconstructs the actor: it reads the process's
arguments and its ancestry and resolves `Actor::script` — "an interpreter takes
the provenance of its script". `moatctl explain` prints it. So **userspace can
see the script and the kernel cannot**, and that asymmetry decides which layer
a tuning belongs in.

## Case 1 — the exclusion that was recorded and inert

**2026-09-07.** A read of an SSH key by `ssh-copy-id` was being refused by an
armed rule. The panel offered "allow /usr/bin/ssh-copy-id". moatd accepted it,
wrote a kernel `matchBinaries` exclusion, re-rendered every policy, deleted
and re-added the tracing policy, re-armed it to `enforce`, and verified the
load.

**Nothing changed.** `ssh-copy-id` is `#!/bin/sh`, so the exclusion named a
binary the kernel would never match. The read went on being refused. Worse: the
*alert* stopped, because moatd suppressed it as a selector contradiction — so
the user was told the program was allowed, kept the denial, and lost the one
record that would have explained it.

An exclusion that is recorded and inert is worse than one that is refused.
`moatd::engine::exclude_binary` now **refuses** this outright and explains why;
see `util::interpreter_of`.

The correct answers were: turn the rule to monitor for as long as the work
takes, or use a route that does not touch what the rule guards. Excluding
`/bin/sh` would have let every shell script on the machine past that rule.

## Case 2 — the allowlist entry that would have said the wrong thing

**2026-09-07.** `gcloud iam service-accounts list` reads its own
`~/.config/gcloud/credentials.db` and then calls Google. Credential read
followed by egress is the exfiltration shape exactly, so the chain went `high`
and moatd **contained** it mid-command.

There was no way to allow it. `gcloud` is a python script, so the alert's `exe`
was `/usr/bin/python3.14`, and an allowlist entry naming that would have let
**any python program on the machine** read the user's cloud credentials. The
kernel could not help either, for the reason above.

moatd already knew the truth — the alert printed *"an interpreter takes the
provenance of its script, /opt/google-cloud-cli/lib/gcloud.py"* and
`Actor::script` carried it. The allowlist simply had no matcher for it.

The fix was a new `script` matcher on allowlist rules. Now the entry says the
true thing:

```toml
# added 2026-09-07: gcloud reading gcloud's own credential store
[[rule]]
name   = "moat-cred-cloud-credential-read"
script = "/opt/google-cloud-cli/lib/gcloud.py"
```

*gcloud* reading *gcloud's own store* — rather than blessing an interpreter.

A rule that names `script` **cannot match an event that was not an interpreter
running one**. That is what stops it widening back out into "any python".

## The rule of thumb

Before you name a binary in any proposal:

```
head -c2 /path/to/the/binary     # "#!" means it is a script
file /path/to/the/binary
```

- **ELF** → it is what the kernel loads. `exe` and `matchBinaries` both work.
- **`#!` script** → the kernel sees the interpreter. Use `--script` in a
  userspace allowlist entry. A kernel exclusion is impossible and moatd will
  refuse it.
- **the binary IS an interpreter** (`bash`, `sh`, `python3.14`, `node`,
  `perl`, `ruby`, `env`, `java`, …) → naming it alone is a grant to everything
  it runs. Add `--script`. `moatctl allow` refuses `--exe <interpreter>` with
  no `--script`.

## How to say this to a user

Not "matchBinaries operates on the loaded binary". Say:

> `ssh-copy-id` is a shell script, so as far as the kernel is concerned the
> program that ran is `/bin/sh`. Telling the kernel to stop watching
> `ssh-copy-id` would be recorded and would do nothing, and telling it to stop
> watching `/bin/sh` would let every shell script on your machine past this
> rule. Here is what does work instead: …
