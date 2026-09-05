# Log shipping and telemetry classes

`moat-ship` gets the record off the machine. `[telemetry]` decides what record
there is to get.

Everything here is off by default and every number below was **measured on a
real workstation** (Omarchy, kernel 7.1, Tetragon 1.7.1, 2026-09-04) rather
than estimated. Section 4 says how.

---

## 1. Why the shipper is a separate binary

`moatd` runs as **root** with the kernel sensor attached to it. Putting an
outbound HTTPS client there would mean a TLS stack, a retry loop and a response
parser inside the one process that owns detection — and it would hand a remote
endpoint a way to make that process block.

`alerts.jsonl` is `0640 root:moat`. A shipper therefore needs **no privilege at
all**: it needs to be in a group. So `moat-ship` is its own binary, its own
unit, its own unprivileged user, with an empty capability set — the same
argument that already put `moat-feeds` (the other direction of network I/O) in
its own binary on a timer.

| | moatd | moat-ship |
|---|---|---|
| user | root | `moat-ship`, supplementary group `moat` |
| capabilities | 6 (kill, ptrace, dac_read_search, …) | **none** |
| writes | alerts, telemetry, quarantine, policies | one cursor file |
| network | none (`RestrictAddressFamilies=AF_UNIX`) | AF_INET/AF_INET6/AF_UNIX |
| knows the other exists | no | reads two files it does not own |

`moat-ship` never reads `/var/log/moat/tetragon.log`. That file is
`0600 root:root` and full of unfiltered kernel events; a privilege-free shipper
must not need it and must not be given it. Everything it ships comes from
`alerts.jsonl` and `telemetry.jsonl`, both of which moatd wrote deliberately.

---

## 2. The four telemetry classes

Configured in `[telemetry]` of `/etc/moat/moat.toml`. Recorded into
`/var/lib/moat/telemetry.jsonl` (`0640 root:moat`, rotates at 16 MiB), except
`alerts`, which *is* `alerts.jsonl`.

| class | default | source | measured volume on this box |
|---|---|---|---|
| `alerts` | **on** | `alerts.jsonl` | a handful a day |
| `process` | off | exec/exit (already exported) | 42 ev/s → **0.99 GB/day** projected |
| `network` | off | `moat-telemetry-network-connect` | 0.26 conn/s → **6.8 MB/day** |
| `file` | off | `moat-telemetry-file-*` | 0.32 ev/s scoped → **9.7 MB/day** |

### `alerts`

What moat already produces. Low volume, high value, and the only class on by
default. Full records including the `explain` block, plus `update` lines (an
ack, an action result) and install receipts.

### `process`

**Already exported whatever you set here.** exec and exit cannot be filtered
in-kernel (TETRAGON-NOTES §10), so Tetragon writes them to `tetragon.log`
either way — which is why that file rotates every 6–7 minutes and why a week of
process history has never existed on this machine. This switch decides whether
moatd *also* writes a compact projection that can be shipped and queried.

The raw export duplicates the **entire parent block inline on every child**,
which is about half of each record. Shipping `parent_exec_id` and reconstructing
the tree at the collector is the same graph for a fraction of the bytes:

| | bytes/record | at 42 ev/s |
|---|---|---|
| raw Tetragon exec event | 3105 | 11.3 GB/day |
| projected, `inline_parent = true` | 509 | 1.9 GB/day |
| **projected, default** (`parent_exec_id`) | **390** exec / **153** exit | **0.99 GB/day** |

An 11× reduction, and the join is a single lookup on a field the collector is
already indexing. Set `inline_parent = true` only for a collector that cannot
join.

Still the most expensive class by two orders of magnitude. Turn it on when you
have somewhere to put a gigabyte a day per host and a reason to want it.

### `network`

Every outbound connect to a public address, with the process that made it and
its ancestry. Private, loopback, link-local and IPv6 ULA destinations are
excluded **in the kernel**, so they are never written anywhere.

Measured at **0.26 connects/s** against exec's 42/s — 160× cheaper — which is
what makes a deliberately broad policy affordable here where it is not for
files. This is the class that answers "what did this machine talk to on Tuesday
afternoon", which the alert stream by construction cannot.

### `file`

The expensive one, and the one that had to be designed rather than switched on.
See section 3.

---

## 3. The `file` class: keyed on the file, not on the operation

A general "log every file write" class is the volume trap. Measured under
`$HOME` during an `npm install` of 171 packages:

```
every write under $HOME ........................ 42.3 events/s   (4359 in 103 s)
 ↓  kernel filter: script suffix OR high-value location, + MAY_WRITE
kernel-filtered ................................ 19.2 events/s   (45.4 %)
 ↓  userspace: the create/modify ladder
recorded ........................................ 0.32 events/s   (0.8 %)
```

Two things to take from that. Unscoped file telemetry costs **as much as the
entire process class** — it is not a cheap extra. And the kernel filter *alone*
is not enough: 19 events/s is still 45% of the flood, because an npm install is
mostly `.js` files.

What makes it affordable is that the class is keyed on **what the file could
become**, and then on **whether it already existed**:

| | recorded? | why |
|---|---|---|
| create of an executable-shaped file | yes | something new can now run |
| **modify of one that already existed** | **yes, and worth more** | see below |
| create inside a build/cache tree | no | `quiet_creates_under` |
| `chmod +x` on anything | yes | the moment it became a program |
| anything else | never reaches userspace | not in the kernel filter |

**The modify case is the point.** On 2026-09-04 a simulated npm package on this
machine took a command over a WebSocket and rewrote its own
`node_modules/express/index.js`, so the payload would survive every future
`require()`. Moat raised nothing at all. An *installed* script being rewritten
after install is close to unambiguous, and no amount of "log every write" makes
it findable — during the install that same path is written 1300 times over.

`quiet_creates_under` therefore drops **creates** under `node_modules/`,
`target/`, `.cache/`, `.git/`, `site-packages/` and friends, and is **never**
applied to a modify. Suppressing the modify would delete the one finding that
made the class worth having.

### How the two stages are split

| decision | where | why there |
|---|---|---|
| suffix is `.sh`/`.js`/… | kernel, `Postfix` | before a byte is written to disk |
| path is under `/usr/bin/`, a unit dir, … | kernel, `Prefix` | same |
| opened for writing (`MAY_WRITE`) | kernel, `Mask 2` | same |
| an execute bit was set | kernel, `path_chmod` `Mask 64/8/1` | one event, not one per write |
| create or modify? | userspace, `statx` birth time | the kernel's open hook cannot report `O_CREAT` in a form a selector or the export can carry |
| is it really an ELF? | userspace, magic bytes | a selector cannot read file contents |
| inside a package install? | userspace, `pkgtree` | ancestry beyond parent (NOTES gap 1) |
| in a build tree? | userspace substring | `NotPrefix` on the same argument index as an existing `Prefix` is UNVERIFIED at runtime (NOTES §2), and `check.py` refuses it |

Filtering in the kernel where it is possible is not just about the collector's
disk: it saves the export write **and** moatd's parse for every event it drops.

### Content capture

`capture_body = false` by default. It is the **only** switch in moat that puts
file *contents* anywhere they can leave the machine.

It is worth having — the body of a freshly written 200-byte dropper is the
evidence — and when on it inherits `evidence::is_secret_path` wholesale: the
same function that stops a credential being staged for an AI. A path that looks
like key material is never read, whatever the config says. Text only (an ELF is
described by size and sha256, never carried), capped at
`capture_body_max_bytes` (default 64 KiB, refused above 1 MiB).

### What the class does not cover

`chmod +x` excludes `pacman`, `tar`, `install`, `fakeroot`, `rsync`, `cp` and
`unzip` in the kernel, which is what keeps it free during a package
transaction. A `chmod +x` performed *by* one of those binaries is invisible to
this class. That is a deliberate trade: those are the bulk chmod-ers by orders
of magnitude, and a package install that also drops something interesting is
still covered by the exec-shape policy beside it and by the `pkg_subtree_*`
rules in moatd.

---

## 4. How the numbers were measured

No estimates. On this machine, 2026-09-04:

| number | method |
|---|---|
| 127 KB/s export, 50 MB per 6–7 min | `stat` on `/var/log/moat/tetragon.log` every 5 s for 300 s, summing across rotations: 39,132,167 bytes in 300 s |
| 42 exec+exit events/s | `/proc` sampled at 2 ms for 300 s: 5565 new pids = 18.55 spawns/s (a **lower bound**; shorter-lived processes are missed) × 2 events each. Cross-checks against 130,440 ÷ 3105 B/event |
| 3105 bytes per raw exec event | measured byte rate ÷ measured event rate |
| 390 / 153 / 509 bytes projected | `serde_json::to_string` of the real projection over a real exec event |
| 0.26 connects/s | `/proc/net/tcp{,6}` sampled at 10 ms for 300 s, non-loopback remotes only: 78 new sockets (a lower bound) |
| 42.3 file writes/s, 4359 in 103 s | `inotifywait -r -e close_write -e create -e moved_to` over `$HOME` while `npm install` pulled 171 packages |
| 19.2/s kernel-filtered, 0.32/s recorded | the same sample, scored against the exact suffix / prefix / quiet-create lists this ships with |
| birth times survive an npm install | `stat -c %W` over 400 freshly installed `node_modules/*.js`: 100% carry the install's own btime, `links=1` — npm copies rather than hard-linking from `~/.npm/_cacache`, so the create/modify split is not fooled by the cache |

Reproduce them: the measurement scripts are three inotify/`/proc` samplers, and
`moatctl status` reports `telemetry.written` and `telemetry.filtered` live once
a class is on.

**These are one machine's numbers.** A CI box or a Kubernetes node will look
completely different. The shape of the argument — that unscoped file telemetry
costs as much as the whole process stream, and that a two-stage filter cuts it
130× — should hold anywhere.

---

## 5. Shipping

### Transports

**HTTPS** (`transport = "https"`). NDJSON batches with caller-supplied headers,
which is how Splunk HEC, Elastic, Loki and Datadog all authenticate.

```toml
[https]
url = "https://splunk.example:8088/services/collector/raw"
token_file = "/etc/moat/ship.token"       # 0600, required
[https.headers]
Authorization = "Splunk ${token}"
```

`${token}` is substituted at send time only. The header **template** is what
lives in the config, gets printed by `moat-ship check` and can be pasted into a
bug report; the token never appears in either.

**Syslog** (`transport = "syslog"`). RFC5424 to `/dev/log` (unix datagram, with
a stream fallback) or `tcp://host:port` (RFC6587 octet counting).

> **Syslog ships a summary, not the record, and that is deliberate.**
>
> A moat alert carries full ancestry and an `explain` block with evidence,
> expected cases and next steps — several kilobytes. RFC5424 guarantees 480
> bytes and most receivers stop near 2048. Sending the whole record over syslog
> would not deliver a moat alert; it would deliver the first third of one,
> silently, with the part that makes it actionable cut off mid-word.
>
> So the syslog transport projects each record to who / what / where / how bad /
> **the alert id**, and if a line still does not fit it is cut with a visible
> `…[truncated]` marker rather than just stopping:
>
> ```
> <107>1 2026-09-04T19:32:45.321Z mars moat 1592301 alert - id=01J8ZK6B4Q3M7N9P2R5S8T1V4W \
>   severity=high rule=moat-cred-ssh-private-key-read family=cred pid=41233 \
>   exe="~/.local/share/mise/installs/node/26.5.0/bin/node" file="~/.ssh/<redacted>" \
>   action=none title="Private SSH key read by an unexpected program"
> ```
>
> 306 bytes against the record's 1.4 KB. The id is there so the whole thing is
> one `moatctl explain <id>` away. **If you want the full record, use HTTPS.**

### Delivery

At-least-once with receiver-side dedupe. Every record carries an `event_id`:

* a full alert → the alert's own **ULID** (`01J8ZK6B4Q3M7N9P2R5S8T1V4W`);
* everything else → `<id>.<12 hex of sha256(line)>`, so a re-send is
  byte-identical and idempotent.

The cursor (`/var/lib/moat/ship/cursor.json`) advances **only** past records the
collector has acknowledged, so:

* a restart mid-outage re-sends at worst one batch and skips nothing;
* a rotation between polls finishes the old file before starting the new one;
* a truncation restarts from 0 rather than reading garbage from mid-record;
* a half-written line waits for its newline.

The last few hundred acknowledged ids are kept in the cursor as a backstop for
the case a byte offset cannot cover.

### When the collector is down

Bounded buffer, **drop-oldest**, counted:

```
[buffer]
max_records = 20000
max_bytes = 33554432        # 32 MiB
retry_min_secs = 5
retry_max_secs = 300
```

Backoff is exponential with jitter (5s → 11s → 22s → … → 300s, so a fleet does
not return in lockstep). Dropping the *oldest* rather than the newest is
deliberate: the newest records describe what is happening right now, which is
exactly what an outage during an incident would otherwise cost you. Every drop
is counted and reported in the heartbeat and in `moat-ship status`.

A permanent rejection (an HTTP 4xx that is not 408/429) drops that batch rather
than retrying it forever — one malformed batch must not wedge the stream behind
it — and is logged and counted as a loss.

`MemoryMax=256M` in the unit is the belt to that braces.

### The heartbeat

```json
{"kind":"heartbeat","shipped":412,"dropped":0,"withheld":1,"backlog":0,
 "backlog_bytes":0,"classes":["alerts"],"last_ok":"...","last_error":""}
```

Emitted every `heartbeat_secs` (default 300) **whether or not anything
happened**, and refused as a configuration if set to 0 while enabled.

**Alert on its absence at your collector.** A shipper that has died is
indistinguishable from a machine with nothing to say — which is the same
failure mode as the blind sensor of 2026-09-03, where systemd, the gRPC socket
and the export log's mtime all read "running" for 25 minutes with zero policies
loaded. "Moat is watching this host" should be a fact you can query, not a hope.

---

## 6. Security

Four things `moat-ship` will not do. None of them is configurable.

### It never ships staged evidence

`/var/lib/moat/incidents/<id>/…`, anything ending `.suspect`, and
`/var/lib/moat/quarantine/…` are the **accused artefacts** — a copy of whatever
the alert was about, which may be the user's credentials. `evidence.rs` already
refuses to hand those to an AI API; the same rule holds for a remote endpoint.

The check is on **path shape**, not on which field the path appeared in, so a
record shape invented later cannot route around it. A hit is replaced with
`<withheld: staged evidence>`, counted, and reported in the heartbeat as
`withheld` — a non-zero number means some record is trying to carry evidence
and someone should look at why.

### Redaction is on by default

* `$HOME` → `~`, for every human home in `/etc/passwd`. The username is the one
  identifier in a moat record that is about the *person* rather than the
  machine, and it appears in paths, arguments, `cwd` and prose alike.
* A path matching `is_secret_path` loses its last component:
  `~/.ssh/id_ed25519` → `~/.ssh/<redacted>`. You keep "something read a private
  key out of `~/.ssh`", which is the whole content of the alert, and lose which
  key.

Both apply **inside sentences**, not only to whole-path fields — an alert's
`summary` and every line of its `evidence` are prose with paths in them, and
redacting one and not the other would be theatre. Turn `secret_paths` off if
your collector is where you do that triage.

### The token never leaks

Resolved once, at startup, into exactly two places: the transport's header map
and the scrubber's deny list. It is
**not** in the config struct that `status` serialises, **not** in `--dry-run`
output, **not** in the cursor file, and every error string and response body
goes through the scrubber before anything is logged — so a collector that
echoes the `Authorization` header back in a 401 body cannot put it in the
journal.

`token_file` must be `0600` or `moat-ship` refuses to start. An inline `token`
requires `ship.toml` itself to be `0600`. These are refusals, not warnings: a
world-readable collector key is a credential leak on the box the product exists
to protect.

### TLS verification is always on

There is no flag for it and there will not be one. A security product with a
MITM switch is not one — and a test asserts that no key named `insecure`,
`skip_verify`, `danger` or `self_signed` exists anywhere in `ship.toml`.

`http://` is accepted **only** for a loopback host (`127.0.0.0/8`, `::1`,
`localhost`), where there is no network segment for anyone to sit in the middle
of and a local vector/fluent-bit/rsyslog sidecar is the normal deployment shape.
Plain HTTP to anything else is refused with the reason.

---

## 7. Switching a telemetry profile

> **A Tetragon restart is the dangerous operation in this project.** On
> 2026-09-03 a bad policy load left the sensor dead for 25 minutes while every
> surface still read "running": systemd said active, the gRPC socket file
> existed (it outlives the process), and the export log kept getting fresh
> writes (every Tetragon start re-walks `/proc`). Turning `network` or `file`
> on or off is exactly that operation.

Use the command. It does the four things doing it by hand skips:

```console
$ sudoedit /etc/moat/moat.toml        # the [telemetry] block
$ sudo moatd telemetry --apply
```

1. **Validate the config.** An unscoped `file` class — `file = true` with empty
   `file_scope` *and* `file_suffixes` — is refused rather than rendered wide
   open, along with over-long `Prefix`/`Postfix` values and scope entries with
   no trailing slash.
2. **Render, then re-run `policies/check.py` over what was written.** Installed
   at `/usr/lib/moat/check.py` for exactly this. If it fails, **the sensor is
   not restarted** and nothing has changed in the kernel.
3. **Restart tetragon, then moatd, in that order.** moatd is `PartOf=`
   tetragon.service and tails the log tetragon writes; the other order leaves it
   waiting on a file nothing is writing.
4. **Verify, rather than assume.** Poll `/sys/fs/bpf/tetragon` until the number
   of *pinned* policies matches what was rendered. That asks the kernel, which
   is the only source that goes to zero the instant the sensor dies. If it does
   not come back inside `--verify-timeout` (60s), the command exits non-zero
   and says so loudly, with the rollback instruction.

`moatd telemetry` with no `--apply` reports and changes nothing.
`--no-restart` renders and validates but tells you plainly that the kernel has
not changed — Tetragon reads `tracing-policy-dir` once at startup and has no
hot-reload.

`process` and `alerts` need no policy and no restart: `systemctl reload moatd`
(SIGHUP) is enough, and a class switched off there stops being written
immediately.

### Rolling back

Put the previous `[telemetry]` block back in `/etc/moat/moat.toml` and run
`sudo moatd telemetry --apply` again. A class that is off is not rendered, so
its policy file is *removed* from `/run/moat/policies` and its name drops out
of the export allowlist — switching a class off really does stop the collection,
rather than leaving a loaded policy being filtered in userspace.

---

## 8. Commands

```console
$ moatd telemetry                     # what is recorded, and what it costs
$ sudo moatd telemetry --apply        # validate, render, check, restart, VERIFY

$ moat-ship check                     # validate ship.toml; sends nothing
$ moat-ship once --dry-run            # print exactly what a collector would get
$ moat-ship once                      # one pass and exit (for a timer)
$ moat-ship status [--json]           # shipped / dropped / withheld / cursor
$ sudo systemctl enable --now moat-ship
```

`--dry-run` does not advance the cursor, so it previews the backlog instead of
consuming it, and can be run twice.

`moatctl status` gains a `telemetry` block — which classes are on, how many
records have been written, how many the ladder filtered — beside
`sensor_unhealthy`. A reader that sees a healthy sensor and
`telemetry.classes: ["alerts"]` knows exactly how much of this machine's
history exists, which is the honest answer to "can I go back and look".

---

## 9. What is unsafe to ship by default

Recorded here because the answer to "should this be on?" is not always no, and
the reasons matter more than the defaults.

1. **`capture_body`.** The only switch that puts file contents on the wire. It
   refuses credential paths, refuses non-text, and caps at 64 KiB — but a
   developer's `~/.local/bin/deploy.sh` may contain an inline secret that
   `is_secret_path` cannot see, because the *path* looks ordinary. Off, and it
   should stay off unless the collector is trusted with source code.

2. **`process` at 1 GB/day/host.** Not unsafe, but not a default either. On a
   fleet this is a budget decision someone has to have made on purpose, and a
   shipper silently sending a gigabyte a day from a laptop on a hotel wifi is a
   bad surprise.

3. **`redact.secret_paths = false`.** Reasonable if the collector is where you
   triage, and the wrong default: the leaf of a credential path is the one part
   of a moat record with no analytic value and real disclosure risk. Which key
   was read is almost never the question; that a key was read always is.

4. **Shipping `file` bodies plus `process` args together.** Command lines
   routinely carry tokens (`curl -H "Authorization: ..."`, `psql "postgres://
   user:pass@..."`). moat does not currently scrub secrets out of `args`, only
   out of paths. If your collector is less trusted than this machine, use
   `redact.extra` to add literal strings, and treat `args` as sensitive.

5. **Enabling `moat-ship` without alerting on the heartbeat.** The most likely
   way this whole feature fails in practice: it works for a month, the token
   expires, the shipper backs off forever, and nobody notices because no alerts
   are the normal case. The heartbeat exists precisely so that absence is
   detectable. Configure that alert before you trust the pipeline.

6. **Trusting `sensors_loaded` from a non-root reader.** `moatd telemetry
   --apply` run without root cannot read `/sys/fs/bpf/tetragon` and reports
   "could not verify" as a failure rather than a success. That distinction —
   "cannot tell" is not "all good" — is the whole lesson of 2026-09-03 and it
   is worth keeping in mind wherever else this data is consumed.
