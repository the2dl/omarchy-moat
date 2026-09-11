<p align="center">
  <img src="assets/svg/mark-accent.svg" alt="" width="76">
</p>

<h1 align="center">Moat</h1>

<p align="center">
  <b>A supply-chain sensor for an Omarchy workstation.</b><br>
  <sub>Tetragon in the kernel · a Rust daemon for correlation · shims and scanners at install time · a shell panel</sub>
</p>

<p align="center">
  <a href="https://the2dl.github.io/omarchy-moat/"><b>Handbook</b></a> ·
  <a href="docs/CLI.md">CLI reference</a> ·
  <a href="docs/CONTRACT.md">Interface spec</a>
</p>

---

## What it watches for

A hijacked package — an npm postinstall, a PyPI wheel, an AUR `PKGBUILD`, an
editor extension — running as you, with your permissions, reading credentials
out of `$HOME` and arranging to run again after a reboot. It does not need an
exploit; you invited it.

Root compromise is out of scope for enforcement, and detected best-effort. This
is not a rootkit hunter and not a server EDR.

It can also plant **decoy files** — fake credentials in `/etc`, `/root`, your
home and the temp directories, with different names on every machine. Nothing
on the system has a reason to open one, so unlike every other rule here that
one needs no allowlist and no tuning: a read is the alert. Off by default; see
[docs/CANARIES.md](docs/CANARIES.md).

Local privilege escalation is watched at the four points that matter on this
kind of machine — `/proc/sys` writes, capabilities gained at runtime, uid
transitions, and root-executed config nobody else watches. The audit behind
those, including what is still not covered, is
[docs/LPE.md](docs/LPE.md).

## How it behaves

**It ships watching, not blocking.** Monitor mode, containment off, killing off.
A wrong guess on day one should be noisy, not expensive.

**It judges sequences, not steps.** A binary running from `/tmp` is ordinary
during a build. The same binary, inside a package install, reaching a host this
machine has never used, is not. Correlation is what turns primitives into a
question worth asking.

**It does not learn trust from repetition.** A pattern is auto-learned only when
it recurs *and* comes from a signed repository — because repetition is precisely
what an attacker can manufacture. Everything else waits for a human decision.

**Reading never needs root; weakening protection always does.** Evidence behind
a password prompt does not get read, and prompting for trivia is how the prompt
that matters gets waved through.

## Install

```sh
git clone https://github.com/the2dl/omarchy-moat && cd omarchy-moat
./install.sh          # --check for preflight only
```

The preflight is the point: it verifies BTF, and that **BPF LSM is enabled** —
without it every deny policy loads, reports `enforce`, and refuses nothing.

After installing, `moatctl status` should show the rendered policy count and the
kernel's pinned count *matching*. A gap between them is a silent sensor outage.

## Layout

```
manifest.json   omarchy-shell plugin manifest (io.github.the2dl.moat)
shell/          QML: service, bar widget, panel
moatd/          Rust: moatd, moatctl, moat-feeds, moat-ship
policies/       Tetragon TracingPolicy YAML — the detection rules
sandbox/        bubblewrap wrapper + PATH shims for npm/pip/cargo/go/makepkg
scanner/        pre-execution scanners: PKGBUILD/.install, npm, cargo, pip, go
assets/         the mark, in SVG and PNG
docs/           CONTRACT.md is the spec every component builds against
```

`docs/CONTRACT.md` before touching anything. `docs/BASELINE.md` for the learning
and noise model, `docs/TETRAGON-NOTES.md` for what the sensor actually reports.
`docs/LPE.md` and `docs/CANARIES.md` cover the two newest detection surfaces,
and `docs/PACKAGE-FEED.md` the malicious-package index the scanners read.

## Turning it on

Each step is reversible, root-gated, and recorded.

1. **Watch for a few days.** The first day is the loudest — nothing has been
   learned yet. Most of it settles without you.
2. **`moatctl set contain on`** — a narrow network cut for a sequence Moat is
   sure about: one binary, one address, ten minutes, auto-released.
3. **Arm one rule at a time** — `moatctl set mode enforce --rule <name>`, for a
   rule whose false-positive surface you have measured.
4. **Only then consider `set kill kill`**, after a week of `moatctl decisions`
   in which you agree with every line.

---

<sub>Sensor is upstream Tetragon, never forked. Licence: see LICENSE.</sub>
