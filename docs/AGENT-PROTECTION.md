# Agent protection on Omarchy

Release 0.1.0-179 adds an opt-in Claude tool-broker launcher and quieter,
optionally expanded configuration correlation to the agent-session and
credential protections introduced in 0.1.0-178.
These are local, deterministic features. They work without an AI triage provider.

## Agent sessions

Moat recognizes native agent invocations and explicit Node/Bun entrypoints for
supported agent packages. The sensor's exec identity becomes the session ID.
Children inherit that identity in the process table, including when intermediate
parents exit, the visible ancestry exceeds eight hops, or a child calls setsid.
Separate agents in one terminal remain separate sessions. Nested agents retain
the outer session for attribution.

Alerts and process/network/file telemetry include `agent_session` with the
session ID, root PID, observed executable, agent name and initial working
directory. The evidence panel displays the session and workspace. The workspace
is the root agent's observed initial working directory, not a verified task
boundary or a claim that every file access was authorized there.

Outside package installs, recognized descendants have `agent` context rather
than inheriting an interactive discount from a terminal. Package-install context
still takes precedence. Agent context leaves the rule's base context score
unchanged; existing provenance and locked-rule safeguards continue to apply.

Identity here is **observed lineage**, not signed binary identity or proof of a
human approval. Renaming a program or impersonating an installed entrypoint can
imitate an agent. No filesystem access is granted by this classification.
Processes launched on the agent's behalf by an unrelated system service cannot
be assigned to that session without a future service/tool integration. This feature adds no prompt or chat transcript collection or inference of user
intent. Existing command-line telemetry may contain prompts supplied as CLI
arguments.

## AI credentials

The credential policy no longer exempts every Node/Bun invocation. Tools, MCP
children, another agent's account access, and generic runtimes accessing the
covered credential stores produce credential findings. An observed session root
accessing its own provider's canonical credential path in its own home is
recorded as low-severity authentication context, outside credential-theft
correlation. A child launching another copy of the agent does not inherit that
classification. This behavioral exception is not binary-authenticity validation
and does not establish that a compromised agent is safe.

The existing narrowly scoped Omarchy usage-widget kernel exception remains.
The daemon rule is configured by `[rules] ai_credentials = true`. Disabling the
userland classifier leaves the kernel policy's ordinary credential findings
available; it does not restore the blanket runtime exception.

AI authentication files and executable agent/editor JSON configurations are
withheld from analysis artifacts regardless of their alert family. Configuration
can contain embedded MCP secrets; only fingerprints and relevant script paths
are used by the configuration detector.

## Configuration followed by execution

Moat observes writes from editors as well as other programs. A write-open is a
low-severity signal, not proof that bytes changed. It fingerprints these files
under the observed agent workspace:

- `.claude/settings.json`, `.claude/settings.local.json`, `.claude/hooks.json`
- `.mcp.json`, `.cursor/mcp.json`
- `.vscode/tasks.json`, `.vscode/launch.json`
- `CLAUDE.md`, `AGENTS.md`

For JSON configuration, it extracts literal in-workspace script paths from
`command`, `args` and `program` fields. A subsequent matching script execution
by the workspace's agent produces a high `moat-agent-config-executed` finding
only when the configuration hash differs from the recorded fingerprint. First
observation, daemon restarts, and expired state establish a quiet baseline;
they do not create a finding merely because a project already has a hook.

Unchanged repeated executions are deduplicated. Even if a configuration changes
repeatedly, it produces at most one finding per user/configuration path per ten
minutes while its state is retained. This deliberately trades some repeated
change visibility for a usable review queue. Different workspaces stay separate. `node -e` text, shell expressions,
Markdown instructions and arbitrary argument mentions are not interpreted as
proof that a script ran. The detector does not claim to prove prompt injection
or that the configuration caused the execution.

Snapshots are bounded to 128 KiB; state is bounded to 512 files and a ten-minute
window. Reads reject non-regular files, ownership mismatches and aliases into
other paths. Non-script execs trigger at most one scan per workspace per second.
The initial implementation supports literal absolute or `./` script paths with
`.js`, `.mjs`, `.cjs`, `.py`, `.sh` or `.bash` extensions. It does not yet parse
arbitrary TOML settings, expand shell variables, resolve arbitrary package
launchers, or validate a complete skill/plugin manifest. The `[rules] agent_config_exec`
toggle controls this detector independently of write telemetry.

Additional `.codex/config.toml`, `.gemini/settings.json`, and `opencode.json`
parsing is **off by default**. To try it, set `[rules] agent_config_extended = true`
in `/etc/moat/moat.toml` and restart `moatd`. Set it back to `false` to turn it
off. The existing `agent_config_exec = false` disables all configuration-to-exec
correlation. Extended formats use the same change/execution requirement and
cooldown; they add no kernel policies or write-only notifications. TOML support
extracts literal command/args/program references, not arbitrary shell semantics.
These additional configuration files are withheld from analysis artifacts too.

## Isolated tool execution

Use this for a shell/tool invocation, while the authenticated agent remains in
its existing session:

```sh
moat-agent-tool --workspace /home/dan/Projects/my-app -- \
  /usr/bin/bash --noprofile --norc -c 'git status --short'
```

The runner creates a fresh Bubblewrap filesystem and namespaces. It grants:

- Read access to system binaries/libraries and selected public system config.
- Read/write access to the explicitly named project directory.
- An empty temporary home and temporary directory.
- No network access by default.

It clears the environment, including API keys, loader variables and agent/socket
variables, and closes inherited descriptors. It hides host homes, runtime sockets
and host processes. Mount sources are pinned by file descriptor before launch;
a path swapped for a symlink is rejected. `MOAT_SANDBOX=0` and nesting markers do
not bypass this runner. A Bubblewrap failure fails the invocation; it never
falls back to running the command on the host. The child process namespace dies
with the wrapper. The command's exit status is preserved.

Explicit per-invocation grants:

```sh
# A user-installed toolchain stays read-only.
moat-agent-tool --workspace /home/dan/Projects/my-app \
  --read-only /home/dan/.local/share/mise/installs/node/24.0.0 -- \
  /home/dan/.local/share/mise/installs/node/24.0.0/bin/node ./test.mjs

# Network access is a separate, broad grant, not a destination allowlist.
moat-agent-tool --workspace /home/dan/Projects/my-app --network -- \
  /usr/bin/git fetch
```

`--network` shares the host network namespace, including reachability of local
services/abstract sockets; it does not expose filesystem sockets or credentials.
`--read-only PATH` deliberately exposes that resource, so granting a credential
file discloses it. Grants last for this invocation. Entire-home/root grants and
grants overlapping the writable workspace are refused. `--dry-run` prints the
planned arguments without executing the tool or claiming protection is active.

The **workspace itself is accessible**, including any `.env` or secrets already
stored there. This is not a secret-content filter. The caller controls the chosen
workspace and extra grants; configure those in a trusted launcher/tool adapter.
The runner does not authorize its caller or prevent an unrestricted agent from
choosing another host command. Use the optional launcher below to restrict the
tool interface of a supported Claude session. Provider authentication proxying
and control over remote MCP services are not implemented.

## Optional Claude tool-broker session

Nothing is enabled globally, no shell alias is replaced, and no agent settings
are rewritten. Ordinary `claude` sessions behave as before. Opt in per session:

```sh
moat-agent claude --workspace "$PWD"
# Inspect the launch configuration without starting Claude:
moat-agent claude --workspace "$PWD" --dry-run
```

**To turn it off, exit this session and launch `claude` normally.** There is no
service or persistent toggle to undo. Install the package first: the launcher
refuses to run when itself or Claude lives inside the writable workspace.

The launcher uses Claude's `--restricted`, an empty built-in tool list, and
`--strict-mcp-config` to expose only Moat's local `shell` MCP tool. That tool
reads, edits, searches, and tests through the existing Bubblewrap runner. User,
project and local settings sources, hooks, skills and Chrome integration are
disabled for the session. Claude retains its normal authentication; its tool
children receive an empty environment and isolated home. Account-connected MCP
servers are disabled. A Claude version missing required launch flags causes an
error, never an unrestricted fallback.

The broker's workspace and optional read/network grants are fixed at launch,
pinned by file descriptor for its lifetime, and cannot be changed by a tool
request. Mount identities are checked when Claude starts the broker so a path
replacement between launcher and broker fails closed. Requests and output are
bounded; tools time out after 120 seconds by default (configurable from 1–600).
Timeouts/output overflow terminate the tool process group. Routine tool calls
do not emit new Moat findings just because they are brokered.

```sh
# Explicit grants last for the whole session, not one command:
moat-agent claude --workspace "$PWD" --network --timeout 300
moat-agent claude --workspace "$PWD" --read-only /path/to/toolchain
```

Network access includes local services; workspace secrets remain accessible.
Granting the shell tool permits writes throughout the selected workspace. Git
identity, SSH authentication, tools installed under your home, network-dependent
builds and existing hooks/plugins may need deliberate grants or a normal session.
The launcher accepts a small set of options, not arbitrary Claude flag passthrough.
`--model NAME` and `--print PROMPT` are supported; session resume is not yet exposed.

This is an experimental **tool-interface integration**, not an OS sandbox around
the authenticated Claude frontend. Claude and administrator-managed policy remain
trusted. It does not protect against a compromised frontend, a same-user host
process, frontend vulnerabilities, or a person changing the frontend's tool setup.
Other clients can connect to `moat-agent serve --workspace PATH`, but that alone
does not disable their other tools. Codex/Gemini launch adapters are not shipped.

The integration follows [Claude's CLI controls](https://code.claude.com/docs/en/cli-reference)
and the [MCP stdio transport](https://modelcontextprotocol.io/specification/2025-06-18/basic/transports).

## Automated triage and desktop notifications

Release 0.1.0-181 moves unattended triage into `moat-triage-sandbox`. It exposes
only the selected incident directory read-only, `/var/log/pacman.log`, system
runtime files, the selected native agent installation, and that agent's own
authentication files read-only. Its working directory is the incident directory.
Host home files, other incidents, live project files, `/var/tmp`, and the Moat
control socket are absent. Symlinks in staged evidence cannot grant access to
unmounted host paths. The prompt asks for uncertainty when staged evidence is
insufficient, rather than a recursive search of the machine.

The sandbox keeps network access for provider authentication and requests; it
is not a destination filter. Only the selected provider API-key variable and
proxy settings are passed, alongside a minimal runtime environment. This path
resolves Omarchy mise shims through their installed native `latest` link,
without invoking mise or its maintenance hooks; other script
shims fail closed and leave
alerts pending. Each bundle is probed through the same sandbox before analysis.
The optional `moat-agent claude` launcher remains separate and opt-in.

Desktop alert popups now require the same `needsYou` state used by the Now
queue. Critical severity, containment actions, and noise-guard announcements do
not bypass that requirement. History-only burst summaries no longer emit desktop
popups. Existing notification mute, severity threshold, startup suppression and
cooldown settings still apply. This does not acknowledge or delete alerts.

## Validation and rollout

The package check runs Rust, policy, scanner, existing sandbox, and dedicated
agent-tool tests. The latter exercise real unprivileged Bubblewrap isolation,
environment/descriptor filtering, network namespace separation, read-only grants,
path-swap rejection, and exit-code propagation. Model tests cover the additional
session metadata; old records still parse without it.

After installing, restart Tetragon and Moat so the updated credential/configuration
policies are loaded. These features add no new kernel policies: 52 alerting
policies remain. Existing armed rules retain their configuration. New credential
and configuration detections are monitor-only; this release does not automatically
arm them or rewrite historical alerts.
