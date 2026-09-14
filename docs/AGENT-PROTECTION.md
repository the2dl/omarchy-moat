# Agent protection on Omarchy

Release 0.1.0-178 adds observed agent sessions, workspace-configuration execution
correlation, narrower AI credential detection, and an opt-in isolated tool runner.
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
by the workspace's agent produces `moat-agent-config-executed`:

- **High** when the configuration hash differs from the recorded fingerprint.
- **Medium** on first observation, with an explicit statement that no older
  fingerprint exists to prove modification.

Unchanged repeated executions are deduplicated within the bounded observation
window. Different workspaces stay separate. `node -e` text, shell expressions,
Markdown instructions and arbitrary argument mentions are not interpreted as
proof that a script ran. The detector does not claim to prove prompt injection
or that the configuration caused the execution.

Snapshots are bounded to 128 KiB; state is bounded to 512 files and a ten-minute
window. Reads reject non-regular files, ownership mismatches and aliases into
other paths. Non-script execs trigger at most one scan per workspace per second.
The initial implementation supports literal absolute or `./` script paths with
`.js`, `.mjs`, `.cjs`, `.py`, `.sh` or `.bash` extensions. It does not yet parse
TOML agent settings, expand shell variables, resolve arbitrary package launchers,
or validate a complete skill/plugin manifest. The `[rules] agent_config_exec`
toggle controls this detector independently of write telemetry.

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
choosing another host command. Routing all tools through an authenticated broker,
a trusted grant UI, provider authentication proxying, and remote MCP control
require further integrations. Existing agents are not silently reconfigured.

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
