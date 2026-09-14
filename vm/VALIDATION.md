# Prototype validation — 2026-09-14

Test host: Omarchy x86_64, KVM, QEMU 11.1.1. Disposable Ubuntu 24.04 guest;
Node 22.23.2, npm 10.9.8, Claude Code 2.1.270, Codex CLI 0.154.0.

Passed:

- 11 automated tests covering snapshot exclusions/link handling, Git ignore
  behavior, hostile export rejection, non-executable review output, network
  destination validation and VM launch boundaries.
- Clean cloud-init boot using a virtio setup disk and pinned SSH host key.
- Public HTTP/HTTPS downloads through the proxy; Node archive checksum verified
  inside the guest. Both agent binaries installed and returned their versions.
- Host-positive-control TCP listener accepted a host connection but could not
  be reached from the guest. Proxy rejected loopback, private and metadata IPs.
  Direct guest TCP and a direct DNS probe also failed.
- Project code execution, a local MCP JSON-RPC tool call, and a skill script
  all worked inside the guest. Claude's `mcp list` discovered the project server
  and reported its normal pending-approval state.
- Export created a separate review copy and change report. Host source files
  and the fake `.env` were unchanged; the fake `.env` was not imported.
- Fresh offline guest boot and absent proxy forwarding.
- Stop/resume preserved files and installed agents. Final stop reported inactive
  with an empty control group. Failed/offline disposable test VMs were removed;
  the prepared demo was left stopped.

The first implementation exposed real compatibility/lifecycle failures: an IDE
setup disk not seen by this minimal guest, Snap seeding waiting for network,
libslirp's `setsid()` blocked by QEMU's privilege-syscall filter, orphaned processes
under a direct launcher, and a rapid disk-lock release race. Final code uses a
virtio setup disk, disables guest Snap seeding, enforces no-new-privileges outside
QEMU, manages the whole process group through a transient user service, and retries
only the bounded disk-lock startup failure. Public proxying and stop/resume were
retested after these fixes.

Ubuntu's packaged npm dependency tree also made the initial tool setup slow.
Final bootstrap uses no recommended apt packages and the verified Node binary
distribution instead. That Node setup was exercised in the guest; a new clean
online setup with the smaller combined bootstrap has not been timed.

Not validated: authenticated model calls, real-world skill/MCP compatibility,
GUI/editor integration, browser callback login, guest Tetragon monitoring, a
malicious-kernel/VMM escape attempt, or a complete proxy security audit. These
results demonstrate the prototype's observed boundaries, not immunity to prompt
injection or a guarantee of containment against every attack.
