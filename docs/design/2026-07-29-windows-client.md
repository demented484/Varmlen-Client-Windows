# Varmlen for Windows — design specification

Date: 2026-07-29

Status: proposed for implementation

License: GPL-3.0-only

## 1. Goal

Build a separate Windows 10/11 client that keeps the current Varmlen product
model and subscription compatibility while using Windows-native networking.
The client must provide:

- system-wide IPv4 and IPv6 tunnelling through Xray's native TUN inbound;
- per-application split tunnelling for TCP and UDP;
- a kill switch that stays closed across reconnects and process crashes;
- DNS routing through the tunnel without silently falling back to a physical
  adapter;
- safe location changes without a real-IP exposure window;
- x64 and ARM64 builds without hard-coded host architecture;
- one elevation prompt during install or uninstall, not on every connection;
- an unprivileged GUI that may be closed while the VPN remains connected.

The Windows client lives in its own repository and reuses current Varmlen UI
and subscription behaviour where those parts are platform-independent.

## 2. Explicit non-goals

- No `tun2socks`.
- No local proxy mode.
- No `netsh` scripts as the primary networking implementation.
- No custom kernel driver.
- No reuse of the old `windows-port` branch's data plane.
- No Windows 7/8 support.
- No Microsoft Store package in the first release.
- No claim that an unsigned installer avoids SmartScreen warnings.

The old branch remains useful only as a reference for the existing NSIS and CI
experiments.

## 3. Architecture

The product is split into three Rust components plus the existing Svelte UI:

1. **Varmlen GUI**
   - Tauri application running as the interactive user.
   - Owns subscriptions, editing, UI settings and app selection.
   - Never requests administrator privileges at startup.
   - Sends bounded commands to the service and displays service state.

2. **Varmlen Windows Service**
   - Runs as `LocalSystem`.
   - Owns Xray lifecycle, WFP filters, TUN health, DNS leak prevention, logs and
     recovery.
   - Stores only validated desired network state.
   - Continues operating when the GUI is closed.

3. **Shared protocol crate**
   - Versioned request/response/event types.
   - Length-prefixed JSON or MessagePack frames with strict size limits.
   - No shell-command transport and no user-provided executable command lines.

The GUI and service communicate over a local named pipe. The pipe ACL allows
`SYSTEM`, administrators, and the local user SID registered during install,
and denies anonymous and network access. The service verifies the client's
token and local session before accepting commands. Every mutating request is
validated again by the service.

The GUI executable also has an unprivileged background-update mode registered
with Windows Task Scheduler. It checks which subscriptions are due and exits;
the privileged service never fetches arbitrary user-supplied subscription URLs.

## 4. Native TUN data plane

The service launches the bundled, pinned Xray binary with a native `tun`
inbound. The configuration includes:

- deterministic adapter name owned by Varmlen;
- IPv4 and IPv6 gateways;
- MTU appropriate for the selected configuration;
- `autoSystemRoutingTable` for `0.0.0.0/0` and `::/0`;
- `autoOutboundsInterface: "auto"`;
- DNS addresses assigned to the TUN adapter;
- explicit proxy, direct, blocked and DNS outbound tags.

Xray uses Wintun directly. The installer bundles the Wintun DLL matching the
package architecture. The service discovers its own architecture at build and
runtime; paths and download names must not contain an unconditional `x64`.

Xray and Wintun are installed under an administrator-owned directory. The
service must not execute a binary from a user-writable location.

## 5. Per-application split tunnelling

Excluded applications are routed by Xray process rules to the direct outbound.
Xray on Windows resolves owners from both the system TCP table and the system
UDP table, so UDP games are part of the acceptance criteria rather than an
unsupported special case.

Each selection stores:

- canonical executable path;
- executable basename for display and compatibility fallback;
- stable application identity where Windows provides one;
- source type: Start Menu discovery, running process, or manually selected
  executable.

Paths are normalized before being sent to Xray:

- absolute canonical path;
- slash form expected by Xray;
- consistent Windows case normalization;
- no desktop shortcut path in place of the actual executable.

The first release supports classic Win32 executables. Packaged MSIX/UWP
applications are shown only when their real application identity can be
resolved and enforced; otherwise the UI reports them as unsupported instead of
pretending the exclusion works.

The service verifies the generated routing configuration before replacing the
active one. Split rules survive GUI restarts and are reapplied after service or
machine restart.

## 6. Kill switch and leak prevention

The kill switch uses Windows Filtering Platform from user-mode service code.
No callout driver is required for the intended permit/block policy.

Varmlen owns a dedicated WFP provider and sublayer. Filter changes are applied
inside WFP transactions. The effective policy:

- permits loopback;
- permits Xray to reach physical adapters;
- permits traffic through the active Varmlen Wintun adapter;
- optionally permits local-network destinations;
- blocks other IPv4 and IPv6 traffic on physical adapters while the hold or
  kill-switch policy is active;
- always blocks TCP and UDP port 53 toward physical/LAN DNS resolvers for
  ordinary application traffic.

Persistent filters protect reconnect and unexpected service/Xray failure.
Intentional disconnect removes them only when the user's kill-switch setting
allows an open network. Uninstall removes the provider and all owned filters.
On service startup, stale state is reconciled before ordinary traffic is
allowed.

Failure to install or verify the required WFP policy aborts connection. Varmlen
must fail closed with an explicit error rather than continue with a partially
configured tunnel.

## 7. DNS

The TUN adapter receives explicit DNS servers. Xray routes port 53 to its DNS
outbound and routes encrypted DNS traffic according to the selected
application's proxy/direct policy.

Physical-adapter DNS is not accepted as a fallback while connected. WFP blocks
plain TCP/UDP DNS on physical adapters even when LAN access is enabled.

Endpoint hostnames needed to establish the tunnel are resolved before route
replacement and retained for the connection attempt without changing TLS SNI
or Reality server-name fields. Bootstrap resolution must be explicit and
observable in logs; it must never turn into general system DNS fallback.

The service health check verifies:

- TUN adapter DNS assignment;
- default IPv4 and IPv6 routes;
- absence of an unprotected physical DNS path;
- a DNS query through the intended outbound.

## 8. Safe connect and reconnect

A connect or location change is a transaction:

1. Parse the location and build the candidate Xray configuration.
2. Run Xray configuration validation.
3. Start a temporary non-TUN validation instance and make a bounded proxy
   reachability request through the candidate location.
4. If validation fails, keep the existing connection untouched.
5. Install and verify the WFP hold policy.
6. Stop the old Xray/TUN instance.
7. Start the candidate native-TUN instance.
8. Wait for Xray readiness, Wintun adapter, routes and DNS.
9. Verify a tunneled request and DNS resolution.
10. Replace saved desired state and release only the temporary hold rules.

If startup fails, the service attempts to restore the previous verified
configuration while the hold remains active. If restoration also fails, the
machine stays blocked and the GUI shows a recoverable error. There is no
fail-open path during reconnect.

Rapid connect/disconnect/location-change requests are serialized by one
service-side state machine. Requests carry operation IDs so stale GUI responses
cannot overwrite current state.

## 9. State and recovery

The service state machine is:

`Disconnected -> Validating -> Holding -> Starting -> Connected`

with explicit `Stopping`, `Restoring`, and `BlockedError` states.

The service persists:

- whether the user intentionally requested a connection;
- the last verified configuration hash and configuration material protected by
  machine-scope DPAPI plus a service-only file ACL;
- kill-switch and LAN policy;
- current operation ID.

After reboot, the service restores the last desired connected state before the
GUI starts. If it cannot reconnect, it obeys the saved kill-switch policy and
reports the reason over IPC and the Windows Event Log.

## 10. Configurations, subscriptions and protocols

The Windows client ports the current Varmlen subscription parser, metadata,
editable locations, JSON preservation, update timers and selectable
subscription user agents.

Full Xray JSON locations remain full JSON: the editor shows and saves the
actual formatted configuration, and the service preserves supported routing
and protocol fields instead of flattening it to one `vless://` link.

For imported URI locations, the structured editor exposes only fields relevant
to that protocol. JSON passthrough accepts every outbound supported by the
bundled Xray version. Structured URI import initially guarantees the same
protocol set as the current Android/Linux clients; unsupported forms produce a
clear import error and are never silently downgraded.

Subscription updates overwrite local edits to subscription-owned locations,
matching the current client rule. Auto-update can be disabled. A per-user,
unprivileged scheduled background run performs updates that are due and
notifies the service when the active location changed. Opening the GUI does not
force an update, and the privileged service does not perform subscription HTTP
requests.

The selected subscription UA is stored as a user choice. Architecture and OS
values, where included by a compatibility profile, are generated from the real
Windows target and never hard-coded to x64.

## 11. Pings and health measurements

Location pings are bounded and parallel, never one-location-at-a-time. Results
measure a real request through the candidate outbound when possible, not only a
TCP connect to the server endpoint. A global concurrency limit avoids launching
an unbounded number of Xray processes.

The active connection health check is separate from list pings. Zero,
timed-out, and unavailable measurements have distinct states and are not shown
as a successful `0 ms`.

## 12. Installer, updates and releases

The first package is a per-machine NSIS installer. It:

- requests elevation once;
- installs the GUI, Windows Service, Xray and architecture-matched Wintun;
- creates and starts the service;
- registers clean uninstall and WFP cleanup;
- leaves the GUI unprivileged.

CI builds x64 and ARM64 artifacts from explicit target matrices and validates
that each package contains matching binaries. Releases start as GitHub
pre-releases until connection, reconnect, DNS, UDP split and uninstall tests
pass on real Windows machines.

Code signing is independent of functionality. Without an Authenticode
certificate and reputation, Windows may show SmartScreen warnings; the client
must not claim otherwise.

## 13. Security boundaries

- Only the service may modify WFP, routes, adapter state or launch Xray.
- GUI input is untrusted at the service boundary.
- Configuration files are written atomically with restrictive ACLs.
- Service executable, Xray and Wintun locations are not writable by ordinary
  users.
- Named-pipe messages have version, type, operation ID and maximum length.
- Logs redact subscription URLs, UUIDs, credentials, keys and complete JSON
  configurations.
- Child processes use fixed executable paths and argument arrays, never shell
  interpolation.

## 14. Verification matrix

Automated tests cover:

- URI and JSON parsing parity with current clients;
- architecture-dependent asset selection;
- path normalization and case handling;
- TCP and UDP process-rule generation;
- service state-machine races and rollback;
- malformed/oversized/unauthorized IPC;
- WFP policy compilation and transaction rollback;
- DNS and routing configuration generation;
- package-content checks for x64 and ARM64.

Real Windows acceptance tests cover:

- Windows 10 x64 and Windows 11 x64;
- Windows 11 ARM64 when hardware or a suitable VM is available;
- connect, disconnect and location change;
- Xray crash, service crash and machine reboot;
- physical link change between Ethernet and Wi-Fi;
- DNS leak checks with LAN disabled and enabled;
- IPv4 and IPv6 leak checks;
- excluded browser and UDP game traffic;
- GUI close/reopen while connected;
- installer upgrade and uninstall with no stale WFP filters.

Tests must not be performed on the developer's current protected connection
without explicit permission. Windows integration tests run only in a dedicated
VM or test machine.

## 15. Delivery order

1. Shared protocol and service state machine.
2. Native Xray TUN service lifecycle.
3. WFP hold and kill-switch policy.
4. DNS and transactional reconnect verification.
5. GUI port and IPC integration.
6. Subscriptions/config editors and parallel pings.
7. Per-app discovery and TCP/UDP split.
8. x64/ARM64 installer and CI.
9. Dedicated-machine acceptance testing.
10. First GitHub pre-release.

No milestone is considered complete merely because the UI says "Connected";
service-side route, DNS and traffic health checks must agree.
