# Windows Runtime Design

Date: 2026-07-30

Status: approved by the request to complete the Windows client in one pass

## Goal

Turn the existing Windows foundation into an installable native-TUN client.
The privileged service must own Xray, WFP policy, DNS protection, reconnect
rollback and persisted desired state. The GUI remains unprivileged and talks
to the service through the existing authenticated named pipe.

## Approaches considered

1. **Xray native TUN plus direct WFP management (selected).** Xray creates the
   architecture-matched Wintun adapter, addresses it, installs IPv4/IPv6
   routes and assigns DNS. The service installs WFP filters in transactions.
   This preserves Xray process routing for TCP and UDP while providing a kill
   switch that survives Xray crashes and reconnects.
2. **WinDivert or a custom callout driver.** This gives deeper packet control
   but adds another signed driver and a much larger privileged attack surface.
   It is unnecessary for a permit/block kill switch.
3. **Windows Firewall or `netsh` orchestration.** This is simpler but does not
   provide one atomic policy transaction with stable ownership and rollback.
   It also violates the already-approved native implementation boundary.

## Runtime layout

The per-machine NSIS installer places these files in the administrator-owned
installation directory:

- `Varmlen.exe`
- `varmlen-service.exe`
- `xray.exe`
- `wintun.dll`
- `geoip.dat`
- `geosite.dat`

The service resolves every runtime path relative to its own executable. It
does not execute binaries from user-writable locations. Mutable state and
redacted logs live under `%ProgramData%\Varmlen`, whose ACL grants full access
only to `SYSTEM` and administrators.

## Xray lifecycle

The GUI sends a native-TUN config, a loopback-SOCKS validation config, resolved
server endpoints, split selectors and policy flags. The service validates both
JSON documents and enforces these native-TUN settings:

- name and description `Varmlen`;
- gateway `10.255.0.1/30` and `fd00:7661:726d:6c65::1/64`;
- DNS `1.1.1.1`;
- automatic routes `0.0.0.0/0` and `::/0`;
- `autoOutboundsInterface: "auto"`.

Before touching an active tunnel, the service runs `xray run -test` and starts
the validation config long enough to complete a bounded SOCKS5 connection.
The native candidate is started with no console window and `kill_on_drop`.
Readiness requires a live process and the Varmlen adapter with IPv4, IPv6 and
DNS. After connected WFP policy is committed, a bounded TCP request and system
DNS resolution must pass through the TUN path.

## WFP policy

Varmlen owns fixed provider, sublayer and filter GUIDs. Provider, sublayer and
filters are persistent. Every replacement is one WFP transaction.

The hold policy:

- permits loopback;
- permits `xray.exe` except plaintext DNS on a non-TUN path;
- blocks all remaining outbound IPv4 and IPv6 traffic.

The connected policy:

- keeps the loopback and Xray permits;
- always blocks TCP and UDP destination port 53 outside the Varmlen adapter;
- optionally permits private/LAN destinations;
- blocks ordinary traffic whenever its selected local interface is not the
  Varmlen adapter.

Filter weights make loopback the highest permit, DNS block higher than the
Xray permit, and the default block lowest. Reconnect replaces connected policy
with hold policy before stopping Xray. Failure leaves the hold in place.
Explicit disconnect removes all filters only when `keep_blocked` is false.
Uninstall invokes service cleanup before deleting the service binary.

## State and recovery

The last verified connect request is serialized and protected with
machine-scope DPAPI. It is written atomically only after route and DNS health
checks pass. On service startup, saved desired state is restored before the
named pipe starts accepting ordinary commands. If restore fails, persistent
WFP hold remains and the service reports `BlockedError`.

Logs never contain complete configs, UUIDs, keys or subscription URLs.

## Installer

The NSIS installer is per-machine and therefore produces one elevation prompt.
Post-install hooks create the restricted ProgramData directory, record the
installing user SID, create `VarmlenService` as an automatic LocalSystem
service, configure recovery and start it. Upgrade stops the old service before
replacing files. Uninstall stops the service, runs `--cleanup`, deletes the
service and removes mutable state.

Separate x64 and ARM64 Tauri overlays include only matching service, Xray and
Wintun binaries. Runtime assets are pinned and checksum-verified before
packaging.

## Verification boundary

Pure policy, config, persistence-envelope and process-plan behavior is covered
on Linux. The entire workspace is cross-compiled for Windows x64 and ARM64,
and x64 contract tests run under Wine where possible. No command in this work
changes the developer machine's routes, DNS, firewall or active VPN.

Real connect, reconnect, DNS-leak, UDP-game split and uninstall acceptance
still require a dedicated Windows machine or VM before publishing a stable
release.
