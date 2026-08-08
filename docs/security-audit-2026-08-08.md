# Windows client security and reliability audit — 2026-08-08

## Scope

Audited `main` around `0946e3f` and the follow-up hardening produced by this
review. The review covered the Tauri/WebView boundary, subscription parsing,
Xray configuration generation, the LocalSystem service and named-pipe protocol,
TUN lifecycle, split routing, persistent state, NSIS install/upgrade/uninstall,
CI, and bundled runtime provenance. For the closest like-for-like comparison,
v2rayN source was additionally reviewed at commit
`31044f449db5562aedb871daf69c0873e4b8a768`.

This is a source review plus Linux-hosted x64/ARM64 cross-build testing. It is
not a substitute for Windows Driver Verifier, packet-capture leak tests, sleep /
resume tests, multi-user tests, or a real Windows install/uninstall cycle.

## Executive conclusion

The current design is suitable for a **preview only**. Removing user-mode WFP
from the connection path was the correct short-term reliability decision: Xray
native TUN can provide ordinary full-tunnel routing and best-effort process /
domain split routing without making startup and uninstall depend on fragile WFP
state. It does **not** provide a kill switch, boot-time leak protection, or the
same process-tree and DNS guarantees as mature Windows VPN clients.

No remotely exploitable vulnerability was established in this review. The most
important remaining security boundary is too broad, however: an unprivileged
client supplies large, nested Xray JSON documents that are parsed and executed
by an Xray process running as LocalSystem. Mature clients send typed connection
parameters to the privileged daemon and construct the final data-plane config
inside that trusted boundary.

## Findings

### High — privileged service accepts opaque Xray configurations

`ConnectRequest` carries `xray_config` and `validation_config` strings. The
service applies size limits, top-level allowlists, loopback-only validation
listeners, fixed TUN settings, and rejects several file-reference keys. These
are useful controls, but nested provider outbounds remain a large parser and
feature surface executed as LocalSystem.

Impact: a malicious same-user process that can access the authorized pipe can
exercise substantially more privileged Xray parsing/configuration code than a
typed VPN API requires. This increases local privilege-escalation blast radius
if Xray ever has a config-triggered vulnerability.

Recommendation: replace opaque JSON in the service protocol with versioned,
typed endpoint, transport, DNS, and split-routing structures. Generate and
validate the final Xray config in the service. Keep raw provider JSON in the
unprivileged process and normalize it before IPC.

### High — no fail-closed Windows enforcement

The preview intentionally disables the kill-switch control and forces
`killswitch = false`. This is truthful and safer than claiming protection that
does not work, but traffic can leave through the physical interface while Xray
is starting, after Xray/service failure, during boot, and during service restart.
Apps that explicitly bind a physical interface can also bypass ordinary routing.

Recommendation: do not re-enable the UI until an enforcement backend passes
Windows packet-capture and failure-injection tests. A production implementation
should use atomic WFP policy changes and signed components where a callout is
needed.

### High — network-change and sleep/resume recovery are missing

The runtime monitor checks only whether the Xray process is alive. It does not
subscribe to default-route, adapter, DNS, power-resume, or network-profile
changes. After a real Windows DNS-timeout failure, startup was hardened to ask
Windows' route table for the VPN endpoint's physical interface and pin Xray to
that exact adapter instead of relying on Xray's name/address heuristic. That
fixes initial selection around Hyper-V/WSL adapters, but the choice can still
become stale when a machine moves between Wi-Fi, Ethernet, docking, or
sleep/resume.

Recommendation: add Windows network and power notifications, debounce them,
re-resolve server endpoints, and transactionally reconnect. Test Wi-Fi changes,
docking, sleep, hibernate, captive portals, Hyper-V, WSL, and interface metric
changes.

### High — release authenticity is not yet production-grade

Runtime downloads are version-pinned and archive hashes are verified, which is
good. The audit installers built on Linux are not Authenticode-signed, and the
Windows release remains intentionally unpublished. CI actions use mutable major
tags and there is no SBOM/provenance attestation.

Recommendation: sign every EXE/DLL/installer, verify signatures in a clean
Windows VM, pin CI actions by commit SHA, generate an SBOM, and publish build
provenance. Keep release publication blocked until real Windows testing passes.

### High, fixed in this review — provider input could disable TLS validation

Share links could set `allowInsecure=1`, and raw JSON outbounds could carry
`allowInsecure: true`. This disabled certificate and hostname validation in
Xray.

Fix: reject insecure TLS overrides in normalized and raw configurations and
always emit `allowInsecure: false`.

### Medium — split tunneling is route/process matching, not process-tree enforcement

Xray's Windows `process` matcher supports exact executable paths and is useful
for a preview. Automatically discovered Steam/Xbox entries and manually added
entries each select one concrete `.exe`; users must add separate campaign,
multiplayer, launcher, or helper binaries when needed. Xray still does not
provide the dedicated parent/child inheritance and socket redirection used by
mature split-tunnel drivers. Browser subprocesses, services, already-running
shared browser instances, and privileged processes can therefore behave
differently from the selected executable.
Domain split routing is also best effort when destinations cannot be inferred
because of encrypted DNS/ECH or process lookup limitations.

Recommendation: state these limitations in the UI. Add tests with Chromium
subprocesses, game launchers, Windows services, UDP/QUIC, DoH, ECH, IPv6, and
already-open sockets.

### Medium — WebView hardening remains incomplete

The CSP still permits inline script/style execution, and all custom commands are
available to the main application window. Provider text is rendered through
Svelte escaping and no remote WebView origin is configured, which lowers the
immediate risk, but WebView compromise would expose subscription data and VPN
commands. This review removed the opener capability for plaintext HTTP URLs;
external navigation is now HTTPS-only.

Recommendation: move to nonce/hash-based scripts where Tauri permits it, keep
commands narrowly scoped, validate all external URLs in Rust, and add a WebView
navigation allowlist.

### Medium — subscription and proxy secrets are stored in WebView localStorage

Subscription URLs commonly contain bearer tokens. Proxy UUIDs/passwords and raw
profiles are persisted in plaintext WebView localStorage. Windows profile ACLs
limit cross-user access, but this is weaker than an explicit native encrypted
store and expands exposure to WebView-origin compromise and profile backups.

Recommendation: move subscriptions and credentials to a native versioned store,
protect secrets with current-user DPAPI, keep only non-sensitive UI state in
localStorage, and provide migration/backup semantics.

### Medium — runtime assets are checked only for presence at service startup

The service verifies that Xray, Wintun and geo databases are non-empty files.
It does not verify expected hashes or Authenticode signatures at runtime.
Program Files ACLs prevent ordinary-user replacement in a correct install, but
explicit integrity verification would detect corruption and packaging errors.

Recommendation: embed architecture-specific hashes in the service and verify
before every privileged spawn; additionally verify Authenticode publisher once
production signing exists.

### Medium — health checks prove reachability, not tunnel identity

Validation verifies a SOCKS CONNECT to `1.1.1.1:443`; the connected check opens
a TUN-bound TCP connection and resolves `mullvad.net`. It does not perform a TLS
request, verify egress identity, or prove that all DNS/IPv6 paths are leak-free.
It also creates dependencies on third parties unrelated to Varmlen.

Recommendation: use a controlled HTTPS `204` endpoint with strict TLS, return
the observed source IP, test IPv4 and IPv6, and retain packet-level Windows leak
tests independent of the health endpoint.

### Medium — long-running debug logging can grow beyond the nominal cap

Log rotation runs when a new Xray process opens the log. A single long-running
process can continue writing beyond 10 MiB indefinitely.

Recommendation: pipe stdout/stderr through a bounded rotating writer or use a
logging backend that enforces a hard total size while the process is running.

### Medium, fixed in this review — uninstall could fail when the service was already absent

The uninstall hook unconditionally called `sc delete` and aborted on a non-zero
status. A partially removed/corrupted installation with no registered service
could therefore be impossible to uninstall normally.

Fix: query first, delete only a registered service, and continue if it is
already absent. Legacy WFP cleanup remains warning-only.

### Medium, fixed in this review — service-control DACL was implicit

The installer relied on the SCM default service DACL.

Fix: install an explicit DACL based on the hardened IVPN pattern: SYSTEM and
Administrators control the service; interactive/service users receive query and
interrogate rights only.

### Low — single-user authorization model

The pipe authorizes LocalSystem and the one interactive SID recorded at install
time. This is stricter than broad local access, but another legitimate Windows
user cannot control the VPN, and RDP/multi-session installation can record an
unexpected account.

Recommendation: make the product policy explicit. If multi-user support is
required, maintain an administrator-controlled authorized-user set rather than
opening mutating commands to all local users.

### Low — stale WFP abstractions remain in shared code and historical tests

`wfp_plan` and generic controller states still model fail-closed policy even
though the Windows backend is cleanup-only. This increases the chance that a
future change reports a blocked state without actual enforcement.

Recommendation: split generic lifecycle state from firewall capability and
remove the dead Windows policy compiler after legacy cleanup is no longer
needed.

## Positive controls already present

- Named pipe rejects remote clients, uses a protected DACL, impersonates each
  client, checks the token SID, caps concurrent clients, limits frames, and has
  I/O timeouts.
- ProgramData state is admin/SYSTEM-only and desired state is protected with
  machine DPAPI and atomic replacement.
- The service executes fixed binaries and fixed argument shapes without shell
  interpolation.
- Xray is placed in a kill-on-close Windows Job object.
- Validation listeners are loopback-only and use service-selected ports.
- Native TUN configuration requires fixed dual-stack gateways, DNS, default
  routes, and automatic physical-interface egress.
- Subscription HTTP has body limits, manual redirect handling, DNS pinning, and
  SSRF checks. This review additionally blocks more non-public ranges, embedded
  credentials, HTTPS downgrade redirects, oversized pasted input, and plaintext
  HTTP external-opener capability.
- Xray/Wintun archives are version-pinned and SHA-256 verified during packaging.
- `npm audit` and `cargo audit` found no known exploitable package
  vulnerabilities in the Windows path at review time. Cargo reported
  informational GTK3/unmaintained warnings from non-Windows Tauri dependencies.

## Focused comparison with v2rayN

v2rayN is the closest functional comparator: both applications consume
provider subscriptions, generate Xray-family configurations, launch a user-mode
core, and can use native TUN plus domain/process routing. It is a general proxy
manager rather than a fail-closed VPN security product, so `strict_route` must
not be read as a complete kill switch.

### Protocol-scope clarification

Bundling Xray does not make a GUI automatically understand every share-link or
configuration shape: the client still has to parse provider input and generate
the corresponding Xray JSON. Varmlen's current allowlist covers the practical
Xray proxy-outbound catalogue used by this product: HTTP, SOCKS, Shadowsocks,
VMess, VLESS, Trojan, Hysteria and WireGuard. The follow-up implementation now
parses direct links for all eight, including both `hy2://` / `hysteria2://` and
v2rayN-compatible `wireguard://`, and imports standard WireGuard
`[Interface]` / `[Peer]` configurations. A lone unauthenticated HTTP(S) URL is
kept as a subscription URL because it is indistinguishable from an anonymous
HTTP-proxy link; such proxies remain importable from a link list, JSON, or the
location editor. Hysteria extensions unavailable in the bundled Xray transport
are rejected rather than silently discarded, as are requests to disable TLS
validation.

Therefore “v2rayN supports more protocols” does **not** mean that Varmlen is
missing the ordinary Xray outbound protocols. v2rayN's larger total catalogue
comes mainly from its additional sing-box, Mihomo and standalone cores, plus
more share-link/subscription parsers. Those non-Xray protocols cannot be gained
merely by bundling Xray.

### Where v2rayN is ahead

- Much broader and more mature multi-core profile ecosystem: Xray, sing-box,
  Mihomo and other cores; more non-Xray protocols, share-link/subscription
  formats, custom configurations, routing editors, system-proxy modes, speed
  tests and backup features.
- TUN exposes `auto_route`, `strict_route`, route exclusions, interface binding,
  IPv6 and ICMP policy. It can use sing-box as a TUN front-end for another core.
- Its native config builder is considerably broader than Varmlen's current
  normalized profile builder, and profiles/subscriptions live in native SQLite
  rather than a WebView origin.
- Public release workflows produce detached GPG signatures with a documented
  fingerprint.

### Where Varmlen has the stronger Windows security boundary

- v2rayN requires the whole GUI to restart with `runas` before Windows TUN can
  be enabled, then launches the selected core as a child of that elevated GUI.
  Varmlen keeps the WebView/GUI unprivileged and delegates fixed lifecycle
  operations to a separately installed, SID-restricted service.
- v2rayN intentionally accepts arbitrary custom core configs and supports
  replaceable/multiple cores. That flexibility increases the elevated parsing,
  executable and configuration surface. Varmlen ships fixed Xray/Wintun paths
  under Program Files ACLs, although its opaque JSON IPC finding still prevents
  this boundary from being considered complete.
- v2rayN accepts HTTP subscription URLs, URL credentials and automatic
  redirects, and does not implement Varmlen's public-address DNS pinning/SSRF
  policy. This is compatible with local/self-hosted proxy-manager use cases but
  is weaker for bearer-token subscriptions.
- v2rayN preserves `allowInsecure` compatibility and warns about insecure
  profiles; hardened Varmlen now rejects them. This is a deliberate
  compatibility-versus-policy difference, not evidence that v2rayN claims
  strict VPN-grade TLS policy.

### Shared limitations

Neither reviewed design has a dedicated Windows fail-closed firewall/callout
backend or explicit process-tree split enforcement. Both therefore depend on
user-mode-core routing semantics and need empirical DNS/IPv4/IPv6, process,
network-change and sleep/resume testing. v2rayN stores URLs and credentials in
an unencrypted SQLite database; Varmlen stores them in WebView localStorage.
Neither is equivalent to a DPAPI-backed secret store. v2rayN's GPG signatures
provide downloadable-artifact integrity when users verify them, but no
Authenticode signing step was found in the reviewed public Windows workflow.

## Comparison with OSS Windows clients

| Area | Varmlen preview | v2rayN | Mullvad | IVPN | PIA | Windscribe | sing-box-style TUN |
|---|---|---|---|---|---|---|---|
| Privileged control plane | LocalSystem Rust service, SID-restricted pipe; GUI unprivileged | Entire GUI/core elevated for TUN; no separate Windows service | Privileged daemon, local management pipe | Privileged daemon/service | Privileged service | Privileged helper/service | Depends on wrapper |
| Data plane | Xray native Wintun TUN | Xray/sing-box/Mihomo and other cores; system proxy or TUN | WireGuard/OpenVPN + platform routing | WireGuard/OpenVPN | WireGuard/OpenVPN | WireGuard/OpenVPN | User-mode TUN |
| Kill switch | Disabled / unavailable | No dedicated kill switch; sing-box `strict_route` is limited | Always-on state firewall, atomic changes | WFP firewall incl. boot handling | WFP firewall | Proactive firewall | `strict_route` adds limited WFP/DNS behavior |
| App split | Xray process/path rule | Xray/sing-box process name/path routing | Dedicated signed KMDF/WFP split driver | Signed WFP callout driver with process tracking | Signed WFP callout driver | Signed split-tunnel callout driver | Process rules; platform caveats |
| Child process handling | No explicit process tree | No dedicated process-tree enforcement | Driver tracks process trees, with documented edge cases | Driver process monitor tracks parent/child | Driver/classify logic | Driver/helper logic | Matcher-dependent |
| DNS split/leak control | Xray DNS + TUN routes; no fail-closed WFP | Core DNS routing; sing-box strict route can reduce DNS leaks | Firewall/DNS integration | Hardened firewall/DNS integration | Driver DNS flow tracking and packet rewrite | DNS firewall/helper | `strict_route` can block port 53 outside TUN |
| Secret persistence | WebView localStorage, plaintext | Native SQLite, plaintext | Native app-managed storage | Native app-managed storage | Native app-managed storage | Native app-managed storage | Wrapper-dependent |
| Release authentication | Preview artifacts unsigned | Detached GPG signatures; no public Authenticode step found | Signed Windows packages/components | Signed Windows packages/components | Signed Windows packages/components | Signed Windows packages/components | Project/wrapper-dependent |
| Driver signing burden | None currently | None for normal core/TUN path | Yes | Yes | EV-signed driver required | Yes | Usually none unless strict integration |
| Reliability/security tradeoff | Narrower product with separated privilege, but incomplete service API and weaker enforcement | Broad compatibility and mature proxy features, but larger elevated surface and no fail-closed firewall | Larger mature platform stack | Larger mature platform stack | Larger mature platform stack | Larger mature platform stack | Similar route-change caveats |

The direct v2rayN lesson is to reuse its broad typed profile/config-builder
ideas, not its full-GUI elevation model. The broader lesson is not “copy another
client's WFP rules.” Mature VPN clients
combine a typed privileged daemon, atomic firewall state machine, signed callout
or split drivers, process lifecycle tracking, DNS-specific handling, route and
power notifications, installer rollback, and extensive Windows testing. Taking
only one component reproduces neither their guarantees nor their reliability.

## Recommended sequence

1. **Before any Windows release:** complete real x64 install-over-old,
   connection, IPv4/IPv6/DNS leak, split, sleep/resume, reboot/reconnect,
   uninstall, reinstall, and rollback testing.
2. Sign installer and all shipped PE files; add clean-VM signature checks.
3. Replace opaque Xray JSON IPC with a typed service-owned config builder.
4. Add network/power change recovery and controlled HTTPS health checks.
5. Move sensitive persisted data out of localStorage.
6. Decide product requirements for a kill switch. If required, design a
   separately reviewed WFP/callout component and testing lab; do not reactivate
   the removed filter implementation.
7. Add process-tree/split semantics only after deciding whether best-effort
   Xray matching is sufficient for the product.

## External references

- v2rayN source: https://github.com/2dust/v2rayN
- v2rayN TUN configuration builder: https://github.com/2dust/v2rayN/tree/master/v2rayN/ServiceLib/Services/CoreConfig
- v2rayN release-signing workflow: https://github.com/2dust/v2rayN/blob/master/.github/workflows/upload-sign.yml
- Mullvad security architecture: https://github.com/mullvad/mullvadvpn-app/blob/main/docs/security.md
- Mullvad split-tunneling semantics: https://github.com/mullvad/mullvadvpn-app/blob/main/docs/split-tunneling.md
- Mullvad Windows split driver: https://github.com/mullvad/win-split-tunnel
- IVPN desktop source and Windows split driver: https://github.com/ivpn/desktop-app
- PIA Windows WFP callout: https://github.com/pia-foss/desktop-windows-wfp-callout
- Windscribe desktop source: https://github.com/Windscribe/Desktop-App
- Xray routing/process matcher: https://xtls.github.io/en/config/routing.html
- Xray TUN inbound: https://xtls.github.io/en/config/inbounds/tun.html
- sing-box TUN/strict route: https://sing-box.sagernet.org/configuration/inbound/tun/
