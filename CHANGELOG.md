# Changelog

## 0.3.1

- Replace the obsolete Xray 26.3.27 service runtime with 26.7.28, including
  Hysteria client and native-TUN UDP fixes while retaining transactional core
  switching to any installed official version.
- Restore the kill-switch setting and carry it unchanged through the GUI,
  named-pipe protocol, reconnect journal and privileged service.
- Replace the removed packet-filter backend with service-owned fail-closed
  IPv4/IPv6 routes and explicit protection against LAN DNS fallback.
- Restore Xray core management: list, download, verify, activate and remove
  official XTLS releases for Windows x64 and ARM64.
- Switch cores transactionally while connected and restore both the previous
  core and tunnel when a candidate cannot start or pass its health check.
- Keep downloaded executables in administrator-only service storage and reject
  non-official URLs, missing SHA-256 digests, oversized archives and mismatched
  executable versions.

## 0.3.0

- Verify the selected profile's effective route before switching traffic;
  optional, fallback, balancer, and chained outbounds no longer make an
  otherwise working connection fail.
- Pin the service-owned core to stable Xray 26.3.27, mark it explicitly in the
  core menu, and configure Windows TUN addresses, DNS and routes in the service.
- Filter uninstall/setup helpers from automatic app discovery and derive names
  such as Chromium from executable version metadata instead of `chrome.exe`.
- Pin native-TUN outbound sockets to the physical interface selected by the
  Windows route table, avoiding DNS/Reality loops through Hyper-V or WSL NICs.
- Discover XboxGames installations, avoid installer/cleaner executables when
  choosing the main Steam/Xbox game binary, use real game/package icons, and
  show only the executable name while retaining the full path in a tooltip.
- Import share links for every supported Xray proxy outbound: add Hysteria2,
  WireGuard, HTTP and SOCKS5 URI parsing plus standard WireGuard config files.
- Reject subscription and JSON settings that disable TLS certificate or
  hostname validation; strengthen subscription SSRF, redirect, and size checks.
- Harden the Windows service DACL and allow uninstall to continue when a
  partially removed installation no longer has a registered service.
- Remove the obsolete user-mode packet-filtering backend after
  real-system failures prevented both VPN startup and clean uninstallation.
- Keep legacy cleanup best-effort and never hold the uninstaller hostage when
  cleanup reports a warning.
- Temporarily disable the kill-switch control pending replacement enforcement;
  Xray native TUN and process/domain split routing remain.
- Discover applications from both 32-bit and 64-bit App Paths and uninstall
  registry views, extract real executable icons, and show compact readable paths.
- Keep every successful subscription refresh authoritative when quota or expiry
  metadata is omitted by the provider.
