# Changelog

## 0.3.0 Preview

- Pin native-TUN outbound sockets to the physical interface selected by the
  Windows route table, avoiding DNS/Reality loops through Hyper-V or WSL NICs.
- Discover XboxGames installations, represent Steam/Xbox games as recursive
  process folders, use real game/package icons, and show only the executable
  name or `*.exe` while retaining the full path in a tooltip.
- Import share links for every supported Xray proxy outbound: add Hysteria2,
  WireGuard, HTTP and SOCKS5 URI parsing plus standard WireGuard config files.
- Reject subscription and JSON settings that disable TLS certificate or
  hostname validation; strengthen subscription SSRF, redirect, and size checks.
- Harden the Windows service DACL and allow uninstall to continue when a
  partially removed installation no longer has a registered service.
- Remove user-mode WFP filters from the active Windows connection path after
  real-system failures prevented both VPN startup and clean uninstallation.
- Keep legacy WFP cleanup for upgrades, but enumerate without a restrictive
  template and never hold the uninstaller hostage when cleanup reports a warning.
- Disable the kill-switch control until a reviewed replacement enforcement
  backend is available; Xray native TUN and process/domain split routing remain.
- Discover applications from both 32-bit and 64-bit App Paths and uninstall
  registry views, extract real executable icons, and show compact readable paths.
- Keep every successful subscription refresh authoritative when quota or expiry
  metadata is omitted by the provider.
