# Varmlen Client Windows

Open-source xray-core VPN client for Windows, with per-app and per-domain split
tunneling. Built on Tauri 2 and SvelteKit.

> Status: pre-release. The x64 and ARM64 installers are complete and pass
> automated build/package checks; final VPN acceptance still requires a real
> Windows machine.

## Screenshots

<table>
  <tr>
    <th width="33.333%">Home</th>
    <th width="33.333%">Split tunneling</th>
    <th width="33.333%">Settings</th>
  </tr>
  <tr>
    <td><img src="docs/screenshots/home.png" width="100%" alt="Varmlen Windows home with AegisVPN locations"></td>
    <td><img src="docs/screenshots/split.png" width="100%" alt="Varmlen Windows per-app split tunneling"></td>
    <td><img src="docs/screenshots/settings.png" width="100%" alt="Varmlen Windows settings in English"></td>
  </tr>
</table>

## Features

- Xray's native TUN inbound over Wintun; there is no tun2socks or proxy mode.
- VLESS, VMess, Trojan, Shadowsocks, Hysteria, WireGuard, HTTP and SOCKS
  outbounds, including provider-supplied multi-outbound JSON profiles.
- Per-app and per-domain split tunneling in independent general/selective modes.
- Transactional reconnect: a temporary WFP hold is installed before the active
  tunnel is stopped, and the previous connection is restored if the candidate
  fails.
- DNS leak prevention and dual-stack WFP policy, including LAN-safe port 53
  blocking.
- A `LocalSystem` service owns Xray, Wintun, WFP and encrypted desired state, so
  the tunnel survives closing the GUI.
- Xray configuration syntax and actual SOCKS5 reachability are checked before
  network policy changes.
- Unexpected Xray exits are detected by the service; the configured kill switch
  remains fail-closed even when the GUI is not running.

## Security model

The unprivileged UI communicates with `VarmlenService` through a versioned,
size-limited named-pipe protocol. The pipe ACL and client-token check restrict
commands to `LocalSystem` and the interactive user recorded by the installer.
Runtime binaries live under the machine installation directory; mutable state
is protected under `%ProgramData%\Varmlen`.

WFP provider, sublayer and filters are persistent. Installation, reconnect and
cleanup use explicit transactions so a failed candidate cannot briefly expose
ordinary traffic.

See [the architecture](docs/design/2026-07-29-windows-client.md).

## Local build

The build scripts download pinned Xray 26.6.27 and Wintun 0.14.1 archives,
verify their SHA-256 hashes, cross-compile the service and GUI, and create a
per-machine NSIS installer:

```text
./scripts/build-windows.sh x64
./scripts/build-windows.sh arm64
```

Requirements: Node.js 22, Rust, `cargo-xwin`, LLVM/Clang, `unzip`, `curl` and
NSIS.

## Verification

```text
npm test
npm run check
npm run build
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo xwin check --workspace --target x86_64-pc-windows-msvc
cargo xwin check --workspace --target aarch64-pc-windows-msvc
```

The release artifacts are:

```text
target/x86_64-pc-windows-msvc/release/bundle/nsis/Varmlen_0.1.0_x64-setup.exe
target/aarch64-pc-windows-msvc/release/bundle/nsis/Varmlen_0.1.0_arm64-setup.exe
```

## License

[GNU General Public License v3.0 only](LICENSE).
