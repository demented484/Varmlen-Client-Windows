# Varmlen for Windows

Native Windows client for Varmlen, built around Xray's native TUN inbound,
Wintun, and a privileged Windows service.

## Current status

The first implementation milestone contains:

- the shared Varmlen frontend, with tests and production build;
- a versioned, size-limited GUI/service protocol;
- a tested transactional connection controller with rollback and blocked-error
  states;
- a `LocalSystem` Windows Service host with graceful SCM shutdown;
- a local named pipe restricted to `SYSTEM`, administrators and the user SID
  registered during installation;
- client-token verification before the service reads a command;
- a minimal Tauri shell and service-status request for x64 and ARM64 builds.

Native Xray TUN/Wintun startup, WFP policies, DNS protection and the installer
are the next implementation slices. This repository does not yet provide a
working Windows VPN build or release.

See [the approved architecture](docs/design/2026-07-29-windows-client.md) and
[the foundation implementation plan](docs/superpowers/plans/2026-07-29-windows-foundation.md).

## Verification

```text
npm test
npm run check
npm run build
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

GitHub Actions additionally tests Windows x64 and checks the complete Rust
workspace for Windows ARM64.

## License

[GNU General Public License v3.0 only](LICENSE).
