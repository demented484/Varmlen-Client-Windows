# Windows Runtime Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build an installable x64/ARM64 Windows client whose LocalSystem
service owns Xray native TUN, WFP leak prevention, DNS health and recovery.

**Architecture:** Platform-independent crates compile and test candidate
validation, WFP policy intent and lifecycle transitions. Windows-only modules
translate those intents into Xray child processes, IP Helper inspection, DPAPI
state and transactional WFP objects. Tauri sends the existing bounded protocol
over the named pipe; NSIS installs all privileged runtime files.

**Tech Stack:** Rust 2021, Tokio, windows-rs, Windows Filtering Platform,
Windows IP Helper, DPAPI, Xray 26.3.27, Wintun 0.14.1, Tauri 2 and NSIS.

## Global Constraints

- No network-changing test runs on the developer machine.
- No `tun2socks`, proxy mode, `netsh` data plane or custom driver.
- The GUI remains unprivileged.
- Reconnect is fail-closed and WFP updates are transactional.
- IPv4, IPv6, TCP, UDP, DNS and Windows process split are represented.
- x64 and ARM64 assets are selected from the actual build target.
- Work is executed inline without subagents and merged after verification.

---

### Task 1: Runtime contracts

**Files:**
- Create: `crates/varmlen-service-core/src/runtime.rs`
- Create: `crates/varmlen-service-core/tests/runtime_contract.rs`
- Modify: `crates/varmlen-service-core/src/lib.rs`

**Interfaces:**
- Produces `inspect_native_tun_config`, `PolicySpec`, `PolicyMode`,
  `RuntimeLayout` and architecture asset selection.

- [ ] Write tests that reject missing IPv6 routes, missing DNS,
  non-loopback validation listeners and target/asset mismatches.
- [ ] Run the test and observe failures caused by missing interfaces.
- [ ] Implement strict JSON inspection and deterministic policy intent.
- [ ] Run the focused and workspace tests.
- [ ] Commit as `feat: define Windows runtime contracts`.

### Task 2: Windows data plane

**Files:**
- Create: `service/src/windows_backend.rs`
- Create: `service/src/windows_process.rs`
- Create: `service/src/windows_adapter.rs`
- Create: `service/src/windows_state.rs`
- Modify: `service/src/lib.rs`
- Modify: `service/Cargo.toml`

**Interfaces:**
- Consumes `ConnectionBackend`, `PolicySpec` and `ConnectRequest`.
- Produces `WindowsBackend` with validation, native candidate startup,
  adapter/DNS health, DPAPI persistence and rollback.

- [ ] Add process-plan and state-envelope contract tests before production
  implementations.
- [ ] Implement bounded Xray validation and SOCKS5 reachability.
- [ ] Implement candidate start, adapter discovery and post-policy health.
- [ ] Implement machine-scope DPAPI state with atomic restricted files.
- [ ] Cross-compile x64 and ARM64.
- [ ] Commit as `feat: add Windows native TUN backend`.

### Task 3: Transactional WFP

**Files:**
- Create: `service/src/windows_wfp.rs`
- Create: `service/tests/wfp_policy_contract.rs`
- Modify: `service/src/windows_backend.rs`
- Modify: `service/Cargo.toml`

**Interfaces:**
- Consumes `PolicySpec`.
- Produces `WfpEngine::apply`, `verify`, `clear` and `remove_all`.

- [ ] Write tests for hold, connected, DNS, LAN, v4/v6 and filter weights.
- [ ] Implement fixed provider/sublayer/filter identities.
- [ ] Translate policy filters to `FWPM_FILTER0` and apply one transaction.
- [ ] Make controller commit run TCP and DNS health before state persistence.
- [ ] Cross-compile both Windows targets.
- [ ] Commit as `feat: enforce Windows WFP leak protection`.

### Task 4: Service and GUI lifecycle

**Files:**
- Modify: `service/src/pipe.rs`
- Modify: `service/src/windows_service.rs`
- Modify: `service/src/main.rs`
- Modify: `src-tauri/src/service_client.rs`
- Modify: `src-tauri/src/lib.rs`

**Interfaces:**
- Produces serialized connect/disconnect/status calls and startup recovery.

- [ ] Write executor and operation-ID tests.
- [ ] Replace `SnapshotExecutor` with the controller-backed runtime executor.
- [ ] Add service `--cleanup` for uninstall.
- [ ] Add Tauri service connect/disconnect commands.
- [ ] Verify native and Windows contract tests.
- [ ] Commit as `feat: connect Windows service lifecycle`.

### Task 5: Windows config and split generation

**Files:**
- Create: `src-tauri/src/subscription.rs`
- Create: `src-tauri/src/split.rs`
- Create: `src-tauri/src/xray.rs`
- Create: `src-tauri/src/vpn.rs`
- Modify: `src-tauri/src/lib.rs`
- Modify: `src-tauri/Cargo.toml`

**Interfaces:**
- Produces Windows native-TUN and loopback validation configs plus resolved
  endpoints and normalized process paths.

- [ ] Port the already-tested protocol/subscription model.
- [ ] Add failing Windows config tests for gateway, DNS, routes, automatic
  outbound interface and forward-slash process paths.
- [ ] Remove Linux marks and generate native Windows TUN settings.
- [ ] Route connect/disconnect through the service protocol.
- [ ] Run parser, config and frontend checks.
- [ ] Commit as `feat: generate Windows native TUN configs`.

### Task 6: Runtime assets and installer

**Files:**
- Create: `scripts/prepare-windows-runtime.sh`
- Create: `scripts/build-windows.sh`
- Create: `src-tauri/windows/installer-hooks.nsh`
- Create: `src-tauri/tauri.x64.conf.json`
- Create: `src-tauri/tauri.arm64.conf.json`
- Modify: `src-tauri/tauri.conf.json`
- Modify: `.github/workflows/ci.yml`
- Modify: `README.md`

**Interfaces:**
- Produces checksum-verified x64/ARM64 NSIS installers containing the matching
  GUI, service, Xray, Wintun and geodata.

- [ ] Add package-manifest tests before installer configuration.
- [ ] Pin Xray 26.3.27 and Wintun 0.14.1 with published SHA-256 values.
- [ ] Add per-machine install, upgrade and cleanup hooks.
- [ ] Build x64 and ARM64 executables and NSIS installers locally.
- [ ] Inspect PE architectures and package contents.
- [ ] Run the complete verification matrix, commit, merge and push.
