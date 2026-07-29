# Windows Client Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Produce a testable Windows-client foundation containing the current Varmlen frontend, a versioned and bounded service protocol, a transactional connection controller, generic framed IPC, and a Windows Service host that compiles in Windows CI.

**Architecture:** The unprivileged Tauri GUI and a `LocalSystem` Windows Service are separate processes. Platform-independent Rust crates define the IPC contract and connection transaction; Windows-only transport and service registration code stay in the service binary behind `cfg(windows)`. This plan is the first independently testable implementation slice; native Xray TUN/Wintun and WFP use the interfaces produced here and are implemented in the next slice.

**Tech Stack:** Rust 2021, Tokio, Serde JSON, async-trait, windows-service, Tauri 2, Svelte 5, TypeScript, Vitest, GitHub Actions.

## Global Constraints

- License is `GPL-3.0-only`.
- Supported systems are Windows 10 and Windows 11.
- Target architectures are `x86_64-pc-windows-msvc` and `aarch64-pc-windows-msvc`.
- There is no `tun2socks`, local proxy mode, `netsh` data plane, or custom kernel driver.
- The GUI is never elevated; privileged network state belongs to the Windows Service.
- IPC is versioned, length-prefixed, size-bounded, and contains operation IDs.
- Connect and reconnect are fail-closed transactions.
- Tests do not touch the developer machine's active VPN or network configuration.
- Work is executed inline without subagents.

## Plan series

1. **This plan:** repository, shared frontend, protocol, transaction controller,
   framed IPC, service host and Windows compile CI.
2. **Native data plane:** Xray native TUN, Wintun, candidate validation, health
   verification and safe process lifecycle.
3. **Leak prevention and split:** WFP provider/filters, DNS enforcement,
   reconnect rollback and TCP/UDP per-app paths.
4. **Product integration:** complete Tauri IPC commands, Windows app discovery,
   background subscription updates, installer, x64/ARM64 packages and
   dedicated-machine acceptance tests.

---

## File structure

- `Cargo.toml` — Rust workspace and shared dependency versions.
- `crates/varmlen-protocol/src/lib.rs` — serialized IPC types, validation and
  frame payload limits.
- `crates/varmlen-service-core/src/controller.rs` — connection transaction and
  rollback orchestration over a backend trait.
- `crates/varmlen-service-core/src/framing.rs` — generic Tokio length-prefixed
  reader/writer.
- `crates/varmlen-service-core/src/handler.rs` — serialized command handling and
  operation-ID preservation.
- `service/src/main.rs` — platform entry point.
- `service/src/windows_service.rs` — Windows SCM lifecycle and named-pipe host.
- `src/`, `static/`, `package.json`, `vite.config.js`, `svelte.config.js` —
  current shared Varmlen UI and its existing tests.
- `.github/workflows/ci.yml` — Linux unit/frontend checks plus Windows target
  compilation.

### Task 1: Import and validate the shared frontend

**Files:**
- Create: `package.json`
- Create: `package-lock.json`
- Create: `src/**`
- Create: `static/**`
- Create: `svelte.config.js`
- Create: `vite.config.js`
- Create: `tsconfig.json`
- Create: `src/lib/windows-platform.test.ts`
- Modify: `src/lib/platform.ts`

**Interfaces:**
- Consumes: frontend files at Linux commit `d614653`.
- Produces: `isWindows(): boolean` and a frontend that passes the existing
  Vitest, Svelte and production-build checks.

- [ ] **Step 1: Import the already-tested platform-independent frontend**

Fetch `d614653` from `Varmlen-Client-Linux` and check out only:

```text
package.json
package-lock.json
src/
static/
svelte.config.js
vite.config.js
tsconfig.json
```

Do not import Linux `daemon/`, `helper/`, packaging, scripts or `src-tauri`.
Set the package version to `0.1.0` and keep
`"license": "GPL-3.0-only"`.

- [ ] **Step 2: Run the imported frontend baseline**

Run:

```bash
npm ci
npm test
npm run check
npm run build
```

Expected: all imported tests pass, Svelte reports zero errors, and
`build/index.html` exists.

- [ ] **Step 3: Write the failing Windows platform test**

Create `src/lib/windows-platform.test.ts`:

```ts
import { describe, expect, it } from "vitest";
import { isWindowsPlatform } from "./platform";

describe("Windows platform contract", () => {
  it("recognizes the Tauri Windows platform value without treating Linux as Windows", () => {
    expect(isWindowsPlatform("win32")).toBe(true);
    expect(isWindowsPlatform("windows")).toBe(true);
    expect(isWindowsPlatform("linux")).toBe(false);
  });
});
```

The production change this catches is a platform predicate that enables
Windows-only service commands on Linux or disables them on Windows.

- [ ] **Step 4: Verify the new test is red**

Run:

```bash
npx vitest run src/lib/windows-platform.test.ts
```

Expected: FAIL because `isWindowsPlatform` is not exported.

- [ ] **Step 5: Add the minimal platform predicate**

Add to `src/lib/platform.ts`:

```ts
export function isWindowsPlatform(value: string): boolean {
  const normalized = value.trim().toLowerCase();
  return normalized === "win32" || normalized === "windows";
}
```

- [ ] **Step 6: Verify green and commit**

Run:

```bash
npx vitest run src/lib/windows-platform.test.ts
npm test
npm run check
npm run build
```

Expected: all commands pass.

Commit:

```bash
git add package.json package-lock.json src static svelte.config.js vite.config.js tsconfig.json
git commit -m "feat: import shared Varmlen frontend"
```

### Task 2: Define the bounded service protocol

**Files:**
- Create: `Cargo.toml`
- Create: `crates/varmlen-protocol/Cargo.toml`
- Create: `crates/varmlen-protocol/src/lib.rs`
- Test: `crates/varmlen-protocol/tests/protocol_contract.rs`

**Interfaces:**
- Produces:
  - `PROTOCOL_VERSION: u16`
  - `RequestEnvelope`
  - `ServiceCommand`
  - `ConnectRequest`
  - `AppSelector`
  - `ResponseEnvelope`
  - `ServiceState`
  - `ConnectionPhase`
  - `validate_request(&RequestEnvelope) -> Result<(), ServiceErrorCode>`
  - `encode_payload<T: Serialize>(&T) -> Result<Vec<u8>, ServiceErrorCode>`
  - `decode_request(&[u8]) -> Result<RequestEnvelope, ServiceErrorCode>`

- [ ] **Step 1: Create workspace manifests and the failing contract test**

Root `Cargo.toml`:

```toml
[workspace]
members = [
  "crates/varmlen-protocol",
]
resolver = "2"

[workspace.package]
version = "0.1.0"
edition = "2021"
license = "GPL-3.0-only"

[workspace.dependencies]
async-trait = "0.1"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
thiserror = "2"
tokio = { version = "1", features = ["io-util", "macros", "rt-multi-thread", "sync"] }
```

Initially include only `crates/varmlen-protocol` in `members`; add the remaining
members in their tasks.

Create `crates/varmlen-protocol/Cargo.toml`:

```toml
[package]
name = "varmlen-protocol"
version.workspace = true
edition.workspace = true
license.workspace = true

[dependencies]
serde.workspace = true
serde_json.workspace = true
```

Create `crates/varmlen-protocol/tests/protocol_contract.rs`:

```rust
use varmlen_protocol::{
    validate_request, AppSelector, ConnectRequest, RequestEnvelope,
    ServiceCommand, ServiceErrorCode, PROTOCOL_VERSION,
};

fn valid_request() -> RequestEnvelope {
    RequestEnvelope {
        version: PROTOCOL_VERSION,
        operation_id: 41,
        command: ServiceCommand::Connect(ConnectRequest {
            xray_config: r#"{"inbounds":[],"outbounds":[]}"#.into(),
            validation_config: r#"{"inbounds":[],"outbounds":[]}"#.into(),
            server_endpoints: vec!["203.0.113.7:443".parse().unwrap()],
            excluded_apps: vec![AppSelector {
                canonical_path: r"C:\Games\Counter-Strike 2\game\bin\win64\cs2.exe".into(),
                basename: "cs2.exe".into(),
            }],
            killswitch: true,
            allow_lan: false,
        }),
    }
}

#[test]
fn rejects_a_nul_in_an_executable_selector() {
    let mut request = valid_request();
    let ServiceCommand::Connect(connect) = &mut request.command else {
        unreachable!()
    };
    connect.excluded_apps[0].canonical_path.push('\0');
    assert_eq!(
        validate_request(&request),
        Err(ServiceErrorCode::InvalidRequest)
    );
}

#[test]
fn rejects_a_withdrawn_protocol_version() {
    let mut request = valid_request();
    request.version = PROTOCOL_VERSION - 1;
    assert_eq!(
        validate_request(&request),
        Err(ServiceErrorCode::UnsupportedVersion)
    );
}
```

The first test catches selectors that can be truncated at a Windows API
boundary. The second catches accidental acceptance of an incompatible client.

- [ ] **Step 2: Verify the protocol test is red**

Run:

```bash
cargo test -p varmlen-protocol --test protocol_contract
```

Expected: compilation fails because the protocol types do not exist.

- [ ] **Step 3: Implement the minimal protocol**

Use these exact limits in `crates/varmlen-protocol/src/lib.rs`:

```rust
pub const PROTOCOL_VERSION: u16 = 1;
pub const MAX_FRAME_BYTES: usize = 1024 * 1024;
const MAX_CONFIG_BYTES: usize = 384 * 1024;
const MAX_SERVER_ENDPOINTS: usize = 64;
const MAX_EXCLUDED_APPS: usize = 256;
const MAX_APP_SELECTOR_BYTES: usize = 4096;
```

Define `ServiceCommand` as:

```rust
pub enum ServiceCommand {
    Status,
    Connect(ConnectRequest),
    Disconnect { keep_blocked: bool },
}
```

Define phases exactly as:

```rust
pub enum ConnectionPhase {
    Disconnected,
    Validating,
    Holding,
    Starting,
    Connected,
    Stopping,
    Restoring,
    BlockedError,
}
```

Define the remaining wire types exactly as:

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppSelector {
    pub canonical_path: String,
    pub basename: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectRequest {
    pub xray_config: String,
    pub validation_config: String,
    pub server_endpoints: Vec<std::net::SocketAddr>,
    pub excluded_apps: Vec<AppSelector>,
    pub killswitch: bool,
    pub allow_lan: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequestEnvelope {
    pub version: u16,
    pub operation_id: u64,
    pub command: ServiceCommand,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceState {
    pub phase: ConnectionPhase,
    pub operation_id: u64,
    pub split_active: bool,
    pub dns_protected: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ServiceErrorCode {
    UnsupportedVersion,
    FrameTooLarge,
    InvalidFrame,
    InvalidRequest,
    Unauthorized,
    ValidationFailed,
    HoldFailed,
    XrayStartFailed,
    HealthCheckFailed,
    RestoreFailed,
    CleanupFailed,
    Internal,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceError {
    pub code: ServiceErrorCode,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResponseEnvelope {
    pub version: u16,
    pub operation_id: u64,
    pub result: Result<ServiceState, ServiceError>,
}
```

Reject empty/oversized configs, an empty endpoint list, zero endpoint ports,
more than 64 endpoints, more than 256 app selectors, empty paths/basenames,
NUL bytes and selector fields over 4096 bytes.

- [ ] **Step 4: Add payload boundary tests**

Append tests with literal expected errors:

```rust
#[test]
fn oversized_serialized_payload_is_rejected() {
    let payload = "x".repeat(1024 * 1024 + 1);
    assert_eq!(
        varmlen_protocol::encode_payload(&payload),
        Err(ServiceErrorCode::FrameTooLarge)
    );
}

#[test]
fn response_preserves_the_request_operation_id() {
    let request = valid_request();
    assert_eq!(request.operation_id, 41);
}
```

The first catches removal or off-by-one weakening of the frame cap. Operation
ID propagation is tested through the real handler in Task 4.

- [ ] **Step 5: Verify green and commit**

Run:

```bash
cargo fmt --all -- --check
cargo test -p varmlen-protocol
```

Expected: all protocol tests pass.

Commit:

```bash
git add Cargo.toml crates/varmlen-protocol
git commit -m "feat: define Windows service protocol"
```

### Task 3: Implement the transactional connection controller

**Files:**
- Modify: `Cargo.toml`
- Create: `crates/varmlen-service-core/Cargo.toml`
- Create: `crates/varmlen-service-core/src/lib.rs`
- Create: `crates/varmlen-service-core/src/controller.rs`
- Test: `crates/varmlen-service-core/tests/controller_contract.rs`

**Interfaces:**
- Consumes: `ConnectRequest`, `ServiceState`, `ConnectionPhase`,
  `ServiceError`, `ServiceErrorCode`.
- Produces:
  - async trait `ConnectionBackend`
  - `ConnectionController<B>`
  - `connect(&mut self, operation_id: u64, ConnectRequest)`
  - `disconnect(&mut self, operation_id: u64, keep_blocked: bool)`

Add `"crates/varmlen-service-core"` to workspace members and create:

```toml
[package]
name = "varmlen-service-core"
version.workspace = true
edition.workspace = true
license.workspace = true

[dependencies]
async-trait.workspace = true
serde_json.workspace = true
tokio.workspace = true
varmlen-protocol = { path = "../varmlen-protocol" }
```

- [ ] **Step 1: Write the failing reconnect-order test**

The fake backend records this public effect enum:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Effect {
    Validate,
    InstallHold,
    VerifyHold,
    StopActive,
    StartCandidate,
    VerifyCandidate,
    CommitPolicy,
    ReleaseHold,
}
```

The test:

```rust
#[tokio::test]
async fn reconnect_installs_and_verifies_hold_before_stopping_active_xray() {
    let backend = RecordingBackend::healthy();
    let mut controller = ConnectionController::connected(backend);

    let state = controller.connect(7, valid_connect()).await.unwrap();

    assert_eq!(state.phase, ConnectionPhase::Connected);
    assert_eq!(
        controller.backend().effects(),
        &[
            Effect::Validate,
            Effect::InstallHold,
            Effect::VerifyHold,
            Effect::StopActive,
            Effect::StartCandidate,
            Effect::VerifyCandidate,
            Effect::CommitPolicy,
            Effect::ReleaseHold,
        ]
    );
}
```

The production change this catches is stopping the old data plane before the
verified WFP hold exists.

- [ ] **Step 2: Verify red**

Run:

```bash
cargo test -p varmlen-service-core --test controller_contract reconnect_installs
```

Expected: compilation fails because `ConnectionController` is absent.

- [ ] **Step 3: Implement the success transaction**

Define `ConnectionBackend` with:

```rust
async fn validate_candidate(&mut self, request: &ConnectRequest) -> Result<(), ServiceError>;
async fn install_transition_hold(&mut self) -> Result<(), ServiceError>;
async fn verify_transition_hold(&mut self) -> Result<(), ServiceError>;
async fn stop_active(&mut self) -> Result<(), ServiceError>;
async fn start_candidate(&mut self, request: &ConnectRequest) -> Result<(), ServiceError>;
async fn verify_candidate(&mut self, request: &ConnectRequest) -> Result<(), ServiceError>;
async fn commit_policy(&mut self, request: &ConnectRequest) -> Result<(), ServiceError>;
async fn release_transition_hold(&mut self) -> Result<(), ServiceError>;
async fn restore_previous(&mut self) -> Result<(), ServiceError>;
async fn clear_network_state(&mut self, keep_blocked: bool) -> Result<(), ServiceError>;
```

The controller must update phases in the same order as the design:
`Validating`, `Holding`, `Starting`, `Connected`.

- [ ] **Step 4: Write the failing validation-preserves-connection test**

```rust
#[tokio::test]
async fn failed_candidate_validation_does_not_touch_the_active_connection() {
    let backend = RecordingBackend::failing(Effect::Validate);
    let mut controller = ConnectionController::connected(backend);

    assert!(controller.connect(8, valid_connect()).await.is_err());

    assert_eq!(controller.state().phase, ConnectionPhase::Connected);
    assert_eq!(controller.backend().effects(), &[Effect::Validate]);
}
```

The production change this catches is installing hold or stopping the active
connection for a candidate that never validated.

- [ ] **Step 5: Implement validation rollback and verify green**

On validation failure, restore the exact pre-operation `ServiceState` without
calling any other backend method.

Run:

```bash
cargo test -p varmlen-service-core --test controller_contract
```

Expected: both tests pass.

- [ ] **Step 6: Write the failing restore test**

```rust
#[tokio::test]
async fn failed_candidate_after_stop_restores_previous_under_hold() {
    let backend = RecordingBackend::failing(Effect::StartCandidate);
    let mut controller = ConnectionController::connected(backend);

    let result = controller.connect(9, valid_connect()).await;

    assert!(result.is_err());
    assert_eq!(controller.state().phase, ConnectionPhase::Connected);
    assert!(controller.backend().restore_was_called_after_hold());
    assert!(!controller.backend().released_hold_before_restore());
}
```

The production change this catches is fail-open reconnect rollback.

- [ ] **Step 7: Implement restore and blocked-error outcomes**

If failure occurs after `stop_active`:

- phase becomes `Restoring`;
- `restore_previous` runs while the hold remains;
- successful restore returns phase `Connected` and releases transition hold;
- failed restore leaves phase `BlockedError` and does not release the hold.

Add a second literal test where both candidate start and restore fail and assert
`ConnectionPhase::BlockedError`.

- [ ] **Step 8: Verify and commit**

Run:

```bash
cargo fmt --all -- --check
cargo test -p varmlen-service-core
```

Expected: all controller tests pass.

Commit:

```bash
git add Cargo.toml crates/varmlen-service-core
git commit -m "feat: add transactional connection controller"
```

### Task 4: Add generic bounded IPC framing and command handling

**Files:**
- Create: `crates/varmlen-service-core/src/framing.rs`
- Create: `crates/varmlen-service-core/src/handler.rs`
- Modify: `crates/varmlen-service-core/src/lib.rs`
- Test: `crates/varmlen-service-core/tests/framing_contract.rs`
- Test: `crates/varmlen-service-core/tests/handler_contract.rs`

**Interfaces:**
- Produces:
  - `read_payload<R: AsyncRead + Unpin>(&mut R)`
  - `write_payload<W: AsyncWrite + Unpin>(&mut W, &[u8])`
  - trait `CommandExecutor`
  - `handle_payload(&dyn CommandExecutor, &[u8]) -> Vec<u8>`

- [ ] **Step 1: Write the failing oversized-prefix test**

```rust
#[tokio::test]
async fn rejects_length_prefix_above_the_protocol_limit_without_allocating_body() {
    let (mut client, mut server) = tokio::io::duplex(16);
    client
        .write_u32((varmlen_protocol::MAX_FRAME_BYTES + 1) as u32)
        .await
        .unwrap();

    assert_eq!(
        read_payload(&mut server).await,
        Err(ServiceErrorCode::FrameTooLarge)
    );
}
```

The production change this catches is allocating attacker-controlled frame
length before enforcing the cap.

- [ ] **Step 2: Verify red, implement framing, verify green**

Run:

```bash
cargo test -p varmlen-service-core --test framing_contract
```

Expected red: `read_payload` is missing.

Implement a four-byte big-endian length followed by exact payload bytes. Reject
the prefix before allocating the body.

Run the same command again. Expected: PASS.

- [ ] **Step 3: Write the failing operation-ID round-trip test**

```rust
#[tokio::test]
async fn status_response_keeps_the_request_operation_id() {
    let request = RequestEnvelope {
        version: PROTOCOL_VERSION,
        operation_id: 0xfeed,
        command: ServiceCommand::Status,
    };
    let response = handle_payload(&SnapshotExecutor::disconnected(), &encode_payload(&request).unwrap())
        .await
        .unwrap();
    let response: ResponseEnvelope = serde_json::from_slice(&response).unwrap();
    assert_eq!(response.operation_id, 0xfeed);
    assert_eq!(response.result.unwrap().phase, ConnectionPhase::Disconnected);
}
```

The production change this catches is a stale response being accepted as the
result of a newer GUI operation.

- [ ] **Step 4: Implement handler and commit**

Decode and validate the request before invoking `CommandExecutor`. Return
structured errors for unsupported version, invalid frame and invalid request.

Run:

```bash
cargo fmt --all -- --check
cargo test -p varmlen-service-core
```

Expected: all tests pass.

Commit:

```bash
git add crates/varmlen-service-core
git commit -m "feat: add bounded service IPC framing"
```

### Task 5: Add the Windows Service and named-pipe host

**Files:**
- Modify: `Cargo.toml`
- Create: `service/Cargo.toml`
- Create: `service/src/main.rs`
- Create: `service/src/windows_service.rs`
- Create: `service/src/pipe.rs`
- Test: `service/tests/pipe_policy_contract.rs`

**Interfaces:**
- Consumes: `read_payload`, `write_payload`, `handle_payload`.
- Produces:
  - service name `VarmlenService`
  - pipe path `\\.\pipe\Varmlen\Service\v1`
  - `PipeClientIdentity::authorize(&self, InstalledUserSid) -> bool`
  - SCM stop event wired to graceful server shutdown.

Use this service manifest:

```toml
[package]
name = "varmlen-service"
version.workspace = true
edition.workspace = true
license.workspace = true

[dependencies]
async-trait.workspace = true
tokio = { workspace = true, features = ["net", "signal"] }
varmlen-protocol = { path = "../crates/varmlen-protocol" }
varmlen-service-core = { path = "../crates/varmlen-service-core" }

[target.'cfg(windows)'.dependencies]
windows = { version = "0.62.2", features = [
  "Win32_Foundation",
  "Win32_Security",
  "Win32_Security_Authorization",
  "Win32_Storage_FileSystem",
  "Win32_System_Pipes",
  "Win32_System_Threading",
] }
windows-service = "0.8.1"
```

Add `"service"` to the root workspace members in this task.

- [ ] **Step 1: Write the failing pure pipe-policy test**

```rust
#[test]
fn denies_remote_or_wrong_sid_pipe_clients() {
    let installed = InstalledUserSid::parse("S-1-5-21-100-200-300-1001").unwrap();
    let wrong = InstalledUserSid::parse("S-1-5-21-100-200-300-1002").unwrap();

    assert!(!PipeClientIdentity::remote(installed.clone()).authorize(&installed));
    assert!(!PipeClientIdentity::local(wrong).authorize(&installed));
    assert!(PipeClientIdentity::local(installed.clone()).authorize(&installed));
    assert!(PipeClientIdentity::local_system().authorize(&installed));
}
```

The production change this catches is allowing a remote or unrelated local
user to control a machine-wide VPN service.

- [ ] **Step 2: Verify red and implement the platform-independent policy**

Run:

```bash
cargo test -p varmlen-service --test pipe_policy_contract
```

Expected red: identity types are absent.

Implement SID syntax validation and authorization without Windows API calls so
the contract runs on Linux.

- [ ] **Step 3: Implement the Windows-only host**

Under `cfg(windows)`:

- register `VarmlenService` with `windows-service`;
- accept stop and shutdown controls;
- create the named pipe with a security descriptor that grants only
  `SYSTEM`, administrators and the installed user SID;
- reject remote clients;
- query and verify the connected client's token before reading a frame;
- process one bounded frame at a time through the shared handler;
- stop accepting clients before service shutdown completes.

The non-Windows `main` exits with:

```text
VarmlenService is only supported on Windows
```

It must not attempt networking.

- [ ] **Step 4: Add Windows compile CI before relying on the host**

Create `.github/workflows/ci.yml` with:

```yaml
name: CI
on:
  push:
  pull_request:

jobs:
  rust:
    strategy:
      matrix:
        include:
          - os: ubuntu-latest
            target: x86_64-unknown-linux-gnu
          - os: windows-latest
            target: x86_64-pc-windows-msvc
          - os: windows-latest
            target: aarch64-pc-windows-msvc
    runs-on: ${{ matrix.os }}
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with:
          targets: ${{ matrix.target }}
      - run: cargo test --workspace --target ${{ matrix.target }}
        if: matrix.target != 'aarch64-pc-windows-msvc'
      - run: cargo check --workspace --target ${{ matrix.target }}
        if: matrix.target == 'aarch64-pc-windows-msvc'
```

- [ ] **Step 5: Verify locally and commit**

Run:

```bash
cargo fmt --all -- --check
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo run -p varmlen-service
```

Expected: tests and clippy pass; the final command exits with the documented
non-Windows message without touching the network.

Commit:

```bash
git add Cargo.toml Cargo.lock service .github/workflows/ci.yml
git commit -m "feat: add Windows service host"
```

### Task 6: Add the minimal Tauri shell and service-status boundary

**Files:**
- Create: `src-tauri/Cargo.toml`
- Create: `src-tauri/build.rs`
- Create: `src-tauri/tauri.conf.json`
- Create: `src-tauri/src/main.rs`
- Create: `src-tauri/src/lib.rs`
- Create: `src-tauri/src/service_client.rs`
- Create: `src/lib/service-status.ts`
- Create: `src/lib/service-status.test.ts`
- Modify: `Cargo.toml`

**Interfaces:**
- Consumes: `RequestEnvelope`, `ServiceCommand::Status`, named-pipe framing.
- Produces:
  - Tauri command `service_status() -> Result<ServiceState, String>`
  - `serviceStatusLabel(ServiceState | null, string | null): string`

Use this Tauri manifest:

```toml
[package]
name = "varmlen"
version.workspace = true
edition.workspace = true
license.workspace = true

[lib]
name = "varmlen_lib"
crate-type = ["staticlib", "cdylib", "rlib"]

[build-dependencies]
tauri-build = { version = "2", features = [] }

[dependencies]
serde.workspace = true
tauri = { version = "2", features = ["tray-icon"] }
tokio = { workspace = true, features = ["net"] }
varmlen-protocol = { path = "../crates/varmlen-protocol" }
varmlen-service-core = { path = "../crates/varmlen-service-core" }
```

Add `"src-tauri"` to the root workspace members in this task. Create
`src-tauri/build.rs` with `tauri_build::build();` and configure
`src-tauri/tauri.conf.json` with product name `Varmlen`, identifier
`app.varmlen.client`, version `0.1.0`, frontend directory `../build`, window
size `440x720`, minimum `380x600`, and Windows bundle target `nsis`.

- [ ] **Step 1: Write the failing UI status test**

```ts
import { describe, expect, it } from "vitest";
import { serviceStatusLabel } from "./service-status";

describe("service status", () => {
  it("does not claim the VPN is disconnected when the service is unreachable", () => {
    expect(serviceStatusLabel(null, "access denied")).toBe("Service unavailable");
  });
});
```

The production change this catches is presenting an IPC/authentication failure
as a trustworthy disconnected network state.

- [ ] **Step 2: Verify red, implement the formatter, verify green**

Run:

```bash
npx vitest run src/lib/service-status.test.ts
```

Expected red: module is missing.

Implement:

```ts
export function serviceStatusLabel(
  state: { phase: string } | null,
  error: string | null,
): string {
  if (error || !state) return "Service unavailable";
  return state.phase.replaceAll("_", " ");
}
```

Run the test again. Expected: PASS.

- [ ] **Step 3: Add the Tauri service-status command**

The Windows client opens `\\.\pipe\Varmlen\Service\v1`, sends:

```rust
RequestEnvelope {
    version: PROTOCOL_VERSION,
    operation_id,
    command: ServiceCommand::Status,
}
```

and rejects a response with another operation ID. The non-Windows
implementation returns `"VarmlenService is only supported on Windows"` and
does not touch the network.

- [ ] **Step 4: Verify and commit**

Run:

```bash
npm test
npm run check
npm run build
cargo fmt --all -- --check
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

Expected: all checks pass.

Commit:

```bash
git add Cargo.toml Cargo.lock src-tauri src/lib/service-status.ts src/lib/service-status.test.ts
git commit -m "feat: connect the Windows UI to service status"
```

### Task 7: Verify the milestone and publish its branch

**Files:**
- Modify: `README.md`
- Modify: `.github/workflows/ci.yml`

**Interfaces:**
- Produces: one feature branch whose local checks and GitHub Windows jobs are
  green.

- [ ] **Step 1: Run the complete local verification**

Run:

```bash
npm test
npm run check
npm run build
cargo fmt --all -- --check
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
git diff --check main...HEAD
```

Expected: every command passes and there are no whitespace errors.

- [ ] **Step 2: Update the README with verified scope**

Document only behavior proved by this milestone:

- frontend imported and building;
- protocol and connection transaction covered by tests;
- Windows Service and named-pipe host compile in CI;
- native TUN/WFP connection is not yet exposed as working.

- [ ] **Step 3: Commit and push**

```bash
git add README.md .github/workflows/ci.yml
git commit -m "docs: record Windows foundation status"
git push -u origin feature/windows-foundation
```

- [ ] **Step 4: Inspect GitHub Actions**

Run:

```bash
gh run list --branch feature/windows-foundation --limit 1
gh run watch --exit-status
```

Expected: Linux tests, Windows x64 tests and Windows ARM64 check are green.

- [ ] **Step 5: Merge only after verification**

After all jobs pass, fast-forward `main` to the verified feature branch and
push `main`. Do not create a release from this foundation milestone.
