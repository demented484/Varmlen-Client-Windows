use std::{
    collections::BTreeSet,
    path::PathBuf,
    sync::OnceLock,
    time::{Duration, Instant},
};

use serde::{Deserialize, Serialize};
use varmlen_protocol::{AppSelector, ConnectRequest, ConnectionPhase, ServiceState};

use crate::{
    service_client,
    split::SplitInput,
    subscription::{server_endpoints, VlessServer},
    xray::{build_ping_config, build_xray_config, ping_proxy_count, validate_server},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HelperResponse {
    pub ok: bool,
    pub state: String,
    pub pid: Option<u32>,
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rtt_ms: Option<u32>,
}

fn response(state: ServiceState) -> HelperResponse {
    let state = match state.phase {
        ConnectionPhase::Connected => "connected",
        ConnectionPhase::Blocked | ConnectionPhase::BlockedError => "dropped",
        ConnectionPhase::Validating | ConnectionPhase::Holding | ConnectionPhase::Starting => {
            "connecting"
        }
        _ => "disconnected",
    };
    HelperResponse {
        ok: true,
        state: state.into(),
        pid: None,
        error: None,
        rtt_ms: None,
    }
}

fn vpn_op_lock() -> &'static tokio::sync::Mutex<()> {
    static LOCK: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
}

#[tauri::command]
pub async fn vpn_connect(
    _app: tauri::AppHandle,
    server: VlessServer,
    mut split: SplitInput,
    killswitch: bool,
    allow_lan: bool,
    log_level: Option<String>,
) -> Result<HelperResponse, String> {
    validate_server(&server)?;
    let _ = killswitch;
    let _operation = vpn_op_lock().lock().await;
    let apps_selective = split.apps_selective();
    let app_selectors = resolve_app_selectors(&split.apps)?;
    split.apps = app_selectors
        .iter()
        .map(|app| app.canonical_path.replace('\\', "/"))
        .collect();

    let level = log_level.unwrap_or_else(|| "warn".into());
    let xray_config =
        serde_json::to_string_pretty(&build_xray_config(&server, &split, allow_lan, &level))
            .map_err(|error| format!("serialize Xray config: {error}"))?;

    let proxy_count = ping_proxy_count(&server)?;
    let validation_ports = validation_placeholder_ports(proxy_count)?;
    let validation_config =
        serde_json::to_string_pretty(&build_ping_config(&server, &validation_ports)?)
            .map_err(|error| format!("serialize Xray validation config: {error}"))?;
    let endpoints = resolve_server_endpoints(&server).await?;

    let state = service_client::connect(ConnectRequest {
        xray_config,
        validation_config,
        server_endpoints: endpoints,
        excluded_apps: app_selectors,
        apps_selective,
        // User-mode WFP enforcement was removed from the Windows preview.
        // Do not claim fail-closed behavior until a reviewed, signed backend is
        // available; native Xray TUN routing remains fully functional.
        killswitch: false,
        allow_lan,
    })
    .await?;
    Ok(response(state))
}

#[tauri::command]
pub async fn vpn_disconnect() -> Result<HelperResponse, String> {
    let _operation = vpn_op_lock().lock().await;
    // An explicit power-button disconnect restores ordinary networking. The
    // service keeps a persistent hold only for an unexpected tunnel failure.
    service_client::disconnect(false).await.map(response)
}

#[tauri::command]
pub async fn vpn_status() -> Result<HelperResponse, String> {
    service_client::service_status().await.map(response)
}

#[tauri::command]
pub async fn vpn_log() -> Result<String, String> {
    service_client::log_tail().await
}

#[tauri::command]
pub async fn clear_vpn_log() -> Result<(), String> {
    service_client::clear_log().await
}

#[tauri::command]
pub async fn read_clipboard() -> Result<String, String> {
    Err("use navigator.clipboard on Windows".into())
}

#[tauri::command]
pub async fn set_status_bar(_light: bool) -> Result<(), String> {
    Ok(())
}

#[tauri::command]
pub async fn notifications_enabled() -> bool {
    true
}

#[tauri::command]
pub async fn open_notification_settings() -> Result<(), String> {
    Ok(())
}

#[tauri::command]
pub async fn tcp_ping_host(
    host: String,
    port: u16,
    timeout_ms: Option<u32>,
) -> Result<u32, String> {
    let started = Instant::now();
    tokio::time::timeout(
        Duration::from_millis(timeout_ms.unwrap_or(2500) as u64),
        tokio::net::TcpStream::connect((host.as_str(), port)),
    )
    .await
    .map_err(|_| "TCP ping timed out".to_string())?
    .map_err(|error| format!("TCP ping failed: {error}"))?;
    Ok(started.elapsed().as_millis().min(u128::from(u32::MAX)) as u32)
}

fn resolve_app_selectors(paths: &[String]) -> Result<Vec<AppSelector>, String> {
    let mut unique = BTreeSet::new();
    let mut selectors = Vec::new();
    for raw in paths
        .iter()
        .map(|path| path.trim())
        .filter(|path| !path.is_empty())
    {
        let canonical = std::fs::canonicalize(raw)
            .map_err(|error| format!("cannot resolve split-tunnel app {raw}: {error}"))?;
        if !canonical.is_file() {
            return Err(format!(
                "split-tunnel app is not a file: {}",
                canonical.display()
            ));
        }
        let canonical = strip_verbatim_prefix(canonical);
        let basename = canonical
            .file_name()
            .and_then(|name| name.to_str())
            .filter(|name| !name.is_empty())
            .ok_or_else(|| format!("split-tunnel app has no executable name: {raw}"))?
            .to_string();
        let canonical_path = canonical.to_string_lossy().into_owned();
        if unique.insert(canonical_path.to_ascii_lowercase()) {
            selectors.push(AppSelector {
                canonical_path,
                basename,
            });
        }
    }
    Ok(selectors)
}

fn strip_verbatim_prefix(path: PathBuf) -> PathBuf {
    let value = path.to_string_lossy();
    value
        .strip_prefix(r"\\?\")
        .map(PathBuf::from)
        .unwrap_or(path)
}

async fn resolve_server_endpoints(
    server: &VlessServer,
) -> Result<Vec<std::net::SocketAddr>, String> {
    let mut endpoints = BTreeSet::new();
    for (host, port) in server_endpoints(server) {
        let resolved = tokio::net::lookup_host((host.as_str(), port))
            .await
            .map_err(|error| format!("could not resolve VPN endpoint {host}:{port}: {error}"))?;
        endpoints.extend(resolved);
    }
    if endpoints.is_empty() {
        return Err(format!(
            "VPN location {} did not resolve to an address",
            server.label
        ));
    }
    if endpoints.len() > 64 {
        return Err(format!(
            "VPN location resolves to {} addresses; the safe limit is 64",
            endpoints.len()
        ));
    }
    Ok(endpoints.into_iter().collect())
}

fn validation_placeholder_ports(count: usize) -> Result<Vec<u16>, String> {
    if !(1..=64).contains(&count) {
        return Err(format!("invalid validation path count: {count}"));
    }
    Ok((0..count).map(|index| 20_810 + index as u16).collect())
}

pub(crate) fn teardown_on_exit(_app: &tauri::AppHandle) {
    // The Windows service owns the tunnel and intentionally outlives the GUI.
}
