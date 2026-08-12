use varmlen_protocol::{CoreCommand, CoreInfo, CoreRelease, ServiceResponse};

use crate::service_client;

fn validate_kind(kind: &str) -> Result<(), String> {
    if kind == "xray" {
        Ok(())
    } else {
        Err(format!("unknown core kind: {kind}"))
    }
}

#[tauri::command]
pub async fn core_info(kind: String) -> Result<CoreInfo, String> {
    validate_kind(&kind)?;
    match service_client::core(CoreCommand::Info).await? {
        ServiceResponse::CoreInfo(info) => Ok(info),
        _ => Err("VarmlenService returned the wrong core-info response".into()),
    }
}

#[tauri::command]
pub async fn list_core_releases(kind: String) -> Result<Vec<CoreRelease>, String> {
    validate_kind(&kind)?;
    match service_client::core(CoreCommand::ListReleases).await? {
        ServiceResponse::CoreReleases(releases) => Ok(releases),
        _ => Err("VarmlenService returned the wrong release-list response".into()),
    }
}

#[tauri::command]
pub async fn core_install(kind: String, version: Option<String>) -> Result<String, String> {
    validate_kind(&kind)?;
    match service_client::core(CoreCommand::Install { tag: version }).await? {
        ServiceResponse::CoreInstalled(tag) => Ok(tag),
        _ => Err("VarmlenService returned the wrong core-install response".into()),
    }
}

#[tauri::command]
pub async fn core_activate(kind: String, tag: String) -> Result<(), String> {
    validate_kind(&kind)?;
    match service_client::core(CoreCommand::Activate { tag }).await? {
        ServiceResponse::Ack => Ok(()),
        _ => Err("VarmlenService returned the wrong core-activate response".into()),
    }
}

#[tauri::command]
pub async fn core_uninstall(kind: String, tag: String) -> Result<(), String> {
    validate_kind(&kind)?;
    match service_client::core(CoreCommand::Uninstall { tag }).await? {
        ServiceResponse::Ack => Ok(()),
        _ => Err("VarmlenService returned the wrong core-uninstall response".into()),
    }
}
