use serde::Serialize;

pub const BUNDLED_XRAY_VERSION: &str = "26.3.27";

#[derive(Serialize, Clone)]
pub struct InstalledVersion {
    pub tag: String,
    pub active: bool,
    pub bundled: bool,
}

#[derive(Serialize)]
pub struct CoreInfo {
    pub installed: Vec<InstalledVersion>,
    pub active: Option<String>,
    pub latest: Option<String>,
    pub has_update: bool,
}

#[derive(Serialize)]
pub struct CoreRelease {
    pub tag: String,
    pub name: String,
    pub date: Option<String>,
    pub prerelease: bool,
}

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
    Ok(CoreInfo {
        installed: vec![InstalledVersion {
            tag: BUNDLED_XRAY_VERSION.into(),
            active: true,
            bundled: true,
        }],
        active: Some(BUNDLED_XRAY_VERSION.into()),
        // The privileged service deliberately runs the installer-pinned core.
        // Replacing it from an unprivileged GUI would defeat asset integrity.
        latest: Some(BUNDLED_XRAY_VERSION.into()),
        has_update: false,
    })
}

#[tauri::command]
pub async fn list_core_releases(kind: String) -> Result<Vec<CoreRelease>, String> {
    validate_kind(&kind)?;
    Ok(vec![CoreRelease {
        tag: BUNDLED_XRAY_VERSION.into(),
        name: format!("Xray {BUNDLED_XRAY_VERSION} (bundled)"),
        date: None,
        prerelease: false,
    }])
}

#[tauri::command]
pub async fn core_install(kind: String, _version: Option<String>) -> Result<String, String> {
    validate_kind(&kind)?;
    Err("Windows core updates are delivered through signed Varmlen installers".into())
}

#[tauri::command]
pub async fn core_activate(kind: String, tag: String) -> Result<(), String> {
    validate_kind(&kind)?;
    if tag.trim_start_matches('v') == BUNDLED_XRAY_VERSION {
        Ok(())
    } else {
        Err("this Xray version is not bundled with the installed service".into())
    }
}

#[tauri::command]
pub async fn core_uninstall(kind: String, _tag: String) -> Result<(), String> {
    validate_kind(&kind)?;
    Err("the privileged Windows core can only be removed by uninstalling Varmlen".into())
}
