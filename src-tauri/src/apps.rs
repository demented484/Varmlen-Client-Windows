use std::path::Path;
#[cfg(windows)]
use std::path::PathBuf;

use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct InstalledApp {
    pub id: String,
    pub name: String,
    pub icon: Option<String>,
}

#[tauri::command]
pub fn app_from_file(path: String) -> Option<InstalledApp> {
    app_from_path(Path::new(&path))
}

#[cfg(windows)]
fn app_from_path(path: &Path) -> Option<InstalledApp> {
    let path = std::fs::canonicalize(path).ok()?;
    if !path.is_file()
        || !path
            .extension()
            .and_then(|extension| extension.to_str())
            .is_some_and(|extension| extension.eq_ignore_ascii_case("exe"))
    {
        return None;
    }
    let path = strip_verbatim_prefix(path);
    let name = path
        .file_stem()
        .and_then(|name| name.to_str())
        .unwrap_or("Application")
        .to_string();
    Some(InstalledApp {
        id: path.to_string_lossy().into_owned(),
        name,
        icon: None,
    })
}

#[cfg(not(windows))]
fn app_from_path(_path: &Path) -> Option<InstalledApp> {
    None
}

#[tauri::command]
pub async fn pick_file() -> Option<String> {
    #[cfg(windows)]
    {
        rfd::AsyncFileDialog::new()
            .add_filter("Windows applications", &["exe"])
            .pick_file()
            .await
            .map(|file| file.path().to_string_lossy().into_owned())
    }
    #[cfg(not(windows))]
    None
}

#[tauri::command]
pub async fn list_installed_apps() -> Vec<InstalledApp> {
    #[cfg(windows)]
    {
        windows_app_paths()
    }
    #[cfg(not(windows))]
    Vec::new()
}

#[cfg(windows)]
fn windows_app_paths() -> Vec<InstalledApp> {
    use std::collections::BTreeMap;
    use winreg::{
        enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ},
        RegKey,
    };

    let mut applications = BTreeMap::<String, InstalledApp>::new();
    for hive in [HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE] {
        let root = RegKey::predef(hive);
        let Ok(paths) = root.open_subkey_with_flags(
            r"Software\Microsoft\Windows\CurrentVersion\App Paths",
            KEY_READ,
        ) else {
            continue;
        };
        for key_name in paths.enum_keys().flatten() {
            let Ok(key) = paths.open_subkey_with_flags(&key_name, KEY_READ) else {
                continue;
            };
            let Ok(path) = key.get_value::<String, _>("") else {
                continue;
            };
            let Some(app) = app_from_path(Path::new(path.trim_matches('"'))) else {
                continue;
            };
            applications
                .entry(app.id.to_ascii_lowercase())
                .or_insert(app);
        }
    }
    applications.into_values().collect()
}

#[cfg(windows)]
fn strip_verbatim_prefix(path: PathBuf) -> PathBuf {
    let value = path.to_string_lossy();
    value
        .strip_prefix(r"\\?\")
        .map(PathBuf::from)
        .unwrap_or(path)
}
