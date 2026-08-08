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
    app_from_path(Path::new(&path), None)
}

#[cfg(windows)]
fn app_from_path(path: &Path, display_name: Option<&str>) -> Option<InstalledApp> {
    let path = std::fs::canonicalize(path).ok()?;
    if !is_executable(&path) {
        return None;
    }
    let path = strip_verbatim_prefix(path);
    let fallback_name = path
        .file_stem()
        .and_then(|name| name.to_str())
        .unwrap_or("Application");
    let name = display_name
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .unwrap_or(fallback_name)
        .to_string();
    Some(InstalledApp {
        id: path.to_string_lossy().into_owned(),
        name,
        icon: executable_icon(&path),
    })
}

#[cfg(not(windows))]
fn app_from_path(_path: &Path, _display_name: Option<&str>) -> Option<InstalledApp> {
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
        tokio::task::spawn_blocking(windows_installed_apps)
            .await
            .unwrap_or_default()
    }
    #[cfg(not(windows))]
    Vec::new()
}

#[cfg(windows)]
fn windows_installed_apps() -> Vec<InstalledApp> {
    use std::collections::BTreeMap;

    let mut applications = BTreeMap::<String, InstalledApp>::new();
    collect_app_paths(&mut applications);
    collect_uninstall_entries(&mut applications);
    let mut applications = applications.into_values().collect::<Vec<_>>();
    applications.sort_by(|left, right| {
        left.name
            .to_lowercase()
            .cmp(&right.name.to_lowercase())
            .then_with(|| left.id.to_lowercase().cmp(&right.id.to_lowercase()))
    });
    applications
}

#[cfg(windows)]
fn collect_app_paths(applications: &mut std::collections::BTreeMap<String, InstalledApp>) {
    use winreg::{
        enums::{
            HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ, KEY_WOW64_32KEY, KEY_WOW64_64KEY,
        },
        RegKey,
    };

    for hive in [HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE] {
        let root = RegKey::predef(hive);
        for view in [KEY_WOW64_64KEY, KEY_WOW64_32KEY] {
            let Ok(paths) = root.open_subkey_with_flags(
                r"Software\Microsoft\Windows\CurrentVersion\App Paths",
                KEY_READ | view,
            ) else {
                continue;
            };
            for key_name in paths.enum_keys().flatten() {
                let Ok(key) = paths.open_subkey_with_flags(&key_name, KEY_READ | view) else {
                    continue;
                };
                let Ok(path) = key.get_value::<String, _>("") else {
                    continue;
                };
                insert_app(
                    applications,
                    app_from_path(Path::new(path.trim_matches('"')), None),
                );
            }
        }
    }
}

#[cfg(windows)]
fn collect_uninstall_entries(applications: &mut std::collections::BTreeMap<String, InstalledApp>) {
    use winreg::{
        enums::{
            HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ, KEY_WOW64_32KEY, KEY_WOW64_64KEY,
        },
        RegKey,
    };

    for hive in [HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE] {
        let root = RegKey::predef(hive);
        for view in [KEY_WOW64_64KEY, KEY_WOW64_32KEY] {
            let Ok(uninstall) = root.open_subkey_with_flags(
                r"Software\Microsoft\Windows\CurrentVersion\Uninstall",
                KEY_READ | view,
            ) else {
                continue;
            };
            for key_name in uninstall.enum_keys().flatten() {
                let Ok(key) = uninstall.open_subkey_with_flags(&key_name, KEY_READ | view) else {
                    continue;
                };
                let Ok(display_name) = key.get_value::<String, _>("DisplayName") else {
                    continue;
                };
                let display_icon = key
                    .get_value::<String, _>("DisplayIcon")
                    .ok()
                    .and_then(|value| executable_from_display_icon(&value));
                let install_candidate = key
                    .get_value::<String, _>("InstallLocation")
                    .ok()
                    .and_then(|location| {
                        find_primary_executable(
                            Path::new(location.trim_matches('"')),
                            &display_name,
                        )
                    });
                insert_app(
                    applications,
                    display_icon
                        .or(install_candidate)
                        .and_then(|path| app_from_path(&path, Some(&display_name))),
                );
            }
        }
    }
}

#[cfg(windows)]
fn insert_app(
    applications: &mut std::collections::BTreeMap<String, InstalledApp>,
    app: Option<InstalledApp>,
) {
    if let Some(app) = app {
        applications
            .entry(app.id.to_ascii_lowercase())
            .or_insert(app);
    }
}

#[cfg(windows)]
fn executable_from_display_icon(value: &str) -> Option<PathBuf> {
    let value = value.trim();
    let path = if let Some(quoted) = value.strip_prefix('"') {
        quoted.split_once('"').map(|(path, _)| path)?
    } else {
        value.rsplit_once(',').map_or(value, |(path, suffix)| {
            if suffix.trim().parse::<i32>().is_ok() {
                path
            } else {
                value
            }
        })
    };
    let path = PathBuf::from(path.trim());
    is_executable(&path).then_some(path)
}

#[cfg(windows)]
fn find_primary_executable(directory: &Path, display_name: &str) -> Option<PathBuf> {
    if !directory.is_dir() {
        return None;
    }
    let wanted = normalized_name(display_name);
    let mut candidates = std::fs::read_dir(directory)
        .ok()?
        .flatten()
        .take(128)
        .map(|entry| entry.path())
        .filter(|path| is_executable(path))
        .filter(|path| {
            let stem = path
                .file_stem()
                .and_then(|stem| stem.to_str())
                .unwrap_or_default()
                .to_ascii_lowercase();
            !["unins", "uninstall", "update", "crash", "report"]
                .iter()
                .any(|excluded| stem.contains(excluded))
        })
        .collect::<Vec<_>>();
    candidates.sort_by_key(|path| {
        let stem = normalized_name(
            path.file_stem()
                .and_then(|stem| stem.to_str())
                .unwrap_or_default(),
        );
        (stem != wanted, stem.len().abs_diff(wanted.len()), stem)
    });
    candidates.into_iter().next()
}

#[cfg(windows)]
fn normalized_name(value: &str) -> String {
    value
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

#[cfg(windows)]
fn executable_icon(path: &Path) -> Option<String> {
    use windows_icons::{get_icon_base64_by_path_with_size, IconSize};

    get_icon_base64_by_path_with_size(path, IconSize::Medium)
        .ok()
        .map(|encoded| format!("data:image/png;base64,{encoded}"))
}

#[cfg(windows)]
fn is_executable(path: &Path) -> bool {
    path.is_file()
        && path
            .extension()
            .and_then(|extension| extension.to_str())
            .is_some_and(|extension| extension.eq_ignore_ascii_case("exe"))
}

#[cfg(windows)]
fn strip_verbatim_prefix(path: PathBuf) -> PathBuf {
    let value = path.to_string_lossy();
    value
        .strip_prefix(r"\\?\")
        .map(PathBuf::from)
        .unwrap_or(path)
}
