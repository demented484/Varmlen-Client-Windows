use std::path::Path;
#[cfg(windows)]
use std::path::PathBuf;

#[cfg(windows)]
use base64::Engine as _;
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
    collect_xbox_games(&mut applications);
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
                let install_location = key
                    .get_value::<String, _>("InstallLocation")
                    .ok()
                    .map(|location| PathBuf::from(location.trim_matches('"')))
                    .filter(|location| location.is_dir());

                // A game is a process family, not only its launcher. Represent
                // Steam/Xbox installs by their folder so Xray's trailing-slash
                // process matcher covers multiplayer, campaign and helper child
                // binaries without showing a misleading installer executable.
                if let Some(location) = install_location
                    .as_deref()
                    .filter(|location| is_game_install_directory(location))
                {
                    insert_app(
                        applications,
                        app_from_directory(location, Some(&display_name)),
                    );
                    continue;
                }

                let install_candidate = install_location
                    .as_deref()
                    .and_then(|location| find_primary_executable(location, &display_name));
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
fn collect_xbox_games(applications: &mut std::collections::BTreeMap<String, InstalledApp>) {
    use windows::Win32::Storage::FileSystem::GetLogicalDrives;

    // GetLogicalDrives returns one bit per drive letter. Xbox installs use an
    // accessible `<drive>:\XboxGames\<title>\Content` tree and are commonly
    // absent from the classic Uninstall/App Paths registry views.
    let drives = unsafe { GetLogicalDrives() };
    for letter in b'A'..=b'Z' {
        let bit = 1u32 << u32::from(letter - b'A');
        if drives & bit == 0 {
            continue;
        }
        let xbox_root = PathBuf::from(format!("{}:\\XboxGames", letter as char));
        let Ok(entries) = std::fs::read_dir(&xbox_root) else {
            continue;
        };
        for entry in entries.flatten().take(512) {
            let game_root = entry.path();
            if !game_root.is_dir() {
                continue;
            }
            let content = game_root.join("Content");
            let selector = if content.is_dir() {
                &content
            } else {
                &game_root
            };
            let fallback = game_root
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("Xbox game");
            let name = xbox_display_name(selector).unwrap_or_else(|| fallback.to_string());
            insert_app(
                applications,
                app_from_directory(selector, Some(name.as_str())),
            );
        }
    }
}

#[cfg(windows)]
fn app_from_directory(directory: &Path, display_name: Option<&str>) -> Option<InstalledApp> {
    let directory = strip_verbatim_prefix(std::fs::canonicalize(directory).ok()?);
    if !directory.is_dir() {
        return None;
    }
    let fallback_name = directory
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("Application folder");
    let name = display_name
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .unwrap_or(fallback_name)
        .to_string();
    let icon = directory_icon(&directory).or_else(|| {
        find_primary_executable(&directory, &name).and_then(|path| executable_icon(&path))
    });
    Some(InstalledApp {
        id: directory.to_string_lossy().into_owned(),
        name,
        icon,
    })
}

#[cfg(windows)]
fn xbox_display_name(directory: &Path) -> Option<String> {
    let config = std::fs::read_to_string(directory.join("MicrosoftGame.Config")).ok()?;
    let marker = "DefaultDisplayName=\"";
    let value = config.split_once(marker)?.1.split_once('"')?.0.trim();
    (!value.is_empty()).then(|| {
        value
            .replace("&amp;", "&")
            .replace("&quot;", "\"")
            .replace("&apos;", "'")
    })
}

#[cfg(windows)]
fn directory_icon(directory: &Path) -> Option<String> {
    for file_name in [
        "Square44x44Logo.png",
        "Square150x150Logo.png",
        "StoreLogo.png",
    ] {
        let path = directory.join(file_name);
        let Ok(metadata) = std::fs::metadata(&path) else {
            continue;
        };
        if !metadata.is_file() || metadata.len() == 0 || metadata.len() > 512 * 1024 {
            continue;
        }
        let bytes = std::fs::read(path).ok()?;
        let encoded = base64::engine::general_purpose::STANDARD.encode(bytes);
        return Some(format!("data:image/png;base64,{encoded}"));
    }
    None
}

#[cfg(windows)]
fn is_game_install_directory(directory: &Path) -> bool {
    let path = directory
        .to_string_lossy()
        .replace('/', "\\")
        .to_ascii_lowercase();
    path.contains(r"\steamapps\common\")
        || path.contains(r"\xboxgames\")
        || path.contains(r"\modifiablewindowsapps\")
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
    let acronym = display_name
        .split(|character: char| !character.is_ascii_alphanumeric())
        .filter(|word| !word.is_empty())
        .filter_map(|word| word.chars().next())
        .flat_map(char::to_lowercase)
        .collect::<String>();
    let mut candidates = Vec::new();
    collect_executables(directory, 0, 3, &mut candidates);
    candidates.retain(|path| !is_helper_executable(path));
    candidates.sort_by_key(|path| {
        let stem = normalized_name(
            path.file_stem()
                .and_then(|stem| stem.to_str())
                .unwrap_or_default(),
        );
        let relationship = if stem == wanted {
            0
        } else if stem.len() >= 3 && (wanted.contains(&stem) || stem.contains(&wanted)) {
            1
        } else if !acronym.is_empty()
            && (stem == acronym || stem.starts_with(&acronym) || acronym.starts_with(&stem))
        {
            2
        } else {
            3
        };
        (
            relationship,
            path.components().count(),
            stem.len().abs_diff(wanted.len()),
            stem,
        )
    });
    candidates.into_iter().next()
}

#[cfg(windows)]
fn collect_executables(
    directory: &Path,
    depth: usize,
    max_depth: usize,
    output: &mut Vec<PathBuf>,
) {
    if depth > max_depth || output.len() >= 512 {
        return;
    }
    let Ok(entries) = std::fs::read_dir(directory) else {
        return;
    };
    for entry in entries.flatten().take(512) {
        if output.len() >= 512 {
            break;
        }
        let path = entry.path();
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if file_type.is_file() && is_executable(&path) {
            output.push(path);
        } else if file_type.is_dir() && !file_type.is_symlink() {
            collect_executables(&path, depth + 1, max_depth, output);
        }
    }
}

#[cfg(windows)]
fn is_helper_executable(path: &Path) -> bool {
    let stem = path
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    [
        "bootstrapper",
        "crash",
        "install",
        "cleaner",
        "report",
        "setup",
        "unins",
        "update",
        "redistributable",
        "vcredist",
    ]
    .iter()
    .any(|excluded| stem.contains(excluded))
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
