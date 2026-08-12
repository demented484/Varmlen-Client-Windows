use varmlen_service::core_manager::{
    parse_releases, select_release_asset, version_cmp, xray_asset_name, CoreManager,
};
use varmlen_service_core::runtime::RuntimeLayout;

fn temporary_directory(label: &str) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!(
        "varmlen-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&path).unwrap();
    path
}

fn runtime_layout(root: &std::path::Path) -> RuntimeLayout {
    let install_dir = root.join("install");
    let state_dir = root.join("state");
    std::fs::create_dir_all(&install_dir).unwrap();
    std::fs::create_dir_all(&state_dir).unwrap();
    RuntimeLayout {
        xray_executable: install_dir.join("xray.exe"),
        wintun_library: install_dir.join("wintun.dll"),
        geoip_database: install_dir.join("geoip.dat"),
        geosite_database: install_dir.join("geosite.dat"),
        desired_state: state_dir.join("desired-state.bin"),
        active_config: state_dir.join("active.json"),
        candidate_config: state_dir.join("candidate.json"),
        validation_config: state_dir.join("validation.json"),
        log_file: state_dir.join("xray.log"),
        install_dir,
        state_dir,
    }
}

const RELEASES: &str = r#"[
  {
    "tag_name": "v26.7.28",
    "name": "Xray-core v26.7.28",
    "published_at": "2026-07-28T08:00:45Z",
    "prerelease": true,
    "assets": [
      {
        "name": "Xray-windows-64.zip",
        "browser_download_url": "https://github.com/XTLS/Xray-core/releases/download/v26.7.28/Xray-windows-64.zip",
        "size": 20913304,
        "digest": "sha256:d004c39288ce9ada487c6f398c7c545f7d749e44bdfdd59dbc9f865afba4e1ad"
      },
      {
        "name": "Xray-windows-arm64-v8a.zip",
        "browser_download_url": "https://github.com/XTLS/Xray-core/releases/download/v26.7.28/Xray-windows-arm64-v8a.zip",
        "size": 19316452,
        "digest": "sha256:35d4ed6ec21224fb22b07c2c3f672e2350cd536f2c74d309150175a76365ea88"
      }
    ]
  }
]"#;

#[test]
fn windows_asset_selection_supports_x64_and_arm64() {
    assert_eq!(xray_asset_name("x86_64").unwrap(), "Xray-windows-64.zip");
    assert_eq!(
        xray_asset_name("aarch64").unwrap(),
        "Xray-windows-arm64-v8a.zip"
    );
    assert!(xray_asset_name("x86").is_err());
}

#[test]
fn release_parser_keeps_prereleases_available_for_manual_core_swap() {
    let releases = parse_releases(RELEASES).unwrap();
    assert_eq!(releases.len(), 1);
    assert_eq!(releases[0].tag, "26.7.28");
    assert!(releases[0].prerelease);
}

#[test]
fn selected_asset_requires_an_official_https_url_and_sha256_digest() {
    let asset = select_release_asset(RELEASES, "26.7.28", "x86_64").unwrap();
    assert_eq!(asset.name, "Xray-windows-64.zip");
    assert_eq!(asset.size, 20_913_304);
    assert_eq!(asset.sha256.len(), 64);

    let missing_digest = RELEASES.replace(
        "sha256:d004c39288ce9ada487c6f398c7c545f7d749e44bdfdd59dbc9f865afba4e1ad",
        "",
    );
    assert!(select_release_asset(&missing_digest, "26.7.28", "x86_64").is_err());

    let foreign_host = RELEASES.replace("github.com/XTLS", "example.com/XTLS");
    assert!(select_release_asset(&foreign_host, "26.7.28", "x86_64").is_err());
}

#[test]
fn numeric_versions_sort_without_lexicographic_regressions() {
    assert!(version_cmp("26.10.1", "26.9.30").is_gt());
    assert!(version_cmp("26.7.28", "26.7.28").is_eq());
}

#[test]
fn switched_cores_receive_an_adjacent_complete_windows_runtime() {
    let root = temporary_directory("core-runtime");
    let layout = runtime_layout(&root);
    for (path, contents) in [
        (&layout.xray_executable, b"bundled-xray".as_slice()),
        (&layout.wintun_library, b"wintun".as_slice()),
        (&layout.geoip_database, b"geoip".as_slice()),
        (&layout.geosite_database, b"geosite".as_slice()),
    ] {
        std::fs::write(path, contents).unwrap();
    }
    let core_directory = layout.state_dir.join("cores/xray/26.3.27");
    std::fs::create_dir_all(&core_directory).unwrap();
    std::fs::write(core_directory.join("xray.exe"), b"selected-xray").unwrap();

    let selected = CoreManager::new(layout.clone())
        .runtime_layout("26.3.27")
        .expect("complete selected runtime");

    assert_eq!(selected.install_dir, core_directory);
    assert_eq!(
        selected.xray_executable,
        selected.install_dir.join("xray.exe")
    );
    assert_eq!(
        selected.wintun_library,
        selected.install_dir.join("wintun.dll")
    );
    assert_eq!(std::fs::read(&selected.wintun_library).unwrap(), b"wintun");
    assert_eq!(std::fs::read(&selected.geoip_database).unwrap(), b"geoip");
    assert_eq!(
        std::fs::read(&selected.geosite_database).unwrap(),
        b"geosite"
    );
    assert_eq!(selected.active_config, layout.active_config);
    assert_eq!(selected.desired_state, layout.desired_state);

    std::fs::remove_dir_all(root).unwrap();
}
