use varmlen_service::core_manager::{
    parse_releases, select_release_asset, version_cmp, xray_asset_name,
};

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
