use std::path::PathBuf;

use serde_json::json;
use varmlen_service_core::runtime::{
    inspect_native_tun_config, inspect_validation_config, AssetArch, PolicyMode, PolicySpec,
    RuntimeLayout, DNS_FILTER_WEIGHT, LOOPBACK_FILTER_WEIGHT, XRAY_FILTER_WEIGHT,
};

fn native_config() -> String {
    json!({
        "inbounds": [{
            "tag": "tun-in",
            "protocol": "tun",
            "settings": {
                "name": "Varmlen",
                "desc": "Varmlen",
                "mtu": 1500,
                "gateway": [
                    "10.255.0.1/30",
                    "fd00:7661:726d:6c65::1/64"
                ],
                "dns": ["1.1.1.1"],
                "autoSystemRoutingTable": ["0.0.0.0/0", "::/0"],
                "autoOutboundsInterface": "auto"
            }
        }],
        "outbounds": [{"tag": "proxy", "protocol": "vless"}]
    })
    .to_string()
}

#[test]
fn native_tun_requires_dual_stack_routes_and_explicit_dns() {
    let inspected = inspect_native_tun_config(&native_config()).expect("valid native TUN");
    assert_eq!(inspected.adapter_name, "Varmlen");
    assert_eq!(inspected.adapter_description, "Varmlen");
    assert!(inspected.has_ipv4_gateway);
    assert!(inspected.has_ipv6_gateway);
    assert_eq!(inspected.dns_servers, vec!["1.1.1.1"]);

    let mut missing_ipv6: serde_json::Value =
        serde_json::from_str(&native_config()).expect("fixture JSON");
    missing_ipv6["inbounds"][0]["settings"]["autoSystemRoutingTable"] = json!(["0.0.0.0/0"]);
    assert!(inspect_native_tun_config(&missing_ipv6.to_string())
        .unwrap_err()
        .contains("IPv6"));

    let mut missing_dns: serde_json::Value =
        serde_json::from_str(&native_config()).expect("fixture JSON");
    missing_dns["inbounds"][0]["settings"]["dns"] = json!([]);
    assert!(inspect_native_tun_config(&missing_dns.to_string())
        .unwrap_err()
        .contains("DNS"));
}

#[test]
fn validation_config_must_only_listen_on_loopback_and_must_not_create_tun() {
    let valid = json!({
        "inbounds": [{
            "tag": "validation",
            "listen": "127.0.0.1",
            "port": 2081,
            "protocol": "socks"
        }]
    })
    .to_string();
    let inspected = inspect_validation_config(&valid).expect("loopback validation");
    assert_eq!(inspected.socks_port, 2081);

    let public_listener = valid.replace("127.0.0.1", "0.0.0.0");
    assert!(inspect_validation_config(&public_listener)
        .unwrap_err()
        .contains("loopback"));

    let tun = json!({
        "inbounds": [{"protocol": "tun", "settings": {"name": "bad"}}]
    })
    .to_string();
    assert!(inspect_validation_config(&tun).unwrap_err().contains("TUN"));
}

#[test]
fn runtime_layout_never_resolves_privileged_binaries_from_user_state() {
    let layout = RuntimeLayout::from_service_executable(
        PathBuf::from(r"C:\Program Files\Varmlen\varmlen-service.exe"),
        PathBuf::from(r"C:\ProgramData\Varmlen"),
    )
    .expect("layout");

    assert_eq!(
        layout.xray_executable,
        PathBuf::from(r"C:\Program Files\Varmlen\xray.exe")
    );
    assert_eq!(
        layout.wintun_library,
        PathBuf::from(r"C:\Program Files\Varmlen\wintun.dll")
    );
    assert_eq!(
        layout.desired_state,
        PathBuf::from(r"C:\ProgramData\Varmlen\desired-state.bin")
    );
}

#[test]
fn architecture_assets_follow_the_real_target() {
    let x64 = AssetArch::from_target("x86_64-pc-windows-msvc").expect("x64");
    assert_eq!(x64.xray_archive(), "Xray-windows-64.zip");
    assert_eq!(x64.wintun_directory(), "amd64");

    let arm64 = AssetArch::from_target("aarch64-pc-windows-msvc").expect("arm64");
    assert_eq!(arm64.xray_archive(), "Xray-windows-arm64-v8a.zip");
    assert_eq!(arm64.wintun_directory(), "arm64");

    assert!(AssetArch::from_target("i686-pc-windows-msvc").is_err());
}

#[test]
fn connected_policy_keeps_dns_above_xray_and_blocks_non_tun_interfaces() {
    let policy = PolicySpec {
        mode: PolicyMode::Connected { tun_luid: 42 },
        allow_lan: true,
        xray_path: PathBuf::from(r"C:\Program Files\Varmlen\xray.exe"),
        excluded_apps: Vec::new(),
    };
    let filters = policy.filters();

    assert!(LOOPBACK_FILTER_WEIGHT > DNS_FILTER_WEIGHT);
    assert!(DNS_FILTER_WEIGHT > XRAY_FILTER_WEIGHT);
    assert!(filters.iter().any(|filter| filter.name == "block-dns-v4"));
    assert!(filters.iter().any(|filter| filter.name == "block-dns-v6"));
    assert!(filters
        .iter()
        .any(|filter| filter.name == "block-outside-tun-v4"));
    assert!(filters.iter().any(|filter| filter.name == "permit-lan-v6"));
    assert!(filters.iter().all(|filter| filter.persistent));
}

#[test]
fn hold_policy_has_no_tun_escape_and_lan_never_bypasses_dns_block() {
    let policy = PolicySpec {
        mode: PolicyMode::Hold,
        allow_lan: true,
        xray_path: PathBuf::from(r"C:\Program Files\Varmlen\xray.exe"),
        excluded_apps: Vec::new(),
    };
    let filters = policy.filters();

    assert!(filters.iter().any(|filter| filter.name == "block-all-v4"));
    assert!(filters.iter().any(|filter| filter.name == "block-all-v6"));
    assert!(!filters
        .iter()
        .any(|filter| filter.name.starts_with("permit-lan")));
    assert!(filters.iter().any(|filter| filter.name == "block-dns-v4"));
    assert!(filters.iter().any(|filter| filter.name == "block-dns-v6"));
}
