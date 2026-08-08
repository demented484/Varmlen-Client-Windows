use std::path::PathBuf;

use serde_json::json;
use varmlen_service_core::runtime::{
    inspect_native_tun_config, inspect_validation_config, rewrite_native_outbound_interface,
    rewrite_validation_ports, AssetArch, PolicyMode, PolicySpec, RuntimeLayout, DNS_FILTER_WEIGHT,
    LOOPBACK_FILTER_WEIGHT, XRAY_FILTER_WEIGHT,
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
fn service_pins_native_tun_to_the_windows_selected_physical_interface() {
    let rewritten = rewrite_native_outbound_interface(&native_config(), "Wi-Fi")
        .expect("service-selected physical interface");
    let value: serde_json::Value = serde_json::from_str(&rewritten).unwrap();
    assert_eq!(
        value["inbounds"][0]["settings"]["autoOutboundsInterface"],
        "Wi-Fi"
    );
    assert!(rewrite_native_outbound_interface(&native_config(), "").is_err());
    assert!(rewrite_native_outbound_interface(&native_config(), "bad\ninterface").is_err());

    let untrusted = native_config().replace(r#""auto""#, r#""attacker-selected""#);
    assert!(rewrite_native_outbound_interface(&untrusted, "Wi-Fi").is_err());
}

#[test]
fn validation_config_must_only_listen_on_loopback_and_must_not_create_tun() {
    let valid = json!({
        "inbounds": [
            {
                "tag": "validation-1",
                "listen": "127.0.0.1",
                "port": 2081,
                "protocol": "socks"
            },
            {
                "tag": "validation-2",
                "listen": "::1",
                "port": 2082,
                "protocol": "socks"
            }
        ]
    })
    .to_string();
    let inspected = inspect_validation_config(&valid).expect("loopback validation");
    assert_eq!(inspected.socks_ports, vec![2081, 2082]);

    let rewritten = rewrite_validation_ports(&valid, &[32_001, 32_002])
        .expect("service-owned validation ports");
    let inspected = inspect_validation_config(&rewritten).expect("rewritten validation config");
    assert_eq!(inspected.socks_ports, vec![32_001, 32_002]);

    let public_listener = valid.replace("127.0.0.1", "0.0.0.0");
    assert!(inspect_validation_config(&public_listener)
        .unwrap_err()
        .contains("loopback"));

    let tun = json!({
        "inbounds": [{"protocol": "tun", "settings": {"name": "bad"}}]
    })
    .to_string();
    assert!(inspect_validation_config(&tun).unwrap_err().contains("TUN"));

    let duplicate_ports = valid.replace("2082", "2081");
    assert!(inspect_validation_config(&duplicate_ports)
        .unwrap_err()
        .contains("unique"));

    let missing_listen = valid.replace(r#""listen":"127.0.0.1","#, "");
    assert!(inspect_validation_config(&missing_listen)
        .unwrap_err()
        .contains("explicit loopback"));
}

#[test]
fn privileged_native_config_rejects_extra_capabilities_and_file_paths() {
    let mut extra_inbound: serde_json::Value =
        serde_json::from_str(&native_config()).expect("fixture JSON");
    extra_inbound["inbounds"]
        .as_array_mut()
        .expect("inbounds")
        .push(json!({"listen":"0.0.0.0","port":1080,"protocol":"socks"}));
    assert!(inspect_native_tun_config(&extra_inbound.to_string())
        .unwrap_err()
        .contains("exactly one inbound"));

    let mut api: serde_json::Value = serde_json::from_str(&native_config()).expect("fixture JSON");
    api["api"] = json!({"tag":"api"});
    assert!(inspect_native_tun_config(&api.to_string())
        .unwrap_err()
        .contains("unsupported top-level field"));

    let mut file_log: serde_json::Value =
        serde_json::from_str(&native_config()).expect("fixture JSON");
    file_log["log"] = json!({"loglevel":"debug","access":"C:\\Windows\\Temp\\access.log"});
    assert!(inspect_native_tun_config(&file_log.to_string())
        .unwrap_err()
        .contains("log file paths"));

    let mut certificate: serde_json::Value =
        serde_json::from_str(&native_config()).expect("fixture JSON");
    certificate["outbounds"][0]["streamSettings"] = json!({
        "security": "tls",
        "tlsSettings": {"certificates": [{"certificateFile":"C:\\secret.pem"}]}
    });
    assert!(inspect_native_tun_config(&certificate.to_string())
        .unwrap_err()
        .contains("privileged file reference"));
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
    assert_eq!(
        layout.candidate_config,
        PathBuf::from(r"C:\ProgramData\Varmlen\candidate.json")
    );
    assert_ne!(layout.candidate_config, layout.active_config);
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
        apps_selective: false,
    };
    let filters = policy.filters();

    const {
        assert!(LOOPBACK_FILTER_WEIGHT > DNS_FILTER_WEIGHT);
        assert!(DNS_FILTER_WEIGHT > XRAY_FILTER_WEIGHT);
    }
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
        apps_selective: false,
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
