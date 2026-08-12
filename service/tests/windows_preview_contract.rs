const BACKEND: &str = include_str!("../src/windows_backend.rs");
const VPN_BRIDGE: &str = include_str!("../../src-tauri/src/vpn.rs");
const SETTINGS_PAGE: &str = include_str!("../../src/routes/settings/+page.svelte");
const PIPE: &str = include_str!("../src/pipe.rs");
const ADAPTER: &str = include_str!("../src/windows_adapter.rs");
const ROUTES: &str = include_str!("../src/windows_routes.rs");

#[test]
fn kill_switch_reaches_the_service_and_uses_route_fallbacks() {
    assert!(BACKEND.contains("unexpected_failure_keep_blocked"));
    assert!(BACKEND.contains("install_killswitch_routes"));
    assert!(BACKEND.contains("remove_killswitch_routes"));
    assert!(VPN_BRIDGE.contains("killswitch,"));
    assert!(!VPN_BRIDGE.contains("killswitch: false"));
    assert!(SETTINGS_PAGE.contains("checked={settings.killswitch}"));
    assert!(SETTINGS_PAGE.contains("settings.setKillswitch"));
    assert!(!SETTINGS_PAGE.contains("settings.killswitchUnavailableWindows"));
    assert!(!PIPE.contains("request.killswitch = false"));
    assert!(!PIPE.contains("previous.killswitch = false"));
    assert!(PIPE.contains("force_blocked(operation_id)"));
    assert!(ROUTES.contains("LOOPBACK_INTERFACE_INDEX: &str = \"1\""));
    assert!(ROUTES.contains("format!(\"interface={interface}\")"));
}

#[test]
fn native_tun_is_pinned_to_windows_route_and_split_selectors_stay_exact() {
    assert!(BACKEND.contains("best_outbound_interface_name"));
    assert!(BACKEND.contains("rewrite_native_outbound_interface"));
    assert!(ADAPTER.contains("GetBestInterfaceEx"));
    assert!(BACKEND.contains("configure_stable_tun_network"));
    assert!(ROUTES.contains("0.0.0.0/1"));
    assert!(ROUTES.contains("128.0.0.0/1"));
    assert!(ROUTES.contains("::/1"));
    assert!(ROUTES.contains("8000::/1"));
    assert!(ROUTES.contains("store=active"));
    assert!(!ROUTES.contains("powershell"));
    assert!(VPN_BRIDGE.contains("if !canonical.is_file()"));
    assert!(!VPN_BRIDGE.contains("canonical_path.push('\\\\')"));
}

#[test]
fn connects_use_the_service_owned_active_core_without_racing_core_changes() {
    assert!(PIPE.contains("ServiceCommand::Connect(mut request)"));
    assert!(PIPE.contains("let _operation = self.core_operations.lock().await;"));
    assert!(PIPE.contains("request.xray_version = self.core_manager.active_tag();"));
}
