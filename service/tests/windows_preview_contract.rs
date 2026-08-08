const BACKEND: &str = include_str!("../src/windows_backend.rs");
const VPN_BRIDGE: &str = include_str!("../../src-tauri/src/vpn.rs");
const SETTINGS_PAGE: &str = include_str!("../../src/routes/settings/+page.svelte");
const WFP: &str = include_str!("../src/windows_wfp.rs");
const PIPE: &str = include_str!("../src/pipe.rs");
const ADAPTER: &str = include_str!("../src/windows_adapter.rs");

#[test]
fn preview_connection_does_not_depend_on_user_mode_wfp_filters() {
    assert!(!BACKEND.contains("apply_policy("));
    assert!(!BACKEND.contains("wfp: WfpEngine"));
    assert!(BACKEND.contains("cleanup_persistent_policy"));
    assert!(BACKEND.contains("unexpected_failure_keep_blocked"));
    assert!(VPN_BRIDGE.contains("killswitch: false"));
    assert!(SETTINGS_PAGE.contains("settings.killswitchUnavailableWindows"));
    assert!(SETTINGS_PAGE.contains("checked={false} disabled"));
    assert!(PIPE.contains("request.killswitch = false"));
    assert!(PIPE.contains("disconnect(operation_id, false)"));
    assert!(PIPE.contains("force_disconnected(operation_id)"));
    assert!(!PIPE.contains("force_blocked(operation_id)"));
}

#[test]
fn native_tun_is_pinned_to_windows_route_and_split_selectors_stay_exact() {
    assert!(BACKEND.contains("best_outbound_interface_name"));
    assert!(BACKEND.contains("rewrite_native_outbound_interface"));
    assert!(ADAPTER.contains("GetBestInterfaceEx"));
    assert!(VPN_BRIDGE.contains("if !canonical.is_file()"));
    assert!(!VPN_BRIDGE.contains("canonical_path.push('\\\\')"));
}

#[test]
fn legacy_wfp_cleanup_uses_unrestricted_enumeration_then_filters_in_process() {
    assert!(WFP.contains("FwpmFilterCreateEnumHandle0(self.handle, None"));
    assert!(WFP.contains("*filter.providerKey == provider_key"));
    assert!(!WFP.contains("provider_filter_enum_template"));
    assert!(!WFP.contains("FwpmProviderAdd0"));
    assert!(!WFP.contains("FwpmSubLayerAdd0"));
    assert!(!WFP.contains("FwpmFilterAdd0"));
}
