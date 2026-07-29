use std::{collections::HashSet, path::PathBuf};

use varmlen_service::wfp_plan::{compile_policy, CompiledCondition, PROVIDER_KEY, SUBLAYER_KEY};
use varmlen_service_core::runtime::{IpFamily, PolicyMode, PolicySpec};

fn spec(mode: PolicyMode, allow_lan: bool) -> PolicySpec {
    PolicySpec {
        mode,
        allow_lan,
        xray_path: PathBuf::from(r"C:\Program Files\Varmlen\xray.exe"),
        excluded_apps: Vec::new(),
        apps_selective: false,
    }
}

#[test]
fn provider_and_sublayer_have_stable_nonzero_identifiers() {
    assert_ne!(PROVIDER_KEY, 0);
    assert_ne!(SUBLAYER_KEY, 0);
    assert_ne!(PROVIDER_KEY, SUBLAYER_KEY);
}

#[test]
fn compiled_connected_policy_has_unique_keys_and_dual_stack_coverage() {
    let rules = compile_policy(&spec(PolicyMode::Connected { tun_luid: 88 }, true))
        .expect("compile policy");
    let keys = rules.iter().map(|rule| rule.key).collect::<HashSet<_>>();
    assert_eq!(keys.len(), rules.len());
    assert!(rules.iter().any(|rule| rule.family == IpFamily::V4));
    assert!(rules.iter().any(|rule| rule.family == IpFamily::V6));
    assert!(rules.iter().any(|rule| {
        rule.conditions
            .contains(&CompiledCondition::InterfaceNot(88))
    }));
}

#[test]
fn every_family_has_dns_block_above_xray_permit() {
    let rules = compile_policy(&spec(PolicyMode::Connected { tun_luid: 12 }, false))
        .expect("compile policy");
    for family in [IpFamily::V4, IpFamily::V6] {
        let dns = rules
            .iter()
            .find(|rule| rule.family == family && rule.name.starts_with("block-dns"))
            .expect("DNS rule");
        let xray = rules
            .iter()
            .find(|rule| rule.family == family && rule.name.starts_with("permit-xray"))
            .expect("Xray rule");
        assert!(dns.weight > xray.weight);
        assert!(dns.conditions.contains(&CompiledCondition::RemotePort(53)));
        assert!(dns.conditions.contains(&CompiledCondition::NotLoopback));
        assert!(dns
            .conditions
            .contains(&CompiledCondition::InterfaceNot(12)));
    }
}

#[test]
fn lan_networks_expand_to_independent_filters_but_not_in_hold_mode() {
    let connected =
        compile_policy(&spec(PolicyMode::Connected { tun_luid: 3 }, true)).expect("connected");
    let lan = connected
        .iter()
        .filter(|rule| rule.name.starts_with("permit-lan"))
        .collect::<Vec<_>>();
    assert_eq!(lan.len(), 7);
    assert!(lan.iter().all(|rule| {
        rule.conditions
            .iter()
            .filter(|condition| matches!(condition, CompiledCondition::RemoteNetwork(_)))
            .count()
            == 1
    }));

    let hold = compile_policy(&spec(PolicyMode::Hold, true)).expect("hold");
    assert!(!hold.iter().any(|rule| rule.name.starts_with("permit-lan")));
    assert!(hold.iter().any(|rule| rule.name == "block-all-v4"));
    assert!(hold.iter().any(|rule| rule.name == "block-all-v6"));
}

#[test]
fn excluded_app_is_permitted_below_dns_block_and_above_default_block() {
    let mut policy = spec(PolicyMode::Connected { tun_luid: 42 }, false);
    policy.excluded_apps = vec![PathBuf::from(r"C:\Games\Counter-Strike 2\cs2.exe")];
    let rules = compile_policy(&policy).expect("policy compiles");

    let app_rules = rules
        .iter()
        .filter(|rule| rule.name.starts_with("permit-selected-app-"))
        .collect::<Vec<_>>();
    assert_eq!(app_rules.len(), 2, "one rule per IP family");
    assert!(app_rules.iter().all(|rule| {
        rule.weight < varmlen_service_core::runtime::DNS_FILTER_WEIGHT
            && rule.weight > varmlen_service_core::runtime::DEFAULT_BLOCK_FILTER_WEIGHT
            && rule.conditions.iter().any(|condition| {
                matches!(
                    condition,
                    CompiledCondition::Application(path)
                        if path.to_string_lossy().ends_with(r"\cs2.exe")
                )
            })
    }));
}

#[test]
fn selective_mode_blocks_only_selected_apps_from_bypassing_tun() {
    let mut policy = spec(PolicyMode::Connected { tun_luid: 77 }, false);
    policy.apps_selective = true;
    policy.excluded_apps = vec![PathBuf::from(r"C:\Apps\browser.exe")];
    let rules = compile_policy(&policy).expect("policy compiles");

    let selected = rules
        .iter()
        .filter(|rule| rule.name.starts_with("block-selected-app-"))
        .collect::<Vec<_>>();
    assert_eq!(selected.len(), 2);
    assert!(selected.iter().all(|rule| {
        rule.action == varmlen_service_core::runtime::FilterAction::Block
            && rule
                .conditions
                .contains(&CompiledCondition::InterfaceNot(77))
    }));
    assert!(!rules
        .iter()
        .any(|rule| rule.name.starts_with("block-outside-tun")));
}
