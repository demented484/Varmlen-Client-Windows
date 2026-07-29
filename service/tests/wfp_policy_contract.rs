use std::{collections::HashSet, path::PathBuf};

use varmlen_service::wfp_plan::{compile_policy, CompiledCondition, PROVIDER_KEY, SUBLAYER_KEY};
use varmlen_service_core::runtime::{IpFamily, PolicyMode, PolicySpec};

fn spec(mode: PolicyMode, allow_lan: bool) -> PolicySpec {
    PolicySpec {
        mode,
        allow_lan,
        xray_path: PathBuf::from(r"C:\Program Files\Varmlen\xray.exe"),
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
