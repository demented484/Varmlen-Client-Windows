use std::path::PathBuf;

use varmlen_service_core::runtime::{
    FilterAction, FilterCondition, IpFamily, PolicyFilter, PolicyMode, PolicySpec,
};

pub const PROVIDER_KEY: u128 = 0x56524d4c_454e_4000_a110_000000000001;
pub const SUBLAYER_KEY: u128 = 0x56524d4c_454e_4000_a110_000000000002;
const FILTER_NAMESPACE: u64 = 0x5652_4d4c_454e_4600;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompiledCondition {
    Loopback,
    NotLoopback,
    Application(PathBuf),
    RemotePort(u16),
    InterfaceNot(u64),
    RemoteNetwork(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledRule {
    pub key: u128,
    pub name: String,
    pub family: IpFamily,
    pub action: FilterAction,
    pub weight: u64,
    pub conditions: Vec<CompiledCondition>,
    pub persistent: bool,
}

pub fn compile_policy(spec: &PolicySpec) -> Result<Vec<CompiledRule>, String> {
    if spec.xray_path.as_os_str().is_empty() {
        return Err("WFP policy needs an absolute Xray path".into());
    }
    if matches!(spec.mode, PolicyMode::Connected { tun_luid: 0 }) {
        return Err("connected WFP policy needs a nonzero TUN LUID".into());
    }

    let mut compiled = Vec::new();
    for filter in spec.filters() {
        expand_filter(filter, &mut compiled)?;
    }
    Ok(compiled)
}

fn expand_filter(filter: PolicyFilter, output: &mut Vec<CompiledRule>) -> Result<(), String> {
    let network_condition = filter
        .conditions
        .iter()
        .position(|condition| matches!(condition, FilterCondition::RemoteNetworks(_)));
    if let Some(index) = network_condition {
        let FilterCondition::RemoteNetworks(networks) = &filter.conditions[index] else {
            unreachable!("condition position checked above")
        };
        if networks.is_empty() {
            return Err(format!("{} has no remote networks", filter.name));
        }
        for (network_index, network) in networks.iter().enumerate() {
            let mut conditions = filter
                .conditions
                .iter()
                .enumerate()
                .filter(|(condition_index, _)| *condition_index != index)
                .map(|(_, condition)| compile_condition(condition))
                .collect::<Result<Vec<_>, _>>()?;
            conditions.push(CompiledCondition::RemoteNetwork(network.clone()));
            let name = format!("{}-{}", filter.name, network_index + 1);
            output.push(compiled_rule(&filter, name, conditions));
        }
    } else {
        let conditions = filter
            .conditions
            .iter()
            .map(compile_condition)
            .collect::<Result<Vec<_>, _>>()?;
        output.push(compiled_rule(&filter, filter.name.clone(), conditions));
    }
    Ok(())
}

fn compiled_rule(
    filter: &PolicyFilter,
    name: String,
    conditions: Vec<CompiledCondition>,
) -> CompiledRule {
    let key_material = format!("{:?}:{name}", filter.family);
    CompiledRule {
        key: ((FILTER_NAMESPACE as u128) << 64) | stable_hash(key_material.as_bytes()) as u128,
        name,
        family: filter.family,
        action: filter.action,
        weight: filter.weight,
        conditions,
        persistent: filter.persistent,
    }
}

fn compile_condition(condition: &FilterCondition) -> Result<CompiledCondition, String> {
    Ok(match condition {
        FilterCondition::Loopback => CompiledCondition::Loopback,
        FilterCondition::NotLoopback => CompiledCondition::NotLoopback,
        FilterCondition::Application(path) => {
            if path.as_os_str().is_empty() {
                return Err("application filter has an empty path".into());
            }
            CompiledCondition::Application(path.clone())
        }
        FilterCondition::RemotePort(port) if *port != 0 => CompiledCondition::RemotePort(*port),
        FilterCondition::RemotePort(_) => return Err("remote port filter uses port zero".into()),
        FilterCondition::InterfaceNot(luid) if *luid != 0 => CompiledCondition::InterfaceNot(*luid),
        FilterCondition::InterfaceNot(_) => return Err("interface filter uses a zero LUID".into()),
        FilterCondition::RemoteNetworks(_) => {
            return Err("remote network list must be expanded first".into())
        }
    })
}

fn stable_hash(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}
