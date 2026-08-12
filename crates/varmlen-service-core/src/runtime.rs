use std::{
    collections::HashSet,
    path::{Path, PathBuf},
};

use serde_json::{Map, Value};

pub const TUN_ADAPTER_NAME: &str = "Varmlen";
pub const TUN_ADAPTER_DESCRIPTION: &str = "Varmlen";
pub const TUN_IPV4_GATEWAY: &str = "10.255.0.1/30";
pub const TUN_IPV6_GATEWAY: &str = "fd00:7661:726d:6c65::1/64";
pub const TUN_DNS: &str = "1.1.1.1";

const IPV4_DEFAULT: &str = "0.0.0.0/0";
const IPV6_DEFAULT: &str = "::/0";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeTunInspection {
    pub adapter_name: String,
    pub adapter_description: String,
    pub has_ipv4_gateway: bool,
    pub has_ipv6_gateway: bool,
    pub dns_servers: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationInspection {
    pub socks_ports: Vec<u16>,
}

pub fn inspect_native_tun_config(config: &str) -> Result<NativeTunInspection, String> {
    let root = parse_object(config, "native Xray config")?;
    reject_unknown_top_level_fields(
        &root,
        &[
            "log",
            "dns",
            "inbounds",
            "outbounds",
            "routing",
            "observatory",
            "burstObservatory",
        ],
        "native Xray config",
    )?;
    reject_log_file_paths(&root, "native Xray config")?;
    reject_privileged_file_references(&Value::Object(root.clone()))?;
    let inbounds = root
        .get("inbounds")
        .and_then(Value::as_array)
        .ok_or_else(|| "native Xray config has no inbounds array".to_string())?;
    if inbounds.len() != 1 {
        return Err("native Xray config must contain exactly one inbound".into());
    }
    let tun = inbounds
        .iter()
        .find(|inbound| inbound.get("protocol").and_then(Value::as_str) == Some("tun"))
        .ok_or_else(|| "native Xray config has no TUN inbound".to_string())?;
    if inbounds
        .iter()
        .filter(|inbound| inbound.get("protocol").and_then(Value::as_str) == Some("tun"))
        .count()
        != 1
    {
        return Err("native Xray config must contain exactly one TUN inbound".into());
    }
    let settings = tun
        .get("settings")
        .and_then(Value::as_object)
        .ok_or_else(|| "TUN inbound has no settings object".to_string())?;
    let name = required_string(settings.get("name"), "TUN adapter name")?;
    if name != TUN_ADAPTER_NAME {
        return Err(format!("TUN adapter name must be {TUN_ADAPTER_NAME}"));
    }
    let description = required_string(settings.get("desc"), "TUN adapter description")?;
    if description != TUN_ADAPTER_DESCRIPTION {
        return Err(format!(
            "TUN adapter description must be {TUN_ADAPTER_DESCRIPTION}"
        ));
    }

    let gateways = string_array(settings.get("gateway"), "TUN gateway")?;
    let has_ipv4_gateway = gateways.iter().any(|gateway| gateway == TUN_IPV4_GATEWAY);
    let has_ipv6_gateway = gateways.iter().any(|gateway| gateway == TUN_IPV6_GATEWAY);
    if !has_ipv4_gateway {
        return Err(format!(
            "TUN config is missing IPv4 gateway {TUN_IPV4_GATEWAY}"
        ));
    }
    if !has_ipv6_gateway {
        return Err(format!(
            "TUN config is missing IPv6 gateway {TUN_IPV6_GATEWAY}"
        ));
    }

    let dns_servers = string_array(settings.get("dns"), "TUN DNS")?;
    if !dns_servers.iter().any(|server| server == TUN_DNS) {
        return Err(format!("TUN DNS must include {TUN_DNS}"));
    }

    let routes = string_array(
        settings.get("autoSystemRoutingTable"),
        "TUN automatic routing table",
    )?;
    if !routes.iter().any(|route| route == IPV4_DEFAULT) {
        return Err("TUN automatic routing table is missing the IPv4 default route".into());
    }
    if !routes.iter().any(|route| route == IPV6_DEFAULT) {
        return Err("TUN automatic routing table is missing the IPv6 default route".into());
    }
    if settings
        .get("autoOutboundsInterface")
        .and_then(Value::as_str)
        != Some("auto")
    {
        return Err("TUN autoOutboundsInterface must be \"auto\"".into());
    }

    Ok(NativeTunInspection {
        adapter_name: name.to_string(),
        adapter_description: description.to_string(),
        has_ipv4_gateway,
        has_ipv6_gateway,
        dns_servers,
    })
}

/// Adapt the portable native-TUN intent to the service-owned Windows network
/// policy. The service configures addresses and routes transactionally, so it
/// strips Xray's overlapping automatic settings. Every
/// network-capable outbound is instead bound to the physical interface selected
/// by Windows before the TUN routes exist.
pub fn rewrite_native_outbound_interface(
    config: &str,
    interface_name: &str,
) -> Result<String, String> {
    inspect_native_tun_config(config)?;
    let interface_name = interface_name.trim();
    if interface_name.is_empty()
        || interface_name.len() > 256
        || interface_name.chars().any(char::is_control)
    {
        return Err("physical outbound interface name is invalid".into());
    }

    let mut root = parse_object(config, "native Xray config")?;
    let tun = root
        .get_mut("inbounds")
        .and_then(Value::as_array_mut)
        .and_then(|inbounds| {
            inbounds
                .iter_mut()
                .find(|inbound| inbound.get("protocol").and_then(Value::as_str) == Some("tun"))
        })
        .ok_or_else(|| "native Xray config has no TUN inbound".to_string())?;
    let settings = tun
        .get_mut("settings")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| "TUN inbound has no settings object".to_string())?;
    for field in [
        "desc",
        "gateway",
        "dns",
        "autoSystemRoutingTable",
        "autoOutboundsInterface",
    ] {
        settings.remove(field);
    }

    let outbounds = root
        .get_mut("outbounds")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| "native Xray config has no outbounds array".to_string())?;
    for outbound in outbounds {
        if matches!(
            outbound.get("protocol").and_then(Value::as_str),
            Some("blackhole" | "dns")
        ) {
            continue;
        }
        let outbound = outbound
            .as_object_mut()
            .ok_or_else(|| "native Xray outbound is not an object".to_string())?;
        let stream = outbound
            .entry("streamSettings")
            .or_insert_with(|| Value::Object(Map::new()))
            .as_object_mut()
            .ok_or_else(|| "native Xray streamSettings is not an object".to_string())?;
        let sockopt = stream
            .entry("sockopt")
            .or_insert_with(|| Value::Object(Map::new()))
            .as_object_mut()
            .ok_or_else(|| "native Xray sockopt is not an object".to_string())?;
        sockopt.insert(
            "interface".into(),
            Value::String(interface_name.to_string()),
        );
    }

    serde_json::to_string_pretty(&Value::Object(root))
        .map_err(|error| format!("could not serialize native Xray config: {error}"))
}

pub fn inspect_validation_config(config: &str) -> Result<ValidationInspection, String> {
    let root = parse_object(config, "validation Xray config")?;
    reject_unknown_top_level_fields(
        &root,
        &[
            "log",
            "dns",
            "inbounds",
            "outbounds",
            "routing",
            "observatory",
            "burstObservatory",
        ],
        "validation Xray config",
    )?;
    reject_log_file_paths(&root, "validation Xray config")?;
    reject_privileged_file_references(&Value::Object(root.clone()))?;
    let inbounds = root
        .get("inbounds")
        .and_then(Value::as_array)
        .ok_or_else(|| "validation Xray config has no inbounds array".to_string())?;
    if inbounds
        .iter()
        .any(|inbound| inbound.get("protocol").and_then(Value::as_str) == Some("tun"))
    {
        return Err("validation Xray config must not create a TUN adapter".into());
    }

    for inbound in inbounds {
        let Some(address) = inbound.get("listen").and_then(Value::as_str) else {
            return Err("every validation inbound must have an explicit loopback listener".into());
        };
        if !matches!(address, "127.0.0.1" | "::1") {
            return Err("every validation inbound must listen on loopback".into());
        }
    }

    let socks_ports = inbounds
        .iter()
        .filter(|inbound| inbound.get("protocol").and_then(Value::as_str) == Some("socks"))
        .map(|socks| {
            socks
                .get("port")
                .and_then(Value::as_u64)
                .and_then(|port| u16::try_from(port).ok())
                .filter(|port| *port != 0)
                .ok_or_else(|| "validation SOCKS inbound has an invalid port".to_string())
        })
        .collect::<Result<Vec<_>, _>>()?;
    if socks_ports.len() != 1 {
        return Err(
            "validation Xray config must contain exactly one effective-route SOCKS inbound".into(),
        );
    }

    Ok(ValidationInspection { socks_ports })
}

/// Replace only the validated loopback SOCKS ports. The privileged service
/// uses this after reserving its own ephemeral ports, so an unprivileged GUI
/// cannot race a stale bind/drop selection made in another process.
pub fn rewrite_validation_ports(config: &str, ports: &[u16]) -> Result<String, String> {
    let inspection = inspect_validation_config(config)?;
    if ports.len() != inspection.socks_ports.len()
        || ports.iter().any(|port| *port < 1024)
        || ports.iter().copied().collect::<HashSet<_>>().len() != ports.len()
    {
        return Err(
            "replacement validation ports must be unique, unprivileged, and complete".into(),
        );
    }
    let mut root = parse_object(config, "validation Xray config")?;
    let inbounds = root
        .get_mut("inbounds")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| "validation Xray config has no inbounds array".to_string())?;
    let mut replacements = ports.iter().copied();
    for inbound in inbounds {
        if inbound.get("protocol").and_then(Value::as_str) == Some("socks") {
            inbound["port"] = serde_json::json!(replacements
                .next()
                .ok_or_else(|| "replacement validation port is missing".to_string())?);
        }
    }
    if replacements.next().is_some() {
        return Err("too many replacement validation ports".into());
    }
    let rewritten = serde_json::to_string(&Value::Object(root))
        .map_err(|error| format!("could not serialize validation config: {error}"))?;
    inspect_validation_config(&rewritten)?;
    Ok(rewritten)
}

fn parse_object(config: &str, label: &str) -> Result<serde_json::Map<String, Value>, String> {
    serde_json::from_str::<Value>(config)
        .map_err(|error| format!("{label} is invalid JSON: {error}"))?
        .as_object()
        .cloned()
        .ok_or_else(|| format!("{label} must be a JSON object"))
}

fn reject_unknown_top_level_fields(
    root: &serde_json::Map<String, Value>,
    allowed: &[&str],
    label: &str,
) -> Result<(), String> {
    if let Some(field) = root.keys().find(|field| !allowed.contains(&field.as_str())) {
        return Err(format!("{label} has unsupported top-level field: {field}"));
    }
    Ok(())
}

fn reject_log_file_paths(root: &serde_json::Map<String, Value>, label: &str) -> Result<(), String> {
    let Some(log) = root.get("log") else {
        return Ok(());
    };
    let log = log
        .as_object()
        .ok_or_else(|| format!("{label} log must be an object"))?;
    if log.contains_key("access") || log.contains_key("error") {
        return Err(format!("{label} must not set log file paths"));
    }
    if let Some(field) = log.keys().find(|field| field.as_str() != "loglevel") {
        return Err(format!("{label} log has unsupported field: {field}"));
    }
    Ok(())
}

fn reject_privileged_file_references(value: &Value) -> Result<(), String> {
    match value {
        Value::Object(object) => {
            for (key, value) in object {
                let key = key.to_ascii_lowercase();
                if matches!(
                    key.as_str(),
                    "file" | "certificatefile" | "keyfile" | "cafile" | "certfile"
                ) {
                    return Err(format!(
                        "privileged file reference is not allowed in Xray config: {key}"
                    ));
                }
                reject_privileged_file_references(value)?;
            }
        }
        Value::Array(values) => {
            for value in values {
                reject_privileged_file_references(value)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn required_string<'a>(value: Option<&'a Value>, label: &str) -> Result<&'a str, String> {
    value
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("{label} must be a non-empty string"))
}

fn string_array(value: Option<&Value>, label: &str) -> Result<Vec<String>, String> {
    let values = value
        .and_then(Value::as_array)
        .ok_or_else(|| format!("{label} must be an array"))?;
    let values = values
        .iter()
        .map(|value| {
            value
                .as_str()
                .filter(|value| !value.is_empty())
                .map(str::to_string)
                .ok_or_else(|| format!("{label} contains a non-string value"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    if values.is_empty() {
        return Err(format!("{label} must not be empty"));
    }
    Ok(values)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeLayout {
    pub install_dir: PathBuf,
    pub xray_executable: PathBuf,
    pub wintun_library: PathBuf,
    pub geoip_database: PathBuf,
    pub geosite_database: PathBuf,
    pub state_dir: PathBuf,
    pub desired_state: PathBuf,
    pub active_config: PathBuf,
    pub candidate_config: PathBuf,
    pub validation_config: PathBuf,
    pub log_file: PathBuf,
}

impl RuntimeLayout {
    pub fn from_service_executable(
        service_executable: PathBuf,
        state_dir: PathBuf,
    ) -> Result<Self, String> {
        let install_dir = portable_parent(&service_executable)
            .ok_or_else(|| "service executable has no installation directory".to_string())?;
        Ok(Self {
            xray_executable: portable_join(&install_dir, "xray.exe"),
            wintun_library: portable_join(&install_dir, "wintun.dll"),
            geoip_database: portable_join(&install_dir, "geoip.dat"),
            geosite_database: portable_join(&install_dir, "geosite.dat"),
            desired_state: portable_join(&state_dir, "desired-state.bin"),
            active_config: portable_join(&state_dir, "active.json"),
            candidate_config: portable_join(&state_dir, "candidate.json"),
            validation_config: portable_join(&state_dir, "validation.json"),
            log_file: portable_join(&state_dir, "xray.log"),
            install_dir,
            state_dir,
        })
    }
}

fn portable_parent(path: &Path) -> Option<PathBuf> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        return Some(parent.to_path_buf());
    }
    let text = path.to_string_lossy();
    text.rfind(['\\', '/'])
        .map(|index| PathBuf::from(&text[..index]))
}

fn portable_join(base: &Path, child: &str) -> PathBuf {
    let text = base.to_string_lossy();
    if text.contains('\\') && !text.contains('/') {
        PathBuf::from(format!("{}\\{child}", text.trim_end_matches('\\')))
    } else {
        base.join(child)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssetArch {
    X64,
    Arm64,
}

impl AssetArch {
    pub fn from_target(target: &str) -> Result<Self, String> {
        match target {
            "x86_64-pc-windows-msvc" => Ok(Self::X64),
            "aarch64-pc-windows-msvc" => Ok(Self::Arm64),
            _ => Err(format!("unsupported Windows target: {target}")),
        }
    }

    pub fn xray_archive(self) -> &'static str {
        match self {
            Self::X64 => "Xray-windows-64.zip",
            Self::Arm64 => "Xray-windows-arm64-v8a.zip",
        }
    }

    pub fn wintun_directory(self) -> &'static str {
        match self {
            Self::X64 => "amd64",
            Self::Arm64 => "arm64",
        }
    }
}
