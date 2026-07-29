use std::path::{Path, PathBuf};

use serde_json::Value;

pub const LOOPBACK_FILTER_WEIGHT: u64 = 0xff;
pub const DNS_FILTER_WEIGHT: u64 = 0xfe;
pub const XRAY_FILTER_WEIGHT: u64 = 0xfd;
pub const LAN_FILTER_WEIGHT: u64 = 0xfc;
pub const EXCLUDED_APP_FILTER_WEIGHT: u64 = 0xfb;
pub const DEFAULT_BLOCK_FILTER_WEIGHT: u64 = 0x10;

pub const TUN_ADAPTER_NAME: &str = "Varmlen";
pub const TUN_ADAPTER_DESCRIPTION: &str = "Varmlen";
pub const TUN_IPV4_GATEWAY: &str = "10.255.0.1/30";
pub const TUN_IPV6_GATEWAY: &str = "fd00:7661:726d:6c65::1/64";
pub const TUN_DNS: &str = "1.1.1.1";

const IPV4_DEFAULT: &str = "0.0.0.0/0";
const IPV6_DEFAULT: &str = "::/0";
const LAN_V4: &[&str] = &[
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "169.254.0.0/16",
    "100.64.0.0/10",
];
const LAN_V6: &[&str] = &["fc00::/7", "fe80::/10"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeTunInspection {
    pub adapter_name: String,
    pub adapter_description: String,
    pub has_ipv4_gateway: bool,
    pub has_ipv6_gateway: bool,
    pub dns_servers: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ValidationInspection {
    pub socks_port: u16,
}

pub fn inspect_native_tun_config(config: &str) -> Result<NativeTunInspection, String> {
    let root = parse_object(config, "native Xray config")?;
    let inbounds = root
        .get("inbounds")
        .and_then(Value::as_array)
        .ok_or_else(|| "native Xray config has no inbounds array".to_string())?;
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

pub fn inspect_validation_config(config: &str) -> Result<ValidationInspection, String> {
    let root = parse_object(config, "validation Xray config")?;
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

    let socks = inbounds
        .iter()
        .find(|inbound| inbound.get("protocol").and_then(Value::as_str) == Some("socks"))
        .ok_or_else(|| "validation Xray config has no SOCKS inbound".to_string())?;
    let listen = socks
        .get("listen")
        .and_then(Value::as_str)
        .ok_or_else(|| "validation SOCKS inbound has no listen address".to_string())?;
    if !matches!(listen, "127.0.0.1" | "::1" | "localhost") {
        return Err("validation SOCKS inbound must listen on loopback".into());
    }
    let port = socks
        .get("port")
        .and_then(Value::as_u64)
        .and_then(|port| u16::try_from(port).ok())
        .filter(|port| *port != 0)
        .ok_or_else(|| "validation SOCKS inbound has an invalid port".to_string())?;
    if inbounds.iter().any(|inbound| {
        inbound
            .get("listen")
            .and_then(Value::as_str)
            .is_some_and(|address| !matches!(address, "127.0.0.1" | "::1" | "localhost"))
    }) {
        return Err("every validation inbound must listen on loopback".into());
    }
    Ok(ValidationInspection { socks_port: port })
}

fn parse_object(config: &str, label: &str) -> Result<serde_json::Map<String, Value>, String> {
    serde_json::from_str::<Value>(config)
        .map_err(|error| format!("{label} is invalid JSON: {error}"))?
        .as_object()
        .cloned()
        .ok_or_else(|| format!("{label} must be a JSON object"))
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpFamily {
    V4,
    V6,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterAction {
    Permit,
    Block,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FilterCondition {
    Loopback,
    NotLoopback,
    Application(PathBuf),
    RemotePort(u16),
    InterfaceNot(u64),
    RemoteNetworks(Vec<String>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyFilter {
    pub name: String,
    pub family: IpFamily,
    pub action: FilterAction,
    pub weight: u64,
    pub conditions: Vec<FilterCondition>,
    pub persistent: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyMode {
    Hold,
    Connected { tun_luid: u64 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicySpec {
    pub mode: PolicyMode,
    pub allow_lan: bool,
    pub xray_path: PathBuf,
    pub excluded_apps: Vec<PathBuf>,
}

impl PolicySpec {
    pub fn filters(&self) -> Vec<PolicyFilter> {
        let mut filters = Vec::new();
        for (family, suffix) in [(IpFamily::V4, "v4"), (IpFamily::V6, "v6")] {
            let mut dns_conditions = vec![
                FilterCondition::NotLoopback,
                FilterCondition::RemotePort(53),
            ];
            if let PolicyMode::Connected { tun_luid } = self.mode {
                dns_conditions.push(FilterCondition::InterfaceNot(tun_luid));
            }
            filters.push(PolicyFilter {
                name: if suffix == "v4" {
                    "permit-loopback-v4"
                } else {
                    "permit-loopback-v6"
                }
                .into(),
                family,
                action: FilterAction::Permit,
                weight: LOOPBACK_FILTER_WEIGHT,
                conditions: vec![FilterCondition::Loopback],
                persistent: true,
            });
            filters.push(PolicyFilter {
                name: if suffix == "v4" {
                    "block-dns-v4"
                } else {
                    "block-dns-v6"
                }
                .into(),
                family,
                action: FilterAction::Block,
                weight: DNS_FILTER_WEIGHT,
                conditions: dns_conditions,
                persistent: true,
            });
            filters.push(PolicyFilter {
                name: if suffix == "v4" {
                    "permit-xray-v4"
                } else {
                    "permit-xray-v6"
                }
                .into(),
                family,
                action: FilterAction::Permit,
                weight: XRAY_FILTER_WEIGHT,
                conditions: vec![FilterCondition::Application(self.xray_path.clone())],
                persistent: true,
            });

            match self.mode {
                PolicyMode::Hold => filters.push(PolicyFilter {
                    name: if suffix == "v4" {
                        "block-all-v4"
                    } else {
                        "block-all-v6"
                    }
                    .into(),
                    family,
                    action: FilterAction::Block,
                    weight: DEFAULT_BLOCK_FILTER_WEIGHT,
                    conditions: Vec::new(),
                    persistent: true,
                }),
                PolicyMode::Connected { tun_luid } => {
                    if self.allow_lan {
                        filters.push(PolicyFilter {
                            name: if suffix == "v4" {
                                "permit-lan-v4"
                            } else {
                                "permit-lan-v6"
                            }
                            .into(),
                            family,
                            action: FilterAction::Permit,
                            weight: LAN_FILTER_WEIGHT,
                            conditions: vec![FilterCondition::RemoteNetworks(
                                if family == IpFamily::V4 {
                                    LAN_V4
                                } else {
                                    LAN_V6
                                }
                                .iter()
                                .map(|network| (*network).to_string())
                                .collect(),
                            )],
                            persistent: true,
                        });
                    }
                    for (index, path) in self.excluded_apps.iter().enumerate() {
                        filters.push(PolicyFilter {
                            name: format!("permit-excluded-app-{suffix}-{}", index + 1),
                            family,
                            action: FilterAction::Permit,
                            weight: EXCLUDED_APP_FILTER_WEIGHT,
                            conditions: vec![FilterCondition::Application(path.clone())],
                            persistent: true,
                        });
                    }
                    filters.push(PolicyFilter {
                        name: if suffix == "v4" {
                            "block-outside-tun-v4"
                        } else {
                            "block-outside-tun-v6"
                        }
                        .into(),
                        family,
                        action: FilterAction::Block,
                        weight: DEFAULT_BLOCK_FILTER_WEIGHT,
                        conditions: vec![FilterCondition::InterfaceNot(tun_luid)],
                        persistent: true,
                    });
                }
            }
        }
        filters
    }
}
