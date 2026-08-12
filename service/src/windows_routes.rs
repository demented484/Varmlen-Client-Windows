use std::{fs, io, net::IpAddr, path::PathBuf, process::Command};

use serde::{Deserialize, Serialize};
use varmlen_service_core::runtime::RuntimeLayout;
use varmlen_service_core::runtime::TUN_ADAPTER_NAME;

use crate::{windows_adapter::physical_dns_servers, windows_state::atomic_write};

const IPV4_ADDRESS: &str = "10.255.0.1";
const IPV4_MASK: &str = "255.255.255.252";
const IPV6_ADDRESS: &str = "fd00:7661:726d:6c65::1/64";
const IPV4_DNS: &str = "1.1.1.1";
const IPV6_DNS: &str = "2606:4700:4700::1111";
const LOOPBACK_INTERFACE_INDEX: &str = "1";
const KILLSWITCH_METRIC: &str = "4096";
const IPV4_DEFAULTS: [&str; 2] = ["0.0.0.0/1", "128.0.0.0/1"];
const IPV6_DEFAULTS: [&str; 2] = ["::/1", "8000::/1"];
const ROUTE_STATE_FILE: &str = "killswitch-routes.json";

#[derive(Debug, Default, Serialize, Deserialize)]
struct KillSwitchRouteState {
    dns_servers: Vec<IpAddr>,
}

/// Install lower-priority split-default routes through Windows' stable
/// loopback interface. The live TUN routes use metric 1 and win while Xray is
/// healthy; if Xray exits and its Wintun routes disappear, these routes remain
/// and fail closed without a packet-filtering backend.
pub fn install_killswitch_routes(layout: &RuntimeLayout) -> io::Result<()> {
    let mut state = load_route_state(layout).unwrap_or_default();
    state.dns_servers.extend(physical_dns_servers()?);
    state.dns_servers.sort_by_key(ToString::to_string);
    state.dns_servers.dedup();
    if state.dns_servers.len() > 128 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "too many physical DNS servers to protect",
        ));
    }
    // Persist the exact host routes before changing the table, so cleanup can
    // remove them after a service or installer crash.
    atomic_write(
        &route_state_path(layout),
        &serde_json::to_vec(&state).map_err(io::Error::other)?,
    )?;
    for prefix in IPV4_DEFAULTS {
        replace_route(
            "ipv4",
            prefix,
            LOOPBACK_INTERFACE_INDEX,
            "0.0.0.0",
            KILLSWITCH_METRIC,
        )?;
    }
    for prefix in IPV6_DEFAULTS {
        replace_route(
            "ipv6",
            prefix,
            LOOPBACK_INTERFACE_INDEX,
            "::",
            KILLSWITCH_METRIC,
        )?;
    }
    for address in &state.dns_servers {
        let (family, prefix, next_hop) = host_route(*address);
        replace_route(family, &prefix, LOOPBACK_INTERFACE_INDEX, next_hop, "1")?;
    }
    verify_killswitch_routes(layout, true)
}

/// Remove only Varmlen's loopback fallback routes. Routes owned by the TUN or
/// the physical interface are scoped to different interface indices.
pub fn remove_killswitch_routes(layout: &RuntimeLayout) -> io::Result<()> {
    let state = load_route_state(layout).unwrap_or_default();
    for prefix in IPV4_DEFAULTS {
        delete_route("ipv4", prefix, LOOPBACK_INTERFACE_INDEX);
    }
    for prefix in IPV6_DEFAULTS {
        delete_route("ipv6", prefix, LOOPBACK_INTERFACE_INDEX);
    }
    for address in &state.dns_servers {
        let (family, prefix, _) = host_route(*address);
        delete_route(family, &prefix, LOOPBACK_INTERFACE_INDEX);
    }
    verify_killswitch_routes(layout, false)?;
    match fs::remove_file(route_state_path(layout)) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

pub fn verify_killswitch_routes(layout: &RuntimeLayout, expected: bool) -> io::Result<()> {
    for (family, prefixes) in [
        ("ipv4", IPV4_DEFAULTS.as_slice()),
        ("ipv6", IPV6_DEFAULTS.as_slice()),
    ] {
        for prefix in prefixes {
            let present = route_exists(family, prefix, LOOPBACK_INTERFACE_INDEX)?;
            if present != expected {
                return Err(io::Error::other(format!(
                    "kill-switch route {prefix} on interface {LOOPBACK_INTERFACE_INDEX} is {}",
                    if present { "still present" } else { "missing" }
                )));
            }
        }
    }
    for address in load_route_state(layout).unwrap_or_default().dns_servers {
        let (family, prefix, _) = host_route(address);
        let present = route_exists(family, &prefix, LOOPBACK_INTERFACE_INDEX)?;
        if present != expected {
            return Err(io::Error::other(format!(
                "kill-switch DNS route {prefix} is {}",
                if present { "still present" } else { "missing" }
            )));
        }
    }
    Ok(())
}

fn host_route(address: IpAddr) -> (&'static str, String, &'static str) {
    match address {
        IpAddr::V4(address) => ("ipv4", format!("{address}/32"), "0.0.0.0"),
        IpAddr::V6(address) => ("ipv6", format!("{address}/128"), "::"),
    }
}

fn route_state_path(layout: &RuntimeLayout) -> PathBuf {
    layout.state_dir.join(ROUTE_STATE_FILE)
}

fn load_route_state(layout: &RuntimeLayout) -> io::Result<KillSwitchRouteState> {
    match fs::read(route_state_path(layout)) {
        Ok(bytes) if bytes.len() <= 64 * 1024 => {
            serde_json::from_slice(&bytes).map_err(io::Error::other)
        }
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "kill-switch route state is too large",
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            Ok(KillSwitchRouteState::default())
        }
        Err(error) => Err(error),
    }
}

/// Configure the address, DNS and split-default routes that newer prerelease
/// Xray builds can create themselves. Varmlen deliberately bundles stable Xray
/// 26.3.27, whose Windows TUN only owns the Wintun packet session.
pub fn configure_stable_tun_network() -> io::Result<()> {
    netsh(&[
        "interface",
        "ipv4",
        "set",
        "address",
        &format!("name={TUN_ADAPTER_NAME}"),
        "source=static",
        &format!("address={IPV4_ADDRESS}"),
        &format!("mask={IPV4_MASK}"),
        "gateway=none",
        "store=active",
    ])?;

    // A reused Wintun adapter can retain an address briefly. Deletion is
    // best-effort; the subsequent add is the authoritative operation.
    let _ = netsh(&[
        "interface",
        "ipv6",
        "delete",
        "address",
        &format!("interface={TUN_ADAPTER_NAME}"),
        &format!("address={IPV6_ADDRESS}"),
        "store=active",
    ]);
    netsh(&[
        "interface",
        "ipv6",
        "add",
        "address",
        &format!("interface={TUN_ADAPTER_NAME}"),
        &format!("address={IPV6_ADDRESS}"),
        "type=unicast",
        "store=active",
    ])?;

    netsh(&[
        "interface",
        "ipv4",
        "set",
        "dnsservers",
        &format!("name={TUN_ADAPTER_NAME}"),
        "source=static",
        &format!("address={IPV4_DNS}"),
        "register=none",
        "validate=no",
    ])?;
    netsh(&[
        "interface",
        "ipv6",
        "set",
        "dnsservers",
        &format!("name={TUN_ADAPTER_NAME}"),
        "source=static",
        &format!("address={IPV6_DNS}"),
        "register=none",
        "validate=no",
    ])?;

    for prefix in IPV4_DEFAULTS {
        let _ = netsh(&[
            "interface",
            "ipv4",
            "delete",
            "route",
            &format!("prefix={prefix}"),
            &format!("interface={TUN_ADAPTER_NAME}"),
            "store=active",
        ]);
        netsh(&[
            "interface",
            "ipv4",
            "add",
            "route",
            &format!("prefix={prefix}"),
            &format!("interface={TUN_ADAPTER_NAME}"),
            "nexthop=0.0.0.0",
            "metric=1",
            "store=active",
        ])?;
    }
    for prefix in IPV6_DEFAULTS {
        let _ = netsh(&[
            "interface",
            "ipv6",
            "delete",
            "route",
            &format!("prefix={prefix}"),
            &format!("interface={TUN_ADAPTER_NAME}"),
            "store=active",
        ]);
        netsh(&[
            "interface",
            "ipv6",
            "add",
            "route",
            &format!("prefix={prefix}"),
            &format!("interface={TUN_ADAPTER_NAME}"),
            "nexthop=::",
            "metric=1",
            "store=active",
        ])?;
    }
    Ok(())
}

fn replace_route(
    family: &str,
    prefix: &str,
    interface: &str,
    next_hop: &str,
    metric: &str,
) -> io::Result<()> {
    delete_route(family, prefix, interface);
    netsh(&[
        "interface",
        family,
        "add",
        "route",
        &format!("prefix={prefix}"),
        &format!("interface={interface}"),
        &format!("nexthop={next_hop}"),
        &format!("metric={metric}"),
        "store=active",
    ])
}

fn delete_route(family: &str, prefix: &str, interface: &str) {
    let _ = netsh(&[
        "interface",
        family,
        "delete",
        "route",
        &format!("prefix={prefix}"),
        &format!("interface={interface}"),
        "store=active",
    ]);
}

fn route_exists(family: &str, prefix: &str, interface: &str) -> io::Result<bool> {
    let output = run_netsh(&[
        "interface",
        family,
        "show",
        "route",
        &format!("prefix={prefix}"),
        &format!("interface={interface}"),
        "store=active",
    ])?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        return Err(io::Error::other(format!(
            "netsh route verification failed ({}): {}{}",
            output.status,
            stdout.trim(),
            stderr.trim()
        )));
    }
    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .any(|line| line.split_whitespace().any(|field| field == prefix)))
}

fn netsh(arguments: &[&str]) -> io::Result<()> {
    let output = run_netsh(arguments)?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    Err(io::Error::other(format!(
        "netsh {} failed ({}): {}{}",
        arguments.join(" "),
        output.status,
        stdout.trim(),
        stderr.trim()
    )))
}

fn run_netsh(arguments: &[&str]) -> io::Result<std::process::Output> {
    let system_root = std::env::var_os("SystemRoot")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\Windows"));
    let executable = system_root.join("System32").join("netsh.exe");
    Command::new(executable).args(arguments).output()
}
