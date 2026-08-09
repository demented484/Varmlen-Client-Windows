use std::{io, path::PathBuf, process::Command};

use varmlen_service_core::runtime::TUN_ADAPTER_NAME;

const IPV4_ADDRESS: &str = "10.255.0.1";
const IPV4_MASK: &str = "255.255.255.252";
const IPV6_ADDRESS: &str = "fd00:7661:726d:6c65::1/64";
const IPV4_DNS: &str = "1.1.1.1";
const IPV6_DNS: &str = "2606:4700:4700::1111";

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

    for prefix in ["0.0.0.0/1", "128.0.0.0/1"] {
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
    for prefix in ["::/1", "8000::/1"] {
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

fn netsh(arguments: &[&str]) -> io::Result<()> {
    let system_root = std::env::var_os("SystemRoot")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\Windows"));
    let executable = system_root.join("System32").join("netsh.exe");
    let output = Command::new(executable).args(arguments).output()?;
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
