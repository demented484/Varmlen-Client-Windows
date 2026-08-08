use std::{io, mem::size_of, net::SocketAddr};

use varmlen_service_core::runtime::{TUN_ADAPTER_DESCRIPTION, TUN_ADAPTER_NAME};
use windows::{
    core::PWSTR,
    Win32::{
        Foundation::{ERROR_BUFFER_OVERFLOW, ERROR_SUCCESS},
        NetworkManagement::IpHelper::{
            GetAdaptersAddresses, GetBestInterfaceEx, GAA_FLAG_INCLUDE_PREFIX,
            IP_ADAPTER_ADDRESSES_LH,
        },
        Networking::WinSock::{
            AF_INET, AF_INET6, AF_UNSPEC, IN6_ADDR, IN6_ADDR_0, IN_ADDR, IN_ADDR_0, SOCKADDR,
            SOCKADDR_IN, SOCKADDR_IN6,
        },
    },
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdapterInfo {
    pub luid: u64,
    pub has_ipv4: bool,
    pub has_ipv6: bool,
    pub dns_count: usize,
}

pub fn find_varmlen_adapter() -> io::Result<Option<AdapterInfo>> {
    let mut bytes = 15 * 1024u32;
    loop {
        let words = (bytes as usize).div_ceil(size_of::<usize>());
        let mut storage = vec![0usize; words];
        // SAFETY: `storage` is pointer-aligned, writable for `bytes`, and lives
        // while the returned linked list is traversed.
        let result = unsafe {
            GetAdaptersAddresses(
                AF_UNSPEC.0 as u32,
                GAA_FLAG_INCLUDE_PREFIX,
                None,
                Some(storage.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>()),
                &mut bytes,
            )
        };
        if result == ERROR_BUFFER_OVERFLOW.0 {
            continue;
        }
        if result != ERROR_SUCCESS.0 {
            return Err(io::Error::from_raw_os_error(result as i32));
        }

        let mut current = storage.as_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
        while !current.is_null() {
            // SAFETY: current points into the valid GetAdaptersAddresses list.
            let adapter = unsafe { &*current };
            let friendly = pwstr_to_string(adapter.FriendlyName);
            let description = pwstr_to_string(adapter.Description);
            if friendly.eq_ignore_ascii_case(TUN_ADAPTER_NAME)
                || description.eq_ignore_ascii_case(TUN_ADAPTER_DESCRIPTION)
            {
                let mut dns_count = 0;
                let mut dns = adapter.FirstDnsServerAddress;
                while !dns.is_null() {
                    dns_count += 1;
                    // SAFETY: DNS entries are part of the same valid list.
                    dns = unsafe { (*dns).Next };
                }
                let mut has_ipv4 = false;
                let mut has_ipv6 = false;
                let mut unicast = adapter.FirstUnicastAddress;
                while !unicast.is_null() {
                    // SAFETY: unicast entries belong to the adapter buffer.
                    let address = unsafe { &(*unicast).Address };
                    if !address.lpSockaddr.is_null() {
                        // SAFETY: lpSockaddr points to a SOCKADDR whose family
                        // is readable for every GetAdaptersAddresses entry.
                        match unsafe { (*address.lpSockaddr).sa_family.0 } {
                            value if value == AF_INET.0 => has_ipv4 = true,
                            value if value == AF_INET6.0 => has_ipv6 = true,
                            _ => {}
                        }
                    }
                    // SAFETY: unicast entries are part of the same valid list.
                    unicast = unsafe { (*unicast).Next };
                }
                // SAFETY: NET_LUID_LH is a C union whose Value view represents
                // the complete locally unique interface identifier.
                let luid = unsafe { adapter.Luid.Value };
                return Ok(Some(AdapterInfo {
                    luid,
                    has_ipv4,
                    has_ipv6,
                    dns_count,
                }));
            }
            current = adapter.Next;
        }
        return Ok(None);
    }
}

/// Resolve the physical adapter Windows would use for the VPN endpoint before
/// the TUN default route is installed. Xray's own `"auto"` heuristic scores
/// adapter names/addresses and can choose the wrong virtual NIC; Windows' route
/// table is authoritative for the actual destination.
pub fn best_outbound_interface_name(endpoints: &[SocketAddr]) -> io::Result<String> {
    let mut last_error = None;
    for endpoint in endpoints {
        let sockaddr = socket_addr(endpoint);
        let mut index = 0u32;
        // SAFETY: sockaddr owns a correctly initialized SOCKADDR_IN/IN6 for the
        // duration of GetBestInterfaceEx and index is writable.
        let result = unsafe { GetBestInterfaceEx(sockaddr.as_ptr(), &mut index) };
        if result != 0 {
            last_error = Some(io::Error::from_raw_os_error(result as i32));
            continue;
        }
        if let Some(name) = adapter_name_for_index(index)? {
            if !name.eq_ignore_ascii_case(TUN_ADAPTER_NAME) {
                return Ok(name);
            }
        }
    }
    Err(last_error.unwrap_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "Windows could not select a physical interface for the VPN endpoint",
        )
    }))
}

enum SocketAddress {
    V4(SOCKADDR_IN),
    V6(SOCKADDR_IN6),
}

impl SocketAddress {
    fn as_ptr(&self) -> *const SOCKADDR {
        match self {
            Self::V4(address) => std::ptr::from_ref(address).cast(),
            Self::V6(address) => std::ptr::from_ref(address).cast(),
        }
    }
}

fn socket_addr(endpoint: &SocketAddr) -> SocketAddress {
    match endpoint {
        SocketAddr::V4(endpoint) => SocketAddress::V4(SOCKADDR_IN {
            sin_family: AF_INET,
            sin_port: endpoint.port().to_be(),
            sin_addr: IN_ADDR {
                S_un: IN_ADDR_0 {
                    S_addr: u32::from_ne_bytes(endpoint.ip().octets()),
                },
            },
            sin_zero: [0; 8],
        }),
        SocketAddr::V6(endpoint) => SocketAddress::V6(SOCKADDR_IN6 {
            sin6_family: AF_INET6,
            sin6_port: endpoint.port().to_be(),
            sin6_flowinfo: endpoint.flowinfo(),
            sin6_addr: IN6_ADDR {
                u: IN6_ADDR_0 {
                    Byte: endpoint.ip().octets(),
                },
            },
            Anonymous: windows::Win32::Networking::WinSock::SOCKADDR_IN6_0 {
                sin6_scope_id: endpoint.scope_id(),
            },
        }),
    }
}

fn adapter_name_for_index(wanted_index: u32) -> io::Result<Option<String>> {
    let mut bytes = 15 * 1024u32;
    loop {
        let words = (bytes as usize).div_ceil(size_of::<usize>());
        let mut storage = vec![0usize; words];
        // SAFETY: storage is aligned, writable for bytes, and remains alive
        // while the linked adapter list is traversed.
        let result = unsafe {
            GetAdaptersAddresses(
                AF_UNSPEC.0 as u32,
                GAA_FLAG_INCLUDE_PREFIX,
                None,
                Some(storage.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>()),
                &mut bytes,
            )
        };
        if result == ERROR_BUFFER_OVERFLOW.0 {
            continue;
        }
        if result != ERROR_SUCCESS.0 {
            return Err(io::Error::from_raw_os_error(result as i32));
        }
        let mut current = storage.as_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
        while !current.is_null() {
            // SAFETY: current points into the valid GetAdaptersAddresses list.
            let adapter = unsafe { &*current };
            // SAFETY: Anonymous1.Anonymous is the documented Length/IfIndex
            // view of IP_ADAPTER_ADDRESSES_LH.
            let ipv4_index = unsafe { adapter.Anonymous1.Anonymous.IfIndex };
            if ipv4_index == wanted_index || adapter.Ipv6IfIndex == wanted_index {
                let name = pwstr_to_string(adapter.FriendlyName);
                return Ok((!name.is_empty()).then_some(name));
            }
            current = adapter.Next;
        }
        return Ok(None);
    }
}

fn pwstr_to_string(value: PWSTR) -> String {
    if value.is_null() {
        return String::new();
    }
    // SAFETY: IP_ADAPTER_ADDRESSES exposes NUL-terminated strings owned by the
    // adapter buffer.
    unsafe { value.to_string() }.unwrap_or_default()
}
