use std::{io, mem::size_of};

use varmlen_service_core::runtime::{TUN_ADAPTER_DESCRIPTION, TUN_ADAPTER_NAME};
use windows::{
    core::PWSTR,
    Win32::{
        Foundation::{ERROR_BUFFER_OVERFLOW, ERROR_SUCCESS},
        NetworkManagement::IpHelper::{
            GetAdaptersAddresses, GAA_FLAG_INCLUDE_PREFIX, IP_ADAPTER_ADDRESSES_LH,
        },
        Networking::WinSock::{AF_INET, AF_INET6, AF_UNSPEC},
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

fn pwstr_to_string(value: PWSTR) -> String {
    if value.is_null() {
        return String::new();
    }
    // SAFETY: IP_ADAPTER_ADDRESSES exposes NUL-terminated strings owned by the
    // adapter buffer.
    unsafe { value.to_string() }.unwrap_or_default()
}
