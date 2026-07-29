use std::{ffi::c_void, io, net::IpAddr, path::Path, ptr};

use varmlen_service_core::runtime::{FilterAction, IpFamily, PolicySpec};
use windows::{
    core::{GUID, PCWSTR, PWSTR},
    Win32::{
        Foundation::{
            FWP_E_ALREADY_EXISTS, FWP_E_FILTER_NOT_FOUND, FWP_E_PROVIDER_NOT_FOUND,
            FWP_E_SUBLAYER_NOT_FOUND, HANDLE,
        },
        NetworkManagement::WindowsFilteringPlatform::*,
        System::Rpc::RPC_C_AUTHN_WINNT,
    },
};

use crate::wfp_plan::{
    compile_policy, CompiledCondition, CompiledRule, PROVIDER_KEY, SUBLAYER_KEY,
};

pub struct WfpEngine {
    handle: usize,
}

impl WfpEngine {
    pub fn open() -> io::Result<Self> {
        let mut handle = HANDLE::default();
        let status =
            // SAFETY: output points to valid storage and all optional inputs
            // are intentionally null for the local persistent engine.
            unsafe { FwpmEngineOpen0(None, RPC_C_AUTHN_WINNT, None, None, &mut handle) };
        check(status, "open WFP engine")?;
        let engine = Self {
            handle: handle.0 as usize,
        };
        engine.ensure_provider_and_sublayer()?;
        Ok(engine)
    }

    pub fn apply_policy(&self, policy: &PolicySpec) -> io::Result<()> {
        let rules = compile_policy(policy).map_err(io::Error::other)?;
        let old_keys = self.provider_filter_keys()?;
        self.transaction(|engine| {
            for key in old_keys {
                ignore_not_found(
                    // SAFETY: engine is valid and key points to a GUID.
                    unsafe { FwpmFilterDeleteByKey0(engine, &key) },
                    FWP_E_FILTER_NOT_FOUND.0 as u32,
                    "delete prior WFP filter",
                )?;
            }
            for rule in &rules {
                add_rule(engine, rule)?;
            }
            Ok(())
        })?;
        self.verify_rules(&rules)
    }

    pub fn clear_filters(&self) -> io::Result<()> {
        let keys = self.provider_filter_keys()?;
        self.transaction(|engine| {
            for key in keys {
                ignore_not_found(
                    // SAFETY: engine is valid and key points to a GUID.
                    unsafe { FwpmFilterDeleteByKey0(engine, &key) },
                    FWP_E_FILTER_NOT_FOUND.0 as u32,
                    "delete WFP filter",
                )?;
            }
            Ok(())
        })
    }

    fn ensure_provider_and_sublayer(&self) -> io::Result<()> {
        let provider_key = GUID::from_u128(PROVIDER_KEY);
        let mut provider_name = wide("Varmlen");
        let mut provider_description = wide("Varmlen fail-closed VPN policy");
        let provider = FWPM_PROVIDER0 {
            providerKey: provider_key,
            displayData: display(&mut provider_name, &mut provider_description),
            flags: FWPM_PROVIDER_FLAG_PERSISTENT,
            serviceName: PWSTR::null(),
            ..Default::default()
        };
        let status =
            // SAFETY: provider and its strings remain alive for the call.
            unsafe { FwpmProviderAdd0(self.native(), &provider, None) };
        if status != 0 && status != FWP_E_ALREADY_EXISTS.0 as u32 {
            return check(status, "add Varmlen WFP provider");
        }

        let mut provider_key_for_sublayer = provider_key;
        let mut sublayer_name = wide("Varmlen");
        let mut sublayer_description = wide("Varmlen outbound VPN enforcement");
        let sublayer = FWPM_SUBLAYER0 {
            subLayerKey: GUID::from_u128(SUBLAYER_KEY),
            displayData: display(&mut sublayer_name, &mut sublayer_description),
            flags: FWPM_SUBLAYER_FLAG_PERSISTENT,
            providerKey: &mut provider_key_for_sublayer,
            weight: 0xff00,
            ..Default::default()
        };
        let status =
            // SAFETY: sublayer, provider key and strings live for the call.
            unsafe { FwpmSubLayerAdd0(self.native(), &sublayer, None) };
        if status != 0 && status != FWP_E_ALREADY_EXISTS.0 as u32 {
            return check(status, "add Varmlen WFP sublayer");
        }
        Ok(())
    }

    fn provider_filter_keys(&self) -> io::Result<Vec<GUID>> {
        let mut provider_key = GUID::from_u128(PROVIDER_KEY);
        let template = FWPM_FILTER_ENUM_TEMPLATE0 {
            providerKey: &mut provider_key,
            ..Default::default()
        };
        let mut enum_handle = HANDLE::default();
        check(
            // SAFETY: template and output storage are valid.
            unsafe {
                FwpmFilterCreateEnumHandle0(self.native(), Some(&template), &mut enum_handle)
            },
            "create WFP filter enumeration",
        )?;
        let enumeration = EnumHandle {
            engine: self.native(),
            handle: enum_handle,
        };

        let mut keys = Vec::new();
        loop {
            let mut entries: *mut *mut FWPM_FILTER0 = ptr::null_mut();
            let mut returned = 0u32;
            check(
                // SAFETY: output pointers are valid; WFP allocates entries.
                unsafe {
                    FwpmFilterEnum0(
                        self.native(),
                        enumeration.handle,
                        128,
                        &mut entries,
                        &mut returned,
                    )
                },
                "enumerate WFP filters",
            )?;
            if returned == 0 {
                break;
            }
            // SAFETY: WFP returned `returned` valid pointers in `entries`.
            let filters = unsafe { std::slice::from_raw_parts(entries, returned as usize) };
            for filter in filters {
                if !filter.is_null() {
                    // SAFETY: each filter pointer is valid until entries free.
                    keys.push(unsafe { (**filter).filterKey });
                }
            }
            let mut allocation = entries.cast::<c_void>();
            // SAFETY: entries was allocated by FwpmFilterEnum0.
            unsafe { FwpmFreeMemory0(&mut allocation) };
        }
        Ok(keys)
    }

    fn verify_rules(&self, rules: &[CompiledRule]) -> io::Result<()> {
        for rule in rules {
            let key = GUID::from_u128(rule.key);
            let mut filter = ptr::null_mut();
            check(
                // SAFETY: output pointer and key are valid.
                unsafe { FwpmFilterGetByKey0(self.native(), &key, &mut filter) },
                "verify WFP filter",
            )?;
            let mut allocation = filter.cast::<c_void>();
            // SAFETY: filter was allocated by FwpmFilterGetByKey0.
            unsafe { FwpmFreeMemory0(&mut allocation) };
        }
        Ok(())
    }

    fn transaction(&self, operation: impl FnOnce(HANDLE) -> io::Result<()>) -> io::Result<()> {
        check(
            // SAFETY: handle is an open engine.
            unsafe { FwpmTransactionBegin0(self.native(), 0) },
            "begin WFP transaction",
        )?;
        match operation(self.native()) {
            Ok(()) => check(
                // SAFETY: a transaction is active on this engine.
                unsafe { FwpmTransactionCommit0(self.native()) },
                "commit WFP transaction",
            ),
            Err(error) => {
                // SAFETY: a transaction is active and abort is best effort.
                unsafe {
                    FwpmTransactionAbort0(self.native());
                }
                Err(error)
            }
        }
    }

    fn native(&self) -> HANDLE {
        HANDLE(self.handle as *mut c_void)
    }
}

impl Drop for WfpEngine {
    fn drop(&mut self) {
        if self.handle != 0 {
            // SAFETY: handle was returned by FwpmEngineOpen0.
            unsafe {
                FwpmEngineClose0(self.native());
            }
        }
    }
}

pub fn cleanup_persistent_policy() -> io::Result<()> {
    let engine = WfpEngine::open()?;
    engine.clear_filters()?;
    ignore_not_found(
        // SAFETY: engine and key are valid.
        unsafe { FwpmSubLayerDeleteByKey0(engine.native(), &GUID::from_u128(SUBLAYER_KEY)) },
        FWP_E_SUBLAYER_NOT_FOUND.0 as u32,
        "delete Varmlen WFP sublayer",
    )?;
    ignore_not_found(
        // SAFETY: engine and key are valid.
        unsafe { FwpmProviderDeleteByKey0(engine.native(), &GUID::from_u128(PROVIDER_KEY)) },
        FWP_E_PROVIDER_NOT_FOUND.0 as u32,
        "delete Varmlen WFP provider",
    )
}

fn add_rule(engine: HANDLE, rule: &CompiledRule) -> io::Result<()> {
    let mut conditions = ConditionSet::new(&rule.conditions)?;
    let mut provider_key = GUID::from_u128(PROVIDER_KEY);
    let mut name = wide(&format!("Varmlen {}", rule.name));
    let mut description = wide("Managed by VarmlenService");
    let mut weight = rule.weight;
    let native_conditions = conditions.native_conditions();
    let filter = FWPM_FILTER0 {
        filterKey: GUID::from_u128(rule.key),
        displayData: display(&mut name, &mut description),
        flags: if rule.persistent {
            FWPM_FILTER_FLAG_PERSISTENT
        } else {
            FWPM_FILTER_FLAG_NONE
        },
        providerKey: &mut provider_key,
        layerKey: match rule.family {
            IpFamily::V4 => FWPM_LAYER_ALE_AUTH_CONNECT_V4,
            IpFamily::V6 => FWPM_LAYER_ALE_AUTH_CONNECT_V6,
        },
        subLayerKey: GUID::from_u128(SUBLAYER_KEY),
        weight: FWP_VALUE0 {
            r#type: FWP_UINT64,
            Anonymous: FWP_VALUE0_0 {
                uint64: &mut weight,
            },
        },
        numFilterConditions: native_conditions.len() as u32,
        filterCondition: native_conditions.as_ptr().cast_mut(),
        action: FWPM_ACTION0 {
            r#type: match rule.action {
                FilterAction::Permit => FWP_ACTION_PERMIT,
                FilterAction::Block => FWP_ACTION_BLOCK,
            },
            ..Default::default()
        },
        ..Default::default()
    };
    check(
        // SAFETY: filter, conditions, pointed values and strings remain valid
        // for this call. BFE copies all supplied data.
        unsafe { FwpmFilterAdd0(engine, &filter, None, None) },
        "add Varmlen WFP filter",
    )
}

struct ConditionSet {
    conditions: Vec<OwnedCondition>,
}

impl ConditionSet {
    fn new(conditions: &[CompiledCondition]) -> io::Result<Self> {
        Ok(Self {
            conditions: conditions
                .iter()
                .map(OwnedCondition::new)
                .collect::<io::Result<_>>()?,
        })
    }

    fn native_conditions(&mut self) -> Vec<FWPM_FILTER_CONDITION0> {
        self.conditions
            .iter_mut()
            .map(OwnedCondition::native)
            .collect()
    }
}

enum ConditionValue {
    U16(u16),
    U32(u32),
    U64(Box<u64>),
    AppId(*mut FWP_BYTE_BLOB),
    V4(Box<FWP_V4_ADDR_AND_MASK>),
    V6(Box<FWP_V6_ADDR_AND_MASK>),
}

struct OwnedCondition {
    field: GUID,
    match_type: FWP_MATCH_TYPE,
    value: ConditionValue,
}

impl OwnedCondition {
    fn new(condition: &CompiledCondition) -> io::Result<Self> {
        match condition {
            CompiledCondition::Loopback => Ok(Self {
                field: FWPM_CONDITION_FLAGS,
                match_type: FWP_MATCH_FLAGS_ALL_SET,
                value: ConditionValue::U32(FWP_CONDITION_FLAG_IS_LOOPBACK),
            }),
            CompiledCondition::NotLoopback => Ok(Self {
                field: FWPM_CONDITION_FLAGS,
                match_type: FWP_MATCH_FLAGS_NONE_SET,
                value: ConditionValue::U32(FWP_CONDITION_FLAG_IS_LOOPBACK),
            }),
            CompiledCondition::Application(path) => Ok(Self {
                field: FWPM_CONDITION_ALE_APP_ID,
                match_type: FWP_MATCH_EQUAL,
                value: ConditionValue::AppId(app_id(path)?),
            }),
            CompiledCondition::RemotePort(port) => Ok(Self {
                field: FWPM_CONDITION_IP_REMOTE_PORT,
                match_type: FWP_MATCH_EQUAL,
                value: ConditionValue::U16(*port),
            }),
            CompiledCondition::InterfaceNot(luid) => Ok(Self {
                field: FWPM_CONDITION_IP_LOCAL_INTERFACE,
                match_type: FWP_MATCH_NOT_EQUAL,
                value: ConditionValue::U64(Box::new(*luid)),
            }),
            CompiledCondition::RemoteNetwork(network) => {
                let (address, prefix) = parse_cidr(network)?;
                match address {
                    IpAddr::V4(address) => {
                        let prefix = prefix.min(32);
                        let mask = if prefix == 0 {
                            0
                        } else {
                            u32::MAX << (32 - prefix)
                        };
                        Ok(Self {
                            field: FWPM_CONDITION_IP_REMOTE_ADDRESS,
                            match_type: FWP_MATCH_EQUAL,
                            value: ConditionValue::V4(Box::new(FWP_V4_ADDR_AND_MASK {
                                addr: u32::from_be_bytes(address.octets()),
                                mask,
                            })),
                        })
                    }
                    IpAddr::V6(address) => Ok(Self {
                        field: FWPM_CONDITION_IP_REMOTE_ADDRESS,
                        match_type: FWP_MATCH_EQUAL,
                        value: ConditionValue::V6(Box::new(FWP_V6_ADDR_AND_MASK {
                            addr: address.octets(),
                            prefixLength: prefix.min(128) as u8,
                        })),
                    }),
                }
            }
        }
    }

    fn native(&mut self) -> FWPM_FILTER_CONDITION0 {
        let (kind, value) = match &mut self.value {
            ConditionValue::U16(value) => (FWP_UINT16, FWP_CONDITION_VALUE0_0 { uint16: *value }),
            ConditionValue::U32(value) => (FWP_UINT32, FWP_CONDITION_VALUE0_0 { uint32: *value }),
            ConditionValue::U64(value) => (
                FWP_UINT64,
                FWP_CONDITION_VALUE0_0 {
                    uint64: value.as_mut(),
                },
            ),
            ConditionValue::AppId(blob) => (
                FWP_BYTE_BLOB_TYPE,
                FWP_CONDITION_VALUE0_0 { byteBlob: *blob },
            ),
            ConditionValue::V4(value) => (
                FWP_V4_ADDR_MASK,
                FWP_CONDITION_VALUE0_0 {
                    v4AddrMask: value.as_mut(),
                },
            ),
            ConditionValue::V6(value) => (
                FWP_V6_ADDR_MASK,
                FWP_CONDITION_VALUE0_0 {
                    v6AddrMask: value.as_mut(),
                },
            ),
        };
        FWPM_FILTER_CONDITION0 {
            fieldKey: self.field,
            matchType: self.match_type,
            conditionValue: FWP_CONDITION_VALUE0 {
                r#type: kind,
                Anonymous: value,
            },
        }
    }
}

impl Drop for OwnedCondition {
    fn drop(&mut self) {
        if let ConditionValue::AppId(blob) = &mut self.value {
            let mut allocation = (*blob).cast::<c_void>();
            // SAFETY: app ID was allocated by FwpmGetAppIdFromFileName0.
            unsafe { FwpmFreeMemory0(&mut allocation) };
            *blob = ptr::null_mut();
        }
    }
}

fn app_id(path: &Path) -> io::Result<*mut FWP_BYTE_BLOB> {
    let path = wide(&path.to_string_lossy());
    let mut blob = ptr::null_mut();
    check(
        // SAFETY: path is NUL terminated and output points to valid storage.
        unsafe { FwpmGetAppIdFromFileName0(PCWSTR(path.as_ptr()), &mut blob) },
        "resolve WFP application identity",
    )?;
    Ok(blob)
}

fn parse_cidr(value: &str) -> io::Result<(IpAddr, u32)> {
    let (address, prefix) = value
        .split_once('/')
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "CIDR has no prefix"))?;
    let address = address
        .parse::<IpAddr>()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    let prefix = prefix
        .parse::<u32>()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    let max = if address.is_ipv4() { 32 } else { 128 };
    if prefix > max {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "CIDR prefix is out of range",
        ));
    }
    Ok((address, prefix))
}

fn display(name: &mut [u16], description: &mut [u16]) -> FWPM_DISPLAY_DATA0 {
    FWPM_DISPLAY_DATA0 {
        name: PWSTR(name.as_mut_ptr()),
        description: PWSTR(description.as_mut_ptr()),
    }
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(Some(0)).collect()
}

fn check(status: u32, operation: &str) -> io::Result<()> {
    if status == 0 {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "{operation} failed with WFP status 0x{status:08x}"
        )))
    }
}

fn ignore_not_found(status: u32, not_found: u32, operation: &str) -> io::Result<()> {
    if status == 0 || status == not_found {
        Ok(())
    } else {
        check(status, operation)
    }
}

struct EnumHandle {
    engine: HANDLE,
    handle: HANDLE,
}

impl Drop for EnumHandle {
    fn drop(&mut self) {
        if !self.handle.is_invalid() {
            // SAFETY: handle was created by FwpmFilterCreateEnumHandle0.
            unsafe {
                FwpmFilterDestroyEnumHandle0(self.engine, self.handle);
            }
        }
    }
}
