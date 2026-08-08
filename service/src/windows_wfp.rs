use std::{ffi::c_void, io, ptr};

use windows::{
    core::GUID,
    Win32::{
        Foundation::{
            FWP_E_FILTER_NOT_FOUND, FWP_E_PROVIDER_NOT_FOUND, FWP_E_SUBLAYER_NOT_FOUND, HANDLE,
        },
        NetworkManagement::WindowsFilteringPlatform::*,
        System::Rpc::RPC_C_AUTHN_WINNT,
    },
};

use crate::wfp_plan::{PROVIDER_KEY, SUBLAYER_KEY};

/// Removes policy left by early 0.3.0 previews.
///
/// Current connections do not create or depend on WFP objects. This module is
/// deliberately cleanup-only and never creates the legacy provider, sublayer,
/// or filters.
pub fn cleanup_persistent_policy() -> io::Result<()> {
    let engine = Engine::open()?;
    if !engine.provider_exists()? {
        return Ok(());
    }

    let keys = engine.provider_filter_keys()?;
    engine.transaction(|handle| {
        for key in keys {
            ignore_not_found(
                // SAFETY: the engine is valid and key points to a GUID.
                unsafe { FwpmFilterDeleteByKey0(handle, &key) },
                FWP_E_FILTER_NOT_FOUND.0 as u32,
                "delete legacy Varmlen WFP filter",
            )?;
        }
        Ok(())
    })?;

    if !engine.provider_filter_keys()?.is_empty() {
        return Err(io::Error::other(
            "legacy Varmlen WFP filters remain after cleanup",
        ));
    }

    ignore_not_found(
        // SAFETY: the engine and key are valid.
        unsafe { FwpmSubLayerDeleteByKey0(engine.handle, &GUID::from_u128(SUBLAYER_KEY)) },
        FWP_E_SUBLAYER_NOT_FOUND.0 as u32,
        "delete legacy Varmlen WFP sublayer",
    )?;
    ignore_not_found(
        // SAFETY: the engine and key are valid.
        unsafe { FwpmProviderDeleteByKey0(engine.handle, &GUID::from_u128(PROVIDER_KEY)) },
        FWP_E_PROVIDER_NOT_FOUND.0 as u32,
        "delete legacy Varmlen WFP provider",
    )
}

struct Engine {
    handle: HANDLE,
}

impl Engine {
    fn open() -> io::Result<Self> {
        let mut handle = HANDLE::default();
        check(
            // SAFETY: output points to valid storage and optional inputs are
            // intentionally null for the local engine.
            unsafe { FwpmEngineOpen0(None, RPC_C_AUTHN_WINNT, None, None, &mut handle) },
            "open WFP engine for legacy cleanup",
        )?;
        Ok(Self { handle })
    }

    fn provider_exists(&self) -> io::Result<bool> {
        let mut provider = ptr::null_mut();
        let status =
            // SAFETY: output pointer and provider key are valid.
            unsafe {
                FwpmProviderGetByKey0(
                    self.handle,
                    &GUID::from_u128(PROVIDER_KEY),
                    &mut provider,
                )
            };
        if status == FWP_E_PROVIDER_NOT_FOUND.0 as u32 {
            return Ok(false);
        }
        check(status, "find legacy Varmlen WFP provider")?;
        let mut allocation = provider.cast::<c_void>();
        // SAFETY: provider was allocated by FwpmProviderGetByKey0.
        unsafe { FwpmFreeMemory0(&mut allocation) };
        Ok(true)
    }

    fn provider_filter_keys(&self) -> io::Result<Vec<GUID>> {
        let provider_key = GUID::from_u128(PROVIDER_KEY);
        let mut enum_handle = HANDLE::default();
        check(
            // SAFETY: a null template is the documented unrestricted
            // enumeration. Filtering in Rust avoids FWP_E_NEVER_MATCH from the
            // provider-only template used by the affected preview.
            unsafe { FwpmFilterCreateEnumHandle0(self.handle, None, &mut enum_handle) },
            "create unrestricted WFP filter enumeration",
        )?;
        let enumeration = EnumHandle {
            engine: self.handle,
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
                        self.handle,
                        enumeration.handle,
                        128,
                        &mut entries,
                        &mut returned,
                    )
                },
                "enumerate WFP filters for legacy cleanup",
            )?;
            if returned == 0 {
                break;
            }
            // SAFETY: WFP returned `returned` valid pointers in `entries`.
            let filters = unsafe { std::slice::from_raw_parts(entries, returned as usize) };
            for filter in filters {
                if !filter.is_null() {
                    // SAFETY: each filter and provider key remain valid until
                    // the entries allocation is freed below.
                    let filter = unsafe { &**filter };
                    if !filter.providerKey.is_null()
                        && unsafe { *filter.providerKey == provider_key }
                    {
                        keys.push(filter.filterKey);
                    }
                }
            }
            let mut allocation = entries.cast::<c_void>();
            // SAFETY: entries was allocated by FwpmFilterEnum0.
            unsafe { FwpmFreeMemory0(&mut allocation) };
        }
        Ok(keys)
    }

    fn transaction(&self, operation: impl FnOnce(HANDLE) -> io::Result<()>) -> io::Result<()> {
        check(
            // SAFETY: handle is an open engine.
            unsafe { FwpmTransactionBegin0(self.handle, 0) },
            "begin legacy WFP cleanup transaction",
        )?;
        match operation(self.handle) {
            Ok(()) => check(
                // SAFETY: a transaction is active on this engine.
                unsafe { FwpmTransactionCommit0(self.handle) },
                "commit legacy WFP cleanup transaction",
            ),
            Err(error) => {
                // SAFETY: a transaction is active and abort is best effort.
                unsafe { FwpmTransactionAbort0(self.handle) };
                Err(error)
            }
        }
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        if !self.handle.is_invalid() {
            // SAFETY: handle was returned by FwpmEngineOpen0.
            unsafe { FwpmEngineClose0(self.handle) };
        }
    }
}

struct EnumHandle {
    engine: HANDLE,
    handle: HANDLE,
}

impl Drop for EnumHandle {
    fn drop(&mut self) {
        if !self.handle.is_invalid() {
            // SAFETY: enum handle belongs to this open engine.
            unsafe { FwpmFilterDestroyEnumHandle0(self.engine, self.handle) };
        }
    }
}

fn check(status: u32, action: &str) -> io::Result<()> {
    if status == 0 {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "{action} failed with WFP status 0x{status:08x}"
        )))
    }
}

fn ignore_not_found(status: u32, not_found: u32, action: &str) -> io::Result<()> {
    if status == 0 || status == not_found {
        Ok(())
    } else {
        check(status, action)
    }
}
