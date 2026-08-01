use std::{
    fs, io,
    os::windows::ffi::OsStrExt,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use varmlen_service_core::runtime::RuntimeLayout;
use windows::{
    core::PCWSTR,
    Win32::{
        Foundation::{LocalFree, HLOCAL},
        Security::Cryptography::{
            CryptProtectData, CryptUnprotectData, CRYPTPROTECT_LOCAL_MACHINE, CRYPT_INTEGER_BLOB,
        },
        Storage::FileSystem::{MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH},
    },
};

use crate::state_record::{decode_desired_state, encode_desired_state, DesiredStateRecord};

const STATE_DIRECTORY: &str = "Varmlen";

pub fn runtime_layout() -> io::Result<RuntimeLayout> {
    let executable = std::env::current_exe()?;
    let program_data = std::env::var_os("ProgramData")
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "ProgramData is not set"))?;
    RuntimeLayout::from_service_executable(
        executable,
        PathBuf::from(program_data).join(STATE_DIRECTORY),
    )
    .map_err(io::Error::other)
}

pub fn ensure_state_directory(layout: &RuntimeLayout) -> io::Result<()> {
    fs::create_dir_all(&layout.state_dir)
}

pub fn persist_desired_state(
    layout: &RuntimeLayout,
    record: &DesiredStateRecord,
) -> io::Result<()> {
    ensure_state_directory(layout)?;
    let encoded = encode_desired_state(record).map_err(io::Error::other)?;
    let protected = protect_machine(&encoded)?;
    atomic_write(&layout.desired_state, &protected)
}

pub fn load_desired_state(layout: &RuntimeLayout) -> io::Result<Option<DesiredStateRecord>> {
    let protected = match fs::read(&layout.desired_state) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let cleartext = unprotect_machine(&protected)?;
    decode_desired_state(&cleartext)
        .map(Some)
        .map_err(io::Error::other)
}

pub fn clear_desired_state(layout: &RuntimeLayout) -> io::Result<()> {
    match fs::remove_file(&layout.desired_state) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

pub fn atomic_write(path: &Path, contents: &[u8]) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no parent"))?;
    fs::create_dir_all(parent)?;
    static NEXT_TEMPORARY: AtomicU64 = AtomicU64::new(1);
    let filename = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no filename"))?
        .to_string_lossy();
    let temporary = parent.join(format!(
        ".{filename}.{}.{}.tmp",
        std::process::id(),
        NEXT_TEMPORARY.fetch_add(1, Ordering::Relaxed)
    ));
    {
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        let mut file = options.open(&temporary)?;
        use io::Write;
        file.write_all(contents)?;
        file.sync_all()?;
    }
    let source = wide_path(&temporary);
    let destination = wide_path(path);
    // SAFETY: both UTF-16 buffers are NUL terminated and remain alive for the
    // duration of the call. The temporary file is on the same volume.
    let replaced = unsafe {
        MoveFileExW(
            PCWSTR(source.as_ptr()),
            PCWSTR(destination.as_ptr()),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if let Err(error) = replaced {
        let _ = fs::remove_file(&temporary);
        return Err(io::Error::other(error));
    }
    Ok(())
}

fn wide_path(path: &Path) -> Vec<u16> {
    path.as_os_str().encode_wide().chain(Some(0)).collect()
}

fn protect_machine(cleartext: &[u8]) -> io::Result<Vec<u8>> {
    let input = blob_for_slice(cleartext);
    let mut output = CRYPT_INTEGER_BLOB::default();
    // SAFETY: input references `cleartext` for this call and output is valid
    // writable storage. Windows allocates output with LocalAlloc.
    unsafe {
        CryptProtectData(
            &input,
            windows::core::w!("Varmlen desired VPN state"),
            None,
            None,
            None,
            CRYPTPROTECT_LOCAL_MACHINE,
            &mut output,
        )
    }
    .map_err(io::Error::other)?;
    take_local_blob(output)
}

fn unprotect_machine(ciphertext: &[u8]) -> io::Result<Vec<u8>> {
    let input = blob_for_slice(ciphertext);
    let mut output = CRYPT_INTEGER_BLOB::default();
    // SAFETY: input references `ciphertext` for this call and output is valid
    // writable storage. Windows allocates output with LocalAlloc.
    unsafe { CryptUnprotectData(&input, None, None, None, None, 0, &mut output) }
        .map_err(io::Error::other)?;
    take_local_blob(output)
}

fn blob_for_slice(bytes: &[u8]) -> CRYPT_INTEGER_BLOB {
    CRYPT_INTEGER_BLOB {
        cbData: bytes.len() as u32,
        pbData: bytes.as_ptr().cast_mut(),
    }
}

fn take_local_blob(blob: CRYPT_INTEGER_BLOB) -> io::Result<Vec<u8>> {
    if blob.cbData > 0 && blob.pbData.is_null() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "DPAPI returned a null output buffer",
        ));
    }
    // SAFETY: DPAPI returned `cbData` initialized bytes at `pbData`.
    let bytes = unsafe { std::slice::from_raw_parts(blob.pbData, blob.cbData as usize) }.to_vec();
    if !blob.pbData.is_null() {
        // SAFETY: DPAPI allocates the output with LocalAlloc.
        unsafe {
            LocalFree(Some(HLOCAL(blob.pbData.cast())));
        }
    }
    Ok(bytes)
}
