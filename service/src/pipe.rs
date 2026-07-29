use std::{
    ffi::c_void,
    fs, io,
    mem::size_of,
    os::windows::io::AsRawHandle,
    path::PathBuf,
    ptr,
    sync::{Arc, RwLock},
};

use async_trait::async_trait;
use tokio::{
    net::windows::named_pipe::{NamedPipeServer, ServerOptions},
    sync::watch,
    task::JoinSet,
};
use varmlen_protocol::{
    ServiceCommand, ServiceError, ServiceErrorCode, ServiceState, MAX_FRAME_BYTES,
};
use varmlen_service_core::{
    framing::{read_payload, write_payload},
    handler::{handle_payload, CommandExecutor},
};
use windows::{
    core::{PCWSTR, PWSTR},
    Win32::{
        Foundation::{CloseHandle, LocalFree, HANDLE, HLOCAL},
        Security::{
            Authorization::{
                ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
                SDDL_REVISION_1,
            },
            GetTokenInformation, RevertToSelf, TokenUser, PSECURITY_DESCRIPTOR,
            SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER,
        },
        System::{
            Pipes::ImpersonateNamedPipeClient,
            Threading::{GetCurrentThread, OpenThreadToken},
        },
    },
};

use crate::{
    pipe_policy::{pipe_security_descriptor_sddl, InstalledUserSid, PipeClientIdentity},
    PIPE_NAME,
};

const INSTALLED_USER_SID_FILE: &str = "installed-user.sid";
const LOCAL_SYSTEM_SID: &str = "S-1-5-18";

pub fn installed_user_sid_path() -> io::Result<PathBuf> {
    let program_data = std::env::var_os("ProgramData")
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "ProgramData is not set"))?;
    Ok(PathBuf::from(program_data)
        .join("Varmlen")
        .join(INSTALLED_USER_SID_FILE))
}

pub fn load_installed_user_sid() -> io::Result<InstalledUserSid> {
    let path = installed_user_sid_path()?;
    let metadata = fs::metadata(&path)?;
    if metadata.len() > 512 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "installed user SID file is too large",
        ));
    }
    let sid = fs::read_to_string(path)?;
    InstalledUserSid::parse(sid.trim_end_matches(['\r', '\n'])).map_err(|message| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid installed user SID: {message}"),
        )
    })
}

#[derive(Clone)]
pub struct SnapshotExecutor {
    state: Arc<RwLock<ServiceState>>,
}

impl SnapshotExecutor {
    pub fn disconnected() -> Self {
        Self {
            state: Arc::new(RwLock::new(ServiceState::disconnected())),
        }
    }
}

#[async_trait]
impl CommandExecutor for SnapshotExecutor {
    async fn execute(&self, command: ServiceCommand) -> Result<ServiceState, ServiceError> {
        match command {
            ServiceCommand::Status => {
                self.state.read().map(|state| state.clone()).map_err(|_| {
                    ServiceError::new(ServiceErrorCode::Internal, "state lock poisoned")
                })
            }
            ServiceCommand::Connect(_) | ServiceCommand::Disconnect { .. } => {
                Err(ServiceError::new(
                    ServiceErrorCode::Internal,
                    "Windows data plane is not implemented in this foundation build",
                ))
            }
        }
    }
}

pub async fn run_pipe_host(mut shutdown: watch::Receiver<bool>) -> io::Result<()> {
    let installed_user = Arc::new(load_installed_user_sid()?);
    let executor = Arc::new(SnapshotExecutor::disconnected());
    let mut clients = JoinSet::new();
    let mut listener = create_pipe_server(&installed_user, true)?;

    loop {
        tokio::select! {
            connect_result = listener.connect() => {
                connect_result?;
                let connected = listener;
                listener = create_pipe_server(&installed_user, false)?;

                let installed_user = Arc::clone(&installed_user);
                let executor = Arc::clone(&executor);
                clients.spawn(async move {
                    let _ = serve_client(connected, &installed_user, executor.as_ref()).await;
                });
            }
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            Some(_) = clients.join_next(), if !clients.is_empty() => {}
        }
    }

    drop(listener);
    clients.shutdown().await;
    Ok(())
}

fn create_pipe_server(
    installed_user: &InstalledUserSid,
    first_instance: bool,
) -> io::Result<NamedPipeServer> {
    let descriptor =
        OwnedSecurityDescriptor::from_sddl(&pipe_security_descriptor_sddl(installed_user))?;
    let mut attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.as_ptr(),
        bInheritHandle: false.into(),
    };
    let mut options = ServerOptions::new();
    options
        .first_pipe_instance(first_instance)
        .reject_remote_clients(true)
        .in_buffer_size(MAX_FRAME_BYTES as u32)
        .out_buffer_size(MAX_FRAME_BYTES as u32);

    // SAFETY: attributes and its security descriptor remain valid for the
    // complete CreateNamedPipeW call. Windows copies the descriptor into the
    // newly created kernel object before this function returns.
    unsafe {
        options.create_with_security_attributes_raw(
            PIPE_NAME,
            ptr::from_mut(&mut attributes).cast::<c_void>(),
        )
    }
}

async fn serve_client<E>(
    mut pipe: NamedPipeServer,
    installed_user: &InstalledUserSid,
    executor: &E,
) -> io::Result<()>
where
    E: CommandExecutor + ?Sized,
{
    let identity = connected_client_identity(&pipe)?;
    if !identity.authorize(installed_user) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "named-pipe client is not authorized",
        ));
    }

    let request = read_payload(&mut pipe).await.map_err(service_code_to_io)?;
    let response = handle_payload(executor, &request)
        .await
        .map_err(service_code_to_io)?;
    write_payload(&mut pipe, &response)
        .await
        .map_err(service_code_to_io)
}

fn connected_client_identity(pipe: &NamedPipeServer) -> io::Result<PipeClientIdentity> {
    let pipe_handle = HANDLE(pipe.as_raw_handle());

    // SAFETY: pipe_handle belongs to a connected NamedPipeServer and remains
    // valid for the entire impersonation/token-query sequence.
    unsafe { ImpersonateNamedPipeClient(pipe_handle) }.map_err(windows_error_to_io)?;
    let _impersonation = ImpersonationGuard;

    let mut token = HANDLE::default();
    // SAFETY: the current thread is impersonating the named-pipe client and
    // token points to valid writable storage.
    unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, true, &mut token) }
        .map_err(windows_error_to_io)?;
    let token = OwnedHandle(token);

    let mut required = 0u32;
    // SAFETY: this first call intentionally provides no buffer so Windows
    // reports the required size through `required`.
    let _ = unsafe { GetTokenInformation(token.0, TokenUser, None, 0, &mut required) };
    if required < size_of::<TOKEN_USER>() as u32 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "client token did not contain a user SID",
        ));
    }

    let words = (required as usize).div_ceil(size_of::<usize>());
    let mut buffer = vec![0usize; words];
    // SAFETY: buffer is aligned to usize, large enough for `required` bytes,
    // and remains alive while TOKEN_USER and its embedded SID are inspected.
    unsafe {
        GetTokenInformation(
            token.0,
            TokenUser,
            Some(buffer.as_mut_ptr().cast::<c_void>()),
            required,
            &mut required,
        )
    }
    .map_err(windows_error_to_io)?;

    // SAFETY: GetTokenInformation(TokenUser) initialized a TOKEN_USER at the
    // start of the aligned buffer.
    let token_user = unsafe { &*buffer.as_ptr().cast::<TOKEN_USER>() };
    let sid = sid_to_string(token_user.User.Sid)?;
    let sid = InstalledUserSid::parse(&sid)
        .map_err(|message| io::Error::new(io::ErrorKind::InvalidData, message))?;

    if sid.as_str() == LOCAL_SYSTEM_SID {
        Ok(PipeClientIdentity::local_system())
    } else {
        Ok(PipeClientIdentity::local(sid))
    }
}

fn sid_to_string(sid: windows::Win32::Security::PSID) -> io::Result<String> {
    let mut text = PWSTR::null();
    // SAFETY: sid belongs to the token buffer and text points to valid writable
    // storage for the LocalAlloc-owned result pointer.
    unsafe { ConvertSidToStringSidW(sid, &mut text) }.map_err(windows_error_to_io)?;
    let _text = OwnedLocal(text.0.cast::<c_void>());

    // SAFETY: ConvertSidToStringSidW returns a NUL-terminated UTF-16 string.
    unsafe { text.to_string() }.map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

fn service_code_to_io(code: ServiceErrorCode) -> io::Error {
    let kind = match code {
        ServiceErrorCode::Unauthorized => io::ErrorKind::PermissionDenied,
        ServiceErrorCode::FrameTooLarge
        | ServiceErrorCode::InvalidFrame
        | ServiceErrorCode::InvalidRequest
        | ServiceErrorCode::UnsupportedVersion => io::ErrorKind::InvalidData,
        _ => io::ErrorKind::Other,
    };
    io::Error::new(kind, format!("service protocol error: {code:?}"))
}

fn windows_error_to_io(error: windows::core::Error) -> io::Error {
    io::Error::other(error)
}

struct OwnedSecurityDescriptor(PSECURITY_DESCRIPTOR);

impl OwnedSecurityDescriptor {
    fn from_sddl(sddl: &str) -> io::Result<Self> {
        let wide = sddl.encode_utf16().chain(Some(0)).collect::<Vec<_>>();
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        // SAFETY: wide is NUL terminated and descriptor points to valid
        // writable storage for the LocalAlloc-owned result.
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(wide.as_ptr()),
                SDDL_REVISION_1,
                &mut descriptor,
                None,
            )
        }
        .map_err(windows_error_to_io)?;
        Ok(Self(descriptor))
    }

    fn as_ptr(&self) -> *mut c_void {
        self.0 .0
    }
}

impl Drop for OwnedSecurityDescriptor {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            // SAFETY: the descriptor was allocated by
            // ConvertStringSecurityDescriptorToSecurityDescriptorW.
            unsafe {
                LocalFree(Some(HLOCAL(self.0 .0)));
            }
        }
    }
}

struct OwnedLocal(*mut c_void);

impl Drop for OwnedLocal {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: this pointer was allocated by a Win32 conversion API
            // documented to require LocalFree.
            unsafe {
                LocalFree(Some(HLOCAL(self.0)));
            }
        }
    }
}

struct OwnedHandle(HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            // SAFETY: this handle was returned by OpenThreadToken and is owned
            // by this guard.
            let _ = unsafe { CloseHandle(self.0) };
        }
    }
}

struct ImpersonationGuard;

impl Drop for ImpersonationGuard {
    fn drop(&mut self) {
        // SAFETY: this guard is created only after successful impersonation.
        let _ = unsafe { RevertToSelf() };
    }
}
