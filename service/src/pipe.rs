use std::{
    ffi::c_void, fs, io, mem::size_of, os::windows::io::AsRawHandle, path::PathBuf, ptr, sync::Arc,
};

use async_trait::async_trait;
use tokio::{
    io::AsyncWriteExt,
    net::windows::named_pipe::{ClientOptions, NamedPipeServer, ServerOptions},
    sync::{watch, Mutex, Semaphore},
    task::JoinSet,
    time::{interval, timeout, MissedTickBehavior},
};
use varmlen_protocol::{
    decode_response, encode_payload, CoreCommand, RequestEnvelope, ServiceCommand, ServiceError,
    ServiceErrorCode, ServiceResponse, ServiceState, MAX_FRAME_BYTES, PROTOCOL_VERSION,
};
use varmlen_service_core::{
    controller::ConnectionController,
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
    core_manager::CoreManager,
    log_store::{clear_logs, tail_log},
    pipe_policy::{
        pipe_security_descriptor_sddl, InstalledUserSid, PipeClientIdentity, CLIENT_IO_TIMEOUT,
        MAX_CONCURRENT_CLIENTS,
    },
    state_record::DesiredStatePhase,
    windows_backend::WindowsBackend,
    windows_state::load_desired_state,
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

pub struct RuntimeExecutor {
    controller: Mutex<ConnectionController<WindowsBackend>>,
    core_manager: CoreManager,
    core_operations: Mutex<()>,
    log_path: PathBuf,
}

impl RuntimeExecutor {
    pub async fn open() -> io::Result<Self> {
        let backend = WindowsBackend::open()?;
        let log_path = backend.layout().log_file.clone();
        let desired = load_desired_state(backend.layout());
        let mut controller = ConnectionController::disconnected(backend);
        let (operation_id, keep_blocked_on_failure, recovery) = match desired {
            Ok(Some(record)) => {
                let operation_id = record.operation_id;
                let keep_blocked_on_failure = match &record.phase {
                    DesiredStatePhase::Connected { request } => request.killswitch,
                    DesiredStatePhase::Connecting {
                        candidate,
                        previous,
                        requested_kill_switch,
                    } => {
                        *requested_kill_switch
                            || candidate.killswitch
                            || previous.as_ref().is_some_and(|request| request.killswitch)
                    }
                    DesiredStatePhase::Disconnecting { keep_blocked } => *keep_blocked,
                    DesiredStatePhase::Blocked { .. } => true,
                    DesiredStatePhase::Disconnected => false,
                };
                let recovery = match record.phase {
                    DesiredStatePhase::Connected { request } => {
                        controller.connect(operation_id, request).await
                    }
                    DesiredStatePhase::Connecting {
                        previous: Some(previous),
                        ..
                    } => controller.connect(operation_id, previous).await,
                    DesiredStatePhase::Connecting {
                        requested_kill_switch,
                        ..
                    } => {
                        controller
                            .disconnect(operation_id, requested_kill_switch)
                            .await
                    }
                    DesiredStatePhase::Disconnecting { keep_blocked } => {
                        controller.disconnect(operation_id, keep_blocked).await
                    }
                    DesiredStatePhase::Blocked { .. } => {
                        controller.disconnect(operation_id, true).await
                    }
                    DesiredStatePhase::Disconnected => {
                        controller.disconnect(operation_id, false).await
                    }
                };
                (operation_id, keep_blocked_on_failure, recovery)
            }
            Ok(None) => (0, false, controller.disconnect(0, false).await),
            Err(_) => (0, false, controller.disconnect(0, false).await),
        };
        if recovery.is_err()
            && controller
                .disconnect(operation_id, keep_blocked_on_failure)
                .await
                .is_err()
        {
            controller.force_blocked(operation_id);
        }
        Ok(Self {
            core_manager: CoreManager::new(controller.backend().layout().clone()),
            core_operations: Mutex::new(()),
            controller: Mutex::new(controller),
            log_path,
        })
    }
}

#[async_trait]
impl CommandExecutor for RuntimeExecutor {
    async fn execute(
        &self,
        operation_id: u64,
        command: ServiceCommand,
    ) -> Result<ServiceResponse, ServiceError> {
        match command {
            ServiceCommand::Status => Ok(ServiceResponse::State(
                self.controller.lock().await.state().clone(),
            )),
            ServiceCommand::Connect(mut request) => {
                let _operation = self.core_operations.lock().await;
                request.xray_version = self.core_manager.active_tag();
                self.controller
                    .lock()
                    .await
                    .connect(operation_id, request)
                    .await
                    .map(ServiceResponse::State)
            }
            ServiceCommand::Disconnect { keep_blocked } => self
                .controller
                .lock()
                .await
                .disconnect(operation_id, keep_blocked)
                .await
                .map(ServiceResponse::State),
            ServiceCommand::LogTail { max_bytes } => tail_log(&self.log_path, max_bytes as usize)
                .map(ServiceResponse::LogTail)
                .map_err(|error| ServiceError::new(ServiceErrorCode::Internal, error.to_string())),
            ServiceCommand::ClearLog => clear_logs(&self.log_path)
                .map(|()| ServiceResponse::Ack)
                .map_err(|error| ServiceError::new(ServiceErrorCode::Internal, error.to_string())),
            ServiceCommand::Core(command) => self.execute_core(operation_id, command).await,
        }
    }
}

impl RuntimeExecutor {
    async fn execute_core(
        &self,
        operation_id: u64,
        command: CoreCommand,
    ) -> Result<ServiceResponse, ServiceError> {
        match command {
            CoreCommand::Info => {
                let latest = self
                    .core_manager
                    .list_releases()
                    .await
                    .ok()
                    .and_then(|releases| releases.into_iter().next().map(|release| release.tag));
                Ok(ServiceResponse::CoreInfo(
                    self.core_manager.local_info(latest),
                ))
            }
            CoreCommand::Active => {
                let _operation = self.core_operations.lock().await;
                Ok(ServiceResponse::CoreActive(self.core_manager.active_tag()))
            }
            CoreCommand::ListReleases => self
                .core_manager
                .list_releases()
                .await
                .map(ServiceResponse::CoreReleases)
                .map_err(core_error),
            CoreCommand::Install { tag } => {
                let _operation = self.core_operations.lock().await;
                self.core_manager
                    .install(tag)
                    .await
                    .map(ServiceResponse::CoreInstalled)
                    .map_err(core_error)
            }
            CoreCommand::Activate { tag } => {
                let _operation = self.core_operations.lock().await;
                let old_tag = self.core_manager.active_tag();
                self.core_manager.activate(&tag).await.map_err(core_error)?;
                let new_tag = self.core_manager.active_tag();
                if new_tag == old_tag {
                    return Ok(ServiceResponse::Ack);
                }

                let mut controller = self.controller.lock().await;
                if controller.state().phase == varmlen_protocol::ConnectionPhase::Connected {
                    let Some(mut request) = controller.backend().active_request() else {
                        let rollback = self.core_manager.activate(&old_tag).await;
                        return Err(ServiceError::new(
                            ServiceErrorCode::Internal,
                            match rollback {
                                Ok(()) => "connected service has no active connection request".into(),
                                Err(rollback) => format!(
                                    "connected service has no active connection request; also failed to restore Xray {old_tag}: {rollback}"
                                ),
                            },
                        ));
                    };
                    request.xray_version = new_tag;
                    if let Err(error) = controller.connect(operation_id, request).await {
                        let rollback = self.core_manager.activate(&old_tag).await;
                        return match rollback {
                            Ok(()) => Err(error),
                            Err(rollback) => Err(ServiceError::new(
                                ServiceErrorCode::RestoreFailed,
                                format!(
                                    "{}; also failed to restore Xray {old_tag}: {rollback}",
                                    error.message
                                ),
                            )),
                        };
                    }
                }
                Ok(ServiceResponse::Ack)
            }
            CoreCommand::Uninstall { tag } => {
                let _operation = self.core_operations.lock().await;
                self.core_manager.uninstall(&tag).map_err(core_error)?;
                Ok(ServiceResponse::Ack)
            }
        }
    }
}

fn core_error(message: impl Into<String>) -> ServiceError {
    ServiceError::new(ServiceErrorCode::Internal, message)
}

pub struct PipeHost {
    installed_user: Arc<InstalledUserSid>,
    executor: Arc<RuntimeExecutor>,
    listener: NamedPipeServer,
}

impl PipeHost {
    pub async fn open() -> io::Result<Self> {
        let installed_user = Arc::new(load_installed_user_sid()?);
        let executor = Arc::new(RuntimeExecutor::open().await?);
        let listener = create_pipe_server(&installed_user, true)?;
        Ok(Self {
            installed_user,
            executor,
            listener,
        })
    }

    pub async fn run(mut self, mut shutdown: watch::Receiver<bool>) -> io::Result<()> {
        let monitor = tokio::spawn(run_runtime_monitor(
            Arc::clone(&self.executor),
            shutdown.clone(),
        ));
        let client_slots = Arc::new(Semaphore::new(MAX_CONCURRENT_CLIENTS));
        let mut clients = JoinSet::new();

        loop {
            tokio::select! {
                connect_result = self.listener.connect() => {
                    connect_result?;
                    let connected = self.listener;
                    self.listener = create_pipe_server(&self.installed_user, false)?;

                    let Ok(slot) = Arc::clone(&client_slots).try_acquire_owned() else {
                        drop(connected);
                        continue;
                    };
                    let installed_user = Arc::clone(&self.installed_user);
                    let executor = Arc::clone(&self.executor);
                    clients.spawn(async move {
                        let _slot = slot;
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

        drop(self.listener);
        clients.shutdown().await;
        monitor.abort();
        let _ = monitor.await;
        Ok(())
    }
}

pub async fn run_pipe_host(shutdown: watch::Receiver<bool>) -> io::Result<()> {
    PipeHost::open().await?.run(shutdown).await
}

pub async fn service_health_check() -> io::Result<ServiceState> {
    let mut pipe = ClientOptions::new()
        .read(true)
        .write(true)
        .open(PIPE_NAME)?;
    let operation_id = u64::MAX;
    let request = encode_payload(&RequestEnvelope {
        version: PROTOCOL_VERSION,
        operation_id,
        command: ServiceCommand::Status,
    })
    .map_err(service_code_to_io)?;
    timeout(CLIENT_IO_TIMEOUT, write_payload(&mut pipe, &request))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "service health write timed out"))?
        .map_err(service_code_to_io)?;
    timeout(CLIENT_IO_TIMEOUT, pipe.flush())
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "service health flush timed out"))??;
    let response = timeout(CLIENT_IO_TIMEOUT, read_payload(&mut pipe))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "service health read timed out"))?
        .map_err(service_code_to_io)?;
    let response = decode_response(&response).map_err(service_code_to_io)?;
    if response.operation_id != operation_id {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "service health response has a mismatched operation ID",
        ));
    }
    match response
        .result
        .map_err(|error| io::Error::other(error.message))?
    {
        ServiceResponse::State(state) => Ok(state),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "service health returned the wrong response type",
        )),
    }
}

async fn run_runtime_monitor(executor: Arc<RuntimeExecutor>, mut shutdown: watch::Receiver<bool>) {
    let mut ticks = interval(std::time::Duration::from_millis(500));
    ticks.set_missed_tick_behavior(MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = ticks.tick() => {
                let mut controller = executor.controller.lock().await;
                let _ = controller.audit_runtime().await;
            }
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    return;
                }
            }
        }
    }
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

    let request = timeout(CLIENT_IO_TIMEOUT, read_payload(&mut pipe))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "pipe request timed out"))?
        .map_err(service_code_to_io)?;
    let response = handle_payload(executor, &request)
        .await
        .map_err(service_code_to_io)?;
    timeout(CLIENT_IO_TIMEOUT, write_payload(&mut pipe, &response))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "pipe response timed out"))?
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
