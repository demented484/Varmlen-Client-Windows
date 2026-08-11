use std::{
    fs::{self, OpenOptions},
    io,
    mem::size_of,
    process::Stdio,
    time::Duration,
};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    process::{Child, Command},
    time::{sleep, timeout, Instant},
};
use varmlen_service_core::runtime::{
    inspect_validation_config, rewrite_validation_ports, RuntimeLayout,
};
use windows::{
    core::PCWSTR,
    Win32::{
        Foundation::{CloseHandle, HANDLE},
        System::{
            JobObjects::{
                AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
                SetInformationJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
                JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
            },
            Threading::CREATE_NO_WINDOW,
        },
    },
};

use crate::{
    log_store::rotate_if_needed,
    process_plan::{
        socks5_ipv4_connect_request, validate_socks5_connect_header, validate_socks5_method_reply,
        XrayConfigTransaction, XrayInvocation,
    },
    windows_state::{atomic_write, ensure_state_directory},
};

pub struct ManagedXray {
    _job: OwnedJob,
    child: Child,
}

#[derive(Debug, Clone)]
pub struct PreparedXrayConfig {
    transaction: XrayConfigTransaction,
    contents: Vec<u8>,
}

impl PreparedXrayConfig {
    pub fn persist_active(&self) -> io::Result<()> {
        atomic_write(self.transaction.active_path(), &self.contents)
    }
}

impl ManagedXray {
    pub fn start(layout: &RuntimeLayout, config: &str) -> io::Result<Self> {
        ensure_runtime_assets(layout)?;
        ensure_state_directory(layout)?;
        atomic_write(&layout.active_config, config.as_bytes())?;
        let log = open_log(layout)?;
        let log_error = log.try_clone()?;
        let invocation =
            XrayInvocation::run(layout.xray_executable.clone(), layout.active_config.clone());
        let mut command = command_for(&invocation);
        command
            .current_dir(&layout.install_dir)
            .stdin(Stdio::null())
            .stdout(Stdio::from(log))
            .stderr(Stdio::from(log_error))
            .kill_on_drop(true);
        let job = OwnedJob::new()?;
        let child = command.spawn()?;
        job.assign(&child)?;
        Ok(Self { _job: job, child })
    }

    pub fn start_prepared(
        layout: &RuntimeLayout,
        prepared: &PreparedXrayConfig,
    ) -> io::Result<Self> {
        ensure_runtime_assets(layout)?;
        let log = open_log(layout)?;
        let log_error = log.try_clone()?;
        let invocation = prepared.transaction.start_candidate();
        let mut command = command_for(&invocation);
        command
            .current_dir(&layout.install_dir)
            .stdin(Stdio::null())
            .stdout(Stdio::from(log))
            .stderr(Stdio::from(log_error))
            .kill_on_drop(true);
        let job = OwnedJob::new()?;
        let child = command.spawn()?;
        job.assign(&child)?;
        Ok(Self { _job: job, child })
    }

    pub fn is_running(&mut self) -> io::Result<bool> {
        Ok(self.child.try_wait()?.is_none())
    }

    pub async fn stop(&mut self) -> io::Result<()> {
        if self.child.try_wait()?.is_none() {
            let _ = self.child.kill().await;
            let _ = timeout(Duration::from_secs(3), self.child.wait()).await;
        }
        Ok(())
    }
}

fn open_log(layout: &RuntimeLayout) -> io::Result<std::fs::File> {
    rotate_if_needed(&layout.log_file)?;
    OpenOptions::new()
        .create(true)
        .append(true)
        .open(&layout.log_file)
}

pub async fn prepare_native_config(
    layout: &RuntimeLayout,
    config: &str,
) -> io::Result<PreparedXrayConfig> {
    ensure_runtime_assets(layout)?;
    ensure_state_directory(layout)?;
    let transaction = XrayConfigTransaction::new(
        layout.xray_executable.clone(),
        layout.candidate_config.clone(),
        layout.active_config.clone(),
    );
    atomic_write(&layout.candidate_config, config.as_bytes())?;
    validate_config_syntax(layout, &transaction.preflight()).await?;
    Ok(PreparedXrayConfig {
        transaction,
        contents: config.as_bytes().to_vec(),
    })
}

impl Drop for ManagedXray {
    fn drop(&mut self) {
        let _ = self.child.start_kill();
    }
}

pub async fn validate_config(layout: &RuntimeLayout, config: &str) -> io::Result<()> {
    ensure_runtime_assets(layout)?;
    ensure_state_directory(layout)?;
    let inspection = inspect_validation_config(config)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let mut last_error = None;
    for _ in 0..4 {
        let (reservations, ports) = reserve_validation_ports(inspection.socks_ports.len())?;
        let rewritten = rewrite_validation_ports(config, &ports)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        atomic_write(&layout.validation_config, rewritten.as_bytes())?;
        let invocation = XrayInvocation::validation(
            layout.xray_executable.clone(),
            layout.validation_config.clone(),
        );
        validate_config_syntax(layout, &invocation).await?;

        // Xray cannot inherit these listener sockets. Release them immediately
        // before spawn and retry the complete reservation/start sequence if a
        // local process steals a port in that narrow interval.
        drop(reservations);
        let invocation = XrayInvocation::run(
            layout.xray_executable.clone(),
            layout.validation_config.clone(),
        );
        let mut command = command_for(&invocation);
        command
            .current_dir(&layout.install_dir)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        let job = OwnedJob::new()?;
        let mut child = match command.spawn() {
            Ok(child) => child,
            Err(error) => {
                last_error = Some(error);
                continue;
            }
        };
        if let Err(error) = job.assign(&child) {
            stop_child(&mut child).await;
            return Err(error);
        }

        let result = wait_for_socks_reachability(&mut child, &ports).await;
        stop_child(&mut child).await;
        drop(job);
        match result {
            Ok(()) => return Ok(()),
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.unwrap_or_else(|| {
        io::Error::new(
            io::ErrorKind::AddrInUse,
            "could not start Xray on service-owned validation ports",
        )
    }))
}

fn reserve_validation_ports(count: usize) -> io::Result<(Vec<std::net::TcpListener>, Vec<u16>)> {
    let mut reservations = Vec::with_capacity(count);
    let mut ports = Vec::with_capacity(count);
    while reservations.len() < count {
        let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        let port = listener.local_addr()?.port();
        if !ports.contains(&port) {
            ports.push(port);
            reservations.push(listener);
        }
    }
    Ok((reservations, ports))
}

async fn validate_config_syntax(
    layout: &RuntimeLayout,
    invocation: &XrayInvocation,
) -> io::Result<()> {
    let mut command = command_for(invocation);
    command
        .current_dir(&layout.install_dir)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let output = timeout(Duration::from_secs(8), command.output())
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "Xray validation timed out"))??;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        format!("Xray rejected the configuration: {stderr}{stdout}"),
    ))
}

async fn wait_for_socks_reachability(child: &mut Child, ports: &[u16]) -> io::Result<()> {
    let [port] = ports else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "validation requires exactly one effective-route SOCKS port",
        ));
    };
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut last_error = "effective route did not accept a connection".to_string();

    loop {
        if let Some(status) = child.try_wait()? {
            return Err(io::Error::other(format!(
                "validation Xray exited before the effective route became reachable: {status}"
            )));
        }

        match timeout(Duration::from_secs(3), probe_socks5(*port)).await {
            Ok(Ok(())) => return Ok(()),
            Ok(Err(error)) => last_error = error.to_string(),
            Err(_) => last_error = format!("SOCKS5 validation timed out on port {port}"),
        }

        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("effective route is unreachable: {last_error}"),
            ));
        }
        sleep(Duration::from_millis(100)).await;
    }
}

async fn probe_socks5(port: u16) -> io::Result<()> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).await?;
    stream.write_all(&[5, 1, 0]).await?;
    let mut method = [0u8; 2];
    stream.read_exact(&mut method).await?;
    validate_socks5_method_reply(method)
        .map_err(|error| io::Error::new(io::ErrorKind::ConnectionRefused, error))?;

    stream
        .write_all(&socks5_ipv4_connect_request([1, 1, 1, 1], 443))
        .await?;
    let mut header = [0u8; 4];
    stream.read_exact(&mut header).await?;
    let tail_len = validate_socks5_connect_header(header)
        .map_err(|error| io::Error::new(io::ErrorKind::ConnectionRefused, error))?;
    if tail_len == 0 {
        let domain_len = stream.read_u8().await? as usize;
        let mut tail = vec![0u8; domain_len + 2];
        stream.read_exact(&mut tail).await?;
    } else {
        let mut tail = vec![0u8; tail_len];
        stream.read_exact(&mut tail).await?;
    }
    Ok(())
}

async fn stop_child(child: &mut Child) {
    if child.try_wait().ok().flatten().is_none() {
        let _ = child.kill().await;
        let _ = timeout(Duration::from_secs(3), child.wait()).await;
    }
}

pub fn ensure_runtime_assets(layout: &RuntimeLayout) -> io::Result<()> {
    for path in [
        &layout.xray_executable,
        &layout.wintun_library,
        &layout.geoip_database,
        &layout.geosite_database,
    ] {
        let metadata = fs::metadata(path)?;
        if !metadata.is_file() || metadata.len() == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("runtime asset is missing or empty: {}", path.display()),
            ));
        }
    }
    Ok(())
}

fn command_for(invocation: &XrayInvocation) -> Command {
    let mut command = Command::new(&invocation.executable);
    command.args(&invocation.arguments);
    command.creation_flags(CREATE_NO_WINDOW.0);
    command
}

struct OwnedJob(HANDLE);

impl OwnedJob {
    fn new() -> io::Result<Self> {
        // SAFETY: no custom security descriptor or shared job name is used.
        let handle = unsafe { CreateJobObjectW(None, PCWSTR::null()) }.map_err(io::Error::other)?;
        let job = Self(handle);
        let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        // SAFETY: `limits` has the exact structure and size required by
        // JobObjectExtendedLimitInformation and remains alive for the call.
        unsafe {
            SetInformationJobObject(
                job.0,
                JobObjectExtendedLimitInformation,
                std::ptr::from_ref(&limits).cast(),
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        }
        .map_err(io::Error::other)?;
        Ok(job)
    }

    fn assign(&self, child: &Child) -> io::Result<()> {
        let process = HANDLE(
            child
                .raw_handle()
                .ok_or_else(|| io::Error::other("spawned Xray has no process handle"))?,
        );
        // SAFETY: both handles are valid and owned for at least this call.
        unsafe { AssignProcessToJobObject(self.0, process) }.map_err(io::Error::other)
    }
}

impl Drop for OwnedJob {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            // SAFETY: this guard exclusively owns the job handle.
            let _ = unsafe { CloseHandle(self.0) };
        }
    }
}

// Windows job handles are process-wide kernel handles. Transferring or sharing
// this owning guard across worker threads does not invalidate the handle; all
// access is through thread-safe Win32 handle operations.
unsafe impl Send for OwnedJob {}
unsafe impl Sync for OwnedJob {}
