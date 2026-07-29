use std::{
    fs::{self, OpenOptions},
    io,
    process::Stdio,
    time::Duration,
};

use tokio::{
    process::{Child, Command},
    time::timeout,
};
use varmlen_service_core::runtime::RuntimeLayout;
use windows::Win32::System::Threading::CREATE_NO_WINDOW;

use crate::{
    process_plan::XrayInvocation,
    windows_state::{atomic_write, ensure_state_directory},
};

pub struct ManagedXray {
    child: Child,
}

impl ManagedXray {
    pub fn start(layout: &RuntimeLayout, config: &str) -> io::Result<Self> {
        ensure_runtime_assets(layout)?;
        ensure_state_directory(layout)?;
        atomic_write(&layout.active_config, config.as_bytes())?;
        let log = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&layout.log_file)?;
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
        let child = command.spawn()?;
        Ok(Self { child })
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

impl Drop for ManagedXray {
    fn drop(&mut self) {
        let _ = self.child.start_kill();
    }
}

pub async fn validate_config(layout: &RuntimeLayout, config: &str) -> io::Result<()> {
    ensure_runtime_assets(layout)?;
    ensure_state_directory(layout)?;
    atomic_write(&layout.validation_config, config.as_bytes())?;
    let invocation = XrayInvocation::validation(
        layout.xray_executable.clone(),
        layout.validation_config.clone(),
    );
    let mut command = command_for(&invocation);
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
