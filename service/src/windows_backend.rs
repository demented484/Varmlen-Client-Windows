use std::{io, path::PathBuf, time::Duration};

use async_trait::async_trait;
use tokio::{
    net::{lookup_host, TcpStream},
    time::{sleep, timeout},
};
use varmlen_protocol::{ConnectRequest, ServiceError, ServiceErrorCode};
use varmlen_service_core::{
    controller::ConnectionBackend,
    runtime::{
        inspect_native_tun_config, inspect_validation_config, PolicyMode, PolicySpec, RuntimeLayout,
    },
};

use crate::{
    state_record::DesiredStateRecord,
    windows_adapter::{find_varmlen_adapter, AdapterInfo},
    windows_process::{prepare_native_config, validate_config, ManagedXray, PreparedXrayConfig},
    windows_state::{ensure_state_directory, persist_desired_state, runtime_layout},
    windows_wfp::WfpEngine,
};

pub struct WindowsBackend {
    layout: RuntimeLayout,
    wfp: WfpEngine,
    active: Option<ManagedXray>,
    active_request: Option<ConnectRequest>,
    previous_request: Option<ConnectRequest>,
    candidate_request: Option<ConnectRequest>,
    prepared_candidate: Option<PreparedXrayConfig>,
    pending_operation_id: u64,
}

impl WindowsBackend {
    pub fn open() -> io::Result<Self> {
        let layout = runtime_layout()?;
        ensure_state_directory(&layout)?;
        Ok(Self {
            layout,
            wfp: WfpEngine::open()?,
            active: None,
            active_request: None,
            previous_request: None,
            candidate_request: None,
            prepared_candidate: None,
            pending_operation_id: 0,
        })
    }

    pub fn layout(&self) -> &RuntimeLayout {
        &self.layout
    }

    async fn stop_process(&mut self) -> io::Result<()> {
        if let Some(mut process) = self.active.take() {
            process.stop().await?;
        }
        Ok(())
    }

    async fn wait_for_candidate(&mut self) -> io::Result<AdapterInfo> {
        for _ in 0..60 {
            let running = self
                .active
                .as_mut()
                .ok_or_else(|| io::Error::other("Xray process was not started"))?
                .is_running()?;
            if !running {
                return Err(io::Error::other("Xray exited during startup"));
            }
            if let Some(adapter) = find_varmlen_adapter()? {
                if adapter.has_ipv4 && adapter.has_ipv6 && adapter.dns_count > 0 {
                    return Ok(adapter);
                }
            }
            sleep(Duration::from_millis(100)).await;
        }
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "Varmlen TUN adapter did not become ready with IPv4, IPv6 and DNS",
        ))
    }

    async fn connected_health_check(&self) -> io::Result<()> {
        timeout(Duration::from_secs(5), TcpStream::connect(("1.1.1.1", 443)))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "TCP health check timed out"))??;
        timeout(Duration::from_secs(5), lookup_host(("mullvad.net", 443)))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "DNS health check timed out"))??
            .next()
            .ok_or_else(|| io::Error::other("DNS health check returned no addresses"))?;
        Ok(())
    }

    fn policy(&self, request: &ConnectRequest, mode: PolicyMode) -> PolicySpec {
        PolicySpec {
            mode,
            allow_lan: request.allow_lan,
            xray_path: self.layout.xray_executable.clone(),
            excluded_apps: request
                .excluded_apps
                .iter()
                .map(|app| PathBuf::from(&app.canonical_path))
                .collect(),
            apps_selective: request.apps_selective,
        }
    }

    fn hold_policy(&self) -> PolicySpec {
        PolicySpec {
            mode: PolicyMode::Hold,
            allow_lan: false,
            xray_path: self.layout.xray_executable.clone(),
            excluded_apps: Vec::new(),
            apps_selective: false,
        }
    }
}

#[async_trait]
impl ConnectionBackend for WindowsBackend {
    fn set_operation_id(&mut self, operation_id: u64) {
        self.pending_operation_id = operation_id;
    }

    async fn validate_candidate(&mut self, request: &ConnectRequest) -> Result<(), ServiceError> {
        inspect_native_tun_config(&request.xray_config)
            .map_err(|error| service_error(ServiceErrorCode::ValidationFailed, error))?;
        inspect_validation_config(&request.validation_config)
            .map_err(|error| service_error(ServiceErrorCode::ValidationFailed, error))?;
        for app in &request.excluded_apps {
            let path = PathBuf::from(&app.canonical_path);
            if !path.is_absolute() || !path.is_file() {
                return Err(service_error(
                    ServiceErrorCode::ValidationFailed,
                    format!(
                        "excluded application does not exist or is not absolute: {}",
                        path.display()
                    ),
                ));
            }
        }
        validate_config(&self.layout, &request.validation_config)
            .await
            .map_err(|error| service_error(ServiceErrorCode::ValidationFailed, error))?;
        self.prepared_candidate = Some(
            prepare_native_config(&self.layout, &request.xray_config)
                .await
                .map_err(|error| service_error(ServiceErrorCode::ValidationFailed, error))?,
        );
        self.candidate_request = Some(request.clone());
        Ok(())
    }

    async fn install_transition_hold(&mut self) -> Result<(), ServiceError> {
        let candidate = self.candidate_request.clone().ok_or_else(|| {
            service_error(
                ServiceErrorCode::Internal,
                "candidate request missing before transition hold",
            )
        })?;
        persist_desired_state(
            &self.layout,
            &DesiredStateRecord::connecting(
                self.pending_operation_id,
                candidate.clone(),
                self.active_request.clone(),
                candidate.killswitch,
            ),
        )
        .map_err(|error| service_error(ServiceErrorCode::Internal, error))?;
        self.wfp
            .apply_policy(&self.hold_policy())
            .map_err(|error| service_error(ServiceErrorCode::HoldFailed, error))
    }

    async fn verify_transition_hold(&mut self) -> Result<(), ServiceError> {
        // apply_policy verifies every persistent filter by key after the
        // transaction commits.
        Ok(())
    }

    async fn stop_active(&mut self) -> Result<(), ServiceError> {
        self.previous_request = self.active_request.take();
        self.stop_process()
            .await
            .map_err(|error| service_error(ServiceErrorCode::XrayStartFailed, error))
    }

    async fn start_candidate(&mut self, request: &ConnectRequest) -> Result<(), ServiceError> {
        let prepared = self.prepared_candidate.as_ref().ok_or_else(|| {
            service_error(
                ServiceErrorCode::ValidationFailed,
                "native candidate was not preflighted",
            )
        })?;
        self.active = Some(
            ManagedXray::start_prepared(&self.layout, prepared)
                .map_err(|error| service_error(ServiceErrorCode::XrayStartFailed, error))?,
        );
        self.candidate_request = Some(request.clone());
        Ok(())
    }

    async fn verify_candidate(&mut self, _request: &ConnectRequest) -> Result<(), ServiceError> {
        self.wait_for_candidate()
            .await
            .map(|_| ())
            .map_err(|error| service_error(ServiceErrorCode::HealthCheckFailed, error))
    }

    async fn commit_policy(&mut self, request: &ConnectRequest) -> Result<(), ServiceError> {
        let adapter = find_varmlen_adapter()
            .map_err(|error| service_error(ServiceErrorCode::HealthCheckFailed, error))?
            .ok_or_else(|| {
                service_error(
                    ServiceErrorCode::HealthCheckFailed,
                    "Varmlen TUN adapter disappeared before policy commit",
                )
            })?;
        self.wfp
            .apply_policy(&self.policy(
                request,
                PolicyMode::Connected {
                    tun_luid: adapter.luid,
                },
            ))
            .map_err(|error| service_error(ServiceErrorCode::HoldFailed, error))?;
        self.connected_health_check()
            .await
            .map_err(|error| service_error(ServiceErrorCode::HealthCheckFailed, error))?;
        self.prepared_candidate
            .as_ref()
            .ok_or_else(|| service_error(ServiceErrorCode::Internal, "candidate config missing"))?
            .persist_active()
            .map_err(|error| service_error(ServiceErrorCode::Internal, error))?;
        persist_desired_state(
            &self.layout,
            &DesiredStateRecord::connected(self.pending_operation_id, request.clone()),
        )
        .map_err(|error| service_error(ServiceErrorCode::Internal, error))?;
        self.active_request = Some(request.clone());
        self.previous_request = None;
        self.candidate_request = None;
        self.prepared_candidate = None;
        Ok(())
    }

    async fn release_transition_hold(&mut self) -> Result<(), ServiceError> {
        // The connected policy atomically replaced the temporary hold.
        Ok(())
    }

    async fn restore_previous(&mut self) -> Result<(), ServiceError> {
        self.stop_process()
            .await
            .map_err(|error| service_error(ServiceErrorCode::RestoreFailed, error))?;
        let previous = self.previous_request.take().ok_or_else(|| {
            service_error(
                ServiceErrorCode::RestoreFailed,
                "there is no previous connection to restore",
            )
        })?;
        self.active = Some(
            ManagedXray::start(&self.layout, &previous.xray_config)
                .map_err(|error| service_error(ServiceErrorCode::RestoreFailed, error))?,
        );
        let adapter = self
            .wait_for_candidate()
            .await
            .map_err(|error| service_error(ServiceErrorCode::RestoreFailed, error))?;
        self.wfp
            .apply_policy(&self.policy(
                &previous,
                PolicyMode::Connected {
                    tun_luid: adapter.luid,
                },
            ))
            .map_err(|error| service_error(ServiceErrorCode::RestoreFailed, error))?;
        self.connected_health_check()
            .await
            .map_err(|error| service_error(ServiceErrorCode::RestoreFailed, error))?;
        persist_desired_state(
            &self.layout,
            &DesiredStateRecord::connected(self.pending_operation_id, previous.clone()),
        )
        .map_err(|error| service_error(ServiceErrorCode::RestoreFailed, error))?;
        self.active_request = Some(previous);
        self.candidate_request = None;
        self.prepared_candidate = None;
        Ok(())
    }

    async fn clear_network_state(&mut self, keep_blocked: bool) -> Result<(), ServiceError> {
        persist_desired_state(
            &self.layout,
            &DesiredStateRecord::disconnecting(self.pending_operation_id, keep_blocked),
        )
        .map_err(|error| service_error(ServiceErrorCode::CleanupFailed, error))?;
        self.stop_process()
            .await
            .map_err(|error| service_error(ServiceErrorCode::CleanupFailed, error))?;
        self.active_request = None;
        self.previous_request = None;
        self.candidate_request = None;
        self.prepared_candidate = None;
        if keep_blocked {
            self.wfp
                .apply_policy(&self.hold_policy())
                .map_err(|error| service_error(ServiceErrorCode::CleanupFailed, error))?;
            persist_desired_state(
                &self.layout,
                &DesiredStateRecord::blocked(
                    self.pending_operation_id,
                    "kill switch requested while disconnected",
                ),
            )
            .map_err(|error| service_error(ServiceErrorCode::CleanupFailed, error))
        } else {
            self.wfp
                .clear_filters()
                .map_err(|error| service_error(ServiceErrorCode::CleanupFailed, error))?;
            persist_desired_state(
                &self.layout,
                &DesiredStateRecord::disconnected(self.pending_operation_id),
            )
            .map_err(|error| service_error(ServiceErrorCode::CleanupFailed, error))
        }
    }

    async fn active_is_running(&mut self) -> Result<bool, ServiceError> {
        match self.active.as_mut() {
            Some(process) => process
                .is_running()
                .map_err(|error| service_error(ServiceErrorCode::Internal, error)),
            None => Ok(false),
        }
    }

    fn unexpected_failure_keep_blocked(&self) -> bool {
        self.active_request
            .as_ref()
            .is_some_and(|request| request.killswitch)
    }
}

fn service_error(code: ServiceErrorCode, error: impl std::fmt::Display) -> ServiceError {
    ServiceError::new(code, error.to_string())
}
