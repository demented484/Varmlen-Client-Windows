use std::{io, path::PathBuf, time::Duration};

use async_trait::async_trait;
use tokio::{
    net::{lookup_host, TcpSocket},
    time::{sleep, timeout},
};
use varmlen_protocol::{ConnectRequest, ServiceError, ServiceErrorCode};
use varmlen_service_core::{
    controller::ConnectionBackend,
    runtime::{
        inspect_native_tun_config, inspect_validation_config, rewrite_native_outbound_interface,
        RuntimeLayout, TUN_IPV4_GATEWAY,
    },
};

use crate::{
    state_record::DesiredStateRecord,
    windows_adapter::{best_outbound_interface_name, find_varmlen_adapter, AdapterInfo},
    windows_process::{prepare_native_config, validate_config, ManagedXray, PreparedXrayConfig},
    windows_state::{ensure_state_directory, persist_desired_state, runtime_layout},
    windows_wfp::cleanup_persistent_policy,
};

pub struct WindowsBackend {
    layout: RuntimeLayout,
    active: Option<ManagedXray>,
    active_request: Option<ConnectRequest>,
    previous_request: Option<ConnectRequest>,
    candidate_request: Option<ConnectRequest>,
    prepared_candidate: Option<PreparedXrayConfig>,
    active_interface: Option<String>,
    previous_interface: Option<String>,
    candidate_interface: Option<String>,
    pending_operation_id: u64,
}

impl WindowsBackend {
    pub fn open() -> io::Result<Self> {
        let layout = runtime_layout()?;
        ensure_state_directory(&layout)?;
        // Version 0.3.0 preview used persistent user-mode WFP filters for a
        // kill switch. They made connection and even uninstallation depend on
        // fragile filter enumeration. The native Xray TUN does not need them;
        // clean up old policy best-effort and keep the data path independent.
        let _ = cleanup_persistent_policy();
        Ok(Self {
            layout,
            active: None,
            active_request: None,
            previous_request: None,
            candidate_request: None,
            prepared_candidate: None,
            active_interface: None,
            previous_interface: None,
            candidate_interface: None,
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
        let source = TUN_IPV4_GATEWAY
            .split_once('/')
            .map(|(address, _)| address)
            .unwrap_or(TUN_IPV4_GATEWAY)
            .parse()
            .map_err(|error| io::Error::other(format!("invalid TUN probe address: {error}")))?;
        let socket = TcpSocket::new_v4()?;
        socket.bind(std::net::SocketAddr::new(source, 0))?;
        timeout(
            Duration::from_secs(5),
            socket.connect("1.1.1.1:443".parse().unwrap()),
        )
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "TUN-bound TCP health check timed out",
            )
        })??;
        let mut last_error = None;
        for _ in 0..3 {
            match timeout(Duration::from_secs(6), lookup_host(("mullvad.net", 443))).await {
                Ok(Ok(mut addresses)) => {
                    if addresses.next().is_some() {
                        return Ok(());
                    }
                    last_error = Some("DNS returned no addresses".to_string());
                }
                Ok(Err(error)) => last_error = Some(error.to_string()),
                Err(_) => last_error = Some("DNS query timed out".to_string()),
            }
            sleep(Duration::from_millis(350)).await;
        }
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            format!(
                "DNS health check failed after adapter startup: {}",
                last_error.unwrap_or_else(|| "unknown DNS error".into())
            ),
        ))
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
            let path_text = app.canonical_path.trim_end_matches(['\\', '/']);
            let path = PathBuf::from(path_text);
            if !path.is_absolute() || (!path.is_file() && !path.is_dir()) {
                return Err(service_error(
                    ServiceErrorCode::ValidationFailed,
                    format!(
                        "split-tunnel application or folder does not exist or is not absolute: {}",
                        path.display()
                    ),
                ));
            }
        }
        validate_config(&self.layout, &request.validation_config)
            .await
            .map_err(|error| service_error(ServiceErrorCode::ValidationFailed, error))?;

        // Resolve the endpoint's actual Windows route while the candidate TUN
        // is still down, then pin Xray to that adapter. This avoids the native
        // TUN's name/address heuristic choosing Hyper-V, WSL, or another
        // virtual interface and looping its own Reality/DoH traffic.
        let interface = match self.active_interface.clone() {
            // Candidate validation intentionally happens before the old tunnel
            // is stopped. Its default route would make GetBestInterfaceEx point
            // at Varmlen itself, so a reconnect reuses the physical adapter
            // already proven by the active connection.
            Some(interface) => interface,
            None => best_outbound_interface_name(&request.server_endpoints)
                .map_err(|error| service_error(ServiceErrorCode::ValidationFailed, error))?,
        };
        let effective_config = rewrite_native_outbound_interface(&request.xray_config, &interface)
            .map_err(|error| service_error(ServiceErrorCode::ValidationFailed, error))?;
        self.prepared_candidate = Some(
            prepare_native_config(&self.layout, &effective_config)
                .await
                .map_err(|error| service_error(ServiceErrorCode::ValidationFailed, error))?,
        );
        // Persist the portable `"auto"` intent. Every cold startup recalculates
        // the physical adapter from the then-current Windows route.
        self.candidate_request = Some(request.clone());
        self.candidate_interface = Some(interface);
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
                false,
            ),
        )
        .map_err(|error| service_error(ServiceErrorCode::Internal, error))
    }

    async fn verify_transition_hold(&mut self) -> Result<(), ServiceError> {
        Ok(())
    }

    async fn stop_active(&mut self) -> Result<(), ServiceError> {
        self.previous_request = self.active_request.take();
        self.previous_interface = self.active_interface.take();
        self.stop_process()
            .await
            .map_err(|error| service_error(ServiceErrorCode::XrayStartFailed, error))
    }

    async fn start_candidate(&mut self, _request: &ConnectRequest) -> Result<(), ServiceError> {
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
        Ok(())
    }

    async fn verify_candidate(&mut self, _request: &ConnectRequest) -> Result<(), ServiceError> {
        self.wait_for_candidate()
            .await
            .map(|_| ())
            .map_err(|error| service_error(ServiceErrorCode::HealthCheckFailed, error))
    }

    async fn commit_policy(&mut self, request: &ConnectRequest) -> Result<(), ServiceError> {
        let _adapter = find_varmlen_adapter()
            .map_err(|error| service_error(ServiceErrorCode::HealthCheckFailed, error))?
            .ok_or_else(|| {
                service_error(
                    ServiceErrorCode::HealthCheckFailed,
                    "Varmlen TUN adapter disappeared before policy commit",
                )
            })?;
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
        self.active_interface = self.candidate_interface.take();
        self.previous_request = None;
        self.previous_interface = None;
        self.candidate_request = None;
        self.prepared_candidate = None;
        Ok(())
    }

    async fn release_transition_hold(&mut self) -> Result<(), ServiceError> {
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
        let interface = match self.previous_interface.take() {
            Some(interface) => interface,
            None => best_outbound_interface_name(&previous.server_endpoints)
                .map_err(|error| service_error(ServiceErrorCode::RestoreFailed, error))?,
        };
        let effective_config = rewrite_native_outbound_interface(&previous.xray_config, &interface)
            .map_err(|error| service_error(ServiceErrorCode::RestoreFailed, error))?;
        self.active = Some(
            ManagedXray::start(&self.layout, &effective_config)
                .map_err(|error| service_error(ServiceErrorCode::RestoreFailed, error))?,
        );
        self.wait_for_candidate()
            .await
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
        self.active_interface = Some(interface);
        self.candidate_interface = None;
        self.candidate_request = None;
        self.prepared_candidate = None;
        Ok(())
    }

    async fn clear_network_state(&mut self, _keep_blocked: bool) -> Result<(), ServiceError> {
        persist_desired_state(
            &self.layout,
            &DesiredStateRecord::disconnecting(self.pending_operation_id, false),
        )
        .map_err(|error| service_error(ServiceErrorCode::CleanupFailed, error))?;
        self.stop_process()
            .await
            .map_err(|error| service_error(ServiceErrorCode::CleanupFailed, error))?;
        self.active_request = None;
        self.previous_request = None;
        self.candidate_request = None;
        self.prepared_candidate = None;
        self.active_interface = None;
        self.previous_interface = None;
        self.candidate_interface = None;
        let _ = cleanup_persistent_policy();
        persist_desired_state(
            &self.layout,
            &DesiredStateRecord::disconnected(self.pending_operation_id),
        )
        .map_err(|error| service_error(ServiceErrorCode::CleanupFailed, error))
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
        false
    }
}

fn service_error(code: ServiceErrorCode, error: impl std::fmt::Display) -> ServiceError {
    ServiceError::new(code, error.to_string())
}
