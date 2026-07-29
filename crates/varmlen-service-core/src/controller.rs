use async_trait::async_trait;
use varmlen_protocol::{ConnectRequest, ConnectionPhase, ServiceError, ServiceState};

#[async_trait]
pub trait ConnectionBackend {
    fn set_operation_id(&mut self, _operation_id: u64) {}
    async fn validate_candidate(&mut self, request: &ConnectRequest) -> Result<(), ServiceError>;
    async fn install_transition_hold(&mut self) -> Result<(), ServiceError>;
    async fn verify_transition_hold(&mut self) -> Result<(), ServiceError>;
    async fn stop_active(&mut self) -> Result<(), ServiceError>;
    async fn start_candidate(&mut self, request: &ConnectRequest) -> Result<(), ServiceError>;
    async fn verify_candidate(&mut self, request: &ConnectRequest) -> Result<(), ServiceError>;
    async fn commit_policy(&mut self, request: &ConnectRequest) -> Result<(), ServiceError>;
    async fn release_transition_hold(&mut self) -> Result<(), ServiceError>;
    async fn restore_previous(&mut self) -> Result<(), ServiceError>;
    async fn clear_network_state(&mut self, keep_blocked: bool) -> Result<(), ServiceError>;
}

pub struct ConnectionController<B> {
    backend: B,
    state: ServiceState,
}

impl<B> ConnectionController<B> {
    pub fn connected(backend: B) -> Self {
        Self {
            backend,
            state: ServiceState {
                phase: ConnectionPhase::Connected,
                operation_id: 0,
                split_active: false,
                dns_protected: true,
                network_blocked: false,
            },
        }
    }

    pub fn disconnected(backend: B) -> Self {
        Self {
            backend,
            state: ServiceState::disconnected(),
        }
    }

    pub fn state(&self) -> &ServiceState {
        &self.state
    }

    pub fn backend(&self) -> &B {
        &self.backend
    }

    pub fn backend_mut(&mut self) -> &mut B {
        &mut self.backend
    }

    pub fn force_blocked(&mut self, operation_id: u64) {
        self.state = ServiceState {
            phase: ConnectionPhase::Blocked,
            operation_id,
            split_active: false,
            dns_protected: false,
            network_blocked: true,
        };
    }
}

impl<B: ConnectionBackend> ConnectionController<B> {
    async fn recover_candidate_failure(
        &mut self,
        operation_id: u64,
        was_connected: bool,
        previous_state: ServiceState,
    ) -> Result<(), ServiceError> {
        if !was_connected {
            self.state = blocked_error_state(operation_id);
            return Ok(());
        }

        self.state.phase = ConnectionPhase::Restoring;
        if let Err(error) = self.backend.restore_previous().await {
            self.state = blocked_error_state(operation_id);
            return Err(error);
        }
        if let Err(error) = self.backend.release_transition_hold().await {
            self.state = blocked_error_state(operation_id);
            return Err(error);
        }
        self.state = previous_state;
        Ok(())
    }

    pub async fn connect(
        &mut self,
        operation_id: u64,
        request: ConnectRequest,
    ) -> Result<ServiceState, ServiceError> {
        self.backend.set_operation_id(operation_id);
        let previous_state = self.state.clone();
        let was_connected = self.state.phase == ConnectionPhase::Connected;

        self.state.phase = ConnectionPhase::Validating;
        self.state.operation_id = operation_id;
        if let Err(error) = self.backend.validate_candidate(&request).await {
            self.state = previous_state;
            return Err(error);
        }

        self.state.phase = ConnectionPhase::Holding;
        if let Err(error) = self.backend.install_transition_hold().await {
            self.state = previous_state;
            return Err(error);
        }
        if let Err(error) = self.backend.verify_transition_hold().await {
            if let Err(release_error) = self.backend.release_transition_hold().await {
                self.state = blocked_error_state(operation_id);
                return Err(release_error);
            }
            self.state = previous_state;
            return Err(error);
        }

        if was_connected {
            if let Err(error) = self.backend.stop_active().await {
                self.state = blocked_error_state(operation_id);
                return Err(error);
            }
        }

        self.state.phase = ConnectionPhase::Starting;
        if let Err(error) = self.backend.start_candidate(&request).await {
            self.recover_candidate_failure(operation_id, was_connected, previous_state)
                .await?;
            return Err(error);
        }
        if let Err(error) = self.backend.verify_candidate(&request).await {
            self.recover_candidate_failure(operation_id, was_connected, previous_state)
                .await?;
            return Err(error);
        }
        if let Err(error) = self.backend.commit_policy(&request).await {
            self.recover_candidate_failure(operation_id, was_connected, previous_state)
                .await?;
            return Err(error);
        }
        if let Err(error) = self.backend.release_transition_hold().await {
            self.state = blocked_error_state(operation_id);
            return Err(error);
        }

        self.state = ServiceState {
            phase: ConnectionPhase::Connected,
            operation_id,
            split_active: !request.excluded_apps.is_empty(),
            dns_protected: true,
            network_blocked: false,
        };
        Ok(self.state.clone())
    }

    pub async fn disconnect(
        &mut self,
        operation_id: u64,
        keep_blocked: bool,
    ) -> Result<ServiceState, ServiceError> {
        self.backend.set_operation_id(operation_id);
        self.state = ServiceState {
            phase: ConnectionPhase::Stopping,
            operation_id,
            split_active: false,
            dns_protected: false,
            network_blocked: true,
        };

        if let Err(error) = self.backend.clear_network_state(keep_blocked).await {
            self.state = blocked_error_state(operation_id);
            return Err(error);
        }

        self.state = ServiceState {
            phase: if keep_blocked {
                ConnectionPhase::Blocked
            } else {
                ConnectionPhase::Disconnected
            },
            operation_id,
            split_active: false,
            dns_protected: false,
            network_blocked: keep_blocked,
        };
        Ok(self.state.clone())
    }
}

fn blocked_error_state(operation_id: u64) -> ServiceState {
    ServiceState {
        phase: ConnectionPhase::BlockedError,
        operation_id,
        split_active: false,
        dns_protected: false,
        network_blocked: true,
    }
}
