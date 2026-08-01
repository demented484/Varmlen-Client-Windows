use std::net::SocketAddr;

use async_trait::async_trait;
use varmlen_protocol::{
    AppSelector, ConnectRequest, ConnectionPhase, ServiceError, ServiceErrorCode,
};
use varmlen_service_core::controller::{ConnectionBackend, ConnectionController};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Effect {
    Validate,
    InstallHold,
    VerifyHold,
    StopActive,
    StartCandidate,
    VerifyCandidate,
    CommitPolicy,
    ReleaseHold,
    RestorePrevious,
    ClearNetworkOpen,
    ClearNetworkBlocked,
    AuditActive,
}

struct RecordingBackend {
    effects: Vec<Effect>,
    failures: Vec<Effect>,
    active_running: bool,
    keep_blocked_on_failure: bool,
}

impl RecordingBackend {
    fn healthy() -> Self {
        Self {
            effects: Vec::new(),
            failures: Vec::new(),
            active_running: true,
            keep_blocked_on_failure: true,
        }
    }

    fn failing(failures: &[Effect]) -> Self {
        Self {
            effects: Vec::new(),
            failures: failures.to_vec(),
            active_running: true,
            keep_blocked_on_failure: true,
        }
    }

    fn record(&mut self, effect: Effect) -> Result<(), ServiceError> {
        self.effects.push(effect);
        if self.failures.contains(&effect) {
            Err(ServiceError::new(
                ServiceErrorCode::Internal,
                format!("injected {effect:?} failure"),
            ))
        } else {
            Ok(())
        }
    }

    fn effects(&self) -> &[Effect] {
        &self.effects
    }
}

#[async_trait]
impl ConnectionBackend for RecordingBackend {
    async fn validate_candidate(&mut self, _request: &ConnectRequest) -> Result<(), ServiceError> {
        self.record(Effect::Validate)
    }

    async fn install_transition_hold(&mut self) -> Result<(), ServiceError> {
        self.record(Effect::InstallHold)
    }

    async fn verify_transition_hold(&mut self) -> Result<(), ServiceError> {
        self.record(Effect::VerifyHold)
    }

    async fn stop_active(&mut self) -> Result<(), ServiceError> {
        self.record(Effect::StopActive)
    }

    async fn start_candidate(&mut self, _request: &ConnectRequest) -> Result<(), ServiceError> {
        self.record(Effect::StartCandidate)
    }

    async fn verify_candidate(&mut self, _request: &ConnectRequest) -> Result<(), ServiceError> {
        self.record(Effect::VerifyCandidate)
    }

    async fn commit_policy(&mut self, _request: &ConnectRequest) -> Result<(), ServiceError> {
        self.record(Effect::CommitPolicy)
    }

    async fn release_transition_hold(&mut self) -> Result<(), ServiceError> {
        self.record(Effect::ReleaseHold)
    }

    async fn restore_previous(&mut self) -> Result<(), ServiceError> {
        self.record(Effect::RestorePrevious)
    }

    async fn clear_network_state(&mut self, keep_blocked: bool) -> Result<(), ServiceError> {
        self.record(if keep_blocked {
            Effect::ClearNetworkBlocked
        } else {
            Effect::ClearNetworkOpen
        })
    }

    async fn active_is_running(&mut self) -> Result<bool, ServiceError> {
        self.record(Effect::AuditActive)?;
        Ok(self.active_running)
    }

    fn unexpected_failure_keep_blocked(&self) -> bool {
        self.keep_blocked_on_failure
    }
}

fn valid_connect() -> ConnectRequest {
    ConnectRequest {
        xray_config: r#"{"inbounds":[],"outbounds":[]}"#.into(),
        validation_config: r#"{"inbounds":[],"outbounds":[]}"#.into(),
        server_endpoints: vec![SocketAddr::from(([203, 0, 113, 7], 443))],
        excluded_apps: vec![AppSelector {
            canonical_path: r"C:\Games\game.exe".into(),
            basename: "game.exe".into(),
        }],
        apps_selective: false,
        killswitch: true,
        allow_lan: false,
    }
}

#[tokio::test]
async fn reconnect_installs_and_verifies_hold_before_stopping_active_xray() {
    let backend = RecordingBackend::healthy();
    let mut controller = ConnectionController::connected(backend);

    let state = controller.connect(7, valid_connect()).await.unwrap();

    assert_eq!(state.phase, ConnectionPhase::Connected);
    assert!(state.split_active);
    assert!(state.dns_protected);
    assert!(!state.network_blocked);
    assert_eq!(
        controller.backend().effects(),
        &[
            Effect::Validate,
            Effect::InstallHold,
            Effect::VerifyHold,
            Effect::StopActive,
            Effect::StartCandidate,
            Effect::VerifyCandidate,
            Effect::CommitPolicy,
            Effect::ReleaseHold,
        ]
    );
}

#[tokio::test]
async fn failed_candidate_validation_does_not_touch_the_active_connection() {
    let backend = RecordingBackend::failing(&[Effect::Validate]);
    let mut controller = ConnectionController::connected(backend);

    assert!(controller.connect(8, valid_connect()).await.is_err());

    assert_eq!(controller.state().phase, ConnectionPhase::Connected);
    assert_eq!(controller.backend().effects(), &[Effect::Validate]);
}

#[tokio::test]
async fn failed_candidate_after_stop_restores_previous_under_hold() {
    let backend = RecordingBackend::failing(&[Effect::StartCandidate]);
    let mut controller = ConnectionController::connected(backend);

    assert!(controller.connect(9, valid_connect()).await.is_err());

    assert_eq!(controller.state().phase, ConnectionPhase::Connected);
    assert_eq!(
        controller.backend().effects(),
        &[
            Effect::Validate,
            Effect::InstallHold,
            Effect::VerifyHold,
            Effect::StopActive,
            Effect::StartCandidate,
            Effect::RestorePrevious,
            Effect::ReleaseHold,
        ]
    );
}

#[tokio::test]
async fn failed_restore_keeps_the_hold_and_reports_blocked_error() {
    let backend = RecordingBackend::failing(&[Effect::StartCandidate, Effect::RestorePrevious]);
    let mut controller = ConnectionController::connected(backend);

    assert!(controller.connect(10, valid_connect()).await.is_err());

    assert_eq!(controller.state().phase, ConnectionPhase::BlockedError);
    assert!(controller.state().network_blocked);
    assert_eq!(
        controller.backend().effects(),
        &[
            Effect::Validate,
            Effect::InstallHold,
            Effect::VerifyHold,
            Effect::StopActive,
            Effect::StartCandidate,
            Effect::RestorePrevious,
        ]
    );
}

#[tokio::test]
async fn failed_initial_candidate_without_kill_switch_stops_candidate_and_opens_network() {
    let backend = RecordingBackend::failing(&[Effect::VerifyCandidate]);
    let mut controller = ConnectionController::disconnected(backend);
    let mut request = valid_connect();
    request.killswitch = false;

    assert!(controller.connect(11, request).await.is_err());

    assert_eq!(controller.state().phase, ConnectionPhase::Disconnected);
    assert!(!controller.state().network_blocked);
    assert_eq!(
        controller.backend().effects(),
        &[
            Effect::Validate,
            Effect::InstallHold,
            Effect::VerifyHold,
            Effect::StartCandidate,
            Effect::VerifyCandidate,
            Effect::ClearNetworkOpen,
        ]
    );
}

#[tokio::test]
async fn failed_initial_candidate_with_kill_switch_stops_candidate_and_verifies_block() {
    let backend = RecordingBackend::failing(&[Effect::VerifyCandidate]);
    let mut controller = ConnectionController::disconnected(backend);

    assert!(controller.connect(12, valid_connect()).await.is_err());

    assert_eq!(controller.state().phase, ConnectionPhase::Blocked);
    assert!(controller.state().network_blocked);
    assert_eq!(
        controller.backend().effects(),
        &[
            Effect::Validate,
            Effect::InstallHold,
            Effect::VerifyHold,
            Effect::StartCandidate,
            Effect::VerifyCandidate,
            Effect::ClearNetworkBlocked,
        ]
    );
}

#[tokio::test]
async fn failed_hold_install_does_not_stop_the_active_connection() {
    let backend = RecordingBackend::failing(&[Effect::InstallHold]);
    let mut controller = ConnectionController::connected(backend);

    assert!(controller.connect(13, valid_connect()).await.is_err());

    assert_eq!(controller.state().phase, ConnectionPhase::Connected);
    assert_eq!(
        controller.backend().effects(),
        &[Effect::Validate, Effect::InstallHold]
    );
}

#[tokio::test]
async fn failed_hold_verification_releases_hold_without_stopping_active_xray() {
    let backend = RecordingBackend::failing(&[Effect::VerifyHold]);
    let mut controller = ConnectionController::connected(backend);

    assert!(controller.connect(13, valid_connect()).await.is_err());

    assert_eq!(controller.state().phase, ConnectionPhase::Connected);
    assert_eq!(
        controller.backend().effects(),
        &[
            Effect::Validate,
            Effect::InstallHold,
            Effect::VerifyHold,
            Effect::ReleaseHold,
        ]
    );
}

#[tokio::test]
async fn failed_stop_keeps_hold_and_reports_blocked_error() {
    let backend = RecordingBackend::failing(&[Effect::StopActive]);
    let mut controller = ConnectionController::connected(backend);

    assert!(controller.connect(14, valid_connect()).await.is_err());

    assert_eq!(controller.state().phase, ConnectionPhase::BlockedError);
    assert!(controller.state().network_blocked);
    assert_eq!(
        controller.backend().effects(),
        &[
            Effect::Validate,
            Effect::InstallHold,
            Effect::VerifyHold,
            Effect::StopActive,
        ]
    );
}

#[tokio::test]
async fn failed_candidate_health_check_restores_previous_under_hold() {
    let backend = RecordingBackend::failing(&[Effect::VerifyCandidate]);
    let mut controller = ConnectionController::connected(backend);

    assert!(controller.connect(15, valid_connect()).await.is_err());

    assert_eq!(controller.state().phase, ConnectionPhase::Connected);
    assert_eq!(
        controller.backend().effects(),
        &[
            Effect::Validate,
            Effect::InstallHold,
            Effect::VerifyHold,
            Effect::StopActive,
            Effect::StartCandidate,
            Effect::VerifyCandidate,
            Effect::RestorePrevious,
            Effect::ReleaseHold,
        ]
    );
}

#[tokio::test]
async fn failed_policy_commit_restores_previous_under_hold() {
    let backend = RecordingBackend::failing(&[Effect::CommitPolicy]);
    let mut controller = ConnectionController::connected(backend);

    assert!(controller.connect(16, valid_connect()).await.is_err());

    assert_eq!(controller.state().phase, ConnectionPhase::Connected);
    assert_eq!(
        controller.backend().effects(),
        &[
            Effect::Validate,
            Effect::InstallHold,
            Effect::VerifyHold,
            Effect::StopActive,
            Effect::StartCandidate,
            Effect::VerifyCandidate,
            Effect::CommitPolicy,
            Effect::RestorePrevious,
            Effect::ReleaseHold,
        ]
    );
}

#[tokio::test]
async fn failed_transition_hold_release_reports_blocked_error() {
    let backend = RecordingBackend::failing(&[Effect::ReleaseHold]);
    let mut controller = ConnectionController::connected(backend);

    assert!(controller.connect(17, valid_connect()).await.is_err());

    assert_eq!(controller.state().phase, ConnectionPhase::BlockedError);
    assert!(controller.state().network_blocked);
}

#[tokio::test]
async fn failed_release_after_hold_verification_failure_stays_blocked() {
    let backend = RecordingBackend::failing(&[Effect::VerifyHold, Effect::ReleaseHold]);
    let mut controller = ConnectionController::connected(backend);

    assert!(controller.connect(18, valid_connect()).await.is_err());

    assert_eq!(controller.state().phase, ConnectionPhase::BlockedError);
    assert!(controller.state().network_blocked);
    assert_eq!(
        controller.backend().effects(),
        &[
            Effect::Validate,
            Effect::InstallHold,
            Effect::VerifyHold,
            Effect::ReleaseHold,
        ]
    );
}

#[tokio::test]
async fn disconnect_can_leave_an_intentional_kill_switch_block() {
    let backend = RecordingBackend::healthy();
    let mut controller = ConnectionController::connected(backend);

    let state = controller.disconnect(19, true).await.unwrap();

    assert_eq!(state.phase, ConnectionPhase::Blocked);
    assert!(state.network_blocked);
    assert_eq!(
        controller.backend().effects(),
        &[Effect::ClearNetworkBlocked]
    );
}

#[tokio::test]
async fn disconnect_without_kill_switch_restores_an_open_network() {
    let backend = RecordingBackend::healthy();
    let mut controller = ConnectionController::connected(backend);

    let state = controller.disconnect(20, false).await.unwrap();

    assert_eq!(state.phase, ConnectionPhase::Disconnected);
    assert!(!state.network_blocked);
    assert_eq!(controller.backend().effects(), &[Effect::ClearNetworkOpen]);
}

#[tokio::test]
async fn failed_disconnect_cleanup_reports_blocked_error() {
    let backend = RecordingBackend::failing(&[Effect::ClearNetworkOpen]);
    let mut controller = ConnectionController::connected(backend);

    assert!(controller.disconnect(21, false).await.is_err());

    assert_eq!(controller.state().phase, ConnectionPhase::BlockedError);
    assert!(controller.state().network_blocked);
}

#[tokio::test]
async fn runtime_audit_keeps_kill_switch_block_when_xray_exits() {
    let mut backend = RecordingBackend::healthy();
    backend.active_running = false;
    backend.keep_blocked_on_failure = true;
    let mut controller = ConnectionController::connected(backend);

    let state = controller.audit_runtime().await.unwrap();

    assert_eq!(state.phase, ConnectionPhase::Blocked);
    assert!(state.network_blocked);
    assert_eq!(
        controller.backend().effects(),
        &[Effect::AuditActive, Effect::ClearNetworkBlocked]
    );
}

#[tokio::test]
async fn runtime_audit_opens_network_without_kill_switch_when_xray_exits() {
    let mut backend = RecordingBackend::healthy();
    backend.active_running = false;
    backend.keep_blocked_on_failure = false;
    let mut controller = ConnectionController::connected(backend);

    let state = controller.audit_runtime().await.unwrap();

    assert_eq!(state.phase, ConnectionPhase::Disconnected);
    assert!(!state.network_blocked);
    assert_eq!(
        controller.backend().effects(),
        &[Effect::AuditActive, Effect::ClearNetworkOpen]
    );
}

#[tokio::test]
async fn runtime_audit_is_a_noop_outside_connected_state() {
    let backend = RecordingBackend::healthy();
    let mut controller = ConnectionController::disconnected(backend);

    let state = controller.audit_runtime().await.unwrap();

    assert_eq!(state.phase, ConnectionPhase::Disconnected);
    assert!(controller.backend().effects().is_empty());
}
