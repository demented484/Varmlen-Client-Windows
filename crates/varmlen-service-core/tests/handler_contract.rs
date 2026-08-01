use std::sync::Mutex;

use async_trait::async_trait;
use varmlen_protocol::{
    decode_response, encode_payload, ConnectionPhase, RequestEnvelope, ServiceCommand,
    ServiceError, ServiceErrorCode, ServiceResponse, ServiceState, PROTOCOL_VERSION,
};
use varmlen_service_core::handler::{handle_payload, CommandExecutor};

struct SnapshotExecutor {
    state: ServiceState,
    seen_operation: Mutex<Option<u64>>,
}

impl SnapshotExecutor {
    fn disconnected() -> Self {
        Self {
            state: ServiceState::disconnected(),
            seen_operation: Mutex::new(None),
        }
    }
}

#[async_trait]
impl CommandExecutor for SnapshotExecutor {
    async fn execute(
        &self,
        operation_id: u64,
        _command: ServiceCommand,
    ) -> Result<ServiceResponse, ServiceError> {
        *self.seen_operation.lock().expect("operation lock") = Some(operation_id);
        Ok(ServiceResponse::State(self.state.clone()))
    }
}

#[tokio::test]
async fn status_response_keeps_the_request_operation_id() {
    let executor = SnapshotExecutor::disconnected();
    let request = RequestEnvelope {
        version: PROTOCOL_VERSION,
        operation_id: 0xfeed,
        command: ServiceCommand::Status,
    };
    let response = handle_payload(&executor, &encode_payload(&request).unwrap())
        .await
        .unwrap();
    let response = decode_response(&response).unwrap();

    assert_eq!(response.operation_id, 0xfeed);
    assert_eq!(
        *executor.seen_operation.lock().expect("operation lock"),
        Some(0xfeed)
    );
    assert!(matches!(
        response.result.unwrap(),
        ServiceResponse::State(ServiceState {
            phase: ConnectionPhase::Disconnected,
            ..
        })
    ));
}

#[tokio::test]
async fn incompatible_version_returns_a_structured_error_with_operation_id() {
    let request = RequestEnvelope {
        version: PROTOCOL_VERSION + 1,
        operation_id: 0xcafe,
        command: ServiceCommand::Status,
    };
    let response = handle_payload(
        &SnapshotExecutor::disconnected(),
        &encode_payload(&request).unwrap(),
    )
    .await
    .unwrap();
    let response = decode_response(&response).unwrap();

    assert_eq!(response.operation_id, 0xcafe);
    assert_eq!(
        response.result.unwrap_err().code,
        ServiceErrorCode::UnsupportedVersion
    );
}

#[tokio::test]
async fn malformed_json_returns_a_structured_invalid_frame_error() {
    let response = handle_payload(&SnapshotExecutor::disconnected(), b"{not-json")
        .await
        .unwrap();
    let response = decode_response(&response).unwrap();

    assert_eq!(response.operation_id, 0);
    assert_eq!(
        response.result.unwrap_err().code,
        ServiceErrorCode::InvalidFrame
    );
}
