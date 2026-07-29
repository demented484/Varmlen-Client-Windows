use async_trait::async_trait;
use varmlen_protocol::{
    encode_payload, validate_request, RequestEnvelope, ResponseEnvelope, ServiceCommand,
    ServiceError, ServiceErrorCode, ServiceState, MAX_FRAME_BYTES, PROTOCOL_VERSION,
};

#[async_trait]
pub trait CommandExecutor: Send + Sync {
    async fn execute(&self, command: ServiceCommand) -> Result<ServiceState, ServiceError>;
}

pub async fn handle_payload<E>(executor: &E, payload: &[u8]) -> Result<Vec<u8>, ServiceErrorCode>
where
    E: CommandExecutor + ?Sized,
{
    if payload.len() > MAX_FRAME_BYTES {
        return encode_error(0, ServiceErrorCode::FrameTooLarge);
    }
    let request: RequestEnvelope = match serde_json::from_slice(payload) {
        Ok(request) => request,
        Err(_) => return encode_error(0, ServiceErrorCode::InvalidFrame),
    };
    if let Err(code) = validate_request(&request) {
        return encode_error(request.operation_id, code);
    }
    let response = ResponseEnvelope {
        version: PROTOCOL_VERSION,
        operation_id: request.operation_id,
        result: executor.execute(request.command).await,
    };
    encode_payload(&response)
}

fn encode_error(operation_id: u64, code: ServiceErrorCode) -> Result<Vec<u8>, ServiceErrorCode> {
    encode_payload(&ResponseEnvelope {
        version: PROTOCOL_VERSION,
        operation_id,
        result: Err(ServiceError::new(code, format!("{code:?}"))),
    })
}
