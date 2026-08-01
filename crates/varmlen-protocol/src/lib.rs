use std::net::SocketAddr;

use serde::{Deserialize, Serialize};

pub const PROTOCOL_VERSION: u16 = 2;
pub const MAX_FRAME_BYTES: usize = 1024 * 1024;
pub const MAX_LOG_TAIL_BYTES: u32 = 256 * 1024;
pub const SERVICE_PIPE_NAME: &str = r"\\.\pipe\Varmlen\Service\v1";
const MAX_CONFIG_BYTES: usize = 384 * 1024;
const MAX_SERVER_ENDPOINTS: usize = 64;
const MAX_EXCLUDED_APPS: usize = 256;
const MAX_APP_SELECTOR_BYTES: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppSelector {
    pub canonical_path: String,
    pub basename: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectRequest {
    pub xray_config: String,
    pub validation_config: String,
    pub server_endpoints: Vec<SocketAddr>,
    pub excluded_apps: Vec<AppSelector>,
    #[serde(default)]
    pub apps_selective: bool,
    pub killswitch: bool,
    pub allow_lan: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceCommand {
    Status,
    Connect(ConnectRequest),
    Disconnect { keep_blocked: bool },
    LogTail { max_bytes: u32 },
    ClearLog,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequestEnvelope {
    pub version: u16,
    pub operation_id: u64,
    pub command: ServiceCommand,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionPhase {
    Disconnected,
    Validating,
    Holding,
    Starting,
    Connected,
    Stopping,
    Blocked,
    Restoring,
    BlockedError,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceState {
    pub phase: ConnectionPhase,
    pub operation_id: u64,
    pub split_active: bool,
    pub dns_protected: bool,
    pub network_blocked: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
pub enum ServiceResponse {
    State(ServiceState),
    LogTail(String),
    Ack,
}

impl ServiceState {
    pub fn disconnected() -> Self {
        Self {
            phase: ConnectionPhase::Disconnected,
            operation_id: 0,
            split_active: false,
            dns_protected: false,
            network_blocked: false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceErrorCode {
    UnsupportedVersion,
    FrameTooLarge,
    InvalidFrame,
    InvalidRequest,
    Unauthorized,
    ValidationFailed,
    HoldFailed,
    XrayStartFailed,
    HealthCheckFailed,
    RestoreFailed,
    CleanupFailed,
    Internal,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceError {
    pub code: ServiceErrorCode,
    pub message: String,
}

impl ServiceError {
    pub fn new(code: ServiceErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResponseEnvelope {
    pub version: u16,
    pub operation_id: u64,
    pub result: Result<ServiceResponse, ServiceError>,
}

pub fn validate_request(request: &RequestEnvelope) -> Result<(), ServiceErrorCode> {
    if request.version != PROTOCOL_VERSION {
        return Err(ServiceErrorCode::UnsupportedVersion);
    }

    match &request.command {
        ServiceCommand::Connect(connect) => validate_connect_request(connect),
        ServiceCommand::LogTail { max_bytes }
            if *max_bytes == 0 || *max_bytes > MAX_LOG_TAIL_BYTES =>
        {
            Err(ServiceErrorCode::InvalidRequest)
        }
        ServiceCommand::Status
        | ServiceCommand::Disconnect { .. }
        | ServiceCommand::LogTail { .. }
        | ServiceCommand::ClearLog => Ok(()),
    }
}

pub fn validate_connect_request(request: &ConnectRequest) -> Result<(), ServiceErrorCode> {
    let configs_invalid = request.xray_config.is_empty()
        || request.validation_config.is_empty()
        || request.xray_config.len() > MAX_CONFIG_BYTES
        || request.validation_config.len() > MAX_CONFIG_BYTES;
    let endpoints_invalid = request.server_endpoints.is_empty()
        || request.server_endpoints.len() > MAX_SERVER_ENDPOINTS
        || request
            .server_endpoints
            .iter()
            .any(|endpoint| endpoint.port() == 0);
    let selectors_invalid = request.excluded_apps.len() > MAX_EXCLUDED_APPS
        || request.excluded_apps.iter().any(|selector| {
            invalid_selector_field(&selector.canonical_path)
                || invalid_selector_field(&selector.basename)
        });

    if configs_invalid || endpoints_invalid || selectors_invalid {
        Err(ServiceErrorCode::InvalidRequest)
    } else {
        Ok(())
    }
}

fn invalid_selector_field(value: &str) -> bool {
    value.trim().is_empty() || value.len() > MAX_APP_SELECTOR_BYTES || value.as_bytes().contains(&0)
}

pub fn encode_payload<T: Serialize>(value: &T) -> Result<Vec<u8>, ServiceErrorCode> {
    let bytes = serde_json::to_vec(value).map_err(|_| ServiceErrorCode::InvalidFrame)?;
    if bytes.len() > MAX_FRAME_BYTES {
        return Err(ServiceErrorCode::FrameTooLarge);
    }
    Ok(bytes)
}

pub fn decode_request(bytes: &[u8]) -> Result<RequestEnvelope, ServiceErrorCode> {
    if bytes.len() > MAX_FRAME_BYTES {
        return Err(ServiceErrorCode::FrameTooLarge);
    }
    let request = serde_json::from_slice(bytes).map_err(|_| ServiceErrorCode::InvalidFrame)?;
    validate_request(&request)?;
    Ok(request)
}

pub fn decode_response(bytes: &[u8]) -> Result<ResponseEnvelope, ServiceErrorCode> {
    if bytes.len() > MAX_FRAME_BYTES {
        return Err(ServiceErrorCode::FrameTooLarge);
    }
    let response: ResponseEnvelope =
        serde_json::from_slice(bytes).map_err(|_| ServiceErrorCode::InvalidFrame)?;
    if response.version != PROTOCOL_VERSION {
        return Err(ServiceErrorCode::UnsupportedVersion);
    }
    Ok(response)
}
