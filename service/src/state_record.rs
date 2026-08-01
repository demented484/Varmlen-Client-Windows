use serde::{Deserialize, Serialize};
use varmlen_protocol::{validate_connect_request, ConnectRequest};

const MAGIC: &[u8; 8] = b"VRMLNST1";
const HEADER_BYTES: usize = MAGIC.len() + size_of::<u32>();
const MAX_STATE_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DesiredStateRecord {
    pub format_version: u16,
    pub operation_id: u64,
    pub phase: DesiredStatePhase,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum DesiredStatePhase {
    Disconnected,
    Connecting {
        candidate: ConnectRequest,
        previous: Option<ConnectRequest>,
        requested_kill_switch: bool,
    },
    Connected {
        request: ConnectRequest,
    },
    Disconnecting {
        keep_blocked: bool,
    },
    Blocked {
        reason: String,
    },
}

impl DesiredStateRecord {
    pub const FORMAT_VERSION: u16 = 2;

    pub fn new(operation_id: u64, request: ConnectRequest) -> Self {
        Self::connected(operation_id, request)
    }

    pub fn disconnected(operation_id: u64) -> Self {
        Self {
            format_version: Self::FORMAT_VERSION,
            operation_id,
            phase: DesiredStatePhase::Disconnected,
        }
    }

    pub fn connecting(
        operation_id: u64,
        candidate: ConnectRequest,
        previous: Option<ConnectRequest>,
        requested_kill_switch: bool,
    ) -> Self {
        Self {
            format_version: Self::FORMAT_VERSION,
            operation_id,
            phase: DesiredStatePhase::Connecting {
                candidate,
                previous,
                requested_kill_switch,
            },
        }
    }

    pub fn connected(operation_id: u64, request: ConnectRequest) -> Self {
        Self {
            format_version: Self::FORMAT_VERSION,
            operation_id,
            phase: DesiredStatePhase::Connected { request },
        }
    }

    pub fn disconnecting(operation_id: u64, keep_blocked: bool) -> Self {
        Self {
            format_version: Self::FORMAT_VERSION,
            operation_id,
            phase: DesiredStatePhase::Disconnecting { keep_blocked },
        }
    }

    pub fn blocked(operation_id: u64, reason: impl Into<String>) -> Self {
        Self {
            format_version: Self::FORMAT_VERSION,
            operation_id,
            phase: DesiredStatePhase::Blocked {
                reason: reason.into(),
            },
        }
    }
}

pub fn encode_desired_state(record: &DesiredStateRecord) -> Result<Vec<u8>, String> {
    validate_record(record)?;
    let payload =
        serde_json::to_vec(record).map_err(|error| format!("encode desired state: {error}"))?;
    if payload.len() > MAX_STATE_BYTES {
        return Err("desired state exceeds the size limit".into());
    }
    let payload_len =
        u32::try_from(payload.len()).map_err(|_| "desired state length overflow".to_string())?;
    let mut encoded = Vec::with_capacity(HEADER_BYTES + payload.len());
    encoded.extend_from_slice(MAGIC);
    encoded.extend_from_slice(&payload_len.to_le_bytes());
    encoded.extend_from_slice(&payload);
    Ok(encoded)
}

pub fn decode_desired_state(encoded: &[u8]) -> Result<DesiredStateRecord, String> {
    if encoded.len() < HEADER_BYTES || &encoded[..MAGIC.len()] != MAGIC {
        return Err("desired state has an invalid header".into());
    }
    let length = u32::from_le_bytes(
        encoded[MAGIC.len()..HEADER_BYTES]
            .try_into()
            .expect("header length checked"),
    ) as usize;
    if length > MAX_STATE_BYTES || encoded.len() != HEADER_BYTES + length {
        return Err("desired state has an invalid payload length".into());
    }
    let payload = &encoded[HEADER_BYTES..];
    let value: serde_json::Value = serde_json::from_slice(payload)
        .map_err(|error| format!("decode desired state: {error}"))?;
    let format_version = value
        .get("format_version")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| "desired state has no format version".to_string())?;
    let record = if format_version == 1 {
        let legacy: LegacyDesiredStateRecord = serde_json::from_value(value)
            .map_err(|error| format!("decode legacy desired state: {error}"))?;
        DesiredStateRecord::connected(legacy.operation_id, legacy.request)
    } else {
        serde_json::from_value(value).map_err(|error| format!("decode desired state: {error}"))?
    };
    validate_record(&record)?;
    Ok(record)
}

#[derive(Debug, Deserialize)]
struct LegacyDesiredStateRecord {
    operation_id: u64,
    request: ConnectRequest,
}

fn validate_record(record: &DesiredStateRecord) -> Result<(), String> {
    if record.format_version != DesiredStateRecord::FORMAT_VERSION {
        return Err(format!(
            "unsupported desired-state version {}",
            record.format_version
        ));
    }
    let validate = |request: &ConnectRequest| {
        validate_connect_request(request)
            .map_err(|error| format!("invalid desired connection request: {error:?}"))
    };
    match &record.phase {
        DesiredStatePhase::Connecting {
            candidate,
            previous,
            ..
        } => {
            validate(candidate)?;
            if let Some(previous) = previous {
                validate(previous)?;
            }
            Ok(())
        }
        DesiredStatePhase::Connected { request } => validate(request),
        DesiredStatePhase::Blocked { reason } if reason.len() > 4096 => {
            Err("blocked-state reason exceeds the size limit".into())
        }
        DesiredStatePhase::Disconnected
        | DesiredStatePhase::Disconnecting { .. }
        | DesiredStatePhase::Blocked { .. } => Ok(()),
    }
}
