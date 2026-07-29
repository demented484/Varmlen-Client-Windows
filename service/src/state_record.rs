use serde::{Deserialize, Serialize};
use varmlen_protocol::{validate_connect_request, ConnectRequest};

const MAGIC: &[u8; 8] = b"VRMLNST1";
const HEADER_BYTES: usize = MAGIC.len() + size_of::<u32>();
const MAX_STATE_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DesiredStateRecord {
    pub format_version: u16,
    pub operation_id: u64,
    pub request: ConnectRequest,
}

impl DesiredStateRecord {
    pub const FORMAT_VERSION: u16 = 1;
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
    let record: DesiredStateRecord = serde_json::from_slice(&encoded[HEADER_BYTES..])
        .map_err(|error| format!("decode desired state: {error}"))?;
    validate_record(&record)?;
    Ok(record)
}

fn validate_record(record: &DesiredStateRecord) -> Result<(), String> {
    if record.format_version != DesiredStateRecord::FORMAT_VERSION {
        return Err(format!(
            "unsupported desired-state version {}",
            record.format_version
        ));
    }
    validate_connect_request(&record.request)
        .map_err(|error| format!("invalid desired connection request: {error:?}"))
}
