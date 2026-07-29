#[cfg(windows)]
mod platform {
    use std::sync::atomic::{AtomicU64, Ordering};

    use tokio::{io::AsyncWriteExt, net::windows::named_pipe::ClientOptions};
    use varmlen_protocol::{
        decode_response, encode_payload, RequestEnvelope, ServiceCommand, ServiceState,
        PROTOCOL_VERSION, SERVICE_PIPE_NAME,
    };
    use varmlen_service_core::framing::{read_payload, write_payload};

    static NEXT_OPERATION_ID: AtomicU64 = AtomicU64::new(1);

    pub async fn service_status() -> Result<ServiceState, String> {
        let operation_id = NEXT_OPERATION_ID.fetch_add(1, Ordering::Relaxed);
        let request = RequestEnvelope {
            version: PROTOCOL_VERSION,
            operation_id,
            command: ServiceCommand::Status,
        };
        let request = encode_payload(&request)
            .map_err(|error| format!("failed to encode service request: {error:?}"))?;

        let mut pipe = ClientOptions::new()
            .read(true)
            .write(true)
            .open(SERVICE_PIPE_NAME)
            .map_err(|error| format!("VarmlenService is unavailable: {error}"))?;
        write_payload(&mut pipe, &request)
            .await
            .map_err(|error| format!("failed to write service request: {error:?}"))?;
        pipe.flush()
            .await
            .map_err(|error| format!("failed to flush service request: {error}"))?;

        let response = read_payload(&mut pipe)
            .await
            .map_err(|error| format!("failed to read service response: {error:?}"))?;
        let response = decode_response(&response)
            .map_err(|error| format!("invalid service response: {error:?}"))?;
        if response.operation_id != operation_id {
            return Err("VarmlenService returned a mismatched operation ID".into());
        }
        response.result.map_err(|error| error.message)
    }
}

#[cfg(not(windows))]
mod platform {
    use varmlen_protocol::ServiceState;

    pub async fn service_status() -> Result<ServiceState, String> {
        Err("VarmlenService is only supported on Windows".into())
    }
}

pub use platform::service_status;
