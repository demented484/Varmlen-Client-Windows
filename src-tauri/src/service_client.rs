#[cfg(windows)]
mod platform {
    use std::sync::atomic::{AtomicU64, Ordering};

    use tokio::{io::AsyncWriteExt, net::windows::named_pipe::ClientOptions};
    use varmlen_protocol::{
        decode_response, encode_payload, ConnectRequest, CoreCommand, RequestEnvelope,
        ServiceCommand, ServiceResponse, ServiceState, MAX_LOG_TAIL_BYTES, PROTOCOL_VERSION,
        SERVICE_PIPE_NAME,
    };
    use varmlen_service_core::framing::{read_payload, write_payload};

    static NEXT_OPERATION_ID: AtomicU64 = AtomicU64::new(1);

    pub async fn service_status() -> Result<ServiceState, String> {
        expect_state(request(ServiceCommand::Status).await?)
    }

    pub async fn connect(request_body: ConnectRequest) -> Result<ServiceState, String> {
        expect_state(request(ServiceCommand::Connect(request_body)).await?)
    }

    pub async fn disconnect(keep_blocked: bool) -> Result<ServiceState, String> {
        expect_state(request(ServiceCommand::Disconnect { keep_blocked }).await?)
    }

    pub async fn log_tail() -> Result<String, String> {
        match request(ServiceCommand::LogTail {
            max_bytes: MAX_LOG_TAIL_BYTES,
        })
        .await?
        {
            ServiceResponse::LogTail(log) => Ok(log),
            _ => Err("VarmlenService returned the wrong log response type".into()),
        }
    }

    pub async fn clear_log() -> Result<(), String> {
        match request(ServiceCommand::ClearLog).await? {
            ServiceResponse::Ack => Ok(()),
            _ => Err("VarmlenService returned the wrong clear-log response type".into()),
        }
    }

    pub async fn core(command: CoreCommand) -> Result<ServiceResponse, String> {
        request(ServiceCommand::Core(command)).await
    }

    fn expect_state(response: ServiceResponse) -> Result<ServiceState, String> {
        match response {
            ServiceResponse::State(state) => Ok(state),
            _ => Err("VarmlenService returned the wrong state response type".into()),
        }
    }

    async fn request(command: ServiceCommand) -> Result<ServiceResponse, String> {
        let response_timeout = match &command {
            ServiceCommand::Core(CoreCommand::Install { .. }) => {
                std::time::Duration::from_secs(600)
            }
            ServiceCommand::Core(CoreCommand::Activate { .. }) => {
                std::time::Duration::from_secs(120)
            }
            _ => std::time::Duration::from_secs(60),
        };
        let operation_id = NEXT_OPERATION_ID.fetch_add(1, Ordering::Relaxed);
        let request = RequestEnvelope {
            version: PROTOCOL_VERSION,
            operation_id,
            command,
        };
        let request = encode_payload(&request)
            .map_err(|error| format!("failed to encode service request: {error:?}"))?;

        let mut pipe = ClientOptions::new()
            .read(true)
            .write(true)
            .open(SERVICE_PIPE_NAME)
            .map_err(|error| format!("VarmlenService is unavailable: {error}"))?;
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            write_payload(&mut pipe, &request),
        )
        .await
        .map_err(|_| "timed out writing the service request".to_string())?
        .map_err(|error| format!("failed to write service request: {error:?}"))?;
        tokio::time::timeout(std::time::Duration::from_secs(5), pipe.flush())
            .await
            .map_err(|_| "timed out flushing the service request".to_string())?
            .map_err(|error| format!("failed to flush service request: {error}"))?;

        let response = tokio::time::timeout(response_timeout, read_payload(&mut pipe))
            .await
            .map_err(|_| "VarmlenService command timed out".to_string())?
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
    use varmlen_protocol::{ConnectRequest, CoreCommand, ServiceResponse, ServiceState};

    pub async fn service_status() -> Result<ServiceState, String> {
        Err("VarmlenService is only supported on Windows".into())
    }

    pub async fn connect(_request: ConnectRequest) -> Result<ServiceState, String> {
        Err("VarmlenService is only supported on Windows".into())
    }

    pub async fn disconnect(_keep_blocked: bool) -> Result<ServiceState, String> {
        Err("VarmlenService is only supported on Windows".into())
    }

    pub async fn log_tail() -> Result<String, String> {
        Err("VarmlenService is only supported on Windows".into())
    }

    pub async fn clear_log() -> Result<(), String> {
        Err("VarmlenService is only supported on Windows".into())
    }

    pub async fn core(_command: CoreCommand) -> Result<ServiceResponse, String> {
        Err("VarmlenService is only supported on Windows".into())
    }
}

pub use platform::{clear_log, connect, core, disconnect, log_tail, service_status};
