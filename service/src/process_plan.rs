use std::path::PathBuf;
use std::{io, time::Duration};

use tokio::time::sleep;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XrayInvocationKind {
    Validate,
    Run,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XrayInvocation {
    pub kind: XrayInvocationKind,
    pub executable: PathBuf,
    pub arguments: Vec<String>,
}

impl XrayInvocation {
    pub fn validation(executable: PathBuf, config: PathBuf) -> Self {
        Self {
            kind: XrayInvocationKind::Validate,
            executable,
            arguments: vec![
                "run".into(),
                "-test".into(),
                "-c".into(),
                config.to_string_lossy().into_owned(),
            ],
        }
    }

    pub fn run(executable: PathBuf, config: PathBuf) -> Self {
        Self {
            kind: XrayInvocationKind::Run,
            executable,
            arguments: vec![
                "run".into(),
                "-c".into(),
                config.to_string_lossy().into_owned(),
            ],
        }
    }

    pub fn config_path(&self) -> &std::path::Path {
        std::path::Path::new(
            self.arguments
                .last()
                .expect("Xray invocation always has a config argument"),
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XrayConfigTransaction {
    executable: PathBuf,
    candidate_path: PathBuf,
    active_path: PathBuf,
}

impl XrayConfigTransaction {
    pub fn new(executable: PathBuf, candidate_path: PathBuf, active_path: PathBuf) -> Self {
        Self {
            executable,
            candidate_path,
            active_path,
        }
    }

    pub fn preflight(&self) -> XrayInvocation {
        XrayInvocation::validation(self.executable.clone(), self.candidate_path.clone())
    }

    pub fn start_candidate(&self) -> XrayInvocation {
        XrayInvocation::run(self.executable.clone(), self.candidate_path.clone())
    }

    pub fn active_path(&self) -> &std::path::Path {
        &self.active_path
    }
}

pub async fn retry_address_not_ready<T, F>(
    mut operation: F,
    attempts: usize,
    delay: Duration,
) -> io::Result<T>
where
    F: FnMut() -> io::Result<T>,
{
    if attempts == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "address readiness requires at least one attempt",
        ));
    }
    for attempt in 0..attempts {
        match operation() {
            Ok(value) => return Ok(value),
            Err(error)
                if attempt + 1 < attempts
                    && (error.raw_os_error() == Some(10049)
                        || error.kind() == io::ErrorKind::AddrNotAvailable) =>
            {
                sleep(delay).await;
            }
            Err(error) => return Err(error),
        }
    }
    unreachable!("attempt loop always returns on its final iteration")
}

pub fn socks5_ipv4_connect_request(address: [u8; 4], port: u16) -> [u8; 10] {
    let [port_high, port_low] = port.to_be_bytes();
    [
        5, 1, 0, 1, address[0], address[1], address[2], address[3], port_high, port_low,
    ]
}

pub fn validate_socks5_method_reply(reply: [u8; 2]) -> Result<(), String> {
    if reply == [5, 0] {
        Ok(())
    } else {
        Err(format!(
            "SOCKS5 proxy rejected no-auth negotiation: {reply:02x?}"
        ))
    }
}

pub fn validate_socks5_connect_header(header: [u8; 4]) -> Result<usize, String> {
    if header[0] != 5 || header[2] != 0 {
        return Err(format!("invalid SOCKS5 CONNECT response: {header:02x?}"));
    }
    if header[1] != 0 {
        return Err(format!(
            "SOCKS5 CONNECT failed with status 0x{:02x}",
            header[1]
        ));
    }
    match header[3] {
        1 => Ok(6),
        4 => Ok(18),
        3 => Ok(0),
        address_type => Err(format!(
            "SOCKS5 CONNECT returned unknown address type 0x{address_type:02x}"
        )),
    }
}
