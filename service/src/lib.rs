pub mod pipe_policy;

pub const SERVICE_NAME: &str = "VarmlenService";
pub use varmlen_protocol::SERVICE_PIPE_NAME as PIPE_NAME;

#[cfg(windows)]
pub mod pipe;
#[cfg(windows)]
pub mod windows_service;
