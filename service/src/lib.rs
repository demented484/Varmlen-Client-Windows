pub mod pipe_policy;

pub const SERVICE_NAME: &str = "VarmlenService";
pub const PIPE_NAME: &str = r"\\.\pipe\Varmlen\Service\v1";

#[cfg(windows)]
pub mod pipe;
#[cfg(windows)]
pub mod windows_service;
