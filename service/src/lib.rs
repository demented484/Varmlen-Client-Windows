pub mod pipe_policy;
pub mod process_plan;
pub mod state_record;
pub mod wfp_plan;

pub const SERVICE_NAME: &str = "VarmlenService";
pub use varmlen_protocol::SERVICE_PIPE_NAME as PIPE_NAME;

#[cfg(windows)]
pub mod pipe;
#[cfg(windows)]
pub mod windows_service;
