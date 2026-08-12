pub mod core_manager;
pub mod log_store;
pub mod pipe_policy;
pub mod process_plan;
pub mod state_record;

pub const SERVICE_NAME: &str = "VarmlenService";
pub use varmlen_protocol::SERVICE_PIPE_NAME as PIPE_NAME;

#[cfg(windows)]
pub mod pipe;
#[cfg(windows)]
pub mod windows_adapter;
#[cfg(windows)]
pub mod windows_backend;
#[cfg(windows)]
pub mod windows_process;
#[cfg(windows)]
pub mod windows_routes;
#[cfg(windows)]
pub mod windows_service;
#[cfg(windows)]
pub mod windows_state;
