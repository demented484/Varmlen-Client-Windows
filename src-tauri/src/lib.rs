pub mod service_client;

use varmlen_protocol::ServiceState;

#[tauri::command]
async fn service_status() -> Result<ServiceState, String> {
    service_client::service_status().await
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![service_status])
        .run(tauri::generate_context!())
        .expect("error while running Varmlen");
}
