use std::collections::HashMap;

#[tauri::command]
pub fn read_legacy_storage() -> HashMap<String, String> {
    // The Windows client has no legacy WebKitGTK localStorage origin.
    HashMap::new()
}
