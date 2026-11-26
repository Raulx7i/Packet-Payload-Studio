mod sidecar;
use serde_json::Value;
use sidecar::SidecarManager;
use tauri::State;

#[tauri::command]
async fn python_rpc(state: State<'_, SidecarManager>, method: String, params: Value) -> Result<Value, String> {
    state.call(method, params).await
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_shell::init())
        .manage(SidecarManager::new())
        .invoke_handler(tauri::generate_handler![python_rpc])
        .run(tauri::generate_context!())
        .expect("error while running Packet Payload Studio");
}
