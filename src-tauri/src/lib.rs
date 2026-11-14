// Copyright (C) 2026 WinIPA Contributors
// SPDX-License-Identifier: GPL-3.0-only

pub mod apple;
pub mod device;
pub mod errors;
pub mod installer;
pub mod ipa;
pub mod pipeline;
pub mod signer;
pub mod store;

use device::{check_driver, list_devices, start_device_monitor, DeviceDriverStatus, DeviceInfo};
use errors::WinIpaError;
use ipa::IpaMetadata;
use std::path::Path;

#[tauri::command]
fn get_app_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[tauri::command]
async fn get_driver_status() -> DeviceDriverStatus {
    check_driver().await
}

#[tauri::command]
async fn get_connected_devices() -> Result<Vec<DeviceInfo>, WinIpaError> {
    list_devices().await
}

#[tauri::command]
async fn refresh_devices() -> Result<Vec<DeviceInfo>, WinIpaError> {
    list_devices().await
}

#[tauri::command]
async fn inspect_ipa_package(path: String) -> Result<IpaMetadata, WinIpaError> {
    tokio::task::spawn_blocking(move || ipa::inspect_ipa(Path::new(&path)))
        .await
        .map_err(|e| WinIpaError::Unknown {
            message: format!("Inspection task panicked or was cancelled: {e}"),
            diagnostics: None,
        })?
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .setup(|app| {
            // Start real-time USB plug/unplug monitor in background
            start_device_monitor(app.handle().clone());
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            get_app_version,
            get_driver_status,
            get_connected_devices,
            refresh_devices,
            inspect_ipa_package
        ])
        .run(tauri::generate_context!())
        .expect("error while running WinIPA application");
}
