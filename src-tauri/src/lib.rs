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

use apple::service::{LoginResult, ProvisioningProfile};
use apple::{get_apple_service, AppleSessionInfo};
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

#[tauri::command]
async fn apple_login(apple_id: String, password: String) -> Result<LoginResult, WinIpaError> {
    let service = get_apple_service();
    let mut lock = service.lock().await;
    lock.login(&apple_id, &password).await
}

#[tauri::command]
async fn apple_submit_2fa(code: String) -> Result<AppleSessionInfo, WinIpaError> {
    let service = get_apple_service();
    let mut lock = service.lock().await;
    lock.submit_2fa(&code).await
}

#[tauri::command]
async fn apple_get_session() -> Result<Option<AppleSessionInfo>, WinIpaError> {
    let service = get_apple_service();
    let lock = service.lock().await;
    lock.get_active_session().await
}

#[tauri::command]
async fn apple_logout() -> Result<(), WinIpaError> {
    let service = get_apple_service();
    let mut lock = service.lock().await;
    lock.logout().await
}

#[tauri::command]
async fn apple_provision_device(
    bundle_id: String,
    udid: String,
    device_name: String,
) -> Result<ProvisioningProfile, WinIpaError> {
    let service = get_apple_service();
    let lock = service.lock().await;

    // 1. Request/reuse dev certificate
    let cert = lock.request_development_certificate().await?;

    // 2. Register device UDID
    let device_id = lock.register_device(&udid, &device_name).await?;

    // 3. Register or fetch App ID
    let app_id = lock.get_or_create_app_id(&bundle_id, &bundle_id).await?;

    // 4. Download team provisioning profile
    lock.request_provisioning_profile(&app_id, &device_id, &cert.cert_id)
        .await
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
            inspect_ipa_package,
            apple_login,
            apple_submit_2fa,
            apple_get_session,
            apple_logout,
            apple_provision_device
        ])
        .run(tauri::generate_context!())
        .expect("error while running WinIPA application");
}
