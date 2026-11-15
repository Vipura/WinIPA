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
use pipeline::{cancel_active_pipeline, execute_pipeline, PipelineRequest, PipelineResult};
use std::path::Path;
use store::{load_installed_apps, remove_installed_app as store_remove_app, InstalledAppRecord};

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
async fn pick_ipa_file() -> Result<Option<String>, WinIpaError> {
    let file = rfd::AsyncFileDialog::new()
        .add_filter("iOS Application Archive (*.ipa)", &["ipa"])
        .set_title("Select iOS Application (.ipa)")
        .pick_file()
        .await;

    Ok(file.map(|f| f.path().to_string_lossy().to_string()))
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
async fn apple_set_team_id(team_id: String) -> Result<AppleSessionInfo, WinIpaError> {
    let service = get_apple_service();
    let mut lock = service.lock().await;
    lock.set_team_id(&team_id).await
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

#[tauri::command]
async fn start_installation_pipeline(
    app: tauri::AppHandle,
    req: PipelineRequest,
) -> Result<PipelineResult, WinIpaError> {
    execute_pipeline(Some(app), req).await
}

#[tauri::command]
fn cancel_installation_pipeline() {
    cancel_active_pipeline();
}

#[tauri::command]
fn get_installed_apps() -> Result<Vec<InstalledAppRecord>, WinIpaError> {
    load_installed_apps()
}

#[tauri::command]
fn remove_installed_app(bundle_id: String) -> Result<(), WinIpaError> {
    store_remove_app(&bundle_id)
}

#[tauri::command]
async fn get_redacted_diagnostics() -> String {
    store::generate_diagnostics_report().await
}

#[tauri::command]
async fn export_diagnostics_to_file(destination: Option<String>) -> Result<String, WinIpaError> {
    store::export_diagnostics_to_file(destination).await
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
            pick_ipa_file,
            apple_login,
            apple_submit_2fa,
            apple_get_session,
            apple_logout,
            apple_set_team_id,
            apple_provision_device,
            start_installation_pipeline,
            cancel_installation_pipeline,
            get_installed_apps,
            remove_installed_app,
            get_redacted_diagnostics,
            export_diagnostics_to_file
        ])
        .run(tauri::generate_context!())
        .expect("error while running WinIPA application");
}
