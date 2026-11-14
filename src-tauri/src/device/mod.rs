// Copyright (C) 2026 WinIPA Contributors
// SPDX-License-Identifier: GPL-3.0-only

pub mod driver;
pub mod lockdown;
pub mod usbmux;

use crate::errors::WinIpaError;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tauri::{AppHandle, Emitter};
use tokio::sync::Mutex;
use usbmux::{
    connect_to_device_port, connect_usbmuxd, parse_usbmux_event, read_usbmux_packet,
    send_listen_request, UsbmuxEvent, LOCKDOWN_PORT,
};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeviceInfo {
    pub udid: String,
    pub name: String,
    pub ios_version: String,
    pub model: String,
    pub is_trusted: bool,
    pub is_locked: bool,
    pub developer_mode_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeviceDriverStatus {
    pub is_installed: bool,
    pub service_running: bool,
    pub driver_source: Option<String>,
}

/// Global cache of currently connected devices.
type DeviceCache = Arc<Mutex<HashMap<u32, DeviceInfo>>>;

/// Checks driver and service presence.
pub async fn check_driver() -> DeviceDriverStatus {
    driver::get_driver_status().await
}

/// Fetches detailed DeviceInfo for a specific device ID over lockdown.
pub async fn inspect_device(device_id: u32, udid_hint: &str) -> DeviceInfo {
    match connect_to_device_port(device_id, LOCKDOWN_PORT).await {
        Ok(mut lockdown_stream) => {
            match lockdown::query_device_info(&mut lockdown_stream, udid_hint).await {
                Ok(info) => info,
                Err(_) => DeviceInfo {
                    udid: udid_hint.to_string(),
                    name: "iPhone (Passcode Locked / Untrusted)".to_string(),
                    ios_version: "Unknown".to_string(),
                    model: "iPhone".to_string(),
                    is_trusted: false,
                    is_locked: false,
                    developer_mode_enabled: false,
                },
            }
        }
        Err(_) => DeviceInfo {
            udid: udid_hint.to_string(),
            name: "iPhone (Connection Failed)".to_string(),
            ios_version: "Unknown".to_string(),
            model: "iPhone".to_string(),
            is_trusted: false,
            is_locked: false,
            developer_mode_enabled: false,
        },
    }
}

/// Queries all currently connected iOS devices from usbmuxd.
pub async fn list_devices() -> Result<Vec<DeviceInfo>, WinIpaError> {
    let driver_status = check_driver().await;
    if !driver_status.service_running {
        return Err(WinIpaError::DriverMissing);
    }

    let mut stream = connect_usbmuxd().await?;
    send_listen_request(&mut stream, 1).await?;

    let mut devices = Vec::new();

    // Read the first batch of attached devices until result or timeout
    let read_result = tokio::time::timeout(Duration::from_millis(1500), async {
        loop {
            let (_header, val) = read_usbmux_packet(&mut stream).await?;
            if let Some(event) = parse_usbmux_event(&val) {
                match event {
                    UsbmuxEvent::Attached(dev) => {
                        let info = inspect_device(dev.device_id, &dev.udid).await;
                        devices.push(info);
                    }
                    UsbmuxEvent::Result { number } => {
                        if number != 0 {
                            return Err(WinIpaError::InstallFailed(format!(
                                "usbmuxd listen returned error {number}"
                            )));
                        }
                    }
                    UsbmuxEvent::Detached { .. } => {}
                }
            }
        }
        #[allow(unreachable_code)]
        Ok::<(), WinIpaError>(())
    })
    .await;

    let _ = read_result;

    Ok(devices)
}

/// Starts a long-running background monitor that detects device plug/unplug events
/// and emits live Tauri events to the React frontend.
pub fn start_device_monitor(app_handle: AppHandle) {
    let cache: DeviceCache = Arc::new(Mutex::new(HashMap::new()));

    tokio::spawn(async move {
        loop {
            // Check driver status periodically
            let driver_status = check_driver().await;
            let _ = app_handle.emit("driver-status-changed", &driver_status);

            if !driver_status.service_running {
                // If service is not running, clear device list and wait before re-checking
                {
                    let mut lock = cache.lock().await;
                    if !lock.is_empty() {
                        lock.clear();
                        let empty_list: Vec<DeviceInfo> = Vec::new();
                        let _ = app_handle.emit("device-list-updated", &empty_list);
                    }
                }
                tokio::time::sleep(Duration::from_secs(3)).await;
                continue;
            }

            // Attempt to connect to usbmuxd and listen for streaming events
            match connect_usbmuxd().await {
                Ok(mut stream) => {
                    if let Err(e) = send_listen_request(&mut stream, 1).await {
                        eprintln!("Failed to send usbmux listen request: {e:?}");
                        tokio::time::sleep(Duration::from_secs(2)).await;
                        continue;
                    }

                    // Loop reading events from the streaming connection
                    while let Ok((_header, val)) = read_usbmux_packet(&mut stream).await {
                        if let Some(event) = parse_usbmux_event(&val) {
                            match event {
                                UsbmuxEvent::Attached(dev) => {
                                    let info = inspect_device(dev.device_id, &dev.udid).await;
                                    {
                                        let mut lock = cache.lock().await;
                                        lock.insert(dev.device_id, info);
                                        let list: Vec<DeviceInfo> =
                                            lock.values().cloned().collect();
                                        let _ = app_handle.emit("device-list-updated", &list);
                                    }
                                }
                                UsbmuxEvent::Detached { device_id } => {
                                    let mut lock = cache.lock().await;
                                    lock.remove(&device_id);
                                    let list: Vec<DeviceInfo> = lock.values().cloned().collect();
                                    let _ = app_handle.emit("device-list-updated", &list);
                                }
                                UsbmuxEvent::Result { .. } => {}
                            }
                        }
                    }
                }
                Err(_) => {
                    tokio::time::sleep(Duration::from_secs(2)).await;
                }
            }
        }
    });
}
