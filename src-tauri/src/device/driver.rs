// Copyright (C) 2026 WinIPA Contributors
// SPDX-License-Identifier: GPL-3.0-only

use super::DeviceDriverStatus;
use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;
use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};
use winreg::RegKey;

pub const USBMUXD_TCP_PORT: u16 = 27015;
pub const USBMUXD_NAMED_PIPE: &str = r"\\.\pipe\usbmuxd";

/// Detects whether Apple Mobile Device Service (or usbmuxd) is running and listening.
pub async fn check_service_running() -> bool {
    // 1. Try TCP connection to 127.0.0.1:27015 (Standard AMDS Windows port)
    let addr: SocketAddr = ([127, 0, 0, 1], USBMUXD_TCP_PORT).into();
    if let Ok(Ok(_)) = timeout(Duration::from_millis(500), TcpStream::connect(addr)).await {
        return true;
    }

    // 2. Check if named pipe \\.\pipe\usbmuxd exists
    Path::new(USBMUXD_NAMED_PIPE).exists()
}

/// Detects whether Apple software (iTunes, Apple Devices, or AMDS) is installed on Windows.
pub fn detect_installed_apple_software() -> Option<String> {
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);

    // 1. Check for standalone Apple Mobile Device Support in registry
    let amds_paths = [
        r"SOFTWARE\Apple Inc.\Apple Mobile Device Support",
        r"SOFTWARE\WOW6432Node\Apple Inc.\Apple Mobile Device Support",
        r"SYSTEM\CurrentControlSet\Services\Apple Mobile Device Service",
    ];
    for path in &amds_paths {
        if hklm.open_subkey(path).is_ok() {
            return Some("Apple Mobile Device Support (Desktop)".to_string());
        }
    }

    // 2. Check for traditional iTunes in registry
    let itunes_paths = [
        r"SOFTWARE\Apple Computer, Inc.\iTunes",
        r"SOFTWARE\WOW6432Node\Apple Computer, Inc.\iTunes",
    ];
    for path in &itunes_paths {
        if hklm.open_subkey(path).is_ok() {
            return Some("iTunes (Desktop Installer)".to_string());
        }
    }

    // 3. Check for Microsoft Store apps in HKCU AppModel repository
    let appx_repo_path = r"Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages";
    if let Ok(repo) = hkcu.open_subkey(appx_repo_path) {
        for key_name in repo.enum_keys().filter_map(|r| r.ok()) {
            if key_name.contains("AppleInc.AppleDevices") {
                return Some("Apple Devices (Microsoft Store)".to_string());
            }
            if key_name.contains("AppleInc.iTunes") {
                return Some("iTunes (Microsoft Store)".to_string());
            }
        }
    }

    // 4. Check standard WindowsApps directory for store packages
    let windows_apps = Path::new(r"C:\Program Files\WindowsApps");
    if windows_apps.exists() {
        if let Ok(entries) = std::fs::read_dir(windows_apps) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if name.starts_with("AppleInc.AppleDevices") {
                    return Some("Apple Devices (Microsoft Store)".to_string());
                }
                if name.starts_with("AppleInc.iTunes") {
                    return Some("iTunes (Microsoft Store)".to_string());
                }
            }
        }
    }

    None
}

/// Returns the comprehensive driver and service status.
pub async fn get_driver_status() -> DeviceDriverStatus {
    let service_running = check_service_running().await;
    let installed_source = detect_installed_apple_software();

    DeviceDriverStatus {
        is_installed: installed_source.is_some() || service_running,
        service_running,
        driver_source: installed_source,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_check_service_running_does_not_panic() {
        let running = check_service_running().await;
        println!("Service running check result: {running}");
    }

    #[test]
    fn test_detect_installed_apple_software_does_not_panic() {
        let detected = detect_installed_apple_software();
        println!("Detected Apple software: {detected:?}");
    }

    #[tokio::test]
    async fn test_get_driver_status_returns_valid_structure() {
        let status = get_driver_status().await;
        println!(
            "Driver status: installed={}, running={}, source={:?}",
            status.is_installed, status.service_running, status.driver_source
        );
        if status.service_running {
            assert!(status.is_installed);
        }
    }
}
