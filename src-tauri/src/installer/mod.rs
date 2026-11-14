// Copyright (C) 2026 WinIPA Contributors
// SPDX-License-Identifier: GPL-3.0-only

pub mod afc;
pub mod proxy;

use crate::device::lockdown::start_lockdown_service;
use crate::device::usbmux::{
    connect_to_device_port, connect_usbmuxd, parse_usbmux_event, read_usbmux_packet,
    send_listen_request, UsbmuxEvent,
};
use crate::errors::WinIpaError;
use afc::{afc_remove_file, upload_file_afc};
use async_trait::async_trait;
use proxy::install_package_proxy;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc::Sender;
use tokio::sync::Mutex;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstallProgress {
    pub percent: f32,
    pub status: String,
}

#[async_trait]
pub trait InstallerService: Send + Sync {
    async fn install_ipa(
        &self,
        udid: &str,
        signed_ipa_path: &Path,
        bundle_id: &str,
        progress_sender: Option<Sender<InstallProgress>>,
        cancel_token: Arc<AtomicBool>,
    ) -> Result<(), WinIpaError>;
}

/// Real USB installer communicating through usbmuxd to Apple Mobile Device Service.
pub struct DeviceUsbInstaller;

impl DeviceUsbInstaller {
    /// Discovers the usbmux device_id corresponding to a device UDID.
    async fn find_device_id_by_udid(&self, target_udid: &str) -> Result<u32, WinIpaError> {
        let mut stream = connect_usbmuxd().await?;
        send_listen_request(&mut stream, 1).await?;

        // Read initial discovery attached events
        for _ in 0..10 {
            let res =
                tokio::time::timeout(Duration::from_millis(500), read_usbmux_packet(&mut stream))
                    .await;

            let (_header, resp) = match res {
                Ok(Ok(p)) => p,
                _ => break,
            };

            if let Some(UsbmuxEvent::Attached(dev)) = parse_usbmux_event(&resp) {
                if dev.udid.eq_ignore_ascii_case(target_udid) {
                    return Ok(dev.device_id);
                }
            }
        }

        Err(WinIpaError::NoDevice)
    }
}

#[async_trait]
impl InstallerService for DeviceUsbInstaller {
    async fn install_ipa(
        &self,
        udid: &str,
        signed_ipa_path: &Path,
        bundle_id: &str,
        progress_sender: Option<Sender<InstallProgress>>,
        cancel_token: Arc<AtomicBool>,
    ) -> Result<(), WinIpaError> {
        if !signed_ipa_path.exists() {
            return Err(WinIpaError::InvalidIpa(format!(
                "Signed IPA file not found: {}",
                signed_ipa_path.display()
            )));
        }

        // 1. Locate device ID from usbmuxd
        let device_id = self.find_device_id_by_udid(udid).await?;

        // Helper to report progress
        let report = |pct: f32, msg: &str| {
            if let Some(ref tx) = progress_sender {
                let _ = tx.try_send(InstallProgress {
                    percent: pct,
                    status: msg.to_string(),
                });
            }
        };

        report(0.0, "Connecting to device lockdown service...");

        // 2. Connect to lockdown (port 62078)
        let mut lockdown_stream = connect_to_device_port(device_id, 62078).await?;

        // 3. Start com.apple.afc service
        report(5.0, "Starting Apple File Conduit (AFC) service...");
        let afc_port = start_lockdown_service(&mut lockdown_stream, "com.apple.afc").await?;

        // 4. Connect to AFC port and upload IPA to staging
        let mut afc_stream = connect_to_device_port(device_id, afc_port).await?;
        let staging_file_name = format!("PublicStaging/winipa_{}.ipa", uuid::Uuid::new_v4());

        let upload_res = upload_file_afc(
            &mut afc_stream,
            signed_ipa_path,
            &staging_file_name,
            |pct, msg| report(pct, msg),
            cancel_token.clone(),
        )
        .await;

        if let Err(e) = upload_res {
            let _ = afc_remove_file(&mut afc_stream, &staging_file_name).await;
            return Err(e);
        }

        // 5. Start com.apple.mobile.installation_proxy service
        report(50.0, "Starting iOS installation proxy...");
        let proxy_port =
            start_lockdown_service(&mut lockdown_stream, "com.apple.mobile.installation_proxy")
                .await?;

        let mut proxy_stream = connect_to_device_port(device_id, proxy_port).await?;

        // 6. Perform installation
        let install_res = install_package_proxy(
            &mut proxy_stream,
            &staging_file_name,
            bundle_id,
            |pct, msg| report(pct, msg),
            cancel_token.clone(),
        )
        .await;

        // 7. Clean up remote staging file via AFC
        let _ = afc_remove_file(&mut afc_stream, &staging_file_name).await;

        install_res?;
        report(100.0, "Installation complete!");
        Ok(())
    }
}

/// Simulated mock installer for offline unit and integration tests.
pub struct MockInstaller {
    pub should_fail: bool,
    pub fail_message: String,
}

impl Default for MockInstaller {
    fn default() -> Self {
        Self {
            should_fail: false,
            fail_message: "Simulated installation failure".into(),
        }
    }
}

#[async_trait]
impl InstallerService for MockInstaller {
    async fn install_ipa(
        &self,
        _udid: &str,
        _signed_ipa_path: &Path,
        _bundle_id: &str,
        progress_sender: Option<Sender<InstallProgress>>,
        cancel_token: Arc<AtomicBool>,
    ) -> Result<(), WinIpaError> {
        let stages = [
            (10.0, "Uploading package over USB: 2.0 MB / 10.0 MB (20%)"),
            (30.0, "Uploading package over USB: 6.0 MB / 10.0 MB (60%)"),
            (50.0, "Uploading package over USB: 10.0 MB / 10.0 MB (100%)"),
            (65.0, "Extracting package contents on iPhone... (65%)"),
            (80.0, "Verifying code signatures and entitlements... (80%)"),
            (95.0, "Registering app in iOS SpringBoard... (95%)"),
            (100.0, "Installation complete! (100%)"),
        ];

        for (pct, msg) in stages {
            if cancel_token.load(Ordering::Relaxed) {
                return Err(WinIpaError::Unknown {
                    message: "Installation cancelled by user".into(),
                    diagnostics: None,
                });
            }

            if let Some(ref tx) = progress_sender {
                let _ = tx
                    .send(InstallProgress {
                        percent: pct,
                        status: msg.to_string(),
                    })
                    .await;
            }

            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        if self.should_fail {
            return Err(WinIpaError::InstallFailed(self.fail_message.clone()));
        }

        Ok(())
    }
}

pub type SharedInstallerService = Arc<Mutex<Box<dyn InstallerService>>>;

pub fn create_default_installer_service() -> SharedInstallerService {
    Arc::new(Mutex::new(Box::new(DeviceUsbInstaller)))
}

static GLOBAL_INSTALLER: std::sync::OnceLock<SharedInstallerService> = std::sync::OnceLock::new();

pub fn get_installer_service() -> SharedInstallerService {
    GLOBAL_INSTALLER
        .get_or_init(create_default_installer_service)
        .clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_mock_installer_progress_and_completion() {
        let installer = MockInstaller::default();
        let (tx, mut rx) = tokio::sync::mpsc::channel(10);
        let cancel = Arc::new(AtomicBool::new(false));

        let install_task = tokio::spawn(async move {
            installer
                .install_ipa(
                    "00008030-001234567890002E",
                    Path::new("dummy.ipa"),
                    "io.winipa.test",
                    Some(tx),
                    cancel,
                )
                .await
        });

        let mut received = Vec::new();
        while let Some(prog) = rx.recv().await {
            received.push(prog.percent);
        }

        let res = install_task.await.unwrap();
        assert!(res.is_ok());
        assert!(!received.is_empty());
        assert_eq!(*received.last().unwrap(), 100.0);
    }

    #[tokio::test]
    async fn test_mock_installer_cancellation() {
        let installer = MockInstaller::default();
        let (tx, _rx) = tokio::sync::mpsc::channel(10);
        let cancel = Arc::new(AtomicBool::new(true)); // Pre-cancelled

        let res = installer
            .install_ipa(
                "00008030-001234567890002E",
                Path::new("dummy.ipa"),
                "io.winipa.test",
                Some(tx),
                cancel,
            )
            .await;

        assert!(res.is_err());
    }
}
