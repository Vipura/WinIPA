// Copyright (C) 2026 WinIPA Contributors
// SPDX-License-Identifier: GPL-3.0-only

pub mod afc;
pub mod proxy;

use crate::device::usbmux::{
    connect_usbmuxd, parse_usbmux_event, read_usbmux_packet, send_listen_request, UsbmuxEvent,
};
use crate::errors::WinIpaError;
use async_trait::async_trait;
use idevice::afc::opcode::AfcFopenMode;
use idevice::afc::AfcClient;
use idevice::pairing_file::PairingFile;
use idevice::provider::{IdeviceProvider, UsbmuxdProvider};
use idevice::services::installation_proxy::InstallationProxyClient;
use idevice::usbmuxd::UsbmuxdAddr;
use idevice::{Idevice, IdeviceError, IdeviceService};
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

/// Custom device provider that wraps UsbmuxdProvider with Windows Lockdown directory fallback.
#[derive(Debug, Clone)]
pub struct WinIpaDeviceProvider {
    pub inner: UsbmuxdProvider,
}

impl IdeviceProvider for WinIpaDeviceProvider {
    fn connect(
        &self,
        port: u16,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Idevice, IdeviceError>> + Send>> {
        self.inner.connect(port)
    }

    fn label(&self) -> &str {
        self.inner.label()
    }

    fn get_pairing_file(
        &self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<PairingFile, IdeviceError>> + Send>> {
        let inner = self.inner.clone();
        let udid = self.inner.udid.clone();
        Box::pin(async move {
            // 1. First attempt: Query pair record from usbmuxd directly
            if let Ok(pf) = inner.get_pairing_file().await {
                return Ok(pf);
            }

            // 2. Fallback: Search Windows Lockdown pairing records on disk
            #[cfg(windows)]
            {
                let candidates = [
                    format!(r"C:\ProgramData\Apple\Lockdown\{udid}.plist"),
                    format!(r"C:\ProgramData\Apple\Lockdown\{}.plist", udid.replace('-', "")),
                    format!(r"C:\ProgramData\Apple\Lockdown\{}.plist", udid.to_uppercase()),
                    format!(r"C:\ProgramData\Apple\Lockdown\{}.plist", udid.to_lowercase()),
                ];
                for path in &candidates {
                    if let Ok(pf) = PairingFile::read_from_file(path) {
                        return Ok(pf);
                    }
                }
            }

            Err(IdeviceError::UnexpectedResponse(
                "Device pairing file not found in usbmuxd or Lockdown folder. Please unlock device and trust this PC.".into(),
            ))
        })
    }
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

        report(0.0, "Establishing authenticated lockdown session with iPhone...");

        // 2. Setup provider with Windows pairing file support
        let usbmuxd_provider = UsbmuxdProvider {
            addr: UsbmuxdAddr::default(),
            tag: 1,
            udid: udid.to_string(),
            device_id,
            label: "WinIPA".to_string(),
        };
        let provider = WinIpaDeviceProvider {
            inner: usbmuxd_provider,
        };

        // 3. Connect to Apple File Conduit (AFC) over encrypted TLS lockdown session
        report(5.0, "Starting Apple File Conduit (AFC) secure service...");
        let mut afc = AfcClient::connect(&provider).await.map_err(|e| {
            WinIpaError::InstallFailed(format!("Failed to connect to Apple File Conduit: {e}"))
        })?;

        let _ = afc.mk_dir("PublicStaging").await;

        let staging_file_name = format!("PublicStaging/winipa_{}.ipa", uuid::Uuid::new_v4());
        let mut fd = afc
            .open(&staging_file_name, AfcFopenMode::WrOnly)
            .await
            .map_err(|e| {
                WinIpaError::InstallFailed(format!("Failed to open staging file on device: {e}"))
            })?;

        // 4. Stream upload IPA to device PublicStaging
        let file_bytes = tokio::fs::read(signed_ipa_path).await.map_err(|e| {
            WinIpaError::InvalidIpa(format!("Failed to read signed IPA file: {e}"))
        })?;
        let total_bytes = file_bytes.len();
        let total_mb = total_bytes as f64 / (1024.0 * 1024.0);
        let chunk_size = 256 * 1024; // 256 KB chunks
        let mut offset = 0;

        while offset < total_bytes {
            if cancel_token.load(Ordering::Relaxed) {
                let _ = fd.close().await;
                let _ = afc.remove(&staging_file_name).await;
                return Err(WinIpaError::Unknown {
                    message: "Installation cancelled by user".into(),
                    diagnostics: None,
                });
            }

            let end = (offset + chunk_size).min(total_bytes);
            if let Err(e) = fd.write_entire(&file_bytes[offset..end]).await {
                let _ = fd.close().await;
                let _ = afc.remove(&staging_file_name).await;
                return Err(WinIpaError::InstallFailed(format!(
                    "Failed uploading package to iPhone: {e}"
                )));
            }

            offset = end;
            let uploaded_mb = offset as f64 / (1024.0 * 1024.0);
            let upload_pct = (offset as f32 / total_bytes as f32) * 100.0;
            let overall_pct = 5.0 + (upload_pct * 0.45); // 5% -> 50%
            report(
                overall_pct,
                &format!(
                    "Uploading package over USB: {:.1} MB / {:.1} MB ({:.0}%)",
                    uploaded_mb, total_mb, upload_pct
                ),
            );
        }

        let _ = fd.close().await;
        drop(afc);

        // 5. Connect to iOS Installation Proxy over authenticated TLS lockdown session
        report(50.0, "Starting iOS installation proxy...");
        let mut inst = InstallationProxyClient::connect(&provider)
            .await
            .map_err(|e| {
                WinIpaError::InstallFailed(format!("Failed to start installation proxy: {e}"))
            })?;

        let options = plist::Value::Dictionary({
            let mut d = plist::Dictionary::new();
            d.insert("PackageType".into(), "Developer".into());
            d.insert("CFBundleIdentifier".into(), bundle_id.into());
            d
        });

        // 6. Perform installation with real-time SpringBoard/AMFI progress callbacks
        let tx = progress_sender.clone();
        let cancel = cancel_token.clone();
        let cb = move |(percent, _): (u64, ())| {
            let tx = tx.clone();
            let cancel = cancel.clone();
            async move {
                if cancel.load(Ordering::Relaxed) {
                    return;
                }
                let overall_percent = 50.0 + (percent as f32 * 0.5);
                let friendly_status = match percent {
                    0..=10 => "Acquiring device install assertion...",
                    11..=25 => "Creating sandbox staging directory...",
                    26..=50 => "Extracting package contents on iPhone...",
                    51..=80 => "Verifying code signatures and entitlements...",
                    81..=99 => "Registering app in iOS SpringBoard...",
                    _ => "Installation complete!",
                };
                if let Some(ref sender) = tx {
                    let _ = sender.try_send(InstallProgress {
                        percent: overall_percent,
                        status: friendly_status.to_string(),
                    });
                }
            }
        };

        let install_res = inst
            .install_with_callback(&staging_file_name, Some(options.clone()), cb, ())
            .await;

        let final_res = match install_res {
            Ok(()) => Ok(()),
            Err(e) => {
                // If standard install failed, attempt upgrade in case package is already present
                inst.upgrade_with_callback(&staging_file_name, Some(options), |_| async {}, ())
                    .await
                    .map_err(|_| e)
            }
        };

        // 7. Clean up remote staging file via AFC
        if let Ok(mut cleanup_afc) = AfcClient::connect(&provider).await {
            let _ = cleanup_afc.remove(&staging_file_name).await;
        }

        // 8. Handle any errors from installation proxy with user-friendly diagnostics
        if let Err(e) = final_res {
            let err_str = e.to_string();
            if err_str.contains("ApplicationVerificationFailed") {
                return Err(WinIpaError::InstallFailed(format!(
                    "Application verification failed on device ({err_str}). Ensure your developer certificate is trusted and entitlements match the provisioning profile."
                )));
            } else if err_str.contains("MismatchedApplicationIdentifierEntitlement") {
                return Err(WinIpaError::InstallFailed(format!(
                    "Application identifier mismatch ({err_str}). The bundle identifier must match your App ID."
                )));
            } else if err_str.contains("DeviceNotRegistered") {
                return Err(WinIpaError::InstallFailed(
                    "Your iPhone UDID is not registered in this provisioning profile.".into(),
                ));
            } else if err_str.contains("DeveloperModeNotEnabled") {
                return Err(WinIpaError::InstallFailed(
                    "Developer Mode is not enabled on your iPhone. Please go to Settings -> Privacy & Security -> Developer Mode to enable it.".into(),
                ));
            } else if err_str.contains("PasswordProtected") || err_str.contains("DeviceLocked") {
                return Err(WinIpaError::DeviceLocked);
            } else {
                return Err(WinIpaError::InstallFailed(format!(
                    "iPhone rejected installation: {err_str}"
                )));
            }
        }

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
