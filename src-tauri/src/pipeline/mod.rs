// Copyright (C) 2026 WinIPA Contributors
// SPDX-License-Identifier: GPL-3.0-only

use crate::apple::get_apple_service;
use crate::device::list_devices;
use crate::errors::WinIpaError;
use crate::installer::{get_installer_service, InstallProgress};
use crate::ipa::inspect_ipa;
use crate::signer::{sign_ipa, SigningOptions};
use crate::store::{save_installed_app, InstalledAppRecord};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tauri::Emitter;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PipelineStep {
    Idle,
    Inspecting,
    ValidatingDevice,
    Authenticating,
    Provisioning,
    Signing,
    Installing,
    Completed,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineStatus {
    pub step: PipelineStep,
    pub progress: f32, // 0.0 - 100.0
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineRequest {
    pub ipa_path: String,
    pub target_udid: String,
    pub custom_bundle_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineResult {
    pub app_name: String,
    pub bundle_id: String,
    pub version: String,
    pub stripped_entitlements: Vec<String>,
    pub cert_expires_at: Option<u64>,
}

// Global cancellation token for the active pipeline
static ACTIVE_PIPELINE_CANCEL: std::sync::OnceLock<Arc<AtomicBool>> = std::sync::OnceLock::new();

fn get_cancel_token() -> Arc<AtomicBool> {
    ACTIVE_PIPELINE_CANCEL
        .get_or_init(|| Arc::new(AtomicBool::new(false)))
        .clone()
}

/// Cancels any currently running installation pipeline.
pub fn cancel_active_pipeline() {
    let token = get_cancel_token();
    token.store(true, Ordering::SeqCst);
}

/// Executes the full end-to-end installation pipeline:
/// Inspect -> Device & DevMode check -> Apple Auth -> Provision -> Sign -> Install -> Remember.
pub async fn execute_pipeline<R: tauri::Runtime>(
    app_handle: Option<tauri::AppHandle<R>>,
    req: PipelineRequest,
) -> Result<PipelineResult, WinIpaError> {
    let cancel_token = get_cancel_token();
    cancel_token.store(false, Ordering::SeqCst);

    let handle_for_report = app_handle.clone();
    let report = move |step: PipelineStep, progress: f32, message: &str| {
        let status = PipelineStatus {
            step: step.clone(),
            progress,
            message: message.to_string(),
        };
        if let Some(ref handle) = handle_for_report {
            let _ = handle.emit("pipeline-status", status);
        }
    };

    let check_cancelled = || -> Result<(), WinIpaError> {
        if cancel_token.load(Ordering::Relaxed) {
            Err(WinIpaError::Unknown {
                message: "Pipeline cancelled by user".into(),
                diagnostics: None,
            })
        } else {
            Ok(())
        }
    };

    let handle_for_install = app_handle.clone();
    let run_steps = async {
        // Step 1: Inspect IPA
        report(
            PipelineStep::Inspecting,
            5.0,
            "Inspecting application package...",
        );
        check_cancelled()?;

        let ipa_path = PathBuf::from(&req.ipa_path);
        let metadata = inspect_ipa(&ipa_path)?;

        // Step 2: Validate Device
        report(
            PipelineStep::ValidatingDevice,
            15.0,
            "Validating connected iPhone...",
        );
        check_cancelled()?;

        let devices = list_devices().await?;
        let target_device = devices
            .into_iter()
            .find(|d| d.udid.eq_ignore_ascii_case(&req.target_udid))
            .ok_or(WinIpaError::NoDevice)?;

        if target_device.is_locked {
            return Err(WinIpaError::DeviceLocked);
        }
        if !target_device.is_trusted {
            return Err(WinIpaError::DeviceNotTrusted);
        }

        // Check iOS version requirement
        if let (Some(req_major), Some(dev_major)) = (
            metadata
                .min_ios_version
                .split('.')
                .next()
                .and_then(|s| s.parse::<u32>().ok()),
            target_device
                .ios_version
                .split('.')
                .next()
                .and_then(|s| s.parse::<u32>().ok()),
        ) {
            if dev_major < req_major {
                return Err(WinIpaError::IosTooOld {
                    required: metadata.min_ios_version.clone(),
                    actual: target_device.ios_version.clone(),
                });
            }
        }

        // Check Developer Mode (iOS 16+)
        if !target_device.developer_mode_enabled {
            return Err(WinIpaError::DeveloperModeOff);
        }

        // Step 3: Check Apple Session
        report(
            PipelineStep::Authenticating,
            25.0,
            "Checking Apple ID signing identity...",
        );
        check_cancelled()?;

        let apple_service = get_apple_service();
        let session = {
            let lock = apple_service.lock().await;
            lock.get_active_session().await?.ok_or_else(|| {
                WinIpaError::AppleAuthFailed(
                    "No Apple ID session active. Please sign in via Device & Account first.".into(),
                )
            })?
        };

        // Step 4: Provision
        report(
            PipelineStep::Provisioning,
            40.0,
            "Requesting development certificate and provisioning profile...",
        );
        check_cancelled()?;

        let target_bundle_id = req
            .custom_bundle_id
            .clone()
            .unwrap_or_else(|| metadata.bundle_id.clone());

        let (cert, profile) = {
            let lock = apple_service.lock().await;
            let cert = lock.request_development_certificate().await?;
            let device_id = lock
                .register_device(&target_device.udid, &target_device.name)
                .await?;
            let app_id = lock
                .get_or_create_app_id(&target_bundle_id, &metadata.app_name)
                .await?;
            let profile = lock
                .request_provisioning_profile(&app_id, &device_id, &cert.cert_id)
                .await?;
            (cert, profile)
        };

        // Step 5: Sign
        report(
            PipelineStep::Signing,
            55.0,
            "Locally re-signing application with your certificate...",
        );
        check_cancelled()?;

        let temp_signed_ipa = std::env::temp_dir()
            .join("WinIPA")
            .join(format!("signed_{}.ipa", uuid::Uuid::new_v4()));

        let is_free = session.account_type == crate::apple::AppleAccountType::Free;
        let cert_pem = String::from_utf8_lossy(&cert.certificate_data).to_string();

        let sign_res = sign_ipa(SigningOptions {
            input_ipa: req.ipa_path.clone(),
            output_ipa: temp_signed_ipa.to_string_lossy().to_string(),
            certificate_pem: cert_pem,
            private_key_pem: cert.private_key_pem,
            mobileprovision_data: profile.profile_data,
            team_id: session.team_id.clone(),
            new_bundle_id: req.custom_bundle_id.clone(),
            is_free_account: is_free,
        })
        .await;

        let signing_result = match sign_res {
            Ok(r) => r,
            Err(e) => {
                let _ = std::fs::remove_file(&temp_signed_ipa);
                return Err(e);
            }
        };

        // Step 6: Install over USB
        report(
            PipelineStep::Installing,
            70.0,
            "Pushing package to iPhone over USB...",
        );
        check_cancelled()?;

        let installer = get_installer_service();
        let (prog_tx, mut prog_rx) = tokio::sync::mpsc::channel::<InstallProgress>(20);

        // Forward installer progress to Tauri
        let forwarder_handle = handle_for_install.clone();
        let progress_forwarder = tokio::spawn(async move {
            while let Some(prog) = prog_rx.recv().await {
                // Scale install phase (70% - 99%)
                let scaled = 70.0 + (prog.percent * 0.29);
                if let Some(ref h) = forwarder_handle {
                    let _ = h.emit(
                        "pipeline-status",
                        PipelineStatus {
                            step: PipelineStep::Installing,
                            progress: scaled,
                            message: prog.status,
                        },
                    );
                }
            }
        });

        let install_res = {
            let lock = installer.lock().await;
            lock.install_ipa(
                &target_device.udid,
                &temp_signed_ipa,
                &target_bundle_id,
                Some(prog_tx),
                cancel_token.clone(),
            )
            .await
        };

        let _ = progress_forwarder.await;
        let _ = std::fs::remove_file(&temp_signed_ipa);

        install_res?;

        // Step 7: Record installed app in store
        let now_sec = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let expiry_sec = profile.expires_at;

        let record = InstalledAppRecord {
            bundle_id: target_bundle_id.clone(),
            app_name: metadata.app_name.clone(),
            version: metadata.version.clone(),
            installed_at: now_sec,
            cert_expires_at: expiry_sec,
        };
        let _ = save_installed_app(record);

        report(
            PipelineStep::Completed,
            100.0,
            "Successfully installed application to iPhone!",
        );

        Ok(PipelineResult {
            app_name: metadata.app_name,
            bundle_id: target_bundle_id,
            version: metadata.version,
            stripped_entitlements: signing_result.stripped_entitlements,
            cert_expires_at: Some(expiry_sec),
        })
    };

    match run_steps.await {
        Ok(res) => Ok(res),
        Err(e) => {
            if cancel_token.load(Ordering::Relaxed) {
                report(PipelineStep::Cancelled, 0.0, "Installation was cancelled.");
                Err(WinIpaError::Unknown {
                    message: "Installation cancelled by user".into(),
                    diagnostics: None,
                })
            } else {
                let err_msg = e.to_string();
                report(PipelineStep::Failed, 0.0, &err_msg);
                Err(e)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cancel_active_pipeline() {
        let token = get_cancel_token();
        token.store(false, Ordering::SeqCst);
        assert!(!token.load(Ordering::SeqCst));

        cancel_active_pipeline();
        assert!(token.load(Ordering::SeqCst));
    }
}
