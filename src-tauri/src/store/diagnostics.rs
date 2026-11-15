// Copyright (C) 2026 WinIPA Contributors
// SPDX-License-Identifier: GPL-3.0-only

use crate::errors::WinIpaError;
use crate::store::load_installed_apps;
use crate::store::redaction::redact_sensitive_info;
use std::fmt::Write;
use std::path::PathBuf;

/// Generates a comprehensive, redacted diagnostics report string for troubleshooting.
pub async fn generate_diagnostics_report() -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "================================================================================"
    );
    let _ = writeln!(out, "WINIPA REDACTED SYSTEM DIAGNOSTICS");
    let _ = writeln!(
        out,
        "================================================================================"
    );
    let _ = writeln!(out, "Report Generated: {}", chrono_or_std_timestamp());
    let _ = writeln!(
        out,
        "Application Version: WinIPA v{} (GPL-3.0)",
        env!("CARGO_PKG_VERSION")
    );
    let _ = writeln!(
        out,
        "Host Platform: {} ({})",
        std::env::consts::OS,
        std::env::consts::ARCH
    );
    let _ = writeln!(out);

    // 1. Driver & AMDS Service Status
    let _ = writeln!(
        out,
        "--------------------------------------------------------------------------------"
    );
    let _ = writeln!(out, "1. APPLE MOBILE DEVICE SERVICE & USB DRIVER STATUS");
    let _ = writeln!(
        out,
        "--------------------------------------------------------------------------------"
    );
    let driver_status = crate::device::check_driver().await;
    let _ = writeln!(out, "Driver Installed: {}", driver_status.is_installed);
    let _ = writeln!(
        out,
        "Driver Source: {}",
        driver_status
            .driver_source
            .as_deref()
            .unwrap_or("None detected")
    );
    let _ = writeln!(
        out,
        "AMDS Service Running: {}",
        driver_status.service_running
    );
    let _ = writeln!(out);

    // 2. Connected Devices
    let _ = writeln!(
        out,
        "--------------------------------------------------------------------------------"
    );
    let _ = writeln!(out, "2. CONNECTED DEVICES VIA USBMUXD");
    let _ = writeln!(
        out,
        "--------------------------------------------------------------------------------"
    );
    match crate::device::list_devices().await {
        Ok(devices) => {
            let _ = writeln!(out, "Total Devices Detected: {}", devices.len());
            if devices.is_empty() {
                let _ = writeln!(out, "No iOS devices currently attached via USB.");
            } else {
                for (idx, dev) in devices.iter().enumerate() {
                    let _ = writeln!(out, "- Device #{}:", idx + 1);
                    let _ = writeln!(out, "    Name: {}", dev.name);
                    let _ = writeln!(out, "    Model Identifier: {}", dev.model);
                    let _ = writeln!(out, "    iOS Version: {}", dev.ios_version);
                    let _ = writeln!(out, "    UDID: {}", redact_sensitive_info(&dev.udid));
                    let _ = writeln!(out, "    Trusted: {}", dev.is_trusted);
                    let _ = writeln!(out, "    Passcode Locked: {}", dev.is_locked);
                    let _ = writeln!(
                        out,
                        "    Developer Mode Enabled: {}",
                        dev.developer_mode_enabled
                    );
                }
            }
        }
        Err(e) => {
            let _ = writeln!(out, "Error querying connected devices: {e}");
        }
    }
    let _ = writeln!(out);

    // 3. Apple Account & Provisioning Status
    let _ = writeln!(
        out,
        "--------------------------------------------------------------------------------"
    );
    let _ = writeln!(out, "3. APPLE ID AUTHENTICATION & PROVISIONING SESSION");
    let _ = writeln!(
        out,
        "--------------------------------------------------------------------------------"
    );
    let apple_svc = crate::apple::get_apple_service();
    let apple_lock = apple_svc.lock().await;
    match apple_lock.get_active_session().await {
        Ok(Some(session)) => {
            let _ = writeln!(out, "Session State: Active");
            let _ = writeln!(out, "Account: {}", redact_sensitive_info(&session.apple_id));
            let _ = writeln!(
                out,
                "Developer Team: {} ({})",
                session.team_name, session.team_id
            );
            let _ = writeln!(out, "Account Tier: {:?}", session.account_type);
            if let Some(exp) = session.cert_expires_at {
                let now_secs = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                let days_left = if exp > now_secs {
                    (exp - now_secs) / 86400
                } else {
                    0
                };
                let _ = writeln!(
                    out,
                    "Development Certificate Expiry: {} days remaining",
                    days_left
                );
            } else {
                let _ = writeln!(out, "Development Certificate: Not yet generated");
            }
        }
        Ok(None) => {
            let _ = writeln!(out, "Session State: Not signed in");
        }
        Err(e) => {
            let _ = writeln!(out, "Session State: Error reading session ({e})");
        }
    }
    let _ = writeln!(out);

    // 4. Local Installed Sideloaded Apps
    let _ = writeln!(
        out,
        "--------------------------------------------------------------------------------"
    );
    let _ = writeln!(out, "4. TRACKED INSTALLED APPS (LOCAL STORE)");
    let _ = writeln!(
        out,
        "--------------------------------------------------------------------------------"
    );
    match load_installed_apps() {
        Ok(apps) => {
            let _ = writeln!(out, "Total Sideloaded Apps Tracked: {}", apps.len());
            if apps.is_empty() {
                let _ = writeln!(out, "No apps currently recorded in local store.");
            } else {
                let now_secs = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                for app in &apps {
                    let days_left = if app.cert_expires_at > now_secs {
                        (app.cert_expires_at - now_secs) / 86400
                    } else {
                        0
                    };
                    let _ = writeln!(
                        out,
                        "- {} ({}) | v{} | Installed: {}s ago | Cert: {}d left",
                        app.app_name,
                        app.bundle_id,
                        app.version,
                        now_secs.saturating_sub(app.installed_at),
                        days_left
                    );
                }
            }
        }
        Err(e) => {
            let _ = writeln!(out, "Error reading installed apps store: {e}");
        }
    }
    let _ = writeln!(out);

    // 5. Helper Tools & Sidecars
    let _ = writeln!(
        out,
        "--------------------------------------------------------------------------------"
    );
    let _ = writeln!(out, "5. HELPER TOOLS & SIDECARS");
    let _ = writeln!(
        out,
        "--------------------------------------------------------------------------------"
    );
    match crate::signer::zsign::find_zsign_binary() {
        Ok(path) => {
            let _ = writeln!(out, "zsign: Located at {}", path.display());
        }
        Err(e) => {
            let _ = writeln!(out, "zsign: MISSING ({e})");
        }
    }
    let _ = writeln!(out);

    // 6. Diagnostics Log Tail
    let _ = writeln!(
        out,
        "--------------------------------------------------------------------------------"
    );
    let _ = writeln!(out, "6. RECENT DIAGNOSTIC LOGS");
    let _ = writeln!(
        out,
        "--------------------------------------------------------------------------------"
    );
    let log_path = get_diagnostics_log_path();
    if log_path.exists() {
        if let Ok(content) = std::fs::read_to_string(&log_path) {
            let lines: Vec<&str> = content.lines().collect();
            let start = lines.len().saturating_sub(50);
            for line in &lines[start..] {
                let _ = writeln!(out, "{}", redact_sensitive_info(line));
            }
        } else {
            let _ = writeln!(out, "(Failed to read diagnostics.log file)");
        }
    } else {
        let _ = writeln!(out, "(No diagnostics.log found; standard operation)");
    }

    let _ = writeln!(
        out,
        "================================================================================"
    );
    let _ = writeln!(out, "END OF WINIPA DIAGNOSTICS");
    let _ = writeln!(
        out,
        "================================================================================"
    );

    // Run full string through redaction as final defense-in-depth
    redact_sensitive_info(&out)
}

/// Exports the redacted diagnostics report to a file on disk.
/// Defaults to `%APPDATA%\WinIPA\diagnostics.txt`.
pub async fn export_diagnostics_to_file(
    custom_destination: Option<String>,
) -> Result<String, WinIpaError> {
    let report = generate_diagnostics_report().await;

    let target_path = if let Some(path_str) = custom_destination {
        PathBuf::from(path_str)
    } else if let Ok(appdata) = std::env::var("APPDATA") {
        let dir = PathBuf::from(appdata).join("WinIPA");
        let _ = std::fs::create_dir_all(&dir);
        dir.join("diagnostics.txt")
    } else {
        PathBuf::from("winipa-diagnostics.txt")
    };

    std::fs::write(&target_path, report).map_err(|e| WinIpaError::Unknown {
        message: format!("Failed to export diagnostics to file: {e}"),
        diagnostics: None,
    })?;

    Ok(target_path.to_string_lossy().to_string())
}

fn get_diagnostics_log_path() -> PathBuf {
    if let Ok(temp) = std::env::var("TEMP") {
        PathBuf::from(temp).join("WinIPA").join("diagnostics.log")
    } else {
        PathBuf::from("diagnostics.log")
    }
}

fn chrono_or_std_timestamp() -> String {
    let now = std::time::SystemTime::now();
    let duration = now
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    format!("Unix {}s", duration.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_generate_diagnostics_report_contains_sections() {
        let report = generate_diagnostics_report().await;
        assert!(report.contains("WINIPA REDACTED SYSTEM DIAGNOSTICS"));
        assert!(report.contains("1. APPLE MOBILE DEVICE SERVICE & USB DRIVER STATUS"));
        assert!(report.contains("2. CONNECTED DEVICES VIA USBMUXD"));
        assert!(report.contains("3. APPLE ID AUTHENTICATION & PROVISIONING SESSION"));
        assert!(report.contains("4. TRACKED INSTALLED APPS (LOCAL STORE)"));
        assert!(report.contains("5. HELPER TOOLS & SIDECARS"));
        assert!(report.contains("6. RECENT DIAGNOSTIC LOGS"));
        assert!(report.contains("END OF WINIPA DIAGNOSTICS"));
    }

    #[tokio::test]
    async fn test_export_diagnostics_to_file() {
        let temp_dir = std::env::temp_dir().join(format!("winipa_test_{}", uuid::Uuid::new_v4()));
        let _ = std::fs::create_dir_all(&temp_dir);
        let test_file = temp_dir.join("test_diagnostics.txt");

        let exported = export_diagnostics_to_file(Some(test_file.to_string_lossy().to_string()))
            .await
            .expect("diagnostics export should succeed");

        assert_eq!(exported, test_file.to_string_lossy().to_string());
        assert!(test_file.exists());
        let content = std::fs::read_to_string(&test_file).unwrap();
        assert!(content.contains("WINIPA REDACTED SYSTEM DIAGNOSTICS"));

        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
