// Copyright (C) 2026 WinIPA Contributors
// SPDX-License-Identifier: GPL-3.0-only

use crate::device::lockdown::{read_lockdown_message, send_lockdown_message};
use crate::errors::WinIpaError;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::net::TcpStream;

/// Commands the iOS `com.apple.mobile.installation_proxy` service to install the uploaded IPA package.
pub async fn install_package_proxy<F>(
    stream: &mut TcpStream,
    staging_path: &str,
    bundle_id: &str,
    progress_callback: F,
    cancel_token: Arc<AtomicBool>,
) -> Result<(), WinIpaError>
where
    F: Fn(f32, &str),
{
    let xml = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Command</key>
    <string>Install</string>
    <key>ClientOptions</key>
    <dict>
        <key>CFBundleIdentifier</key>
        <string>{bundle_id}</string>
        <key>PackageType</key>
        <string>Developer</string>
    </dict>
    <key>PackagePath</key>
    <string>{staging_path}</string>
</dict>
</plist>"#
    );

    send_lockdown_message(stream, &xml).await?;

    loop {
        if cancel_token.load(Ordering::Relaxed) {
            return Err(WinIpaError::Unknown {
                message: "Installation cancelled by user".into(),
                diagnostics: None,
            });
        }

        let resp = read_lockdown_message(stream).await?;
        let dict = match resp.as_dictionary() {
            Some(d) => d,
            None => continue,
        };

        // Check for error responses
        if let Some(err) = dict.get("Error").and_then(|v| v.as_string()) {
            let desc = dict
                .get("ErrorDescription")
                .and_then(|v| v.as_string())
                .unwrap_or(err);

            return Err(match err {
                "ApplicationVerificationFailed" => WinIpaError::InstallFailed(format!(
                    "Application verification failed on device ({desc}). Ensure your developer certificate is trusted and entitlements match the provisioning profile."
                )),
                "MismatchedApplicationIdentifierEntitlement" => WinIpaError::InstallFailed(format!(
                    "Application identifier mismatch ({desc}). The bundle identifier must match your App ID."
                )),
                "DeviceNotRegistered" => WinIpaError::InstallFailed(
                    "Your iPhone UDID is not registered in this provisioning profile.".into(),
                ),
                _ => WinIpaError::InstallFailed(format!("Installation error {err}: {desc}")),
            });
        }

        let status = dict
            .get("Status")
            .and_then(|v| v.as_string())
            .unwrap_or("Installing");

        let percent = dict
            .get("PercentComplete")
            .and_then(|v| v.as_signed_integer())
            .unwrap_or(0) as f32;

        // Scale installation proxy progress from 50% to 100%
        let overall_percent = 50.0 + (percent * 0.5);

        let friendly_status = match status {
            "TakingInstallAssertion" => "Acquiring device install assertion...",
            "CreatingStagingDirectory" => "Creating sandbox staging directory...",
            "ExtractingPackage" => "Extracting package contents on iPhone...",
            "VerifyingApplication" => "Verifying code signatures and entitlements...",
            "GeneratingApplicationMap" => "Registering app in iOS SpringBoard...",
            "Complete" => "Installation complete!",
            other => other,
        };

        let msg = format!("{friendly_status} ({:.0}%)", overall_percent);
        progress_callback(overall_percent, &msg);

        if status == "Complete" || percent >= 100.0 {
            break;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use plist::Value;

    #[test]
    fn test_parse_installation_error() {
        let err_xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Error</key>
    <string>ApplicationVerificationFailed</string>
    <key>ErrorDescription</key>
    <string>Failed to verify code signature</string>
</dict>
</plist>"#;

        let val = Value::from_reader_xml(std::io::Cursor::new(err_xml.as_bytes())).unwrap();
        let dict = val.as_dictionary().unwrap();
        assert_eq!(
            dict.get("Error").and_then(|v| v.as_string()),
            Some("ApplicationVerificationFailed")
        );
    }
}
