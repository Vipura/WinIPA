// Copyright (C) 2026 WinIPA Contributors
// SPDX-License-Identifier: GPL-3.0-only

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Human-readable error information returned across Tauri IPC to the frontend.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorDetail {
    pub code: String,
    pub title: String,
    pub message: String,
    pub remedy: String,
    pub diagnostics: Option<String>,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum WinIpaError {
    #[error("No iPhone Connected")]
    NoDevice,

    #[error("iPhone is Locked")]
    DeviceLocked,

    #[error("Device Not Trusted")]
    DeviceNotTrusted,

    #[error("Apple USB Driver Missing")]
    DriverMissing,

    #[error("Developer Mode Disabled")]
    DeveloperModeOff,

    #[error("iOS Version Too Low")]
    IosTooOld { required: String, actual: String },

    #[error("Invalid IPA Package")]
    InvalidIpa(String),

    #[error("App Store DRM Encrypted")]
    EncryptedIpa,

    #[error("Apple ID Authentication Failed")]
    AppleAuthFailed(String),

    #[error("Two-Factor Authentication Failed")]
    TwoFactorFailed(String),

    #[error("Apple Rate Limited")]
    AppleRateLimited,

    #[error("Account Limit Reached")]
    AccountLimitReached(String),

    #[error("Certificate Request Failed")]
    CertificateFailed(String),

    #[error("Provisioning Profile Failed")]
    ProfileFailed(String),

    #[error("Signing Failed")]
    SigningFailed(String),

    #[error("Installation Failed")]
    InstallFailed(String),

    #[error("Required Tool Missing")]
    ToolMissing(String),

    #[error("Operation Timed Out")]
    Timeout(String),

    #[error("Operation Cancelled")]
    Cancelled,

    #[error("Unknown Error")]
    Unknown {
        message: String,
        diagnostics: Option<String>,
    },
}

impl WinIpaError {
    pub fn to_detail(&self) -> ErrorDetail {
        match self {
            Self::NoDevice => ErrorDetail {
                code: "NoDevice".into(),
                title: "No iPhone Connected".into(),
                message: "WinIPA could not detect any connected iOS device over USB.".into(),
                remedy: "Connect your iPhone using a working USB cable, unlock the screen, and ensure the phone is powered on.".into(),
                diagnostics: None,
            },
            Self::DeviceLocked => ErrorDetail {
                code: "DeviceLocked".into(),
                title: "iPhone is Passcode Locked".into(),
                message: "The connected iPhone is locked with a passcode, preventing USB communication.".into(),
                remedy: "Unlock your iPhone by entering your passcode on the lock screen.".into(),
                diagnostics: None,
            },
            Self::DeviceNotTrusted => ErrorDetail {
                code: "DeviceNotTrusted".into(),
                title: "Computer Not Trusted".into(),
                message: "This computer has not been paired and trusted by the connected iPhone.".into(),
                remedy: "Unlock your iPhone and tap 'Trust This Computer' on the prompt that appears.".into(),
                diagnostics: None,
            },
            Self::DriverMissing => ErrorDetail {
                code: "DriverMissing".into(),
                title: "Apple USB Driver Missing".into(),
                message: "The Apple Mobile Device Service or USB driver is not detected on your Windows PC.".into(),
                remedy: "Install 'Apple Devices' or 'iTunes' from the Microsoft Store, then restart WinIPA.".into(),
                diagnostics: None,
            },
            Self::DeveloperModeOff => ErrorDetail {
                code: "DeveloperModeOff".into(),
                title: "Developer Mode Disabled".into(),
                message: "iOS 16+ requires Developer Mode to run sideloaded development applications.".into(),
                remedy: "On your iPhone, navigate to Settings > Privacy & Security > Developer Mode, turn it ON, and restart the device.".into(),
                diagnostics: None,
            },
            Self::IosTooOld { required, actual } => ErrorDetail {
                code: "IosTooOld".into(),
                title: "iOS Version Too Low".into(),
                message: format!("This app requires at least iOS {required}, but your iPhone is running iOS {actual}."),
                remedy: "Update your iPhone to a newer iOS version, or obtain an IPA built for your iOS version.".into(),
                diagnostics: None,
            },
            Self::InvalidIpa(msg) => ErrorDetail {
                code: "InvalidIpa".into(),
                title: "Invalid IPA Package".into(),
                message: format!("The selected file is not a valid iOS application archive: {msg}"),
                remedy: "Verify the .ipa file is not corrupted and contains a valid Payload/*.app bundle with Info.plist.".into(),
                diagnostics: None,
            },
            Self::EncryptedIpa => ErrorDetail {
                code: "EncryptedIpa".into(),
                title: "App Store DRM Encrypted".into(),
                message: "This IPA was downloaded directly from the Apple App Store and is encrypted with FairPlay DRM.".into(),
                remedy: "App Store binaries cannot be sideloaded. Use an unencrypted development build from your project, or a decrypted IPA.".into(),
                diagnostics: None,
            },
            Self::AppleAuthFailed(msg) => ErrorDetail {
                code: "AppleAuthFailed".into(),
                title: "Apple ID Login Failed".into(),
                message: format!("Apple rejected authentication: {msg}"),
                remedy: "Check your Apple ID email and password and try logging in again.".into(),
                diagnostics: None,
            },
            Self::TwoFactorFailed(msg) => ErrorDetail {
                code: "TwoFactorFailed".into(),
                title: "Two-Factor Code Verification Failed".into(),
                message: format!("The two-factor authentication code could not be verified: {msg}"),
                remedy: "Check the 6-digit code sent to your trusted Apple devices or SMS and re-enter it.".into(),
                diagnostics: None,
            },
            Self::AppleRateLimited => ErrorDetail {
                code: "AppleRateLimited".into(),
                title: "Apple Server Rate Limited".into(),
                message: "Apple's authentication or developer portal servers are temporarily throttling requests.".into(),
                remedy: "Wait 15 to 60 minutes before attempting to authenticate or request certificates again.".into(),
                diagnostics: None,
            },
            Self::AccountLimitReached(msg) => ErrorDetail {
                code: "AccountLimitReached".into(),
                title: "Free Account Limit Reached".into(),
                message: format!("Free Apple ID limit reached: {msg}"),
                remedy: "Free accounts can have up to 3 active sideloaded apps at a time and ~10 App IDs per week. Delete an existing app or wait for weekly quota reset.".into(),
                diagnostics: None,
            },
            Self::CertificateFailed(msg) => ErrorDetail {
                code: "CertificateFailed".into(),
                title: "Certificate Generation Failed".into(),
                message: format!("Could not generate or download a development certificate: {msg}"),
                remedy: "If you have reached the maximum active development certificates, revoke old certificates via Apple Developer or AltStore.".into(),
                diagnostics: None,
            },
            Self::ProfileFailed(msg) => ErrorDetail {
                code: "ProfileFailed".into(),
                title: "Provisioning Profile Failed".into(),
                message: format!("Could not generate provisioning profile: {msg}"),
                remedy: "Ensure your device UDID is registered and your App ID is valid for this account.".into(),
                diagnostics: None,
            },
            Self::SigningFailed(msg) => ErrorDetail {
                code: "SigningFailed".into(),
                title: "IPA Code Signing Failed".into(),
                message: format!("The code signing process failed: {msg}"),
                remedy: "Review the diagnostics log for signing tool output. Ensure the certificate and profile match.".into(),
                diagnostics: None,
            },
            Self::InstallFailed(msg) => ErrorDetail {
                code: "InstallFailed".into(),
                title: "App Installation Failed".into(),
                message: format!("iPhone rejected installation of the package: {msg}"),
                remedy: "Check your iPhone storage space, verify device lock status, and ensure your developer profile is trusted in Settings > General > VPN & Device Management.".into(),
                diagnostics: None,
            },
            Self::ToolMissing(tool) => ErrorDetail {
                code: "ToolMissing".into(),
                title: "Helper Tool Missing".into(),
                message: format!("Required helper tool '{tool}' was not found in WinIPA installation."),
                remedy: "Ensure WinIPA is installed properly and your antivirus did not quarantine helper binaries.".into(),
                diagnostics: None,
            },
            Self::Timeout(op) => ErrorDetail {
                code: "Timeout".into(),
                title: "Operation Timed Out".into(),
                message: format!("The operation '{op}' timed out waiting for a response."),
                remedy: "Check your USB cable connection and internet connectivity, then try again.".into(),
                diagnostics: None,
            },
            Self::Cancelled => ErrorDetail {
                code: "Cancelled".into(),
                title: "Operation Cancelled".into(),
                message: "The operation was cancelled by the user.".into(),
                remedy: "You can start a new operation when ready.".into(),
                diagnostics: None,
            },
            Self::Unknown { message, diagnostics } => ErrorDetail {
                code: "Unknown".into(),
                title: "Unexpected Error".into(),
                message: message.clone(),
                remedy: "Copy the diagnostics log and report this issue on GitHub.".into(),
                diagnostics: diagnostics.clone(),
            },
        }
    }
}

impl Serialize for WinIpaError {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.to_detail().serialize(serializer)
    }
}
