// Copyright (C) 2026 WinIPA Contributors
// SPDX-License-Identifier: GPL-3.0-only

pub mod redaction;

use crate::errors::WinIpaError;
use keyring::Entry;
use serde::{Deserialize, Serialize};

const SERVICE_NAME: &str = "WinIPA";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstalledAppRecord {
    pub bundle_id: String,
    pub app_name: String,
    pub version: String,
    pub installed_at: u64,
    pub cert_expires_at: u64,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct AppStore {
    pub installed_apps: Vec<InstalledAppRecord>,
}

/// Stores a secure secret (such as session token or password) in Windows Credential Manager.
pub fn store_secret(key: &str, secret: &str) -> Result<(), WinIpaError> {
    let entry = Entry::new(SERVICE_NAME, key)
        .map_err(|e| WinIpaError::AppleAuthFailed(format!("Keyring error: {e}")))?;
    entry
        .set_password(secret)
        .map_err(|e| WinIpaError::AppleAuthFailed(format!("Failed to store secret: {e}")))?;
    Ok(())
}

/// Retrieves a secure secret from Windows Credential Manager.
pub fn get_secret(key: &str) -> Result<Option<String>, WinIpaError> {
    let entry = Entry::new(SERVICE_NAME, key)
        .map_err(|e| WinIpaError::AppleAuthFailed(format!("Keyring error: {e}")))?;
    match entry.get_password() {
        Ok(secret) => Ok(Some(secret)),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(WinIpaError::AppleAuthFailed(format!(
            "Failed to read secret: {e}"
        ))),
    }
}

/// Deletes a secure secret from Windows Credential Manager.
pub fn delete_secret(key: &str) -> Result<(), WinIpaError> {
    let entry = Entry::new(SERVICE_NAME, key)
        .map_err(|e| WinIpaError::AppleAuthFailed(format!("Keyring error: {e}")))?;
    match entry.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(WinIpaError::AppleAuthFailed(format!(
            "Failed to delete secret: {e}"
        ))),
    }
}
