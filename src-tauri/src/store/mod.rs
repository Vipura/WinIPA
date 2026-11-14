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

fn get_app_store_path() -> std::path::PathBuf {
    if let Ok(appdata) = std::env::var("APPDATA") {
        let dir = std::path::PathBuf::from(appdata).join("WinIPA");
        let _ = std::fs::create_dir_all(&dir);
        dir.join("installed_apps.json")
    } else {
        std::path::PathBuf::from("installed_apps.json")
    }
}

/// Loads all tracked installed sideloaded apps from the local store.
pub fn load_installed_apps() -> Result<Vec<InstalledAppRecord>, WinIpaError> {
    let path = get_app_store_path();
    if !path.exists() {
        return Ok(Vec::new());
    }

    let data = std::fs::read(&path).map_err(|e| WinIpaError::Unknown {
        message: format!("Failed to read installed apps database: {e}"),
        diagnostics: None,
    })?;

    if data.is_empty() {
        return Ok(Vec::new());
    }

    let records: Vec<InstalledAppRecord> = serde_json::from_slice(&data).unwrap_or_default();
    Ok(records)
}

/// Saves an installed app record to the local store (updating existing record if bundle_id matches).
pub fn save_installed_app(record: InstalledAppRecord) -> Result<(), WinIpaError> {
    let mut apps = load_installed_apps()?;
    if let Some(pos) = apps.iter().position(|a| a.bundle_id == record.bundle_id) {
        apps[pos] = record;
    } else {
        apps.push(record);
    }

    let path = get_app_store_path();
    let data = serde_json::to_vec_pretty(&apps).map_err(|e| WinIpaError::Unknown {
        message: format!("Failed to serialize installed apps database: {e}"),
        diagnostics: None,
    })?;

    std::fs::write(&path, data).map_err(|e| WinIpaError::Unknown {
        message: format!("Failed to write installed apps database: {e}"),
        diagnostics: None,
    })?;

    Ok(())
}

/// Removes an app record by its bundle ID.
pub fn remove_installed_app(bundle_id: &str) -> Result<(), WinIpaError> {
    let mut apps = load_installed_apps()?;
    apps.retain(|a| a.bundle_id != bundle_id);

    let path = get_app_store_path();
    let data = serde_json::to_vec_pretty(&apps).map_err(|e| WinIpaError::Unknown {
        message: format!("Failed to serialize installed apps database: {e}"),
        diagnostics: None,
    })?;

    std::fs::write(&path, data).map_err(|e| WinIpaError::Unknown {
        message: format!("Failed to write installed apps database: {e}"),
        diagnostics: None,
    })?;

    Ok(())
}
