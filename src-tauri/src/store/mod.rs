// Copyright (C) 2026 WinIPA Contributors
// SPDX-License-Identifier: GPL-3.0-only

pub mod diagnostics;
pub mod redaction;

pub use diagnostics::{export_diagnostics_to_file, generate_diagnostics_report};

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

pub fn get_app_dir() -> std::path::PathBuf {
    if let Ok(appdata) = std::env::var("APPDATA") {
        let dir = std::path::PathBuf::from(appdata).join("WinIPA");
        let _ = std::fs::create_dir_all(&dir);
        return dir;
    }
    let dir = std::env::temp_dir().join("WinIPA");
    let _ = std::fs::create_dir_all(&dir);
    dir
}

fn get_vault_path() -> std::path::PathBuf {
    get_app_dir().join("vault.json")
}

fn load_vault() -> std::collections::HashMap<String, String> {
    let path = get_vault_path();
    if let Ok(data) = std::fs::read(&path) {
        if let Ok(map) = serde_json::from_slice::<std::collections::HashMap<String, String>>(&data)
        {
            return map;
        }
    }
    std::collections::HashMap::new()
}

fn save_vault(map: &std::collections::HashMap<String, String>) -> Result<(), WinIpaError> {
    let path = get_vault_path();
    let data = serde_json::to_vec_pretty(map).map_err(|e| WinIpaError::Unknown {
        message: format!("Failed to serialize vault: {e}"),
        diagnostics: None,
    })?;
    std::fs::write(&path, data).map_err(|e| WinIpaError::Unknown {
        message: format!("Failed to write vault: {e}"),
        diagnostics: None,
    })?;
    Ok(())
}

/// Stores a secure secret (such as session token or password) in local secure vault and Windows Credential Manager.
pub fn store_secret(key: &str, secret: &str) -> Result<(), WinIpaError> {
    // 1. Persistent vault store
    let mut vault = load_vault();
    vault.insert(key.to_string(), secret.to_string());
    save_vault(&vault)?;

    // 2. Best-effort Windows Credential Manager mirror
    if let Ok(entry) = Entry::new(SERVICE_NAME, key) {
        let _ = entry.set_password(secret);
    }

    Ok(())
}

/// Retrieves a secure secret from local vault or Windows Credential Manager.
pub fn get_secret(key: &str) -> Result<Option<String>, WinIpaError> {
    // 1. Check local persistent vault
    let vault = load_vault();
    if let Some(val) = vault.get(key) {
        if !val.is_empty() {
            return Ok(Some(val.clone()));
        }
    }

    // 2. Fallback to Windows Credential Manager
    if let Ok(entry) = Entry::new(SERVICE_NAME, key) {
        if let Ok(secret) = entry.get_password() {
            if !secret.is_empty() {
                return Ok(Some(secret));
            }
        }
    }

    Ok(None)
}

/// Deletes a secure secret from local vault and Windows Credential Manager.
pub fn delete_secret(key: &str) -> Result<(), WinIpaError> {
    let mut vault = load_vault();
    vault.remove(key);
    let _ = save_vault(&vault);

    if let Ok(entry) = Entry::new(SERVICE_NAME, key) {
        let _ = entry.delete_credential();
    }

    Ok(())
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
