// Copyright (C) 2026 WinIPA Contributors
// SPDX-License-Identifier: GPL-3.0-only

use crate::errors::WinIpaError;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::path::{Path, PathBuf};
use tempfile::Builder as TempBuilder;
use zip::ZipArchive;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpaMetadata {
    pub file_path: String,
    pub app_name: String,
    pub bundle_id: String,
    pub version: String,
    pub build_number: String,
    pub min_ios_version: String,
    pub icon_base64: Option<String>,
    pub is_encrypted: bool,
    pub is_already_signed: bool,
    pub original_entitlements: Vec<String>,
}

/// Creates an isolated temporary directory under %TEMP%\WinIPA for safe extraction and signing.
pub fn create_temp_work_dir() -> Result<tempfile::TempDir, WinIpaError> {
    let base_temp = std::env::temp_dir().join("WinIPA");
    std::fs::create_dir_all(&base_temp).map_err(|e| WinIpaError::Unknown {
        message: format!("Failed to create WinIPA temp directory: {e}"),
        diagnostics: None,
    })?;

    TempBuilder::new()
        .prefix("ipa_work_")
        .tempdir_in(&base_temp)
        .map_err(|e| WinIpaError::Unknown {
            message: format!("Failed to create isolated temp work dir: {e}"),
            diagnostics: None,
        })
}

/// Verifies that a file path exists and is a readable Zip archive.
pub fn verify_zip_archive(path: &Path) -> Result<PathBuf, WinIpaError> {
    if !path.exists() {
        return Err(WinIpaError::InvalidIpa("File does not exist".into()));
    }

    let file = File::open(path)
        .map_err(|e| WinIpaError::InvalidIpa(format!("Cannot open file for reading: {e}")))?;

    ZipArchive::new(file)
        .map_err(|e| WinIpaError::InvalidIpa(format!("File is not a valid zip archive: {e}")))?;

    Ok(path.to_path_buf())
}
