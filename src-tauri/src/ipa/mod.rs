// Copyright (C) 2026 WinIPA Contributors
// SPDX-License-Identifier: GPL-3.0-only

pub mod macho;
pub mod reader;

use crate::errors::WinIpaError;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::path::{Path, PathBuf};
use tempfile::Builder as TempBuilder;
use zip::ZipArchive;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
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

/// Intelligently resolves an IPA path:
/// 1. Checks if the given path exists as-is.
/// 2. If given a relative path or filename, checks %USERPROFILE%\Downloads and %USERPROFILE%\Desktop.
pub fn resolve_ipa_path(input_path: &Path) -> PathBuf {
    if input_path.exists() {
        return input_path.to_path_buf();
    }

    if let Some(file_name) = input_path.file_name() {
        if let Ok(profile) = std::env::var("USERPROFILE") {
            let in_downloads = PathBuf::from(&profile).join("Downloads").join(file_name);
            if in_downloads.exists() {
                return in_downloads;
            }
            let in_desktop = PathBuf::from(&profile).join("Desktop").join(file_name);
            if in_desktop.exists() {
                return in_desktop;
            }
        }
    }

    input_path.to_path_buf()
}

/// Inspects an IPA package from a file path.
pub fn inspect_ipa(path: &Path) -> Result<IpaMetadata, WinIpaError> {
    let resolved = resolve_ipa_path(path);
    reader::inspect_ipa_file(&resolved)
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
    let resolved = resolve_ipa_path(path);
    if !resolved.exists() {
        return Err(WinIpaError::InvalidIpa("File does not exist".into()));
    }

    let file = File::open(&resolved)
        .map_err(|e| WinIpaError::InvalidIpa(format!("Cannot open file for reading: {e}")))?;

    ZipArchive::new(file)
        .map_err(|e| WinIpaError::InvalidIpa(format!("File is not a valid zip archive: {e}")))?;

    Ok(resolved)
}

#[cfg(test)]
mod tests {
    use super::macho::create_test_macho;
    use super::*;
    use std::io::Write;
    use tempfile::tempdir;
    use zip::write::SimpleFileOptions;
    use zip::ZipWriter;

    /// Helper to create synthetic IPA archives in a temporary directory for test fixtures.
    fn create_fixture_ipa(
        dir: &Path,
        name: &str,
        has_payload: bool,
        has_plist: bool,
        encrypted_binary: bool,
    ) -> PathBuf {
        let ipa_path = dir.join(name);
        let file = File::create(&ipa_path).expect("create test ipa file");
        let mut zip = ZipWriter::new(file);
        let options = SimpleFileOptions::default();

        if has_payload {
            if has_plist {
                zip.start_file("Payload/SampleApp.app/Info.plist", options)
                    .unwrap();
                let plist_content = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleDisplayName</key>
    <string>Test Sample App</string>
    <key>CFBundleIdentifier</key>
    <string>com.winipa.sampleapp</string>
    <key>CFBundleShortVersionString</key>
    <string>2.4.0</string>
    <key>CFBundleVersion</key>
    <string>128</string>
    <key>MinimumOSVersion</key>
    <string>16.0</string>
    <key>CFBundleExecutable</key>
    <string>SampleApp</string>
</dict>
</plist>"#;
                zip.write_all(plist_content.as_bytes()).unwrap();

                // Add synthetic Mach-O binary
                zip.start_file("Payload/SampleApp.app/SampleApp", options)
                    .unwrap();
                let macho = create_test_macho(encrypted_binary, false);
                zip.write_all(&macho).unwrap();

                // Add a small dummy PNG icon
                zip.start_file("Payload/SampleApp.app/AppIcon60x60@2x.png", options)
                    .unwrap();
                // 1x1 minimal transparent PNG
                let dummy_png = [
                    0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, 0x49,
                    0x48, 0x44, 0x52, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06,
                    0x00, 0x00, 0x00, 0x1F, 0x15, 0xC4, 0x89, 0x00, 0x00, 0x00, 0x0A, 0x49, 0x44,
                    0x41, 0x54, 0x78, 0x9C, 0x63, 0x00, 0x01, 0x00, 0x00, 0x05, 0x00, 0x01, 0x0D,
                    0x0A, 0x2D, 0xB4, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42,
                    0x60, 0x82,
                ];
                zip.write_all(&dummy_png).unwrap();
            } else {
                zip.start_file("Payload/SampleApp.app/placeholder.txt", options)
                    .unwrap();
                zip.write_all(b"No plist").unwrap();
            }
        } else {
            zip.start_file("OtherFolder/file.txt", options).unwrap();
            zip.write_all(b"Corrupted archive with no payload").unwrap();
        }

        zip.finish().expect("finish test zip");
        ipa_path
    }

    #[test]
    fn test_inspect_valid_ipa() {
        let temp = tempdir().unwrap();
        let ipa = create_fixture_ipa(temp.path(), "valid.ipa", true, true, false);

        let metadata = inspect_ipa(&ipa).expect("Valid IPA should parse successfully");
        assert_eq!(metadata.app_name, "Test Sample App");
        assert_eq!(metadata.bundle_id, "com.winipa.sampleapp");
        assert_eq!(metadata.version, "2.4.0");
        assert_eq!(metadata.build_number, "128");
        assert_eq!(metadata.min_ios_version, "16.0");
        assert!(!metadata.is_encrypted);
        assert!(metadata.icon_base64.is_some());
        assert!(metadata
            .icon_base64
            .unwrap()
            .starts_with("data:image/png;base64,"));
    }

    #[test]
    fn test_inspect_encrypted_ipa() {
        let temp = tempdir().unwrap();
        let ipa = create_fixture_ipa(temp.path(), "encrypted.ipa", true, true, true);

        let err = inspect_ipa(&ipa).expect_err("Encrypted IPA must return EncryptedIpa error");
        assert_eq!(err, WinIpaError::EncryptedIpa);
    }

    #[test]
    fn test_inspect_no_plist_ipa() {
        let temp = tempdir().unwrap();
        let ipa = create_fixture_ipa(temp.path(), "no_plist.ipa", true, false, false);

        let err = inspect_ipa(&ipa).expect_err("Missing plist must return InvalidIpa error");
        match err {
            WinIpaError::InvalidIpa(msg) => {
                assert!(msg.contains("Info.plist"));
            }
            _ => panic!("Expected InvalidIpa error"),
        }
    }

    #[test]
    fn test_inspect_invalid_payload_ipa() {
        let temp = tempdir().unwrap();
        let ipa = create_fixture_ipa(temp.path(), "invalid.ipa", false, false, false);

        let err = inspect_ipa(&ipa).expect_err("Missing payload must return InvalidIpa error");
        match err {
            WinIpaError::InvalidIpa(msg) => {
                assert!(msg.contains("Payload"));
            }
            _ => panic!("Expected InvalidIpa error"),
        }
    }

    #[test]
    fn test_inspect_nonexistent_file() {
        let err = inspect_ipa(Path::new("c:/nonexistent/file.ipa"))
            .expect_err("Nonexistent file must return error");
        match err {
            WinIpaError::InvalidIpa(msg) => {
                assert!(msg.contains("exist"));
            }
            _ => panic!("Expected InvalidIpa error"),
        }
    }
}
