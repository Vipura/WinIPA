// Copyright (C) 2026 WinIPA Contributors
// SPDX-License-Identifier: GPL-3.0-only

use super::macho::inspect_macho;
use super::IpaMetadata;
use crate::errors::WinIpaError;
use plist::Value;
use std::fs::File;
use std::io::{Cursor, Read};
use std::path::Path;
use zip::ZipArchive;

/// Reads and inspects an IPA file from disk.
pub fn inspect_ipa_file(path: &Path) -> Result<IpaMetadata, WinIpaError> {
    if !path.exists() {
        return Err(WinIpaError::InvalidIpa("File does not exist".into()));
    }

    let file = File::open(path)
        .map_err(|e| WinIpaError::InvalidIpa(format!("Cannot open file for reading: {e}")))?;

    let mut archive = ZipArchive::new(file)
        .map_err(|e| WinIpaError::InvalidIpa(format!("File is not a valid zip archive: {e}")))?;

    // 1. Locate Payload/*.app directory
    let mut app_prefix: Option<String> = None;
    for i in 0..archive.len() {
        let entry = archive.by_index(i).map_err(|e| {
            WinIpaError::InvalidIpa(format!("Corrupted zip entry at index {i}: {e}"))
        })?;
        let name = entry.name().replace('\\', "/");
        if name.starts_with("Payload/") && name.contains(".app/") {
            let parts: Vec<&str> = name.split('/').collect();
            if parts.len() >= 2 && parts[1].ends_with(".app") {
                app_prefix = Some(format!("Payload/{}/", parts[1]));
                break;
            }
        }
    }

    let prefix = match app_prefix {
        Some(p) => p,
        None => {
            return Err(WinIpaError::InvalidIpa(
                "Missing 'Payload/*.app' bundle directory".into(),
            ));
        }
    };

    // 2. Locate and read Info.plist
    let info_plist_entry_name = format!("{prefix}Info.plist");
    let mut plist_bytes = Vec::new();
    {
        let mut info_file = archive.by_name(&info_plist_entry_name).map_err(|_| {
            WinIpaError::InvalidIpa(format!("Missing '{info_plist_entry_name}' in bundle"))
        })?;
        info_file
            .read_to_end(&mut plist_bytes)
            .map_err(|e| WinIpaError::InvalidIpa(format!("Failed to read Info.plist: {e}")))?;
    }

    let plist_val = Value::from_reader(Cursor::new(&plist_bytes))
        .map_err(|e| WinIpaError::InvalidIpa(format!("Failed to parse Info.plist: {e}")))?;

    let dict = plist_val
        .as_dictionary()
        .ok_or_else(|| WinIpaError::InvalidIpa("Info.plist root is not a dictionary".into()))?;

    // Extract App Name
    let app_name = dict
        .get("CFBundleDisplayName")
        .and_then(|v| v.as_string())
        .or_else(|| dict.get("CFBundleName").and_then(|v| v.as_string()))
        .unwrap_or_else(|| {
            prefix
                .strip_prefix("Payload/")
                .unwrap_or(&prefix)
                .trim_end_matches('/')
                .trim_end_matches(".app")
        })
        .to_string();

    // Extract Bundle ID
    let bundle_id = dict
        .get("CFBundleIdentifier")
        .and_then(|v| v.as_string())
        .ok_or_else(|| WinIpaError::InvalidIpa("Info.plist missing 'CFBundleIdentifier'".into()))?
        .to_string();

    // Extract Version and Build
    let version = dict
        .get("CFBundleShortVersionString")
        .and_then(|v| v.as_string())
        .unwrap_or("1.0.0")
        .to_string();

    let build_number = dict
        .get("CFBundleVersion")
        .and_then(|v| v.as_string())
        .unwrap_or("1")
        .to_string();

    // Extract Minimum OS Version
    let min_ios_version = dict
        .get("MinimumOSVersion")
        .and_then(|v| v.as_string())
        .unwrap_or("12.0")
        .to_string();

    // Extract Executable Name and Inspect Mach-O
    let executable_name = dict
        .get("CFBundleExecutable")
        .and_then(|v| v.as_string())
        .unwrap_or(&app_name);

    let executable_entry_name = format!("{prefix}{executable_name}");
    let mut is_encrypted = false;
    let mut is_signed = false;

    if let Ok(mut exe_file) = archive.by_name(&executable_entry_name) {
        let mut exe_bytes = Vec::new();
        // Read executable header and load commands
        let _ = exe_file.read_to_end(&mut exe_bytes);
        if !exe_bytes.is_empty() {
            let macho_info = inspect_macho(&exe_bytes);
            is_encrypted = macho_info.is_encrypted;
            is_signed = macho_info.is_signed;
        }
    }

    // Check for _CodeSignature in archive
    let code_sig_entry = format!("{prefix}_CodeSignature/CodeResources");
    if archive.by_name(&code_sig_entry).is_ok() {
        is_signed = true;
    }

    // 3. Extract Icon if present
    let icon_base64 = extract_app_icon(&mut archive, &prefix, dict);

    // If binary is FairPlay encrypted, immediately return typed error as specified in Section 4 Step 2
    if is_encrypted {
        return Err(WinIpaError::EncryptedIpa);
    }

    Ok(IpaMetadata {
        file_path: path.to_string_lossy().to_string(),
        app_name,
        bundle_id,
        version,
        build_number,
        min_ios_version,
        icon_base64,
        is_encrypted,
        is_already_signed: is_signed,
        original_entitlements: vec![],
    })
}

/// Attempts to find and extract an app icon from the bundle, returning base64 data URI.
fn extract_app_icon(
    archive: &mut ZipArchive<File>,
    prefix: &str,
    _info_dict: &plist::Dictionary,
) -> Option<String> {
    // 1. Scan for AppIcon*.png or Icon*.png files in the app bundle
    let mut candidate_icons = Vec::new();

    for i in 0..archive.len() {
        if let Ok(entry) = archive.by_index(i) {
            let name = entry.name().replace('\\', "/");
            if name.starts_with(prefix) && name.ends_with(".png") {
                let file_name = name.strip_prefix(prefix).unwrap_or(&name);
                if file_name.contains("AppIcon") || file_name.contains("Icon") {
                    candidate_icons.push(name.clone());
                }
            }
        }
    }

    // Sort to prefer 60x60@2x, 60x60@3x, or larger icons
    candidate_icons.sort_by_key(|a| std::cmp::Reverse(a.len()));

    for icon_name in candidate_icons {
        if let Ok(mut file) = archive.by_name(&icon_name) {
            let mut buf = Vec::new();
            if file.read_to_end(&mut buf).is_ok() && !buf.is_empty() {
                // Return as base64 data URL
                let encoded = base64_encode(&buf);
                return Some(format!("data:image/png;base64,{encoded}"));
            }
        }
    }

    None
}

/// Helper for base64 encoding icon bytes without pulling in external crate.
fn base64_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::with_capacity(data.len().div_ceil(3) * 4);

    for chunk in data.chunks(3) {
        let b0 = chunk[0];
        let b1 = if chunk.len() > 1 { chunk[1] } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] } else { 0 };

        let n = ((b0 as u32) << 16) | ((b1 as u32) << 8) | (b2 as u32);

        result.push(ALPHABET[((n >> 18) & 63) as usize] as char);
        result.push(ALPHABET[((n >> 12) & 63) as usize] as char);

        if chunk.len() > 1 {
            result.push(ALPHABET[((n >> 6) & 63) as usize] as char);
        } else {
            result.push('=');
        }

        if chunk.len() > 2 {
            result.push(ALPHABET[(n & 63) as usize] as char);
        } else {
            result.push('=');
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base64_encode() {
        assert_eq!(base64_encode(b"hello"), "aGVsbG8=");
        assert_eq!(base64_encode(b"WinIPA"), "V2luSVBB");
    }
}
