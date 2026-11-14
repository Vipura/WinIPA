// Copyright (C) 2026 WinIPA Contributors
// SPDX-License-Identifier: GPL-3.0-only

use super::macho::inspect_macho;
use super::IpaMetadata;
use crate::errors::WinIpaError;
use flate2::read::{DeflateDecoder, ZlibDecoder};
use flate2::write::ZlibEncoder;
use flate2::Compression;
use plist::Value;
use std::fs::File;
use std::io::{Cursor, Read, Write};
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
    info_dict: &plist::Dictionary,
) -> Option<String> {
    // 1. Scan for AppIcon*.png or Icon*.png files in the app bundle
    let mut candidate_icons = Vec::new();

    // Check Info.plist CFBundleIcons / CFBundleIconFiles / CFBundleIconFile
    let mut plist_icon_names = Vec::new();
    if let Some(cf_icons) = info_dict
        .get("CFBundleIcons")
        .and_then(|v| v.as_dictionary())
    {
        if let Some(primary) = cf_icons
            .get("CFBundlePrimaryIcon")
            .and_then(|v| v.as_dictionary())
        {
            if let Some(files) = primary.get("CFBundleIconFiles").and_then(|v| v.as_array()) {
                for f in files {
                    if let Some(s) = f.as_string() {
                        plist_icon_names.push(s.to_string());
                    }
                }
            }
        }
    }
    if let Some(files) = info_dict
        .get("CFBundleIconFiles")
        .and_then(|v| v.as_array())
    {
        for f in files {
            if let Some(s) = f.as_string() {
                plist_icon_names.push(s.to_string());
            }
        }
    }
    if let Some(file) = info_dict
        .get("CFBundleIconFile")
        .and_then(|v| v.as_string())
    {
        plist_icon_names.push(file.to_string());
    }

    for i in 0..archive.len() {
        if let Ok(entry) = archive.by_index(i) {
            let name = entry.name().replace('\\', "/");
            if name.starts_with(prefix) && name.ends_with(".png") {
                let file_name = name.strip_prefix(prefix).unwrap_or(&name);
                let is_plist_match = plist_icon_names
                    .iter()
                    .any(|pname| file_name.starts_with(pname));
                if file_name.contains("AppIcon") || file_name.contains("Icon") || is_plist_match {
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
                // If it is an Apple CgBI PNG, uncrush it to standard compliant PNG
                let final_png = uncrush_cgbi_png(&buf).unwrap_or(buf);
                let encoded = base64_encode(&final_png);
                return Some(format!("data:image/png;base64,{encoded}"));
            }
        }
    }

    None
}

/// Detects if PNG bytes contain Apple's proprietary CgBI chunk.
pub fn is_cgbi_png(data: &[u8]) -> bool {
    const PNG_HEADER: &[u8; 8] = &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
    if data.len() < 16 || &data[0..8] != PNG_HEADER {
        return false;
    }
    if &data[12..16] == b"CgBI" {
        return true;
    }
    let mut offset = 8;
    while offset + 8 <= data.len() {
        let length = match data[offset..offset + 4].try_into() {
            Ok(b) => u32::from_be_bytes(b) as usize,
            Err(_) => return false,
        };
        let chunk_type = &data[offset + 4..offset + 8];
        if chunk_type == b"CgBI" {
            return true;
        }
        if chunk_type == b"IEND" {
            break;
        }
        offset += 12 + length;
    }
    false
}

/// Converts an Apple CgBI proprietary PNG into a standard compliant PNG.
/// If data is not CgBI, returns it untouched.
#[allow(clippy::chunks_exact_to_as_chunks)]
pub fn uncrush_cgbi_png(data: &[u8]) -> Option<Vec<u8>> {
    const PNG_HEADER: &[u8; 8] = &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
    if data.len() < 8 || &data[0..8] != PNG_HEADER {
        return None;
    }

    if !is_cgbi_png(data) {
        return Some(data.to_vec());
    }

    let mut width = 0u32;
    let mut height = 0u32;
    let mut bit_depth = 8u8;
    let mut color_type = 6u8;
    let mut idat_data = Vec::new();

    let mut offset = 8;
    while offset + 8 <= data.len() {
        let length = u32::from_be_bytes(data[offset..offset + 4].try_into().ok()?) as usize;
        let chunk_type = &data[offset + 4..offset + 8];
        let chunk_data_start = offset + 8;
        let chunk_data_end = chunk_data_start + length;
        if chunk_data_end + 4 > data.len() {
            break;
        }

        if chunk_type == b"IHDR" && length >= 13 {
            let d = &data[chunk_data_start..chunk_data_end];
            width = u32::from_be_bytes(d[0..4].try_into().ok()?);
            height = u32::from_be_bytes(d[4..8].try_into().ok()?);
            bit_depth = d[8];
            color_type = d[9];
        } else if chunk_type == b"IDAT" {
            idat_data.extend_from_slice(&data[chunk_data_start..chunk_data_end]);
        } else if chunk_type == b"IEND" {
            break;
        }

        offset = chunk_data_end + 4; // skip CRC
    }

    if width == 0 || height == 0 || idat_data.is_empty() {
        return None;
    }

    // Decompress raw deflate stream
    let mut inflated = Vec::new();
    let mut deflate = DeflateDecoder::new(&idat_data[..]);
    if deflate.read_to_end(&mut inflated).is_err() {
        let mut zlib = ZlibDecoder::new(&idat_data[..]);
        inflated.clear();
        if zlib.read_to_end(&mut inflated).is_err() {
            return None;
        }
    }

    let bpp: usize = match color_type {
        6 => 4, // RGBA
        2 => 3, // RGB
        0 => 1, // Grayscale
        4 => 2, // Grayscale + Alpha
        _ => return None,
    };

    let row_bytes = width as usize * bpp;
    let expected_len = height as usize * (1 + row_bytes);
    if inflated.len() < expected_len {
        return None;
    }

    let mut defiltered_rows: Vec<Vec<u8>> = Vec::with_capacity(height as usize);
    let mut prev_row = vec![0u8; row_bytes];
    let mut in_offset = 0;

    for _ in 0..height {
        let filter_type = inflated[in_offset];
        in_offset += 1;
        let row_slice = &inflated[in_offset..in_offset + row_bytes];
        in_offset += row_bytes;

        let mut current_row = vec![0u8; row_bytes];
        match filter_type {
            0 => {
                current_row.copy_from_slice(row_slice);
            }
            1 => {
                for i in 0..row_bytes {
                    let a = if i >= bpp { current_row[i - bpp] } else { 0 };
                    current_row[i] = row_slice[i].wrapping_add(a);
                }
            }
            2 => {
                for i in 0..row_bytes {
                    let b = prev_row[i];
                    current_row[i] = row_slice[i].wrapping_add(b);
                }
            }
            3 => {
                for i in 0..row_bytes {
                    let a = if i >= bpp {
                        current_row[i - bpp] as u16
                    } else {
                        0
                    };
                    let b = prev_row[i] as u16;
                    let avg = ((a + b) / 2) as u8;
                    current_row[i] = row_slice[i].wrapping_add(avg);
                }
            }
            4 => {
                for i in 0..row_bytes {
                    let a = if i >= bpp {
                        current_row[i - bpp] as i32
                    } else {
                        0
                    };
                    let b = prev_row[i] as i32;
                    let c = if i >= bpp {
                        prev_row[i - bpp] as i32
                    } else {
                        0
                    };
                    let p = a + b - c;
                    let pa = (p - a).abs();
                    let pb = (p - b).abs();
                    let pc = (p - c).abs();
                    let pred = if pa <= pb && pa <= pc {
                        a as u8
                    } else if pb <= pc {
                        b as u8
                    } else {
                        c as u8
                    };
                    current_row[i] = row_slice[i].wrapping_add(pred);
                }
            }
            _ => {
                current_row.copy_from_slice(row_slice);
            }
        }

        // Color swap (BGR -> RGB) & alpha un-premultiply
        if bpp == 4 {
            for chunk in current_row.chunks_exact_mut(4) {
                let b = chunk[0];
                let g = chunk[1];
                let r = chunk[2];
                let a = chunk[3];

                let mut new_r = r;
                let mut new_g = g;
                let mut new_b = b;

                if a > 0 && a < 255 {
                    new_r = ((r as u32 * 255 + (a as u32 / 2)) / a as u32).min(255) as u8;
                    new_g = ((g as u32 * 255 + (a as u32 / 2)) / a as u32).min(255) as u8;
                    new_b = ((b as u32 * 255 + (a as u32 / 2)) / a as u32).min(255) as u8;
                }

                chunk[0] = new_r;
                chunk[1] = new_g;
                chunk[2] = new_b;
                chunk[3] = a;
            }
        } else if bpp == 3 {
            for chunk in current_row.chunks_exact_mut(3) {
                chunk.swap(0, 2);
            }
        }

        prev_row = current_row.clone();
        defiltered_rows.push(current_row);
    }

    // Re-encode into standard compliant PNG
    let mut raw_png_data = Vec::with_capacity(height as usize * (1 + row_bytes));
    for row in defiltered_rows {
        raw_png_data.push(0); // Filter type 0 (None)
        raw_png_data.extend_from_slice(&row);
    }

    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(&raw_png_data).ok()?;
    let compressed_idat = encoder.finish().ok()?;

    let mut out = Vec::new();
    out.extend_from_slice(PNG_HEADER);

    let write_chunk = |out: &mut Vec<u8>, chunk_type: &[u8; 4], data: &[u8]| {
        out.extend_from_slice(&(data.len() as u32).to_be_bytes());
        out.extend_from_slice(chunk_type);
        out.extend_from_slice(data);
        let mut hasher = crc32fast::Hasher::new();
        hasher.update(chunk_type);
        hasher.update(data);
        let crc = hasher.finalize();
        out.extend_from_slice(&crc.to_be_bytes());
    };

    // IHDR
    let mut ihdr_data = [0u8; 13];
    ihdr_data[0..4].copy_from_slice(&width.to_be_bytes());
    ihdr_data[4..8].copy_from_slice(&height.to_be_bytes());
    ihdr_data[8] = bit_depth;
    ihdr_data[9] = color_type;
    ihdr_data[10] = 0; // deflate compression
    ihdr_data[11] = 0; // adaptive filter
    ihdr_data[12] = 0; // non-interlaced
    write_chunk(&mut out, b"IHDR", &ihdr_data);

    // IDAT
    write_chunk(&mut out, b"IDAT", &compressed_idat);

    // IEND
    write_chunk(&mut out, b"IEND", &[]);

    Some(out)
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

    #[test]
    fn test_is_cgbi_png_detection() {
        let not_png = b"NOT_A_PNG_DATA";
        assert!(!is_cgbi_png(not_png));

        let standard_png = [
            0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, b'I', b'H',
            b'D', b'R',
        ];
        assert!(!is_cgbi_png(&standard_png));

        let cgbi_png = [
            0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x04, b'C', b'g',
            b'B', b'I', 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        assert!(is_cgbi_png(&cgbi_png));
    }

    #[test]
    fn test_uncrush_cgbi_png() {
        use flate2::write::DeflateEncoder;

        // Build a synthetic 1x1 CgBI PNG:
        // Width 1, Height 1, RGBA (color_type 6, bit_depth 8)
        // Scanline: 1 byte filter (0), then 4 bytes [B, G, R, A] = [255, 0, 100, 255]
        let scanline = vec![0u8, 255, 0, 100, 255];
        let mut deflater = DeflateEncoder::new(Vec::new(), Compression::default());
        deflater.write_all(&scanline).unwrap();
        let raw_deflate_idat = deflater.finish().unwrap();

        let mut cgbi_file = Vec::new();
        cgbi_file.extend_from_slice(&[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]);

        let write_chunk = |out: &mut Vec<u8>, chunk_type: &[u8; 4], data: &[u8]| {
            out.extend_from_slice(&(data.len() as u32).to_be_bytes());
            out.extend_from_slice(chunk_type);
            out.extend_from_slice(data);
            let mut hasher = crc32fast::Hasher::new();
            hasher.update(chunk_type);
            hasher.update(data);
            let crc = hasher.finalize();
            out.extend_from_slice(&crc.to_be_bytes());
        };

        // CgBI chunk
        write_chunk(&mut cgbi_file, b"CgBI", &[0, 0, 0, 0]);

        // IHDR chunk (1x1, 8-bit RGBA)
        let mut ihdr = [0u8; 13];
        ihdr[0..4].copy_from_slice(&1u32.to_be_bytes());
        ihdr[4..8].copy_from_slice(&1u32.to_be_bytes());
        ihdr[8] = 8;
        ihdr[9] = 6;
        write_chunk(&mut cgbi_file, b"IHDR", &ihdr);

        // IDAT chunk (raw deflate)
        write_chunk(&mut cgbi_file, b"IDAT", &raw_deflate_idat);

        // IEND chunk
        write_chunk(&mut cgbi_file, b"IEND", &[]);

        assert!(is_cgbi_png(&cgbi_file));

        let uncrushed = uncrush_cgbi_png(&cgbi_file).expect("uncrush must succeed");
        assert!(!is_cgbi_png(&uncrushed), "uncrushed PNG must not have CgBI");

        // Verify standard PNG structure
        assert_eq!(
            &uncrushed[0..8],
            &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]
        );
    }
}
