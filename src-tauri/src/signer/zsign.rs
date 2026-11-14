// Copyright (C) 2026 WinIPA Contributors
// SPDX-License-Identifier: GPL-3.0-only

use crate::errors::WinIpaError;
use crate::store::redaction::redact_sensitive_info;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::process::Command;
use tokio::time::timeout;

/// Locates the `zsign.exe` binary across supported paths.
pub fn find_zsign_binary() -> Result<PathBuf, WinIpaError> {
    // 1. Check relative to current working directory (dev mode)
    let dev_paths = [
        PathBuf::from("src-tauri/bin/zsign-x86_64-pc-windows-msvc.exe"),
        PathBuf::from("src-tauri/bin/zsign.exe"),
        PathBuf::from("bin/zsign.exe"),
    ];

    for p in &dev_paths {
        if p.exists() {
            if let Ok(abs) = p.canonicalize() {
                return Ok(abs);
            }
            return Ok(p.clone());
        }
    }

    // 2. Check next to running executable (installed mode)
    if let Ok(current_exe) = std::env::current_exe() {
        if let Some(exe_dir) = current_exe.parent() {
            let candidate1 = exe_dir.join("zsign.exe");
            if candidate1.exists() {
                return Ok(candidate1);
            }
            let candidate2 = exe_dir.join("bin").join("zsign.exe");
            if candidate2.exists() {
                return Ok(candidate2);
            }
            let candidate3 = exe_dir.join("bin").join("zsign-x86_64-pc-windows-msvc.exe");
            if candidate3.exists() {
                return Ok(candidate3);
            }
            let candidate4 = exe_dir.join("resources").join("bin").join("zsign.exe");
            if candidate4.exists() {
                return Ok(candidate4);
            }
            let candidate5 = exe_dir.join("resources").join("zsign.exe");
            if candidate5.exists() {
                return Ok(candidate5);
            }
        }
    }

    // 3. Check %APPDATA%\WinIPA\bin\zsign.exe
    if let Ok(appdata) = std::env::var("APPDATA") {
        let appdata_bin = PathBuf::from(appdata)
            .join("WinIPA")
            .join("bin")
            .join("zsign.exe");
        if appdata_bin.exists() {
            return Ok(appdata_bin);
        }
    }

    // 4. Check system PATH
    if let Ok(path_var) = std::env::var("PATH") {
        for dir in std::env::split_paths(&path_var) {
            let candidate = dir.join("zsign.exe");
            if candidate.exists() {
                return Ok(candidate);
            }
        }
    }

    Err(WinIpaError::SigningFailed(
        "Could not find 'zsign.exe' signing tool. Please ensure zsign is placed in WinIPA's bin folder."
            .into(),
    ))
}

pub struct ZsignInvocation<'a> {
    pub input_ipa: &'a Path,
    pub output_ipa: &'a Path,
    pub cert_path: &'a Path,
    pub key_path: &'a Path,
    pub prov_path: &'a Path,
    pub entitlements_path: Option<&'a Path>,
    pub new_bundle_id: Option<&'a str>,
    pub temp_dir: &'a Path,
}

/// Executes zsign to re-sign an IPA file.
pub async fn run_zsign(invocation: ZsignInvocation<'_>) -> Result<(), WinIpaError> {
    let zsign_bin = find_zsign_binary()?;

    let mut cmd = Command::new(&zsign_bin);
    cmd.arg("-c").arg(invocation.cert_path);
    cmd.arg("-k").arg(invocation.key_path);
    cmd.arg("-m").arg(invocation.prov_path);
    cmd.arg("-o").arg(invocation.output_ipa);
    cmd.arg("-t").arg(invocation.temp_dir);

    if let Some(ent_path) = invocation.entitlements_path {
        cmd.arg("-e").arg(ent_path);
    }

    if let Some(bundle_id) = invocation.new_bundle_id {
        cmd.arg("-b").arg(bundle_id);
    }

    // Input IPA is the last argument
    cmd.arg(invocation.input_ipa);

    // Timeout after 180 seconds to prevent hangs on huge IPA archives
    let execution = timeout(Duration::from_secs(180), cmd.output());

    let output = execution
        .await
        .map_err(|_| {
            WinIpaError::Timeout("Code signing process timed out after 180 seconds.".into())
        })?
        .map_err(|e| WinIpaError::SigningFailed(format!("Failed to spawn zsign process: {e}")))?;

    let stdout_str = String::from_utf8_lossy(&output.stdout);
    let stderr_str = String::from_utf8_lossy(&output.stderr);
    let combined_log = format!("{stdout_str}\n{stderr_str}");
    let redacted_output = redact_sensitive_info(&combined_log);

    if !output.status.success() {
        return Err(WinIpaError::SigningFailed(format!(
            "zsign failed with exit code {:?}: {}",
            output.status.code(),
            redacted_output.trim()
        )));
    }

    if !invocation.output_ipa.exists() {
        return Err(WinIpaError::SigningFailed(
            "zsign completed but output IPA was not created.".into(),
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_zsign_binary_finds_local_copy() {
        // Our project has zsign.exe in src-tauri/bin/
        let bin = find_zsign_binary();
        assert!(
            bin.is_ok(),
            "find_zsign_binary should find the placed binary: {:?}",
            bin
        );
    }
}
