// Copyright (C) 2026 WinIPA Contributors
// SPDX-License-Identifier: GPL-3.0-only

use crate::errors::WinIpaError;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub const AFC_MAGIC: u64 = 0x41364c3441364643; // "CFA6L4A6" in little-endian
pub const AFC_HEADER_SIZE: usize = 40;

pub const AFC_OP_STATUS: u64 = 1;
pub const AFC_OP_DATA: u64 = 2;
pub const AFC_OP_FILE_REF_OPEN: u64 = 8;
pub const AFC_OP_FILE_REF_OPEN_RES: u64 = 9;
pub const AFC_OP_FILE_REF_WRITE: u64 = 11;
pub const AFC_OP_FILE_REF_CLOSE: u64 = 13;
pub const AFC_OP_FILE_REMOVE: u64 = 15;

pub const AFC_MODE_WRONLY: u64 = 2;
pub const AFC_MODE_RDWR: u64 = 3;

#[derive(Debug, Clone)]
pub struct AfcHeader {
    pub magic: u64,
    pub entire_len: u64,
    pub this_len: u64,
    pub packet_num: u64,
    pub operation: u64,
}

impl AfcHeader {
    pub fn new(operation: u64, payload_len: usize, packet_num: u64) -> Self {
        Self {
            magic: AFC_MAGIC,
            entire_len: (AFC_HEADER_SIZE + payload_len) as u64,
            this_len: AFC_HEADER_SIZE as u64,
            packet_num,
            operation,
        }
    }

    pub fn to_bytes(&self) -> [u8; AFC_HEADER_SIZE] {
        let mut buf = [0u8; AFC_HEADER_SIZE];
        buf[0..8].copy_from_slice(&self.magic.to_le_bytes());
        buf[8..16].copy_from_slice(&self.entire_len.to_le_bytes());
        buf[16..24].copy_from_slice(&self.this_len.to_le_bytes());
        buf[24..32].copy_from_slice(&self.packet_num.to_le_bytes());
        buf[32..40].copy_from_slice(&self.operation.to_le_bytes());
        buf
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < AFC_HEADER_SIZE {
            return None;
        }
        let magic = u64::from_le_bytes(bytes[0..8].try_into().ok()?);
        if magic != AFC_MAGIC {
            return None;
        }
        let entire_len = u64::from_le_bytes(bytes[8..16].try_into().ok()?);
        let this_len = u64::from_le_bytes(bytes[16..24].try_into().ok()?);
        let packet_num = u64::from_le_bytes(bytes[24..32].try_into().ok()?);
        let operation = u64::from_le_bytes(bytes[32..40].try_into().ok()?);

        Some(Self {
            magic,
            entire_len,
            this_len,
            packet_num,
            operation,
        })
    }
}

pub async fn send_afc_packet(
    stream: &mut TcpStream,
    header: &AfcHeader,
    payload: &[u8],
) -> Result<(), WinIpaError> {
    stream
        .write_all(&header.to_bytes())
        .await
        .map_err(|e| WinIpaError::InstallFailed(format!("Failed to write AFC header: {e}")))?;

    if !payload.is_empty() {
        stream
            .write_all(payload)
            .await
            .map_err(|e| WinIpaError::InstallFailed(format!("Failed to write AFC payload: {e}")))?;
    }

    stream
        .flush()
        .await
        .map_err(|e| WinIpaError::InstallFailed(format!("Failed to flush AFC stream: {e}")))?;

    Ok(())
}

pub async fn read_afc_packet(stream: &mut TcpStream) -> Result<(AfcHeader, Vec<u8>), WinIpaError> {
    let mut header_bytes = [0u8; AFC_HEADER_SIZE];
    stream
        .read_exact(&mut header_bytes)
        .await
        .map_err(|e| WinIpaError::InstallFailed(format!("Failed to read AFC header: {e}")))?;

    let header = AfcHeader::from_bytes(&header_bytes)
        .ok_or_else(|| WinIpaError::InstallFailed("Invalid AFC packet magic header".into()))?;

    let payload_len = (header.entire_len - header.this_len) as usize;
    let mut payload = vec![0u8; payload_len];
    if payload_len > 0 {
        stream
            .read_exact(&mut payload)
            .await
            .map_err(|e| WinIpaError::InstallFailed(format!("Failed to read AFC payload: {e}")))?;
    }

    Ok((header, payload))
}

/// Opens a remote file on the iOS device via AFC and returns the file handle.
pub async fn afc_file_open(
    stream: &mut TcpStream,
    path: &str,
    mode: u64,
) -> Result<u64, WinIpaError> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&mode.to_le_bytes());
    payload.extend_from_slice(path.as_bytes());
    payload.push(0); // Null terminator

    let header = AfcHeader::new(AFC_OP_FILE_REF_OPEN, payload.len(), 1);
    send_afc_packet(stream, &header, &payload).await?;

    let (resp_header, resp_payload) = read_afc_packet(stream).await?;
    if resp_header.operation == AFC_OP_FILE_REF_OPEN_RES && resp_payload.len() >= 8 {
        let handle = u64::from_le_bytes(resp_payload[0..8].try_into().unwrap());
        Ok(handle)
    } else {
        Err(WinIpaError::InstallFailed(format!(
            "AFC file open failed for {path} (op: {})",
            resp_header.operation
        )))
    }
}

/// Writes data to an open AFC file handle.
pub async fn afc_file_write(
    stream: &mut TcpStream,
    handle: u64,
    data: &[u8],
) -> Result<(), WinIpaError> {
    let mut payload = Vec::with_capacity(8 + data.len());
    payload.extend_from_slice(&handle.to_le_bytes());
    payload.extend_from_slice(data);

    let header = AfcHeader::new(AFC_OP_FILE_REF_WRITE, payload.len(), 1);
    send_afc_packet(stream, &header, &payload).await?;

    let (resp_header, _resp_payload) = read_afc_packet(stream).await?;
    if resp_header.operation != AFC_OP_STATUS {
        return Err(WinIpaError::InstallFailed(format!(
            "AFC file write failed (op: {})",
            resp_header.operation
        )));
    }

    Ok(())
}

/// Closes an open AFC file handle.
pub async fn afc_file_close(stream: &mut TcpStream, handle: u64) -> Result<(), WinIpaError> {
    let payload = handle.to_le_bytes().to_vec();
    let header = AfcHeader::new(AFC_OP_FILE_REF_CLOSE, payload.len(), 1);
    send_afc_packet(stream, &header, &payload).await?;

    let (resp_header, _resp_payload) = read_afc_packet(stream).await?;
    if resp_header.operation != AFC_OP_STATUS {
        return Err(WinIpaError::InstallFailed(format!(
            "AFC file close failed (op: {})",
            resp_header.operation
        )));
    }

    Ok(())
}

/// Removes a remote file via AFC.
pub async fn afc_remove_file(stream: &mut TcpStream, path: &str) -> Result<(), WinIpaError> {
    let mut payload = path.as_bytes().to_vec();
    payload.push(0); // Null terminator

    let header = AfcHeader::new(AFC_OP_FILE_REMOVE, payload.len(), 1);
    send_afc_packet(stream, &header, &payload).await?;

    let (resp_header, _resp_payload) = read_afc_packet(stream).await?;
    if resp_header.operation != AFC_OP_STATUS {
        return Err(WinIpaError::InstallFailed(format!(
            "AFC remove file failed for {path} (op: {})",
            resp_header.operation
        )));
    }

    Ok(())
}

/// Uploads a local IPA file to a remote path on the iOS device via AFC with progress streaming.
pub async fn upload_file_afc<F>(
    stream: &mut TcpStream,
    local_path: &Path,
    remote_path: &str,
    progress_callback: F,
    cancel_token: Arc<AtomicBool>,
) -> Result<(), WinIpaError>
where
    F: Fn(f32, &str),
{
    let mut file = File::open(local_path)
        .await
        .map_err(|e| WinIpaError::InstallFailed(format!("Failed to open local IPA: {e}")))?;

    let total_size = file
        .metadata()
        .await
        .map_err(|e| WinIpaError::InstallFailed(format!("Failed to read IPA metadata: {e}")))?
        .len();

    let handle = afc_file_open(stream, remote_path, AFC_MODE_WRONLY).await?;

    let mut buf = vec![0u8; 64 * 1024]; // 64KB chunks
    let mut transferred = 0u64;

    loop {
        if cancel_token.load(Ordering::Relaxed) {
            let _ = afc_file_close(stream, handle).await;
            let _ = afc_remove_file(stream, remote_path).await;
            return Err(WinIpaError::Unknown {
                message: "Installation cancelled by user".into(),
                diagnostics: None,
            });
        }

        let n = file
            .read(&mut buf)
            .await
            .map_err(|e| WinIpaError::InstallFailed(format!("Failed to read IPA chunk: {e}")))?;

        if n == 0 {
            break;
        }

        afc_file_write(stream, handle, &buf[..n]).await?;
        transferred += n as u64;

        if total_size > 0 {
            let frac = (transferred as f32 / total_size as f32).min(1.0);
            // Staging upload accounts for 0% to 50% of total installation progress
            let scaled_percent = frac * 50.0;
            let msg = format!(
                "Uploading package over USB: {:.1} MB / {:.1} MB ({:.0}%)",
                transferred as f32 / (1024.0 * 1024.0),
                total_size as f32 / (1024.0 * 1024.0),
                frac * 100.0
            );
            progress_callback(scaled_percent, &msg);
        }
    }

    afc_file_close(stream, handle).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_afc_header_serialization() {
        let header = AfcHeader::new(AFC_OP_FILE_REF_OPEN, 128, 42);
        let bytes = header.to_bytes();
        let parsed = AfcHeader::from_bytes(&bytes).expect("Should parse AFC header");

        assert_eq!(parsed.magic, AFC_MAGIC);
        assert_eq!(parsed.operation, AFC_OP_FILE_REF_OPEN);
        assert_eq!(parsed.this_len, 40);
        assert_eq!(parsed.entire_len, 40 + 128);
        assert_eq!(parsed.packet_num, 42);
    }
}
