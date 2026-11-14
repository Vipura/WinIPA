// Copyright (C) 2026 WinIPA Contributors
// SPDX-License-Identifier: GPL-3.0-only

use crate::errors::WinIpaError;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AnisetteHeaders {
    #[serde(rename = "X-Apple-I-MD")]
    pub x_apple_i_md: String,

    #[serde(rename = "X-Apple-I-MD-M")]
    pub x_apple_i_md_m: String,

    #[serde(rename = "X-Apple-I-MD-RINFO")]
    pub x_apple_i_md_rinfo: String,

    #[serde(rename = "X-Apple-I-MD-LU")]
    pub x_apple_i_md_lu: String,

    #[serde(rename = "X-Mme-Device-Id")]
    pub x_mme_device_id: String,

    #[serde(rename = "X-Mme-Client-Info")]
    pub x_mme_client_info: String,
}

#[async_trait]
pub trait AnisetteProvider: Send + Sync {
    async fn get_headers(&self) -> Result<AnisetteHeaders, WinIpaError>;
}

/// Remote Anisette provider communicating with an Anisette v3 server (e.g. SideStore server or custom).
pub struct RemoteAnisetteProvider {
    pub server_url: String,
    pub client: reqwest::Client,
}

impl RemoteAnisetteProvider {
    pub fn new(server_url: Option<String>) -> Self {
        let url = server_url.unwrap_or_else(|| "https://ani.sidestore.io".to_string());
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap_or_default();
        Self {
            server_url: url,
            client,
        }
    }
}

#[async_trait]
impl AnisetteProvider for RemoteAnisetteProvider {
    async fn get_headers(&self) -> Result<AnisetteHeaders, WinIpaError> {
        let resp = self
            .client
            .get(&self.server_url)
            .send()
            .await
            .map_err(|e| {
                WinIpaError::AppleAuthFailed(format!("Anisette server unreachable: {e}"))
            })?;

        if !resp.status().is_success() {
            return Err(WinIpaError::AppleAuthFailed(format!(
                "Anisette server returned HTTP {}",
                resp.status()
            )));
        }

        let headers: AnisetteHeaders = resp.json().await.map_err(|e| {
            WinIpaError::AppleAuthFailed(format!("Failed to parse Anisette response: {e}"))
        })?;

        Ok(headers)
    }
}

/// Mock Anisette provider for tests and offline scenarios.
pub struct MockAnisetteProvider;

#[async_trait]
impl AnisetteProvider for MockAnisetteProvider {
    async fn get_headers(&self) -> Result<AnisetteHeaders, WinIpaError> {
        Ok(AnisetteHeaders {
            x_apple_i_md: "MOCK_MD_DATA".into(),
            x_apple_i_md_m: "MOCK_MD_M_DATA".into(),
            x_apple_i_md_rinfo: "17106176".into(),
            x_apple_i_md_lu: "MOCK_LU".into(),
            x_mme_device_id: "MOCK_DEVICE_ID".into(),
            x_mme_client_info: "<WinIPA> <Windows NT 10.0>".into(),
        })
    }
}
