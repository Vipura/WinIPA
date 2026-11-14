// Copyright (C) 2026 WinIPA Contributors
// SPDX-License-Identifier: GPL-3.0-only

use crate::errors::WinIpaError;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AnisetteHeaders {
    #[serde(rename = "X-Apple-I-MD", alias = "x-apple-i-md")]
    pub x_apple_i_md: String,

    #[serde(rename = "X-Apple-I-MD-M", alias = "x-apple-i-md-m")]
    pub x_apple_i_md_m: String,

    #[serde(rename = "X-Apple-I-MD-RINFO", alias = "x-apple-i-md-rinfo")]
    pub x_apple_i_md_rinfo: String,

    #[serde(rename = "X-Apple-I-MD-LU", alias = "x-apple-i-md-lu")]
    pub x_apple_i_md_lu: String,

    #[serde(
        rename = "X-Mme-Device-Id",
        alias = "X-MMe-Device-Id",
        alias = "x-mme-device-id"
    )]
    pub x_mme_device_id: String,

    #[serde(
        rename = "X-Mme-Client-Info",
        alias = "X-MMe-Client-Info",
        alias = "x-mme-client-info"
    )]
    pub x_mme_client_info: String,

    #[serde(
        rename = "X-Apple-I-Client-Time",
        alias = "x-apple-i-client-time",
        default
    )]
    pub x_apple_i_client_time: Option<String>,

    #[serde(
        rename = "X-Apple-I-TimeZone",
        alias = "X-Apple-I-Time-Zone",
        alias = "x-apple-i-time-zone",
        default
    )]
    pub x_apple_i_time_zone: Option<String>,

    #[serde(rename = "X-Apple-Locale", alias = "x-apple-locale", default)]
    pub x_apple_locale: Option<String>,

    #[serde(rename = "X-Apple-I-SRL-NO", alias = "x-apple-i-srl-no", default)]
    pub x_apple_i_srl_no: Option<String>,
}

#[async_trait]
pub trait AnisetteProvider: Send + Sync {
    async fn get_headers(&self) -> Result<AnisetteHeaders, WinIpaError>;
}

/// Helper to generate current UTC ISO 8601 timestamp string without external dependencies
pub fn current_utc_iso8601() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let sec = secs % 60;
    let mins = secs / 60;
    let min = mins % 60;
    let hours = mins / 60;
    let hour = hours % 24;
    let days = (hours / 24) as i64;

    // Civil day from days since 1970-01-01
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let final_y = if m <= 2 { y + 1 } else { y };

    format!("{final_y:04}-{m:02}-{d:02}T{hour:02}:{min:02}:{sec:02}Z")
}

/// Remote Anisette provider communicating with Anisette v3 servers with automatic fallback.
pub struct RemoteAnisetteProvider {
    pub server_urls: Vec<String>,
    pub client: reqwest::Client,
}

impl RemoteAnisetteProvider {
    pub fn new(server_url: Option<String>) -> Self {
        let mut urls = Vec::new();
        if let Some(url) = server_url {
            let trimmed = url.trim();
            if !trimmed.is_empty() {
                urls.push(trimmed.to_string());
            }
        }

        // Known high-uptime public Anisette v3 endpoints
        let defaults = [
            "https://ani.sidestore.io",
            "https://anisette.apsteam.org",
            "https://ani.f1sh.me",
        ];
        for d in defaults {
            if !urls.contains(&d.to_string()) {
                urls.push(d.to_string());
            }
        }

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(6))
            .build()
            .unwrap_or_default();

        Self {
            server_urls: urls,
            client,
        }
    }
}

#[async_trait]
impl AnisetteProvider for RemoteAnisetteProvider {
    async fn get_headers(&self) -> Result<AnisetteHeaders, WinIpaError> {
        let mut last_err = String::new();

        for url in &self.server_urls {
            match self.client.get(url).send().await {
                Ok(resp) => {
                    let status = resp.status();
                    if status.is_success() {
                        match resp.json::<AnisetteHeaders>().await {
                            Ok(mut headers) => {
                                if headers.x_apple_i_client_time.is_none() {
                                    headers.x_apple_i_client_time = Some(current_utc_iso8601());
                                }
                                if headers.x_apple_i_time_zone.is_none() {
                                    headers.x_apple_i_time_zone = Some("UTC".to_string());
                                }
                                if headers.x_apple_locale.is_none() {
                                    headers.x_apple_locale = Some("en_US".to_string());
                                }
                                return Ok(headers);
                            }
                            Err(e) => {
                                last_err =
                                    format!("Failed to parse Anisette response from {url}: {e}");
                            }
                        }
                    } else {
                        last_err = format!("Anisette server {url} returned HTTP {status}");
                    }
                }
                Err(e) => {
                    last_err = format!("Failed to reach Anisette server {url}: {e}");
                }
            }
        }

        Err(WinIpaError::AppleAuthFailed(format!(
            "Unable to generate device verification tokens (Anisette). {last_err}. Please check your internet connection or firewall."
        )))
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
            x_apple_i_client_time: Some("2026-11-14T20:34:14Z".into()),
            x_apple_i_time_zone: Some("UTC".into()),
            x_apple_locale: Some("en_US".into()),
            x_apple_i_srl_no: Some("0".into()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deserialize_sidestore_response() {
        let json_data = r#"{"X-Apple-I-Client-Time":"2026-11-14T20:34:14Z","X-Apple-I-MD":"AAAABQAAABCCDUgsTehgKhR76QTx6o9FAAAABA==","X-Apple-I-MD-LU":"B40967D2ABC88B0F71BE0BC81C7BA6F0DAAA9106F737FD9AC298E7C8D217F4EF","X-Apple-I-MD-M":"MDBqxEcq3BbgwOVmPthvJ0lUcA8LyjEBAgMO5QXUNfGS/TfXU3opMcvc4zvhdhSjI3gEE1h3TaRhmZqD","X-Apple-I-MD-RINFO":"17106176","X-Apple-I-SRL-NO":"0","X-Apple-I-TimeZone":"UTC","X-Apple-Locale":"en_US","X-MMe-Client-Info":"<MacBookPro13,2> <macOS;13.1;22C65> <com.apple.AuthKit/1 (com.apple.akd/1.0)>","X-Mme-Device-Id":"0FC27F94-48B8-4917-A43F-AD3336AE849B"}"#;
        let headers: AnisetteHeaders =
            serde_json::from_str(json_data).expect("Must deserialize SideStore Anisette response");

        assert_eq!(headers.x_apple_i_md_rinfo, "17106176");
        assert_eq!(
            headers.x_mme_client_info,
            "<MacBookPro13,2> <macOS;13.1;22C65> <com.apple.AuthKit/1 (com.apple.akd/1.0)>"
        );
        assert_eq!(
            headers.x_mme_device_id,
            "0FC27F94-48B8-4917-A43F-AD3336AE849B"
        );
        assert_eq!(
            headers.x_apple_i_client_time.as_deref(),
            Some("2026-11-14T20:34:14Z")
        );
    }

    #[test]
    fn test_current_utc_iso8601() {
        let ts = current_utc_iso8601();
        assert!(ts.ends_with('Z'));
        assert_eq!(ts.len(), 20);
        assert_eq!(&ts[10..11], "T");
    }
}
