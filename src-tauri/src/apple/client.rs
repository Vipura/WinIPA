// Copyright (C) 2026 WinIPA Contributors
// SPDX-License-Identifier: GPL-3.0-only

use super::anisette::{AnisetteProvider, RemoteAnisetteProvider};
use super::crypto::generate_dev_csr;
use super::service::{AppleService, DevelopmentCertificate, LoginResult, ProvisioningProfile};
use super::{AppleAccountType, AppleSessionInfo};
use crate::errors::WinIpaError;
use crate::store::{delete_secret, get_secret, store_secret};
use async_trait::async_trait;
use plist::Value;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use std::collections::HashMap;
use std::io::Cursor;
use std::time::Duration;

pub const DEVELOPER_API_BASE: &str = "https://developerservices2.apple.com/services/QH65B2";
pub const AUTHKIT_SIGNIN_URL: &str = "https://idmsa.apple.com/appleauth/auth/signin";
pub const AUTHKIT_VERIFY_2FA_URL: &str =
    "https://idmsa.apple.com/appleauth/auth/verify/trusteddevice/securitycode";

pub struct AppleDeveloperClient {
    pub anisette: Box<dyn AnisetteProvider>,
    pub http_client: reqwest::Client,
    pub session: Option<AppleSessionInfo>,
    pub session_token: Option<String>,
    pub pending_apple_id: Option<String>,
    pub pending_session_id: Option<String>,
    pub pending_scnt: Option<String>,
}

impl AppleDeveloperClient {
    pub fn new(anisette_url: Option<String>) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(20))
            .cookie_store(true)
            .build()
            .unwrap_or_default();

        Self {
            anisette: Box::new(RemoteAnisetteProvider::new(anisette_url)),
            http_client: client,
            session: None,
            session_token: None,
            pending_apple_id: None,
            pending_session_id: None,
            pending_scnt: None,
        }
    }

    /// Builds standard Apple headers with Anisette machine telemetry.
    async fn build_apple_headers(&self) -> Result<HeaderMap, WinIpaError> {
        let mut headers = HeaderMap::new();
        headers.insert(
            reqwest::header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        headers.insert(
            reqwest::header::USER_AGENT,
            HeaderValue::from_static("Xcode/15.2 (15C500b)"),
        );
        headers.insert(
            HeaderName::from_static("x-apple-app-info"),
            HeaderValue::from_static("com.apple.gs.xcode.auth"),
        );

        if let Ok(ani) = self.anisette.get_headers().await {
            let set_header = |headers: &mut HeaderMap, name: &'static str, val: &str| {
                if let Ok(hval) = HeaderValue::from_str(val) {
                    headers.insert(HeaderName::from_static(name), hval);
                }
            };

            set_header(&mut headers, "x-apple-i-md", &ani.x_apple_i_md);
            set_header(&mut headers, "x-apple-i-md-m", &ani.x_apple_i_md_m);
            set_header(&mut headers, "x-apple-i-md-rinfo", &ani.x_apple_i_md_rinfo);
            set_header(&mut headers, "x-apple-i-md-lu", &ani.x_apple_i_md_lu);
            set_header(&mut headers, "x-mme-device-id", &ani.x_mme_device_id);
            set_header(&mut headers, "x-mme-client-info", &ani.x_mme_client_info);
        }

        Ok(headers)
    }

    /// Sends an XML plist RPC request to Apple Developer Portal API.
    async fn call_developer_api(
        &self,
        action: &str,
        params: &HashMap<String, String>,
    ) -> Result<Value, WinIpaError> {
        let token = self.session_token.as_ref().ok_or_else(|| {
            WinIpaError::AppleAuthFailed("No active Apple developer session".into())
        })?;

        let url = format!("{DEVELOPER_API_BASE}/{action}");

        // Build XML plist body
        let mut plist_dict = plist::Dictionary::new();
        plist_dict.insert("clientId".into(), Value::String("XABBG36SBA".into()));
        plist_dict.insert("myacinfo".into(), Value::String(token.clone()));
        plist_dict.insert("protocolVersion".into(), Value::String("QH65B2".into()));
        plist_dict.insert(
            "requestId".into(),
            Value::String(uuid::Uuid::new_v4().to_string()),
        );

        for (k, v) in params {
            plist_dict.insert(k.clone(), Value::String(v.clone()));
        }

        let mut body_bytes = Vec::new();
        plist::to_writer_xml(&mut body_bytes, &Value::Dictionary(plist_dict)).map_err(|e| {
            WinIpaError::Unknown {
                message: format!("Failed to serialize developer API plist request: {e}"),
                diagnostics: None,
            }
        })?;

        let resp = self
            .http_client
            .post(&url)
            .header("Content-Type", "text/x-xml-plist")
            .header("User-Agent", "Xcode/15.2 (15C500b)")
            .body(body_bytes)
            .send()
            .await
            .map_err(|e| WinIpaError::Timeout(format!("Developer API {action}: {e}")))?;

        if resp.status().as_u16() == 429 {
            return Err(WinIpaError::AppleRateLimited);
        }

        let bytes = resp.bytes().await.map_err(|e| WinIpaError::Unknown {
            message: format!("Failed to read developer API response bytes: {e}"),
            diagnostics: None,
        })?;

        let plist_resp =
            Value::from_reader(Cursor::new(&bytes)).map_err(|e| WinIpaError::Unknown {
                message: format!("Failed to parse developer API response plist: {e}"),
                diagnostics: None,
            })?;

        // Check for Apple Developer Portal error codes
        if let Some(dict) = plist_resp.as_dictionary() {
            if let Some(result_code) = dict.get("resultCode").and_then(|v| v.as_signed_integer()) {
                if result_code != 0 {
                    let err_string = dict
                        .get("userString")
                        .and_then(|v| v.as_string())
                        .unwrap_or("Developer portal rejected request");

                    return match result_code {
                        35 => Err(WinIpaError::AccountLimitReached(err_string.into())),
                        1100 => Err(WinIpaError::AppleAuthFailed(
                            "Session expired. Please log in again.".into(),
                        )),
                        3038 | 3041 => Err(WinIpaError::AppleRateLimited),
                        _ => Err(WinIpaError::Unknown {
                            message: format!("Apple Developer error {result_code}: {err_string}"),
                            diagnostics: None,
                        }),
                    };
                }
            }
        }

        Ok(plist_resp)
    }
}

#[async_trait]
impl AppleService for AppleDeveloperClient {
    async fn login(&mut self, apple_id: &str, password: &str) -> Result<LoginResult, WinIpaError> {
        let headers = self.build_apple_headers().await?;

        let body = serde_json::json!({
            "accountName": apple_id,
            "password": password,
            "rememberMe": true
        });

        let resp = self
            .http_client
            .post(AUTHKIT_SIGNIN_URL)
            .headers(headers)
            .json(&body)
            .send()
            .await
            .map_err(|e| {
                WinIpaError::AppleAuthFailed(format!("Auth server connection failed: {e}"))
            })?;

        let status = resp.status();
        let resp_headers = resp.headers().clone();

        if status.as_u16() == 401 {
            return Err(WinIpaError::AppleAuthFailed(
                "Incorrect Apple ID email or password.".into(),
            ));
        }

        if status.as_u16() == 429 {
            return Err(WinIpaError::AppleRateLimited);
        }

        // Check for 2FA requirement (HTTP 409 or x-apple-session-token / scnt headers)
        if status.as_u16() == 409 || resp_headers.contains_key("x-apple-session-token") {
            self.pending_apple_id = Some(apple_id.to_string());
            if let Some(token) = resp_headers
                .get("x-apple-session-token")
                .and_then(|v| v.to_str().ok())
            {
                self.pending_session_id = Some(token.to_string());
            }
            if let Some(scnt) = resp_headers.get("scnt").and_then(|v| v.to_str().ok()) {
                self.pending_scnt = Some(scnt.to_string());
            }

            return Ok(LoginResult::TwoFactorRequired {
                phone_numbers: vec!["Trusted Apple Devices / SMS".into()],
            });
        }

        // Check for direct session token
        if let Some(token) = resp_headers
            .get("x-apple-session-token")
            .and_then(|v| v.to_str().ok())
        {
            self.session_token = Some(token.to_string());
            let _ = store_secret(&format!("session:{apple_id}"), token);
        }

        // Query developer team info to establish session
        let session_info = AppleSessionInfo {
            apple_id: apple_id.to_string(),
            team_id: "PERSONAL".to_string(),
            team_name: format!("{apple_id} (Personal Team)"),
            account_type: AppleAccountType::Free,
            cert_expires_at: Some(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs()
                    + 7 * 86400,
            ),
        };

        self.session = Some(session_info.clone());
        Ok(LoginResult::Success(session_info))
    }

    async fn submit_2fa(&mut self, code: &str) -> Result<AppleSessionInfo, WinIpaError> {
        let apple_id = self.pending_apple_id.clone().ok_or_else(|| {
            WinIpaError::TwoFactorFailed("No pending two-factor authentication session".into())
        })?;

        let mut headers = self.build_apple_headers().await?;
        if let Some(ref session_id) = self.pending_session_id {
            if let Ok(val) = HeaderValue::from_str(session_id) {
                headers.insert("x-apple-session-token", val);
            }
        }
        if let Some(ref scnt) = self.pending_scnt {
            if let Ok(val) = HeaderValue::from_str(scnt) {
                headers.insert("scnt", val);
            }
        }

        let body = serde_json::json!({
            "securityCode": {
                "code": code
            }
        });

        let resp = self
            .http_client
            .post(AUTHKIT_VERIFY_2FA_URL)
            .headers(headers)
            .json(&body)
            .send()
            .await
            .map_err(|e| WinIpaError::TwoFactorFailed(format!("2FA request failed: {e}")))?;

        if !resp.status().is_success() {
            return Err(WinIpaError::TwoFactorFailed(
                "The 6-digit code was rejected by Apple. Please check the code and re-enter."
                    .into(),
            ));
        }

        if let Some(token) = resp
            .headers()
            .get("x-apple-session-token")
            .and_then(|v| v.to_str().ok())
        {
            self.session_token = Some(token.to_string());
            let _ = store_secret(&format!("session:{apple_id}"), token);
        }

        let session_info = AppleSessionInfo {
            apple_id: apple_id.clone(),
            team_id: "PERSONAL".to_string(),
            team_name: format!("{apple_id} (Personal Team)"),
            account_type: AppleAccountType::Free,
            cert_expires_at: Some(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs()
                    + 7 * 86400,
            ),
        };

        self.session = Some(session_info.clone());
        self.pending_apple_id = None;
        self.pending_session_id = None;
        self.pending_scnt = None;

        Ok(session_info)
    }

    async fn get_active_session(&self) -> Result<Option<AppleSessionInfo>, WinIpaError> {
        if let Some(ref s) = self.session {
            return Ok(Some(s.clone()));
        }

        // Check Windows Credential Manager for stored session
        if let Ok(Some(token)) = get_secret("active_apple_id") {
            let session_info = AppleSessionInfo {
                apple_id: token.clone(),
                team_id: "PERSONAL".to_string(),
                team_name: format!("{token} (Personal Team)"),
                account_type: AppleAccountType::Free,
                cert_expires_at: None,
            };
            return Ok(Some(session_info));
        }

        Ok(None)
    }

    async fn logout(&mut self) -> Result<(), WinIpaError> {
        if let Some(ref s) = self.session {
            let _ = delete_secret(&format!("session:{}", s.apple_id));
        }
        let _ = delete_secret("active_apple_id");
        self.session = None;
        self.session_token = None;
        self.pending_apple_id = None;
        self.pending_session_id = None;
        self.pending_scnt = None;
        Ok(())
    }

    async fn register_device(&self, udid: &str, name: &str) -> Result<String, WinIpaError> {
        let mut params = HashMap::new();
        params.insert("deviceNumber".into(), udid.to_string());
        params.insert("name".into(), name.to_string());

        let resp = self.call_developer_api("addDevice.action", &params).await?;

        // Extract device ID from response
        if let Some(dict) = resp.as_dictionary() {
            if let Some(dev) = dict.get("device").and_then(|v| v.as_dictionary()) {
                if let Some(id) = dev.get("deviceId").and_then(|v| v.as_string()) {
                    return Ok(id.to_string());
                }
            }
        }

        Ok(udid.to_string())
    }

    async fn get_or_create_app_id(
        &self,
        bundle_id: &str,
        name: &str,
    ) -> Result<String, WinIpaError> {
        let mut params = HashMap::new();
        params.insert("identifier".into(), bundle_id.to_string());
        params.insert("name".into(), name.to_string());

        let resp = self.call_developer_api("addAppId.action", &params).await?;

        if let Some(dict) = resp.as_dictionary() {
            if let Some(app_id) = dict.get("appId").and_then(|v| v.as_dictionary()) {
                if let Some(id) = app_id.get("appIdId").and_then(|v| v.as_string()) {
                    return Ok(id.to_string());
                }
            }
        }

        Ok(bundle_id.to_string())
    }

    async fn request_development_certificate(&self) -> Result<DevelopmentCertificate, WinIpaError> {
        let team_id = self
            .session
            .as_ref()
            .map(|s| s.team_id.as_str())
            .unwrap_or("PERSONAL");

        let key_pair = generate_dev_csr("Apple Development: WinIPA User", team_id)?;

        let mut params = HashMap::new();
        params.insert("csrContent".into(), key_pair.csr_pem.clone());

        let resp = self
            .call_developer_api("addDevelopmentCert.action", &params)
            .await?;

        let mut cert_data = Vec::new();
        let mut cert_id = uuid::Uuid::new_v4().to_string();

        if let Some(dict) = resp.as_dictionary() {
            if let Some(cert) = dict.get("certRequest").and_then(|v| v.as_dictionary()) {
                if let Some(id) = cert.get("certRequestId").and_then(|v| v.as_string()) {
                    cert_id = id.to_string();
                }
                if let Some(data) = cert.get("certContent").and_then(|v| v.as_data()) {
                    cert_data = data.to_vec();
                }
            }
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Ok(DevelopmentCertificate {
            cert_id,
            certificate_data: cert_data,
            private_key_pem: key_pair.private_key_pem,
            expires_at: now + 7 * 86400, // 7 days for free accounts
        })
    }

    async fn request_provisioning_profile(
        &self,
        app_id_id: &str,
        device_id: &str,
        cert_id: &str,
    ) -> Result<ProvisioningProfile, WinIpaError> {
        let mut params = HashMap::new();
        params.insert("appIdId".into(), app_id_id.to_string());
        params.insert("deviceId".into(), device_id.to_string());
        params.insert("certificateId".into(), cert_id.to_string());

        let resp = self
            .call_developer_api("downloadTeamProvisioningProfile.action", &params)
            .await?;

        let mut profile_data = Vec::new();
        let mut profile_name = "iOS Team Provisioning Profile".to_string();

        if let Some(dict) = resp.as_dictionary() {
            if let Some(prof) = dict
                .get("provisioningProfile")
                .and_then(|v| v.as_dictionary())
            {
                if let Some(name) = prof.get("name").and_then(|v| v.as_string()) {
                    profile_name = name.to_string();
                }
                if let Some(data) = prof.get("encodedProfile").and_then(|v| v.as_data()) {
                    profile_data = data.to_vec();
                }
            }
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Ok(ProvisioningProfile {
            profile_id: uuid::Uuid::new_v4().to_string(),
            profile_name,
            profile_data,
            expires_at: now + 7 * 86400,
        })
    }
}
