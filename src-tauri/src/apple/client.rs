// Copyright (C) 2026 WinIPA Contributors
// SPDX-License-Identifier: GPL-3.0-only

use super::anisette::{AnisetteProvider, RemoteAnisetteProvider};
use super::crypto::generate_dev_csr;
use super::service::{AppleService, DevelopmentCertificate, LoginResult, ProvisioningProfile};
use super::srp::AppleSrpClient;
use super::{AppleAccountType, AppleSessionInfo};
use crate::errors::WinIpaError;
use crate::store::{delete_secret, get_secret, store_secret};
use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use plist::Value;
use reqwest::cookie::{CookieStore, Jar};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use serde::Deserialize;
use std::collections::HashMap;
use std::io::Cursor;
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub const DEVELOPER_API_BASE: &str = "https://developerservices2.apple.com/services/QH65B2";
pub const AUTHKIT_SIGNIN_URL: &str = "https://idmsa.apple.com/appleauth/auth/signin";
pub const AUTHKIT_INIT_URL: &str = "https://idmsa.apple.com/appleauth/auth/signin/init";
pub const AUTHKIT_COMPLETE_URL: &str =
    "https://idmsa.apple.com/appleauth/auth/signin/complete?isRememberMeEnabled=false";
pub const AUTHKIT_VERIFY_2FA_URL: &str =
    "https://idmsa.apple.com/appleauth/auth/verify/trusteddevice/securitycode";
pub const DEFAULT_WIDGET_KEY: &str =
    "e0b80c3bf78523bfe80974d320935bfa30add02e1bff88ec2166c6bd5a706c42";

#[derive(Debug, Deserialize)]
struct SrpInitResponse {
    iteration: u32,
    salt: String,
    protocol: String,
    b: String,
    c: String,
}

#[derive(Debug, Deserialize)]
struct AppleServiceError {
    #[serde(default)]
    message: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AppleAuthErrorResponse {
    #[serde(rename = "serviceErrors")]
    service_errors: Option<Vec<AppleServiceError>>,
}

pub struct AppleDeveloperClient {
    pub anisette: Box<dyn AnisetteProvider>,
    pub http_client: reqwest::Client,
    pub cookie_jar: Arc<Jar>,
    pub session: Mutex<Option<AppleSessionInfo>>,
    pub session_token: Mutex<Option<String>>,
    pub session_token_header: Mutex<Option<String>>,
    pub pending_apple_id: Option<String>,
    pub pending_password: Option<String>,
    pub pending_session_id: Option<String>,
    pub pending_scnt: Option<String>,
    pub pending_widget_key: Option<String>,
    pub pending_apple_id_session_id: Option<String>,
}

/// Helper function to extract a `myacinfo` cookie from Set-Cookie headers.
fn extract_myacinfo_from_headers(headers: &HeaderMap) -> Option<String> {
    for cookie in headers.get_all(reqwest::header::SET_COOKIE) {
        if let Ok(c_str) = cookie.to_str() {
            for part in c_str.split(';') {
                let part = part.trim();
                if let Some(val) = part.strip_prefix("myacinfo=") {
                    let trimmed = val.trim();
                    if !trimmed.is_empty() {
                        return Some(trimmed.to_string());
                    }
                }
            }
        }
    }
    None
}

/// Helper function to extract an Apple session token / myacinfo cookie
fn extract_apple_session_token(headers: &HeaderMap, fallback: Option<&str>) -> Option<String> {
    // 1. Highest priority: myacinfo cookie from Set-Cookie
    if let Some(myac) = extract_myacinfo_from_headers(headers) {
        return Some(myac);
    }

    // 2. Direct x-apple-session-token header
    if let Some(t) = headers
        .get("x-apple-session-token")
        .and_then(|v| v.to_str().ok())
    {
        let trimmed = t.trim();
        if !trimmed.is_empty() {
            return Some(trimmed.to_string());
        }
    }

    // 3. Fallback to pending session id (from initial 409 response)
    fallback.map(|s| s.to_string())
}

/// Helper function to parse Apple AuthKit error responses into clean messages.
fn extract_apple_error_message(status: reqwest::StatusCode, body: &str) -> String {
    if let Ok(err_json) = serde_json::from_str::<AppleAuthErrorResponse>(body) {
        if let Some(errs) = err_json.service_errors {
            if let Some(first_msg) = errs.into_iter().find_map(|e| e.message) {
                if !first_msg.trim().is_empty() {
                    return first_msg;
                }
            }
        }
    }
    if status.as_u16() == 401 || status.as_u16() == 403 {
        return "Incorrect Apple ID email or password.".into();
    }
    if status.as_u16() == 503 {
        return "Apple authentication servers are temporarily unavailable or rate-limiting requests. Please wait a few moments and try again.".into();
    }
    if body.contains("<html") || body.contains("<HTML") {
        return format!(
            "Apple sign-in failed (HTTP {}). Please check your internet connection or try again later.",
            status.as_u16()
        );
    }
    if !body.is_empty() {
        return format!("Apple sign-in failed (HTTP {}): {}", status.as_u16(), body);
    }
    format!(
        "Apple sign-in failed (HTTP {}). Please check your credentials or network connection.",
        status.as_u16()
    )
}

impl AppleDeveloperClient {
    pub fn new(anisette_url: Option<String>) -> Self {
        let cookie_jar = Arc::new(Jar::default());
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(20))
            .cookie_provider(cookie_jar.clone())
            .build()
            .unwrap_or_default();

        Self {
            anisette: Box::new(RemoteAnisetteProvider::new(anisette_url)),
            http_client: client,
            cookie_jar,
            session: Mutex::new(None),
            session_token: Mutex::new(None),
            session_token_header: Mutex::new(None),
            pending_apple_id: None,
            pending_password: None,
            pending_session_id: None,
            pending_scnt: None,
            pending_widget_key: None,
            pending_apple_id_session_id: None,
        }
    }

    /// Discovers dynamic widgetKey from App Store Connect or falls back to standard key.
    pub async fn resolve_widget_key(&self) -> String {
        if let Ok(resp) = self
            .http_client
            .head("https://appstoreconnect.apple.com/logout")
            .send()
            .await
        {
            if let Some(loc) = resp.headers().get(reqwest::header::LOCATION) {
                if let Ok(loc_str) = loc.to_str() {
                    if let Some(idx) = loc_str.find("widgetKey=") {
                        let sub = &loc_str[idx + "widgetKey=".len()..];
                        let key = sub.split('&').next().unwrap_or("");
                        if !key.is_empty() {
                            return key.to_string();
                        }
                    }
                }
            }
        }
        DEFAULT_WIDGET_KEY.to_string()
    }

    /// Extracts `myacinfo` cookie from the client's cookie jar.
    fn extract_myacinfo_from_jar(&self) -> Option<String> {
        let urls = [
            reqwest::Url::parse("https://idmsa.apple.com/").ok(),
            reqwest::Url::parse("https://apple.com/").ok(),
            reqwest::Url::parse("https://developerservices2.apple.com/").ok(),
            reqwest::Url::parse("https://appstoreconnect.apple.com/").ok(),
        ];
        for u in urls.into_iter().flatten() {
            if let Some(cookie_hdr) = self.cookie_jar.cookies(&u) {
                if let Ok(c_str) = cookie_hdr.to_str() {
                    for part in c_str.split(';') {
                        let part = part.trim();
                        if let Some(val) = part.strip_prefix("myacinfo=") {
                            let trimmed = val.trim();
                            if !trimmed.is_empty() {
                                return Some(trimmed.to_string());
                            }
                        }
                    }
                }
            }
        }
        None
    }

    /// Retrieves the active session token (myacinfo) from memory, cookie jar, or persistent vault.
    fn get_or_restore_session_token(&self) -> Option<String> {
        // 1. In-memory session_token
        if let Ok(guard) = self.session_token.lock() {
            if let Some(ref t) = *guard {
                let trimmed = t.trim();
                if !trimmed.is_empty() {
                    return Some(trimmed.to_string());
                }
            }
        }

        // 2. Cookie jar
        if let Some(token) = self.extract_myacinfo_from_jar() {
            if let Ok(mut guard) = self.session_token.lock() {
                *guard = Some(token.clone());
            }
            return Some(token);
        }

        // 3. Persistent vault
        if let Ok(Some(apple_id)) = get_secret("active_apple_id") {
            if let Ok(Some(token)) = get_secret(&format!("session:{apple_id}")) {
                let trimmed = token.trim();
                if !trimmed.is_empty() {
                    if let Ok(mut guard) = self.session_token.lock() {
                        *guard = Some(trimmed.to_string());
                    }
                    return Some(trimmed.to_string());
                }
            }
            if let Ok(Some(st)) = get_secret(&format!("token_header:{apple_id}")) {
                let trimmed = st.trim();
                if !trimmed.is_empty() {
                    if let Ok(mut guard) = self.session_token.lock() {
                        *guard = Some(trimmed.to_string());
                    }
                    return Some(trimmed.to_string());
                }
            }
        }

        // 4. Pending session ID fallback
        if let Some(ref pending) = self.pending_session_id {
            let trimmed = pending.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }

        None
    }

    /// Retrieves current team ID if available.
    fn get_current_team_id(&self) -> String {
        if let Ok(guard) = self.session.lock() {
            if let Some(ref s) = *guard {
                return s.team_id.clone();
            }
        }
        if let Ok(Some(apple_id)) = get_secret("active_apple_id") {
            if let Ok(Some(info_json)) = get_secret(&format!("info:{apple_id}")) {
                if let Ok(s) = serde_json::from_str::<AppleSessionInfo>(&info_json) {
                    return s.team_id;
                }
            }
        }
        "PERSONAL".to_string()
    }

    /// Resolves active team ID, querying developer API if stored value is placeholder or missing.
    async fn resolve_team_id(&self) -> Result<String, WinIpaError> {
        let current = self.get_current_team_id();
        if current != "PERSONAL" && !current.is_empty() {
            return Ok(current);
        }

        // Attempt to fetch real team from Developer API
        if let Ok(teams) = self.fetch_teams().await {
            if let Some((tid, tname, acct)) = teams.into_iter().next() {
                if !tid.is_empty() && tid != "PERSONAL" {
                    // Update session in memory and vault
                    if let Ok(mut guard) = self.session.lock() {
                        if let Some(ref mut s) = *guard {
                            s.team_id = tid.clone();
                            s.team_name = tname.clone();
                            s.account_type = acct;
                            if let Ok(info_json) = serde_json::to_string(s) {
                                let _ = store_secret(&format!("info:{}", s.apple_id), &info_json);
                            }
                        }
                    } else if let Ok(Some(apple_id)) = get_secret("active_apple_id") {
                        let new_info = AppleSessionInfo {
                            apple_id: apple_id.clone(),
                            team_id: tid.clone(),
                            team_name: tname,
                            account_type: acct,
                            cert_expires_at: Some(
                                std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .unwrap_or_default()
                                    .as_secs()
                                    + 7 * 86400,
                            ),
                        };
                        if let Ok(info_json) = serde_json::to_string(&new_info) {
                            let _ = store_secret(&format!("info:{apple_id}"), &info_json);
                        }
                    }
                    return Ok(tid);
                }
            }
        }

        Err(WinIpaError::AppleAuthFailed(
            "Apple Developer error 3050 (Please select a team): No active developer team was found automatically for this Apple ID. Because this is a free Apple ID, Apple's portal does not list teams via API. Since you previously used this Apple ID with Xcode on a Mac, please enter your 10-character Personal Team ID (from Xcode Settings > Accounts or Mac Keychain) to proceed with signing.".into(),
        ))
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

        let ani = self.anisette.get_headers().await?;

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

        if let Some(ref ct) = ani.x_apple_i_client_time {
            set_header(&mut headers, "x-apple-i-client-time", ct);
        }
        if let Some(ref tz) = ani.x_apple_i_time_zone {
            set_header(&mut headers, "x-apple-i-time-zone", tz);
        }
        if let Some(ref loc) = ani.x_apple_locale {
            set_header(&mut headers, "x-apple-locale", loc);
        }
        if let Some(ref srl) = ani.x_apple_i_srl_no {
            set_header(&mut headers, "x-apple-i-srl-no", srl);
        }

        Ok(headers)
    }

    /// Sends an XML plist RPC request to Apple Developer Portal API.
    async fn call_developer_api(
        &self,
        action: &str,
        params: &HashMap<String, String>,
    ) -> Result<Value, WinIpaError> {
        let token = self.get_or_restore_session_token().ok_or_else(|| {
            WinIpaError::AppleAuthFailed(
                "No active Apple developer session. Please click 'Sign Out' in Device & Account and log in again to establish a fresh session.".into(),
            )
        })?;

        let url = format!("{DEVELOPER_API_BASE}/{action}?clientId=XABBG36SBA");

        // Build XML plist body
        let mut plist_dict = plist::Dictionary::new();
        plist_dict.insert("clientId".into(), Value::String("XABBG36SBA".into()));
        plist_dict.insert("myacinfo".into(), Value::String(token.clone()));
        plist_dict.insert("protocolVersion".into(), Value::String("QH65B2".into()));
        plist_dict.insert(
            "requestId".into(),
            Value::String(uuid::Uuid::new_v4().to_string().to_uppercase()),
        );
        plist_dict.insert(
            "userLocale".into(),
            Value::Array(vec![Value::String("en_US".into())]),
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

        // Ensure session_token_header is restored from vault if not currently in memory
        if let Ok(mut guard) = self.session_token_header.lock() {
            if guard.is_none() {
                if let Ok(Some(apple_id)) = get_secret("active_apple_id") {
                    if let Ok(Some(st)) = get_secret(&format!("token_header:{apple_id}")) {
                        *guard = Some(st);
                    }
                }
            }
        }

        let mut req = self
            .http_client
            .post(&url)
            .header("Content-Type", "text/x-xml-plist")
            .header("Accept", "text/x-xml-plist")
            .header("User-Agent", "Xcode/15.2 (15C500b)")
            .header("X-Xcode-Version", "15.2 (15C500b)")
            .header("X-Apple-App-Info", "com.apple.gs.xcode.auth")
            .header("Connection", "close")
            .header("Cookie", format!("myacinfo={token}"))
            .body(body_bytes);

        if let Ok(guard) = self.session_token_header.lock() {
            if let Some(ref st) = *guard {
                if let Ok(hval) = HeaderValue::from_str(st) {
                    req = req.header("x-apple-session-token", hval);
                }
            }
        }

        if let Ok(ani) = self.anisette.get_headers().await {
            let set_header = |headers: &mut HeaderMap, name: &'static str, val: &str| {
                if let Ok(hval) = HeaderValue::from_str(val) {
                    headers.insert(HeaderName::from_static(name), hval);
                }
            };
            let mut hmap = HeaderMap::new();
            set_header(&mut hmap, "x-apple-i-md", &ani.x_apple_i_md);
            set_header(&mut hmap, "x-apple-i-md-m", &ani.x_apple_i_md_m);
            set_header(&mut hmap, "x-apple-i-md-rinfo", &ani.x_apple_i_md_rinfo);
            set_header(&mut hmap, "x-apple-i-md-lu", &ani.x_apple_i_md_lu);
            set_header(&mut hmap, "x-mme-device-id", &ani.x_mme_device_id);
            set_header(&mut hmap, "x-mme-client-info", &ani.x_mme_client_info);
            if let Some(ref ct) = ani.x_apple_i_client_time {
                set_header(&mut hmap, "x-apple-i-client-time", ct);
            }
            if let Some(ref tz) = ani.x_apple_i_time_zone {
                set_header(&mut hmap, "x-apple-i-time-zone", tz);
            }
            if let Some(ref loc) = ani.x_apple_locale {
                set_header(&mut hmap, "x-apple-locale", loc);
            }
            if let Some(ref srl) = ani.x_apple_i_srl_no {
                set_header(&mut hmap, "x-apple-i-srl-no", srl);
            }
            req = req.headers(hmap);
        }

        let resp = req
            .send()
            .await
            .map_err(|e| WinIpaError::Timeout(format!("Developer API {action}: {e}")))?;

        let status = resp.status();
        if status.as_u16() == 429 {
            return Err(WinIpaError::AppleRateLimited);
        }

        let bytes = resp.bytes().await.map_err(|e| WinIpaError::Unknown {
            message: format!("Failed to read developer API response bytes: {e}"),
            diagnostics: None,
        })?;

        let body_preview = String::from_utf8_lossy(&bytes[..std::cmp::min(bytes.len(), 300)]);

        // 1. Detect plain-text session expiration response
        if body_preview.contains("session has expired") || body_preview.contains("Please log in") {
            if let Ok(mut lock) = self.session_token.lock() {
                *lock = None;
            }
            return Err(WinIpaError::AppleAuthFailed(
                "Apple developer session expired. Please click 'Sign Out' in Device & Account and log in again to establish a fresh session.".into(),
            ));
        }

        // 2. Detect HTML error/maintenance page
        if body_preview.trim_start().starts_with("<!DOCTYPE")
            || body_preview.trim_start().starts_with("<html")
        {
            return Err(WinIpaError::AppleAuthFailed(format!(
                "Apple Developer portal returned an unexpected web page: {}",
                body_preview.chars().take(150).collect::<String>()
            )));
        }

        // 3. Detect non-success HTTP status
        if !status.is_success() {
            return Err(WinIpaError::AppleAuthFailed(format!(
                "Apple Developer service error (HTTP {}): {}",
                status.as_u16(),
                body_preview.chars().take(150).collect::<String>()
            )));
        }

        // 4. Detect empty response body (which causes UnexpectedEndOfEventStream)
        if bytes.is_empty() || bytes.iter().all(|b| b.is_ascii_whitespace()) {
            if let Ok(mut lock) = self.session_token.lock() {
                *lock = None;
            }
            return Err(WinIpaError::AppleAuthFailed(format!(
                "Apple Developer service returned an empty response for action '{action}' (HTTP {}). Please click 'Sign Out' in Device & Account and log in again to establish a fresh session.",
                status.as_u16()
            )));
        }

        let plist_resp =
            Value::from_reader(Cursor::new(&bytes)).map_err(|e| WinIpaError::Unknown {
                message: format!(
                    "Failed to parse developer API response plist for '{action}' (HTTP {}, {} bytes): {e}",
                    status.as_u16(),
                    bytes.len()
                ),
                diagnostics: Some(format!(
                    "action={action}, status={}, len={}, preview={:?}",
                    status.as_u16(),
                    bytes.len(),
                    body_preview.chars().take(200).collect::<String>()
                )),
            })?;

        // Check for Apple Developer Portal error codes
        if let Some(dict) = plist_resp.as_dictionary() {
            if let Some(result_code) = dict.get("resultCode").and_then(|v| v.as_signed_integer()) {
                if result_code != 0 {
                    let err_string = dict
                        .get("userString")
                        .and_then(|v| v.as_string())
                        .or_else(|| dict.get("errorMessage").and_then(|v| v.as_string()))
                        .unwrap_or("Developer portal rejected request");

                    return match result_code {
                        35 => Err(WinIpaError::AccountLimitReached(err_string.into())),
                        1100 => {
                            if let Ok(mut lock) = self.session_token.lock() {
                                *lock = None;
                            }
                            Err(WinIpaError::AppleAuthFailed(
                                "Apple developer session expired. Please click 'Sign Out' in Device & Account and log in again.".into(),
                            ))
                        }
                        3018 | 3019 => {
                            if let Ok(mut lock) = self.session_token.lock() {
                                *lock = None;
                            }
                            if let Ok(mut lock) = self.session_token_header.lock() {
                                *lock = None;
                            }
                            if let Ok(Some(apple_id)) = get_secret("active_apple_id") {
                                let _ = delete_secret(&format!("token_header:{apple_id}"));
                                let _ = delete_secret(&format!("session:{apple_id}"));
                            }
                            Err(WinIpaError::AppleAuthFailed(
                                format!("Your Apple Developer session requires two-factor authentication refresh (Apple error {result_code}). Please click 'Log Out & Sign In Again' to authenticate with your 6-digit 2FA code."),
                            ))
                        }
                        3038 | 3041 => Err(WinIpaError::AppleRateLimited),
                        3050 => Err(WinIpaError::AppleAuthFailed(
                            "Apple Developer error 3050 (Please select a team): No active developer team was found for this Apple ID. If this is a new Apple ID, please sign in once to https://developer.apple.com/account in your web browser, accept the free Apple Developer Agreement to activate your Personal Team, then click Try Again.".into(),
                        )),
                        _ => Err(WinIpaError::Unknown {
                            message: format!("Apple Developer error {result_code} on '{action}': {err_string}"),
                            diagnostics: None,
                        }),
                    };
                }
            }
        }

        Ok(plist_resp)
    }

    /// Queries Developer Portal for user teams.
    pub async fn fetch_teams(
        &self,
    ) -> Result<Vec<(String, String, AppleAccountType)>, WinIpaError> {
        let params = HashMap::new();
        let resp = match self.call_developer_api("listTeams.action", &params).await {
            Ok(r) => r,
            Err(_) => {
                self.call_developer_api("ios/listTeams.action", &params)
                    .await?
            }
        };
        let mut teams = Vec::new();
        if let Some(dict) = resp.as_dictionary() {
            if let Some(teams_arr) = dict.get("teams").and_then(|v| v.as_array()) {
                for t in teams_arr {
                    if let Some(tdict) = t.as_dictionary() {
                        let tid = tdict
                            .get("teamId")
                            .and_then(|v| v.as_string())
                            .unwrap_or("")
                            .to_string();
                        let tname = tdict
                            .get("name")
                            .and_then(|v| v.as_string())
                            .unwrap_or("Personal Team")
                            .to_string();
                        let ttype_str = tdict
                            .get("type")
                            .and_then(|v| v.as_string())
                            .unwrap_or("Free");
                        let acct_type = if ttype_str.eq_ignore_ascii_case("Company/Organization")
                            || ttype_str.eq_ignore_ascii_case("Paid")
                        {
                            AppleAccountType::Paid
                        } else {
                            AppleAccountType::Free
                        };
                        if !tid.is_empty() {
                            teams.push((tid, tname, acct_type));
                        }
                    }
                }
            }
        }
        Ok(teams)
    }

    async fn try_fetch_initial_team(&self, apple_id: &str) -> (String, String, AppleAccountType) {
        match self.fetch_teams().await {
            Ok(teams) if !teams.is_empty() => {
                let (tid, tname, acct) = teams.into_iter().next().unwrap();
                (tid, tname, acct)
            }
            _ => {
                if let Ok(Some(saved_tid)) = get_secret(&format!("saved_team:{apple_id}")) {
                    let clean = saved_tid.trim().to_uppercase();
                    if clean.len() == 10 {
                        return (
                            clean,
                            format!("{apple_id} (Personal Team)"),
                            AppleAccountType::Free,
                        );
                    }
                }
                (
                    "PERSONAL".to_string(),
                    format!("{apple_id} (Personal Team)"),
                    AppleAccountType::Free,
                )
            }
        }
    }
}

#[async_trait]
impl AppleService for AppleDeveloperClient {
    async fn login(&mut self, apple_id: &str, password: &str) -> Result<LoginResult, WinIpaError> {
        // Reset pending state and cookie jar to ensure fresh session
        self.pending_apple_id = None;
        self.pending_password = None;
        self.pending_session_id = None;
        self.pending_scnt = None;
        self.pending_widget_key = None;
        self.pending_apple_id_session_id = None;
        let new_jar = Arc::new(Jar::default());
        self.cookie_jar = new_jar.clone();
        self.http_client = reqwest::Client::builder()
            .timeout(Duration::from_secs(20))
            .cookie_provider(new_jar)
            .build()
            .unwrap_or_default();

        let widget_key = self.resolve_widget_key().await;
        let (srp_client, a_b64) = AppleSrpClient::new();

        let mut headers = self.build_apple_headers().await?;
        headers.insert(
            reqwest::header::ACCEPT,
            HeaderValue::from_static("application/json"),
        );
        headers.insert(
            HeaderName::from_static("x-apple-widget-key"),
            HeaderValue::from_str(&widget_key)
                .unwrap_or_else(|_| HeaderValue::from_static(DEFAULT_WIDGET_KEY)),
        );
        headers.insert(
            HeaderName::from_static("x-requested-with"),
            HeaderValue::from_static("XMLHttpRequest"),
        );

        let init_body = serde_json::json!({
            "accountName": apple_id,
            "protocols": ["s2k", "s2k_fo"],
            "a": a_b64
        });

        let init_resp = self
            .http_client
            .post(AUTHKIT_INIT_URL)
            .headers(headers.clone())
            .json(&init_body)
            .send()
            .await
            .map_err(|e| {
                WinIpaError::AppleAuthFailed(format!("Auth server connection failed: {e}"))
            })?;

        let init_status = init_resp.status();
        let init_resp_headers = init_resp.headers().clone();

        if !init_status.is_success() {
            let err_body = init_resp.text().await.unwrap_or_default();
            if init_status.as_u16() == 429 {
                return Err(WinIpaError::AppleRateLimited);
            }
            return Err(WinIpaError::AppleAuthFailed(extract_apple_error_message(
                init_status,
                &err_body,
            )));
        }

        let init_bytes = init_resp.bytes().await.map_err(|e| {
            WinIpaError::AppleAuthFailed(format!("Failed to read SRP init response: {e}"))
        })?;

        let srp_init: SrpInitResponse = serde_json::from_slice(&init_bytes).map_err(|e| {
            WinIpaError::AppleAuthFailed(format!("Failed to parse SRP init response: {e}"))
        })?;

        let salt_bytes = BASE64
            .decode(&srp_init.salt)
            .map_err(|e| WinIpaError::AppleAuthFailed(format!("Invalid SRP salt base64: {e}")))?;

        let b_bytes = BASE64.decode(&srp_init.b).map_err(|e| {
            WinIpaError::AppleAuthFailed(format!("Invalid SRP server public key b: {e}"))
        })?;

        let (m1_b64, m2_b64) = srp_client.compute_proofs(
            apple_id,
            password,
            &salt_bytes,
            srp_init.iteration,
            &srp_init.protocol,
            &b_bytes,
        )?;

        let mut complete_headers = headers.clone();
        if let Some(scnt) = init_resp_headers.get("scnt").and_then(|v| v.to_str().ok()) {
            if let Ok(val) = HeaderValue::from_str(scnt) {
                complete_headers.insert(HeaderName::from_static("scnt"), val);
            }
        }
        if let Some(id_sid) = init_resp_headers
            .get("x-apple-id-session-id")
            .and_then(|v| v.to_str().ok())
        {
            if let Ok(val) = HeaderValue::from_str(id_sid) {
                complete_headers.insert(HeaderName::from_static("x-apple-id-session-id"), val);
            }
        }

        let complete_body = serde_json::json!({
            "accountName": apple_id,
            "c": srp_init.c,
            "m1": m1_b64,
            "m2": m2_b64,
            "rememberMe": false
        });

        let complete_resp = self
            .http_client
            .post(AUTHKIT_COMPLETE_URL)
            .headers(complete_headers)
            .json(&complete_body)
            .send()
            .await
            .map_err(|e| {
                WinIpaError::AppleAuthFailed(format!("Auth server complete failed: {e}"))
            })?;

        let comp_status = complete_resp.status();
        let comp_headers = complete_resp.headers().clone();

        self.pending_apple_id = Some(apple_id.to_string());
        self.pending_password = Some(password.to_string());
        self.pending_widget_key = Some(widget_key);

        if let Some(scnt) = comp_headers
            .get("scnt")
            .and_then(|v| v.to_str().ok())
            .or_else(|| init_resp_headers.get("scnt").and_then(|v| v.to_str().ok()))
        {
            self.pending_scnt = Some(scnt.to_string());
        }

        if let Some(id_sid) = comp_headers
            .get("x-apple-id-session-id")
            .and_then(|v| v.to_str().ok())
            .or_else(|| {
                init_resp_headers
                    .get("x-apple-id-session-id")
                    .and_then(|v| v.to_str().ok())
            })
        {
            self.pending_apple_id_session_id = Some(id_sid.to_string());
        }

        if let Some(token) = comp_headers
            .get("x-apple-session-token")
            .and_then(|v| v.to_str().ok())
        {
            self.pending_session_id = Some(token.to_string());
        } else {
            self.pending_session_id = None;
        }

        // Check for 2FA requirement (HTTP 409)
        if comp_status.as_u16() == 409 {
            return Ok(LoginResult::TwoFactorRequired {
                phone_numbers: vec!["Trusted Apple Devices / SMS".into()],
            });
        }

        if comp_status.as_u16() == 429 {
            return Err(WinIpaError::AppleRateLimited);
        }

        if !comp_status.is_success() {
            let err_body = complete_resp.text().await.unwrap_or_default();
            return Err(WinIpaError::AppleAuthFailed(extract_apple_error_message(
                comp_status,
                &err_body,
            )));
        }

        // Direct success without 2FA
        if let Some(st) = comp_headers
            .get("x-apple-session-token")
            .and_then(|v| v.to_str().ok())
        {
            if let Ok(mut lock) = self.session_token_header.lock() {
                *lock = Some(st.to_string());
            }
            let _ = store_secret(&format!("token_header:{apple_id}"), st);
        }

        let token_opt = extract_apple_session_token(&comp_headers, None)
            .or_else(|| self.extract_myacinfo_from_jar());

        if let Some(ref token) = token_opt {
            if let Ok(mut lock) = self.session_token.lock() {
                *lock = Some(token.clone());
            }
            let _ = store_secret(&format!("session:{apple_id}"), token);
        }

        let _ = store_secret("active_apple_id", apple_id);
        let _ = store_secret(&format!("auth:{apple_id}"), password);

        let (team_id, team_name, account_type) = self.try_fetch_initial_team(apple_id).await;

        let session_info = AppleSessionInfo {
            apple_id: apple_id.to_string(),
            team_id,
            team_name,
            account_type,
            cert_expires_at: Some(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs()
                    + 7 * 86400,
            ),
        };

        if let Ok(info_json) = serde_json::to_string(&session_info) {
            let _ = store_secret(&format!("info:{apple_id}"), &info_json);
        }

        if let Ok(mut lock) = self.session.lock() {
            *lock = Some(session_info.clone());
        }

        Ok(LoginResult::Success(session_info))
    }

    async fn submit_2fa(&mut self, code: &str) -> Result<AppleSessionInfo, WinIpaError> {
        let code = code.trim();
        let apple_id = self.pending_apple_id.clone().ok_or_else(|| {
            WinIpaError::TwoFactorFailed("No pending two-factor authentication session".into())
        })?;

        let widget_key = self
            .pending_widget_key
            .clone()
            .unwrap_or_else(|| DEFAULT_WIDGET_KEY.to_string());

        let mut headers = self.build_apple_headers().await?;
        headers.insert(
            reqwest::header::ACCEPT,
            HeaderValue::from_static("application/json"),
        );
        headers.insert(
            HeaderName::from_static("x-apple-widget-key"),
            HeaderValue::from_str(&widget_key)
                .unwrap_or_else(|_| HeaderValue::from_static(DEFAULT_WIDGET_KEY)),
        );
        headers.insert(
            HeaderName::from_static("x-requested-with"),
            HeaderValue::from_static("XMLHttpRequest"),
        );

        // Apple AuthKit uses scnt and x-apple-id-session-id for 2FA verification.
        // Fastlane Spaceship and Apple IDMS reject verify requests if an invalid/premature
        // x-apple-session-token is provided.
        if let Some(ref scnt) = self.pending_scnt {
            if let Ok(val) = HeaderValue::from_str(scnt) {
                headers.insert(HeaderName::from_static("scnt"), val);
            }
        }
        if let Some(ref id_sid) = self.pending_apple_id_session_id {
            if let Ok(val) = HeaderValue::from_str(id_sid) {
                headers.insert(HeaderName::from_static("x-apple-id-session-id"), val);
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

        let resp_status = resp.status();
        let resp_headers = resp.headers().clone();

        if !resp_status.is_success() {
            let status_code = resp_status.as_u16();
            let err_body = resp.text().await.unwrap_or_default();

            let mut parsed_msg: Option<String> = None;
            if let Ok(val) = serde_json::from_str::<serde_json::Value>(&err_body) {
                if let Some(errs) = val.get("serviceErrors").and_then(|v| v.as_array()) {
                    for err in errs {
                        if let Some(msg) = err.get("message").and_then(|v| v.as_str()) {
                            if !msg.trim().is_empty() {
                                parsed_msg = Some(msg.to_string());
                                break;
                            }
                        }
                    }
                }
                if parsed_msg.is_none() {
                    if let Some(msg) = val
                        .get("message")
                        .or_else(|| val.get("title"))
                        .or_else(|| val.get("errorMessage"))
                        .and_then(|v| v.as_str())
                    {
                        if !msg.trim().is_empty() {
                            parsed_msg = Some(msg.to_string());
                        }
                    }
                }
            }

            if let Some(msg) = parsed_msg {
                return Err(WinIpaError::TwoFactorFailed(msg));
            }

            if status_code == 400 || status_code == 401 || status_code == 403 {
                return Err(WinIpaError::TwoFactorFailed(
                    "The 6-digit code was rejected by Apple. Please check the code and re-enter."
                        .into(),
                ));
            }

            return Err(WinIpaError::TwoFactorFailed(format!(
                "Apple 2FA verification failed (HTTP {status_code}): {err_body}"
            )));
        }

        // Update scnt / session id if updated headers returned
        if let Some(scnt) = resp_headers.get("scnt").and_then(|v| v.to_str().ok()) {
            self.pending_scnt = Some(scnt.to_string());
        }
        if let Some(sid) = resp_headers
            .get("x-apple-id-session-id")
            .and_then(|v| v.to_str().ok())
        {
            self.pending_apple_id_session_id = Some(sid.to_string());
        }

        let verify_session_token = resp_headers
            .get("x-apple-session-token")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        if let Some(ref st) = verify_session_token {
            if let Ok(mut lock) = self.session_token_header.lock() {
                *lock = Some(st.clone());
            }
            let _ = store_secret(&format!("token_header:{apple_id}"), st);
        }

        // Send trust request to establish persistent session cookies (Fastlane store_session / 2sv/trust)
        let mut trust_headers = self.build_apple_headers().await.unwrap_or_default();
        trust_headers.insert(
            reqwest::header::ACCEPT,
            HeaderValue::from_static("application/json"),
        );
        trust_headers.insert(
            HeaderName::from_static("x-apple-widget-key"),
            HeaderValue::from_str(&widget_key)
                .unwrap_or_else(|_| HeaderValue::from_static(DEFAULT_WIDGET_KEY)),
        );
        if let Some(ref scnt) = self.pending_scnt {
            if let Ok(val) = HeaderValue::from_str(scnt) {
                trust_headers.insert(HeaderName::from_static("scnt"), val);
            }
        }
        if let Some(ref id_sid) = self.pending_apple_id_session_id {
            if let Ok(val) = HeaderValue::from_str(id_sid) {
                trust_headers.insert(HeaderName::from_static("x-apple-id-session-id"), val);
            }
        }
        if let Some(ref st) = verify_session_token {
            if let Ok(val) = HeaderValue::from_str(st) {
                trust_headers.insert(HeaderName::from_static("x-apple-session-token"), val);
            }
        }

        let trust_resp = self
            .http_client
            .get("https://idmsa.apple.com/appleauth/auth/2sv/trust")
            .headers(trust_headers)
            .send()
            .await;

        let trust_headers_opt = trust_resp.ok().map(|r| r.headers().clone());

        // Extract session token from verify response, trust response, or pending complete response
        let final_session_token = verify_session_token
            .or_else(|| {
                trust_headers_opt
                    .as_ref()
                    .and_then(|h| h.get("x-apple-session-token"))
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string())
            })
            .or_else(|| self.pending_session_id.clone());

        if let Some(ref st) = final_session_token {
            if let Ok(mut lock) = self.session_token_header.lock() {
                *lock = Some(st.clone());
            }
            let _ = store_secret(&format!("token_header:{apple_id}"), st);
        }

        let myacinfo_opt = trust_headers_opt
            .as_ref()
            .and_then(extract_myacinfo_from_headers)
            .or_else(|| self.extract_myacinfo_from_jar())
            .or_else(|| extract_myacinfo_from_headers(&resp_headers));

        let token_opt = myacinfo_opt.or_else(|| final_session_token.clone());

        if let Some(ref token) = token_opt {
            if let Ok(mut lock) = self.session_token.lock() {
                *lock = Some(token.clone());
            }
            let _ = store_secret(&format!("session:{apple_id}"), token);
        }
        let _ = store_secret("active_apple_id", &apple_id);

        if let Some(ref pwd) = self.pending_password {
            let _ = store_secret(&format!("auth:{apple_id}"), pwd);
        }

        let (team_id, team_name, account_type) = self.try_fetch_initial_team(&apple_id).await;

        let session_info = AppleSessionInfo {
            apple_id: apple_id.clone(),
            team_id,
            team_name,
            account_type,
            cert_expires_at: Some(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs()
                    + 7 * 86400,
            ),
        };

        if let Ok(info_json) = serde_json::to_string(&session_info) {
            let _ = store_secret(&format!("info:{apple_id}"), &info_json);
        }

        if let Ok(mut lock) = self.session.lock() {
            *lock = Some(session_info.clone());
        }

        self.pending_apple_id = None;
        self.pending_password = None;
        self.pending_session_id = None;
        self.pending_scnt = None;
        self.pending_widget_key = None;
        self.pending_apple_id_session_id = None;

        Ok(session_info)
    }

    async fn get_active_session(&self) -> Result<Option<AppleSessionInfo>, WinIpaError> {
        // If we have an active session in memory, verify whether we have a session token
        if let Ok(guard) = self.session.lock() {
            if let Some(ref s) = *guard {
                if self.get_or_restore_session_token().is_some() {
                    return Ok(Some(s.clone()));
                }
            }
        }

        // Check persistent store for stored session
        if let Ok(Some(apple_id)) = get_secret("active_apple_id") {
            // Restore session token (myacinfo)
            if let Ok(Some(token)) = get_secret(&format!("session:{apple_id}")) {
                if let Ok(mut guard) = self.session_token.lock() {
                    *guard = Some(token);
                }
            }

            // Restore 2FA session token header (x-apple-session-token)
            if let Ok(Some(st)) = get_secret(&format!("token_header:{apple_id}")) {
                if let Ok(mut guard) = self.session_token_header.lock() {
                    *guard = Some(st);
                }
            }

            let has_token = self.get_or_restore_session_token().is_some();
            if !has_token {
                // If there is no token, do not return a fake active session
                return Ok(None);
            }

            let mut session_info = if let Ok(Some(info_json)) = get_secret(&format!("info:{apple_id}"))
            {
                serde_json::from_str::<AppleSessionInfo>(&info_json).unwrap_or_else(|_| {
                    AppleSessionInfo {
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
                    }
                })
            } else {
                AppleSessionInfo {
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
                }
            };

            // If team_id is PERSONAL or empty, restore saved_team if present
            if session_info.team_id == "PERSONAL" || session_info.team_id.is_empty() {
                if let Ok(Some(saved_tid)) = get_secret(&format!("saved_team:{apple_id}")) {
                    let clean = saved_tid.trim().to_uppercase();
                    if clean.len() == 10 {
                        session_info.team_id = clean;
                    }
                }
            }

            if let Ok(mut guard) = self.session.lock() {
                *guard = Some(session_info.clone());
            }

            return Ok(Some(session_info));
        }

        Ok(None)
    }

    async fn logout(&mut self) -> Result<(), WinIpaError> {
        if let Ok(Some(apple_id)) = get_secret("active_apple_id") {
            let _ = delete_secret(&format!("session:{apple_id}"));
            let _ = delete_secret(&format!("token_header:{apple_id}"));
            let _ = delete_secret(&format!("auth:{apple_id}"));
            let _ = delete_secret(&format!("info:{apple_id}"));
        }
        if let Ok(guard) = self.session.lock() {
            if let Some(ref s) = *guard {
                let _ = delete_secret(&format!("session:{}", s.apple_id));
                let _ = delete_secret(&format!("token_header:{}", s.apple_id));
                let _ = delete_secret(&format!("auth:{}", s.apple_id));
                let _ = delete_secret(&format!("info:{}", s.apple_id));
            }
        }
        let _ = delete_secret("active_apple_id");

        if let Ok(mut guard) = self.session.lock() {
            *guard = None;
        }
        if let Ok(mut guard) = self.session_token.lock() {
            *guard = None;
        }
        if let Ok(mut guard) = self.session_token_header.lock() {
            *guard = None;
        }
        self.pending_apple_id = None;
        self.pending_password = None;
        self.pending_session_id = None;
        self.pending_scnt = None;
        self.pending_widget_key = None;
        self.pending_apple_id_session_id = None;

        let new_jar = Arc::new(Jar::default());
        self.cookie_jar = new_jar.clone();
        self.http_client = reqwest::Client::builder()
            .timeout(Duration::from_secs(20))
            .cookie_provider(new_jar)
            .build()
            .unwrap_or_default();

        Ok(())
    }

    async fn register_device(&self, udid: &str, name: &str) -> Result<String, WinIpaError> {
        let team_id = self.resolve_team_id().await?;
        let mut params = HashMap::new();
        params.insert("deviceNumber".into(), udid.to_string());
        params.insert("name".into(), name.to_string());
        params.insert("teamId".into(), team_id.clone());

        let resp_res = self
            .call_developer_api("ios/addDevice.action", &params)
            .await;

        let resp = match resp_res {
            Ok(v) => v,
            Err(e) => {
                // If device registration fails because it's already registered, query listDevices
                let mut list_params = HashMap::new();
                list_params.insert("teamId".into(), team_id.clone());
                if let Ok(list_resp) = self
                    .call_developer_api("ios/listDevices.action", &list_params)
                    .await
                {
                    if let Some(dict) = list_resp.as_dictionary() {
                        if let Some(devices) = dict.get("devices").and_then(|v| v.as_array()) {
                            for dev in devices {
                                if let Some(d) = dev.as_dictionary() {
                                    let dev_num = d
                                        .get("deviceNumber")
                                        .and_then(|v| v.as_string())
                                        .unwrap_or("");
                                    if dev_num.eq_ignore_ascii_case(udid) {
                                        if let Some(id) =
                                            d.get("deviceId").and_then(|v| v.as_string())
                                        {
                                            return Ok(id.to_string());
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                return Err(e);
            }
        };

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
        let team_id = self.resolve_team_id().await?;
        let mut params = HashMap::new();
        params.insert("identifier".into(), bundle_id.to_string());
        params.insert("name".into(), format!("WinIPA {name}"));
        params.insert("teamId".into(), team_id.clone());

        let resp_res = self
            .call_developer_api("ios/addAppId.action", &params)
            .await;

        let resp = match resp_res {
            Ok(v) => v,
            Err(e) => {
                // If App ID registration fails because it's already registered, query listAppIds
                let mut list_params = HashMap::new();
                list_params.insert("teamId".into(), team_id.clone());
                if let Ok(list_resp) = self
                    .call_developer_api("ios/listAppIds.action", &list_params)
                    .await
                {
                    if let Some(dict) = list_resp.as_dictionary() {
                        if let Some(app_ids) = dict.get("appIds").and_then(|v| v.as_array()) {
                            for app in app_ids {
                                if let Some(ad) = app.as_dictionary() {
                                    let ident = ad
                                        .get("identifier")
                                        .and_then(|v| v.as_string())
                                        .unwrap_or("");
                                    if ident.eq_ignore_ascii_case(bundle_id) {
                                        if let Some(id) =
                                            ad.get("appIdId").and_then(|v| v.as_string())
                                        {
                                            return Ok(id.to_string());
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                return Err(e);
            }
        };

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
        let team_id = self.resolve_team_id().await?;
        let apple_id = get_secret("active_apple_id")
            .ok()
            .flatten()
            .unwrap_or_else(|| "WinIPA User".to_string());
        let cn = format!("Apple Development: {apple_id} ({team_id})");
        let key_pair = generate_dev_csr(&cn, &team_id)?;

        let mut params = HashMap::new();
        params.insert("csrContent".into(), key_pair.csr_pem.clone());
        params.insert("teamId".into(), team_id.clone());
        params.insert("machineName".into(), "WinIPA-PC".into());
        params.insert(
            "machineId".into(),
            uuid::Uuid::new_v4().to_string().to_uppercase(),
        );

        let resp_res = self
            .call_developer_api("ios/submitDevelopmentCSR.action", &params)
            .await;

        let resp = match resp_res {
            Ok(v) => v,
            Err(ref e) => {
                let err_str = e.to_string();
                if err_str.contains("7460")
                    || err_str.contains("already have a current iOS Development certificate")
                {
                    // Query existing certificates, revoke stale cert, and retry CSR submission
                    let mut list_params = HashMap::new();
                    list_params.insert("teamId".into(), team_id.clone());
                    if let Ok(list_resp) = self
                        .call_developer_api("ios/listAllDevelopmentCerts.action", &list_params)
                        .await
                    {
                        if let Some(dict) = list_resp.as_dictionary() {
                            if let Some(certs) = dict.get("certificates").and_then(|v| v.as_array())
                            {
                                for c in certs {
                                    if let Some(cd) = c.as_dictionary() {
                                        if let Some(serial) =
                                            cd.get("serialNumber").and_then(|v| v.as_string())
                                        {
                                            let mut rev_params = HashMap::new();
                                            rev_params
                                                .insert("serialNumber".into(), serial.to_string());
                                            rev_params.insert("teamId".into(), team_id.clone());
                                            let _ = self
                                                .call_developer_api(
                                                    "ios/revokeDevelopmentCert.action",
                                                    &rev_params,
                                                )
                                                .await;
                                        }
                                    }
                                }
                            }
                        }
                    }
                    // Retry submission once
                    self.call_developer_api("ios/submitDevelopmentCSR.action", &params)
                        .await?
                } else {
                    return Err(resp_res.err().unwrap());
                }
            }
        };

        let mut cert_data = Vec::new();
        let mut cert_id = uuid::Uuid::new_v4().to_string();

        if let Some(dict) = resp.as_dictionary() {
            let cert_dict = dict
                .get("certRequest")
                .or_else(|| dict.get("developerCertificate"))
                .and_then(|v| v.as_dictionary());

            if let Some(cert) = cert_dict {
                if let Some(id) = cert
                    .get("certRequestId")
                    .or_else(|| cert.get("certificateId"))
                    .and_then(|v| v.as_string())
                {
                    cert_id = id.to_string();
                }
                if let Some(data) = cert.get("certContent").and_then(|v| v.as_data()) {
                    cert_data = data.to_vec();
                } else if let Some(s) = cert.get("certContent").and_then(|v| v.as_string()) {
                    if let Ok(decoded) = BASE64.decode(s.trim()) {
                        cert_data = decoded;
                    } else {
                        cert_data = s.as_bytes().to_vec();
                    }
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
            expires_at: now + 7 * 86400,
        })
    }

    async fn request_provisioning_profile(
        &self,
        app_id_id: &str,
        device_id: &str,
        cert_id: &str,
    ) -> Result<ProvisioningProfile, WinIpaError> {
        let team_id = self.resolve_team_id().await?;
        let mut params = HashMap::new();
        params.insert("appIdId".into(), app_id_id.to_string());
        params.insert("deviceId".into(), device_id.to_string());
        params.insert("certificateId".into(), cert_id.to_string());
        params.insert("teamId".into(), team_id);

        let resp = self
            .call_developer_api("ios/downloadTeamProvisioningProfile.action", &params)
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
                } else if let Some(s) = prof.get("encodedProfile").and_then(|v| v.as_string()) {
                    if let Ok(decoded) = BASE64.decode(s.trim()) {
                        profile_data = decoded;
                    } else {
                        profile_data = s.as_bytes().to_vec();
                    }
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

    async fn set_team_id(&mut self, team_id: &str) -> Result<AppleSessionInfo, WinIpaError> {
        let team_id_clean = team_id.trim().to_uppercase();
        if team_id_clean.len() != 10 || !team_id_clean.chars().all(|c| c.is_ascii_alphanumeric()) {
            return Err(WinIpaError::AppleAuthFailed(
                "Team ID must be exactly 10 alphanumeric characters (e.g. 7X8Y9Z1A2B)".into(),
            ));
        }

        let apple_id = if let Ok(guard) = self.session.lock() {
            guard.as_ref().map(|s| s.apple_id.clone())
        } else {
            None
        }
        .or_else(|| get_secret("active_apple_id").ok().flatten())
        .ok_or_else(|| {
            WinIpaError::AppleAuthFailed("No active Apple ID session found. Please log in first.".into())
        })?;

        let mut updated_session: Option<AppleSessionInfo> = None;

        if let Ok(mut guard) = self.session.lock() {
            if let Some(ref mut s) = *guard {
                s.team_id = team_id_clean.clone();
                s.team_name = format!("{} (Personal Team)", s.apple_id);
                updated_session = Some(s.clone());
            }
        }

        let session_info = match updated_session {
            Some(s) => s,
            None => {
                let s = AppleSessionInfo {
                    apple_id: apple_id.clone(),
                    team_id: team_id_clean.clone(),
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
                if let Ok(mut guard) = self.session.lock() {
                    *guard = Some(s.clone());
                }
                s
            }
        };

        if let Ok(info_json) = serde_json::to_string(&session_info) {
            let _ = store_secret(&format!("info:{apple_id}"), &info_json);
        }
        let _ = store_secret(&format!("saved_team:{apple_id}"), &team_id_clean);

        Ok(session_info)
    }
}
