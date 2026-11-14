// Copyright (C) 2026 WinIPA Contributors
// SPDX-License-Identifier: GPL-3.0-only

use super::AppleSessionInfo;
use crate::errors::WinIpaError;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum LoginResult {
    Success(AppleSessionInfo),
    TwoFactorRequired { phone_numbers: Vec<String> },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DevelopmentCertificate {
    pub cert_id: String,
    pub certificate_data: Vec<u8>,
    pub private_key_pem: String,
    pub expires_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvisioningProfile {
    pub profile_id: String,
    pub profile_name: String,
    pub profile_data: Vec<u8>,
    pub expires_at: u64,
}

#[async_trait]
pub trait AppleService: Send + Sync {
    async fn login(&mut self, apple_id: &str, password: &str) -> Result<LoginResult, WinIpaError>;
    async fn submit_2fa(&mut self, code: &str) -> Result<AppleSessionInfo, WinIpaError>;
    async fn get_active_session(&self) -> Result<Option<AppleSessionInfo>, WinIpaError>;
    async fn logout(&mut self) -> Result<(), WinIpaError>;
    async fn register_device(&self, udid: &str, name: &str) -> Result<String, WinIpaError>;
    async fn get_or_create_app_id(
        &self,
        bundle_id: &str,
        name: &str,
    ) -> Result<String, WinIpaError>;
    async fn request_development_certificate(&self) -> Result<DevelopmentCertificate, WinIpaError>;
    async fn request_provisioning_profile(
        &self,
        app_id_id: &str,
        device_id: &str,
        cert_id: &str,
    ) -> Result<ProvisioningProfile, WinIpaError>;
}
