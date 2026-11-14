// Copyright (C) 2026 WinIPA Contributors
// SPDX-License-Identifier: GPL-3.0-only

pub mod anisette;
pub mod client;
pub mod crypto;
pub mod mock;
pub mod service;

use client::AppleDeveloperClient;
use serde::{Deserialize, Serialize};
pub use service::{AppleService, DevelopmentCertificate, LoginResult, ProvisioningProfile};
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AppleAccountType {
    Free,
    Paid,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AppleSessionInfo {
    pub apple_id: String,
    pub team_id: String,
    pub team_name: String,
    pub account_type: AppleAccountType,
    pub cert_expires_at: Option<u64>,
}

pub type SharedAppleService = Arc<Mutex<Box<dyn AppleService>>>;

pub fn create_default_apple_service() -> SharedAppleService {
    Arc::new(Mutex::new(Box::new(AppleDeveloperClient::new(None))))
}

/// Helper to get or initialize the global shared AppleService.
static GLOBAL_APPLE_SERVICE: std::sync::OnceLock<SharedAppleService> = std::sync::OnceLock::new();

pub fn get_apple_service() -> SharedAppleService {
    GLOBAL_APPLE_SERVICE
        .get_or_init(create_default_apple_service)
        .clone()
}
