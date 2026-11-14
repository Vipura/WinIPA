// Copyright (C) 2026 WinIPA Contributors
// SPDX-License-Identifier: GPL-3.0-only

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AppleAccountType {
    Free,
    Paid,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppleSessionInfo {
    pub apple_id: String,
    pub team_id: String,
    pub team_name: String,
    pub account_type: AppleAccountType,
    pub cert_expires_at: Option<u64>,
}
