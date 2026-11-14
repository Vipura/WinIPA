// Copyright (C) 2026 WinIPA Contributors
// SPDX-License-Identifier: GPL-3.0-only

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigningOptions {
    pub input_ipa: String,
    pub output_ipa: String,
    pub certificate_data: Vec<u8>,
    pub private_key_data: Vec<u8>,
    pub mobileprovision_data: Vec<u8>,
    pub new_bundle_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigningResult {
    pub signed_ipa_path: String,
    pub stripped_entitlements: Vec<String>,
}
