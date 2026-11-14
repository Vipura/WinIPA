// Copyright (C) 2026 WinIPA Contributors
// SPDX-License-Identifier: GPL-3.0-only

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceInfo {
    pub udid: String,
    pub name: String,
    pub ios_version: String,
    pub model: String,
    pub is_trusted: bool,
    pub is_locked: bool,
    pub developer_mode_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceDriverStatus {
    pub is_installed: bool,
    pub service_running: bool,
    pub driver_source: Option<String>,
}
