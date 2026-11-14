// Copyright (C) 2026 WinIPA Contributors
// SPDX-License-Identifier: GPL-3.0-only

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PipelineStep {
    Idle,
    Inspecting,
    Authenticating,
    Signing,
    Installing,
    Completed,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineStatus {
    pub step: PipelineStep,
    pub progress: f32,
    pub message: String,
}
