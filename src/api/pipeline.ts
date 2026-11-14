// Copyright (C) 2026 WinIPA Contributors
// SPDX-License-Identifier: GPL-3.0-only

import { invoke } from "@tauri-apps/api/core";
import { listen, UnlistenFn } from "@tauri-apps/api/event";
import {
  InstalledAppRecord,
  PipelineRequest,
  PipelineResult,
  PipelineStatus,
} from "../types";

export async function startInstallationPipeline(
  req: PipelineRequest
): Promise<PipelineResult> {
  return await invoke<PipelineResult>("start_installation_pipeline", { req });
}

export async function cancelInstallationPipeline(): Promise<void> {
  return await invoke<void>("cancel_installation_pipeline");
}

export async function listenToPipelineStatus(
  callback: (status: PipelineStatus) => void
): Promise<UnlistenFn> {
  return await listen<PipelineStatus>("pipeline-status", (event) => {
    callback(event.payload);
  });
}

export async function getInstalledApps(): Promise<InstalledAppRecord[]> {
  return await invoke<InstalledAppRecord[]>("get_installed_apps");
}

export async function removeInstalledApp(bundleId: string): Promise<void> {
  return await invoke<void>("remove_installed_app", { bundleId });
}
