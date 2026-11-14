// Copyright (C) 2026 WinIPA Contributors
// SPDX-License-Identifier: GPL-3.0-only

import { invoke } from "@tauri-apps/api/core";

/**
 * Generates and returns a full redacted diagnostics report string.
 */
export async function getRedactedDiagnostics(): Promise<string> {
  return await invoke<string>("get_redacted_diagnostics");
}

/**
 * Generates and exports the redacted diagnostics report to a file on disk.
 * Returns the saved file path.
 */
export async function exportDiagnosticsToFile(destination?: string): Promise<string> {
  return await invoke<string>("export_diagnostics_to_file", { destination });
}
