// Copyright (C) 2026 WinIPA Contributors
// SPDX-License-Identifier: GPL-3.0-only

import { invoke } from "@tauri-apps/api/core";
import { IpaMetadata } from "../types";

export async function inspectIpaPackage(path: string): Promise<IpaMetadata> {
  return await invoke<IpaMetadata>("inspect_ipa_package", { path });
}
