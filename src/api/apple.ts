// Copyright (C) 2026 WinIPA Contributors
// SPDX-License-Identifier: GPL-3.0-only

import { invoke } from "@tauri-apps/api/core";
import { AppleSessionInfo, LoginResult, ProvisioningProfile } from "../types";

export async function appleLogin(
  appleId: string,
  password: string
): Promise<LoginResult> {
  return await invoke<LoginResult>("apple_login", {
    appleId,
    password,
  });
}

export async function appleSubmit2Fa(
  code: string
): Promise<AppleSessionInfo> {
  return await invoke<AppleSessionInfo>("apple_submit_2fa", { code });
}

export async function appleGetSession(): Promise<AppleSessionInfo | null> {
  return await invoke<AppleSessionInfo | null>("apple_get_session");
}

export async function appleLogout(): Promise<void> {
  return await invoke<void>("apple_logout");
}

export async function appleProvisionDevice(
  bundleId: string,
  udid: string,
  deviceName: string
): Promise<ProvisioningProfile> {
  return await invoke<ProvisioningProfile>("apple_provision_device", {
    bundleId,
    udid,
    deviceName,
  });
}
