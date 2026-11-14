// Copyright (C) 2026 WinIPA Contributors
// SPDX-License-Identifier: GPL-3.0-only

export interface ErrorDetail {
  code: string;
  title: string;
  message: string;
  remedy: string;
  diagnostics?: string;
}

export interface DeviceInfo {
  udid: string;
  name: string;
  ios_version: string;
  model: string;
  is_trusted: boolean;
  is_locked: boolean;
  developer_mode_enabled: boolean;
}

export interface DeviceDriverStatus {
  is_installed: boolean;
  service_running: boolean;
  driver_source?: string;
}

export interface IpaMetadata {
  file_path: string;
  app_name: string;
  bundle_id: string;
  version: string;
  build_number: string;
  min_ios_version: string;
  icon_base64?: string;
  is_encrypted: boolean;
  is_already_signed: boolean;
  original_entitlements: string[];
}

export type AppleAccountType = "Free" | "Paid" | "Unknown";

export interface AppleSessionInfo {
  apple_id: string;
  team_id: string;
  team_name: string;
  account_type: AppleAccountType;
  cert_expires_at?: number;
}

export type LoginResult =
  | { type: "Success"; data: AppleSessionInfo }
  | { type: "TwoFactorRequired"; data: { phone_numbers: string[] } };

export interface DevelopmentCertificate {
  cert_id: string;
  serial_number: string;
  pem_certificate: string;
  private_key_pem: string;
}

export interface ProvisioningProfile {
  profile_id: string;
  profile_name: string;
  profile_data_base64: string;
  expiration_date: number;
}

export interface InstalledAppRecord {
  bundle_id: string;
  app_name: string;
  version: string;
  installed_at: number;
  cert_expires_at: number;
}
