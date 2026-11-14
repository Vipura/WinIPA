// Copyright (C) 2026 WinIPA Contributors
// SPDX-License-Identifier: GPL-3.0-only

import { invoke } from "@tauri-apps/api/core";
import { listen, UnlistenFn } from "@tauri-apps/api/event";
import { DeviceDriverStatus, DeviceInfo } from "../types";

export async function getDriverStatus(): Promise<DeviceDriverStatus> {
  return await invoke<DeviceDriverStatus>("get_driver_status");
}

export async function getConnectedDevices(): Promise<DeviceInfo[]> {
  return await invoke<DeviceInfo[]>("get_connected_devices");
}

export async function refreshDevices(): Promise<DeviceInfo[]> {
  return await invoke<DeviceInfo[]>("refresh_devices");
}

export async function listenToDeviceUpdates(
  callback: (devices: DeviceInfo[]) => void
): Promise<UnlistenFn> {
  return await listen<DeviceInfo[]>("device-list-updated", (event) => {
    callback(event.payload);
  });
}

export async function listenToDriverUpdates(
  callback: (status: DeviceDriverStatus) => void
): Promise<UnlistenFn> {
  return await listen<DeviceDriverStatus>("driver-status-changed", (event) => {
    callback(event.payload);
  });
}
