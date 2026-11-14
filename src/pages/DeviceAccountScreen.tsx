// Copyright (C) 2026 WinIPA Contributors
// SPDX-License-Identifier: GPL-3.0-only

import React, { useState, useEffect, useCallback } from "react";
import { STRINGS } from "../strings";
import { DeviceInfo, DeviceDriverStatus, AppleSessionInfo, InstalledAppRecord } from "../types";
import {
  getDriverStatus,
  getConnectedDevices,
  refreshDevices,
  listenToDeviceUpdates,
  listenToDriverUpdates,
} from "../api/device";
import {
  Smartphone,
  User,
  ShieldAlert,
  AlertTriangle,
  KeyRound,
  ArrowLeft,
  RefreshCw,
  ExternalLink,
  ShieldX,
  Lock,
} from "lucide-react";

interface DeviceAccountScreenProps {
  onNavigate: (view: "home" | "install" | "device-account") => void;
}

export const DeviceAccountScreen: React.FC<DeviceAccountScreenProps> = ({ onNavigate }) => {
  const [driverStatus, setDriverStatus] = useState<DeviceDriverStatus | null>(null);
  const [devices, setDevices] = useState<DeviceInfo[]>([]);
  const [appleSession] = useState<AppleSessionInfo | null>(null);
  const [installedApps] = useState<InstalledAppRecord[]>([]);
  const [isRefreshing, setIsRefreshing] = useState<boolean>(false);

  const fetchStatus = useCallback(async () => {
    try {
      const status = await getDriverStatus();
      setDriverStatus(status);
      if (status.service_running) {
        const devs = await getConnectedDevices();
        setDevices(devs);
      } else {
        setDevices([]);
      }
    } catch (err) {
      console.error("Failed to load device/driver status:", err);
    }
  }, []);

  useEffect(() => {
    fetchStatus();

    let unlistenDevices: (() => void) | undefined;
    let unlistenDriver: (() => void) | undefined;

    listenToDeviceUpdates((updatedDevices) => {
      setDevices(updatedDevices);
    }).then((unsub) => {
      unlistenDevices = unsub;
    });

    listenToDriverUpdates((updatedDriver) => {
      setDriverStatus(updatedDriver);
    }).then((unsub) => {
      unlistenDriver = unsub;
    });

    return () => {
      unlistenDevices?.();
      unlistenDriver?.();
    };
  }, [fetchStatus]);

  const handleRefresh = async () => {
    setIsRefreshing(true);
    try {
      const status = await getDriverStatus();
      setDriverStatus(status);
      if (status.service_running) {
        const devs = await refreshDevices();
        setDevices(devs);
      } else {
        setDevices([]);
      }
    } catch (err) {
      console.error("Error refreshing devices:", err);
    } finally {
      setIsRefreshing(false);
    }
  };

  const activeDevice = devices.length > 0 ? devices[0] : null;

  return (
    <div className="device-account-screen">
      <div className="page-header justify-between">
        <div style={{ display: "flex", alignItems: "center", gap: "1rem" }}>
          <button
            type="button"
            className="back-btn"
            onClick={() => onNavigate("home")}
            aria-label={STRINGS.nav.backToHome}
          >
            <ArrowLeft size={18} />
            <span>{STRINGS.nav.backToHome}</span>
          </button>
          <h2 className="page-title">{STRINGS.device.title}</h2>
        </div>

        <button
          type="button"
          className="btn btn-outline btn-sm"
          onClick={handleRefresh}
          disabled={isRefreshing}
          style={{ display: "flex", gap: "0.4rem", alignItems: "center" }}
        >
          <RefreshCw size={14} className={isRefreshing ? "spin-icon" : ""} />
          <span>{isRefreshing ? STRINGS.device.refreshing : STRINGS.device.refreshBtn}</span>
        </button>
      </div>

      {/* Driver Warning Banner if Missing or Stopped */}
      {driverStatus && !driverStatus.is_installed && (
        <div className="alert-card alert-warning mb-4">
          <AlertTriangle size={24} className="shrink-0" />
          <div className="alert-content">
            <strong>{STRINGS.device.driverMissingTitle}</strong>
            <p className="mt-1 text-sm">{STRINGS.device.driverMissingMsg}</p>
            <a
              href="ms-windows-store://pdp/?productid=9NP83LWLPZ9K"
              className="store-link mt-2"
              target="_blank"
              rel="noreferrer"
            >
              <span>{STRINGS.device.microsoftStoreGuide}</span>
              <ExternalLink size={14} />
            </a>
          </div>
        </div>
      )}

      {driverStatus && driverStatus.is_installed && !driverStatus.service_running && (
        <div className="alert-card alert-warning mb-4">
          <AlertTriangle size={24} className="shrink-0" />
          <div className="alert-content">
            <strong>{STRINGS.device.serviceStoppedTitle}</strong>
            <p className="mt-1 text-sm">{STRINGS.device.serviceStoppedMsg}</p>
            {driverStatus.driver_source && (
              <span className="driver-source-tag mt-2">
                {STRINGS.device.driverInstalledSource} {driverStatus.driver_source}
              </span>
            )}
          </div>
        </div>
      )}

      <div className="sections-grid">
        {/* Device Info Section */}
        <section className="info-card">
          <div className="section-title-row">
            <Smartphone size={20} className="section-icon" />
            <h3 className="section-title">{STRINGS.device.deviceSection}</h3>
          </div>

          {activeDevice ? (
            <div className="device-details">
              <div className="detail-row">
                <span className="detail-label">Device Name:</span>
                <span className="detail-value">{activeDevice.name}</span>
              </div>
              <div className="detail-row">
                <span className="detail-label">iOS Version:</span>
                <span className="detail-value">{activeDevice.ios_version}</span>
              </div>
              <div className="detail-row">
                <span className="detail-label">Model Identifier:</span>
                <span className="detail-value">{activeDevice.model}</span>
              </div>
              <div className="detail-row">
                <span className="detail-label">UDID:</span>
                <span className="detail-value font-mono">
                  {activeDevice.udid.length > 12
                    ? `${activeDevice.udid.slice(0, 8)}...${activeDevice.udid.slice(-4)}`
                    : activeDevice.udid}
                </span>
              </div>
              <div className="detail-row">
                <span className="detail-label">Trust & Lock Status:</span>
                <span
                  className={`status-pill ${
                    activeDevice.is_trusted && !activeDevice.is_locked
                      ? "pill-success"
                      : "pill-warning"
                  }`}
                >
                  {activeDevice.is_locked
                    ? "Passcode Locked"
                    : activeDevice.is_trusted
                    ? "Trusted"
                    : "Untrusted"}
                </span>
              </div>
              <div className="detail-row">
                <span className="detail-label">Developer Mode:</span>
                <span
                  className={`status-pill ${
                    activeDevice.developer_mode_enabled ? "pill-success" : "pill-danger"
                  }`}
                >
                  {activeDevice.developer_mode_enabled ? "Enabled" : "Disabled"}
                </span>
              </div>

              {/* Warnings for Passcode / Untrusted */}
              {(!activeDevice.is_trusted || activeDevice.is_locked) && (
                <div className="status-notice notice-warning mt-3">
                  <Lock size={16} className="shrink-0" />
                  <div>
                    <strong>{STRINGS.device.lockedOrUntrustedTitle}</strong>
                    <p className="text-sm mt-0.5">{STRINGS.device.lockedOrUntrustedMsg}</p>
                  </div>
                </div>
              )}

              {/* Warning for Developer Mode Off on iOS 16+ */}
              {!activeDevice.developer_mode_enabled && (
                <div className="status-notice notice-danger mt-3">
                  <ShieldX size={16} className="shrink-0" />
                  <div>
                    <strong>{STRINGS.device.developerModeTitle}</strong>
                    <p className="text-sm mt-0.5">{STRINGS.device.developerModeMsg}</p>
                  </div>
                </div>
              )}
            </div>
          ) : (
            <div className="empty-state">
              <AlertTriangle size={32} className="text-warning mb-2" />
              <h4 className="empty-title">{STRINGS.device.noDeviceTitle}</h4>
              <p className="empty-msg">{STRINGS.device.noDeviceMsg}</p>
            </div>
          )}
        </section>

        {/* Apple ID Account Section */}
        <section className="info-card">
          <div className="section-title-row">
            <User size={20} className="section-icon" />
            <h3 className="section-title">{STRINGS.device.accountSection}</h3>
          </div>

          {appleSession ? (
            <div className="account-details">
              <div className="detail-row">
                <span className="detail-label">Apple ID:</span>
                <span className="detail-value">{appleSession.apple_id}</span>
              </div>
              <div className="detail-row">
                <span className="detail-label">Team:</span>
                <span className="detail-value">
                  {appleSession.team_name} ({appleSession.team_id})
                </span>
              </div>
              <div className="detail-row">
                <span className="detail-label">Account Tier:</span>
                <span className="status-pill pill-info">{appleSession.account_type} Account</span>
              </div>
              <button type="button" className="btn btn-outline btn-sm mt-3">
                {STRINGS.device.logoutBtn}
              </button>
            </div>
          ) : (
            <div className="empty-state">
              <KeyRound size={32} className="text-muted mb-2" />
              <p className="empty-msg">{STRINGS.device.notLoggedIn}</p>
              <button
                type="button"
                className="btn btn-primary btn-sm mt-2"
                onClick={() => alert("Apple ID authentication will be active in Milestone 3.")}
              >
                {STRINGS.device.loginBtn}
              </button>
            </div>
          )}

          <div className="account-limits-box">
            <ShieldAlert size={16} className="text-info shrink-0 mt-0.5" />
            <div className="limits-text">
              <strong>Account Limits (Free Tier):</strong>
              <ul>
                <li>7-day certificate validity period.</li>
                <li>Maximum 3 active sideloaded apps per device.</li>
                <li>~10 App IDs generated per week.</li>
              </ul>
            </div>
          </div>
        </section>
      </div>

      {/* Installed Apps Section */}
      <section className="info-card full-width mt-4">
        <h3 className="section-title mb-3">{STRINGS.device.appsSection}</h3>
        {installedApps.length === 0 ? (
          <p className="empty-msg text-center">{STRINGS.device.noApps}</p>
        ) : (
          <div className="installed-apps-table"></div>
        )}
      </section>
    </div>
  );
};
