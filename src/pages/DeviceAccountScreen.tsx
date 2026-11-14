// Copyright (C) 2026 WinIPA Contributors
// SPDX-License-Identifier: GPL-3.0-only

import React, { useState } from "react";
import { STRINGS } from "../strings";
import { DeviceInfo, AppleSessionInfo, InstalledAppRecord } from "../types";
import { Smartphone, User, ShieldAlert, AlertTriangle, KeyRound, ArrowLeft } from "lucide-react";

interface DeviceAccountScreenProps {
  onNavigate: (view: "home" | "install" | "device-account") => void;
}

export const DeviceAccountScreen: React.FC<DeviceAccountScreenProps> = ({ onNavigate }) => {
  // In M0/M1 these will be populated from Tauri backend events/commands
  const [device] = useState<DeviceInfo | null>(null);
  const [appleSession] = useState<AppleSessionInfo | null>(null);
  const [installedApps] = useState<InstalledAppRecord[]>([]);

  return (
    <div className="device-account-screen">
      <div className="page-header">
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

      <div className="sections-grid">
        {/* Device Info Section */}
        <section className="info-card">
          <div className="section-title-row">
            <Smartphone size={20} className="section-icon" />
            <h3 className="section-title">{STRINGS.device.deviceSection}</h3>
          </div>

          {device ? (
            <div className="device-details">
              <div className="detail-row">
                <span className="detail-label">Device Name:</span>
                <span className="detail-value">{device.name}</span>
              </div>
              <div className="detail-row">
                <span className="detail-label">iOS Version:</span>
                <span className="detail-value">{device.ios_version}</span>
              </div>
              <div className="detail-row">
                <span className="detail-label">Model:</span>
                <span className="detail-value">{device.model}</span>
              </div>
              <div className="detail-row">
                <span className="detail-label">Trust Status:</span>
                <span className={`status-pill ${device.is_trusted ? "pill-success" : "pill-warning"}`}>
                  {device.is_trusted ? "Trusted" : "Untrusted / Locked"}
                </span>
              </div>
              <div className="detail-row">
                <span className="detail-label">Developer Mode:</span>
                <span className={`status-pill ${device.developer_mode_enabled ? "pill-success" : "pill-danger"}`}>
                  {device.developer_mode_enabled ? "Enabled" : "Disabled"}
                </span>
              </div>
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
                <span className="detail-value">{appleSession.team_name} ({appleSession.team_id})</span>
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
          <div className="installed-apps-table">
            {/* Installed apps listed in M5 */}
          </div>
        )}
      </section>
    </div>
  );
};
