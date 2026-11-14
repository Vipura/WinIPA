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
  appleLogin,
  appleSubmit2Fa,
  appleGetSession,
  appleLogout,
} from "../api/apple";
import { getInstalledApps, removeInstalledApp } from "../api/pipeline";
import { getRedactedDiagnostics, exportDiagnosticsToFile } from "../api/diagnostics";
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
  LogOut,
  X,
  ShieldCheck,
  Calendar,
  CheckCircle2,
  Info,
  Trash2,
  Download,
  PlusCircle,
} from "lucide-react";

interface DeviceAccountScreenProps {
  onNavigate: (view: "home" | "install" | "device-account") => void;
  appleSession?: AppleSessionInfo | null;
  onSessionChange?: (session: AppleSessionInfo | null) => void;
}

export const DeviceAccountScreen: React.FC<DeviceAccountScreenProps> = ({
  onNavigate,
  appleSession: initialAppleSession,
  onSessionChange,
}) => {
  const [driverStatus, setDriverStatus] = useState<DeviceDriverStatus | null>(null);
  const [devices, setDevices] = useState<DeviceInfo[]>([]);
  const [appleSession, setAppleSession] = useState<AppleSessionInfo | null>(
    initialAppleSession || null
  );

  useEffect(() => {
    if (initialAppleSession !== undefined) {
      setAppleSession(initialAppleSession);
    }
  }, [initialAppleSession]);
  const [installedApps, setInstalledApps] = useState<InstalledAppRecord[]>([]);
  const [isRefreshing, setIsRefreshing] = useState<boolean>(false);
  const [isExportingDiagnostics, setIsExportingDiagnostics] = useState<boolean>(false);
  const [diagnosticsExportMsg, setDiagnosticsExportMsg] = useState<string | null>(null);
  const [manualDevModeConfirmed, setManualDevModeConfirmed] = useState<boolean>(false);

  // Auth Modal State
  const [isAuthModalOpen, setIsAuthModalOpen] = useState<boolean>(false);
  const [authStep, setAuthStep] = useState<"credentials" | "2fa">("credentials");
  const [email, setEmail] = useState<string>("");
  const [password, setPassword] = useState<string>("");
  const [twoFaCode, setTwoFaCode] = useState<string>("");
  const [authLoading, setAuthLoading] = useState<boolean>(false);
  const [authError, setAuthError] = useState<string | null>(null);

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

      // Check for active Apple session
      const session = await appleGetSession();
      setAppleSession(session);

      // Load installed sideloaded apps
      const apps = await getInstalledApps();
      setInstalledApps(apps);
    } catch (err) {
      console.error("Failed to load device/driver/session status:", err);
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
      const session = await appleGetSession();
      setAppleSession(session);
      const apps = await getInstalledApps();
      setInstalledApps(apps);
    } catch (err) {
      console.error("Error refreshing devices/session:", err);
    } finally {
      setIsRefreshing(false);
    }
  };

  const handleOpenLogin = () => {
    setAuthStep("credentials");
    setEmail("");
    setPassword("");
    setTwoFaCode("");
    setAuthError(null);
    setIsAuthModalOpen(true);
  };

  const handleCloseModal = () => {
    if (authLoading) return;
    setIsAuthModalOpen(false);
    setAuthError(null);
    setPassword("");
    setTwoFaCode("");
  };

  const handleSignInSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!email.trim() || !password.trim()) {
      setAuthError("Please provide both Apple ID email and password.");
      return;
    }

    setAuthLoading(true);
    setAuthError(null);

    try {
      const res = await appleLogin(email.trim(), password);
      if (res.type === "Success") {
        setAppleSession(res.data);
        onSessionChange?.(res.data);
        setIsAuthModalOpen(false);
        setPassword("");
      } else if (res.type === "TwoFactorRequired") {
        setAuthStep("2fa");
      }
    } catch (err: unknown) {
      const msg = typeof err === "string" ? err : (err as Error)?.message || "Failed to sign in to Apple ID";
      setAuthError(msg);
    } finally {
      setAuthLoading(false);
    }
  };

  const handleTwoFaSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (twoFaCode.length < 6) {
      setAuthError("Please enter the complete 6-digit verification code.");
      return;
    }

    setAuthLoading(true);
    setAuthError(null);

    try {
      const session = await appleSubmit2Fa(twoFaCode.trim());
      setAppleSession(session);
      onSessionChange?.(session);
      setIsAuthModalOpen(false);
      setPassword("");
      setTwoFaCode("");
    } catch (err: unknown) {
      const msg = typeof err === "string" ? err : (err as Error)?.message || "Two-factor verification failed";
      setAuthError(msg);
    } finally {
      setAuthLoading(false);
    }
  };

  const handleLogout = async () => {
    try {
      await appleLogout();
      setAppleSession(null);
      onSessionChange?.(null);
    } catch (err) {
      console.error("Failed to log out:", err);
    }
  };

  const handleRemoveApp = async (bundleId: string) => {
    try {
      await removeInstalledApp(bundleId);
      setInstalledApps((prev) => prev.filter((a) => a.bundle_id !== bundleId));
    } catch (err) {
      console.error("Failed to remove app from store:", err);
    }
  };

  const handleExportDiagnostics = async () => {
    setIsExportingDiagnostics(true);
    setDiagnosticsExportMsg(null);
    try {
      const savedPath = await exportDiagnosticsToFile();
      const report = await getRedactedDiagnostics();
      await navigator.clipboard.writeText(report);
      setDiagnosticsExportMsg(`Diagnostics saved to: ${savedPath} (and copied to clipboard)`);
      setTimeout(() => setDiagnosticsExportMsg(null), 8000);
    } catch (err) {
      console.error("Failed to export diagnostics:", err);
      setDiagnosticsExportMsg("Failed to export diagnostics");
      setTimeout(() => setDiagnosticsExportMsg(null), 4000);
    } finally {
      setIsExportingDiagnostics(false);
    }
  };

  const activeDevice = devices.length > 0 ? devices[0] : null;

  // Calculate certificate days remaining
  const calculateDaysLeft = (expiryTimestamp?: number): number | null => {
    if (!expiryTimestamp) return null;
    const nowSecs = Math.floor(Date.now() / 1000);
    const diffSecs = expiryTimestamp - nowSecs;
    return Math.max(0, Math.ceil(diffSecs / 86400));
  };

  const daysLeft = calculateDaysLeft(appleSession?.cert_expires_at);

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

        <div style={{ display: "flex", gap: "0.5rem", alignItems: "center" }}>
          <button
            type="button"
            className="btn btn-outline btn-sm"
            onClick={handleExportDiagnostics}
            disabled={isExportingDiagnostics}
            title="Export redacted diagnostics report to file and clipboard"
            style={{ display: "flex", gap: "0.4rem", alignItems: "center" }}
          >
            {isExportingDiagnostics ? (
              <RefreshCw size={14} className="spin-icon" />
            ) : (
              <Download size={14} />
            )}
            <span>Export Diagnostics</span>
          </button>

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
      </div>

      {/* Diagnostics Export Notification */}
      {diagnosticsExportMsg && (
        <div
          className="status-notice notice-info mb-4"
          style={{
            backgroundColor: "var(--accent-light)",
            border: "1px solid var(--accent)",
            color: "var(--text-main)",
            display: "flex",
            alignItems: "center",
            gap: "0.6rem",
          }}
        >
          <CheckCircle2 size={16} className="text-accent shrink-0" />
          <span style={{ fontSize: "0.85rem" }}>{diagnosticsExportMsg}</span>
        </div>
      )}

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
                    activeDevice.developer_mode_enabled || manualDevModeConfirmed
                      ? "pill-success"
                      : "pill-warning"
                  }`}
                >
                  {activeDevice.developer_mode_enabled || manualDevModeConfirmed
                    ? "Enabled"
                    : "Disabled / Unverified"}
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
              {!activeDevice.developer_mode_enabled && !manualDevModeConfirmed && (
                <div className="status-notice notice-danger mt-3">
                  <ShieldX size={16} className="shrink-0" />
                  <div>
                    <strong>{STRINGS.device.developerModeTitle}</strong>
                    <p className="text-sm mt-0.5">{STRINGS.device.developerModeMsg}</p>
                    <button
                      type="button"
                      className="btn btn-outline btn-sm text-accent mt-2"
                      onClick={() => setManualDevModeConfirmed(true)}
                      style={{ fontSize: "0.75rem", padding: "0.25rem 0.6rem" }}
                    >
                      I have already enabled Developer Mode
                    </button>
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
                <span className="detail-value font-mono">{appleSession.apple_id}</span>
              </div>
              <div className="detail-row">
                <span className="detail-label">Team:</span>
                <span className="detail-value">
                  {appleSession.team_name} ({appleSession.team_id})
                </span>
              </div>
              <div className="detail-row">
                <span className="detail-label">Account Tier:</span>
                <span
                  className={`tier-badge ${
                    appleSession.account_type === "Paid" ? "paid" : "free"
                  }`}
                >
                  {appleSession.account_type} Account
                </span>
              </div>

              {appleSession.cert_expires_at && daysLeft !== null && (
                <div className="detail-row">
                  <span className="detail-label">Certificate Status:</span>
                  <span
                    className={`cert-expiry-pill ${
                      daysLeft > 2 ? "valid" : "expiring-soon"
                    }`}
                  >
                    <Calendar size={12} style={{ display: "inline", marginRight: "4px" }} />
                    {daysLeft > 0
                      ? `${daysLeft} days remaining (${new Date(
                          appleSession.cert_expires_at * 1000
                        ).toLocaleDateString()})`
                      : "Expired"}
                  </span>
                </div>
              )}

              <button
                type="button"
                className="btn btn-outline btn-sm mt-3"
                onClick={handleLogout}
                style={{ display: "inline-flex", gap: "0.4rem", alignItems: "center" }}
              >
                <LogOut size={14} />
                <span>{STRINGS.device.logoutBtn}</span>
              </button>
            </div>
          ) : (
            <div className="empty-state">
              <KeyRound size={32} className="text-muted mb-2" />
              <p className="empty-msg">{STRINGS.device.notLoggedIn}</p>
              <button
                type="button"
                className="btn btn-primary btn-sm mt-2"
                onClick={handleOpenLogin}
              >
                {STRINGS.device.loginBtn}
              </button>
            </div>
          )}

          {/* Honest Account Limits Disclosure */}
          <div className="account-limits-box mt-4">
            <ShieldAlert size={16} className="text-info shrink-0 mt-0.5" />
            <div className="limits-text">
              {appleSession?.account_type === "Paid" ? (
                <>
                  <strong>{STRINGS.device.auth.paidLimitsTitle}</strong>
                  <div className="limits-item">
                    <CheckCircle2 size={13} className="text-success shrink-0 mt-0.5" />
                    <span>{STRINGS.device.auth.paidLimit1}</span>
                  </div>
                  <div className="limits-item">
                    <CheckCircle2 size={13} className="text-success shrink-0 mt-0.5" />
                    <span>{STRINGS.device.auth.paidLimit2}</span>
                  </div>
                  <div className="limits-item">
                    <CheckCircle2 size={13} className="text-success shrink-0 mt-0.5" />
                    <span>{STRINGS.device.auth.paidLimit3}</span>
                  </div>
                </>
              ) : (
                <>
                  <strong>{STRINGS.device.auth.freeLimitsTitle}</strong>
                  <div className="limits-item">
                    <Info size={13} className="text-muted shrink-0 mt-0.5" />
                    <span>{STRINGS.device.auth.freeLimit1}</span>
                  </div>
                  <div className="limits-item">
                    <Info size={13} className="text-muted shrink-0 mt-0.5" />
                    <span>{STRINGS.device.auth.freeLimit2}</span>
                  </div>
                  <div className="limits-item">
                    <Info size={13} className="text-muted shrink-0 mt-0.5" />
                    <span>{STRINGS.device.auth.freeLimit3}</span>
                  </div>
                  <div className="limits-item">
                    <Info size={13} className="text-muted shrink-0 mt-0.5" />
                    <span>{STRINGS.device.auth.freeLimit4}</span>
                  </div>
                </>
              )}
            </div>
          </div>
        </section>
      </div>

      {/* Installed Apps Section */}
      <section className="info-card full-width mt-4">
        <h3 className="section-title mb-3">{STRINGS.device.appsSection}</h3>
        {installedApps.length === 0 ? (
          <div className="empty-state">
            <p className="empty-msg text-center mb-3">{STRINGS.device.noApps}</p>
            <button
              type="button"
              className="btn btn-primary btn-sm"
              onClick={() => onNavigate("install")}
              style={{ display: "inline-flex", gap: "0.4rem", alignItems: "center" }}
            >
              <PlusCircle size={14} />
              <span>Install New IPA</span>
            </button>
          </div>
        ) : (
          <div style={{ overflowX: "auto" }}>
            <table className="installed-apps-table">
              <thead>
                <tr>
                  <th>App Name</th>
                  <th>Bundle ID</th>
                  <th>Version</th>
                  <th>Installed Date</th>
                  <th>Certificate Expiry</th>
                  <th style={{ textAlign: "right" }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {installedApps.map((app) => {
                  const days = calculateDaysLeft(app.cert_expires_at);
                  return (
                    <tr key={app.bundle_id}>
                      <td style={{ fontWeight: 600 }}>{app.app_name}</td>
                      <td>
                        <code className="font-mono" style={{ fontSize: "0.8rem" }}>
                          {app.bundle_id}
                        </code>
                      </td>
                      <td>{app.version}</td>
                      <td>{new Date(app.installed_at * 1000).toLocaleDateString()}</td>
                      <td>
                        {days !== null ? (
                          days > 2 ? (
                            <span className="cert-expiry-pill valid">
                              <Calendar size={12} style={{ display: "inline", marginRight: "4px" }} />
                              {days} days left
                            </span>
                          ) : days > 0 ? (
                            <span className="cert-expiry-pill expiring-soon">
                              <AlertTriangle size={12} style={{ display: "inline", marginRight: "4px" }} />
                              {days} {days === 1 ? "day" : "days"} left
                            </span>
                          ) : (
                            <span className="status-pill pill-danger">Expired</span>
                          )
                        ) : (
                          <span className="text-muted">N/A</span>
                        )}
                      </td>
                      <td style={{ textAlign: "right" }}>
                        <div style={{ display: "inline-flex", gap: "0.4rem" }}>
                          {days !== null && days <= 2 && (
                            <button
                              type="button"
                              className="btn btn-outline btn-sm text-accent"
                              onClick={() => onNavigate("install")}
                              title="Re-sign and install"
                              style={{ padding: "0.25rem 0.5rem", fontSize: "0.75rem" }}
                            >
                              <RefreshCw size={12} style={{ marginRight: "3px" }} />
                              Re-sign
                            </button>
                          )}
                          <button
                            type="button"
                            className="btn btn-outline btn-sm text-danger"
                            onClick={() => handleRemoveApp(app.bundle_id)}
                            title="Remove from history"
                            style={{ padding: "0.25rem 0.5rem" }}
                          >
                            <Trash2 size={14} />
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {/* Apple ID Sign-In & 2FA Modal */}
      {isAuthModalOpen && (
        <div className="modal-overlay" role="dialog" aria-modal="true">
          <div className="modal-card">
            <div className="modal-header">
              <h3 className="modal-title">
                {authStep === "credentials"
                  ? STRINGS.device.auth.signInTitle
                  : STRINGS.device.auth.twoFactorTitle}
              </h3>
              <button
                type="button"
                className="modal-close-btn"
                onClick={handleCloseModal}
                disabled={authLoading}
                aria-label="Close"
              >
                <X size={18} />
              </button>
            </div>

            {authStep === "credentials" ? (
              <form onSubmit={handleSignInSubmit}>
                <div className="modal-body">
                  <div className="auth-security-notice">
                    <ShieldCheck size={20} className="text-accent shrink-0 mt-0.5" />
                    <span>{STRINGS.device.auth.privacyNotice}</span>
                  </div>

                  {authError && (
                    <div className="status-notice notice-danger">
                      <AlertTriangle size={16} className="shrink-0" />
                      <span>{authError}</span>
                    </div>
                  )}

                  <div className="form-group">
                    <label className="form-label" htmlFor="apple-id-input">
                      {STRINGS.device.auth.emailLabel}
                    </label>
                    <input
                      id="apple-id-input"
                      type="email"
                      className="form-input"
                      placeholder={STRINGS.device.auth.emailPlaceholder}
                      value={email}
                      onChange={(e) => setEmail(e.target.value)}
                      disabled={authLoading}
                      required
                      autoFocus
                    />
                  </div>

                  <div className="form-group">
                    <label className="form-label" htmlFor="apple-password-input">
                      {STRINGS.device.auth.passwordLabel}
                    </label>
                    <input
                      id="apple-password-input"
                      type="password"
                      className="form-input"
                      placeholder={STRINGS.device.auth.passwordPlaceholder}
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      disabled={authLoading}
                      required
                    />
                  </div>
                </div>

                <div className="modal-footer">
                  <button
                    type="button"
                    className="btn btn-outline btn-sm"
                    onClick={handleCloseModal}
                    disabled={authLoading}
                  >
                    {STRINGS.device.auth.cancelBtn}
                  </button>
                  <button
                    type="submit"
                    className="btn btn-primary btn-sm"
                    disabled={authLoading}
                    style={{ display: "inline-flex", gap: "0.4rem", alignItems: "center" }}
                  >
                    {authLoading && <RefreshCw size={14} className="spin-icon" />}
                    <span>
                      {authLoading
                        ? STRINGS.device.auth.signingIn
                        : STRINGS.device.auth.signInBtn}
                    </span>
                  </button>
                </div>
              </form>
            ) : (
              <form onSubmit={handleTwoFaSubmit}>
                <div className="modal-body">
                  <p className="text-sm text-muted">
                    {STRINGS.device.auth.twoFactorPrompt}
                  </p>

                  {authError && (
                    <div className="status-notice notice-danger">
                      <AlertTriangle size={16} className="shrink-0" />
                      <span>{authError}</span>
                    </div>
                  )}

                  <div className="form-group">
                    <input
                      id="twofa-code-input"
                      type="text"
                      className="form-input code-input"
                      placeholder="······"
                      maxLength={6}
                      value={twoFaCode}
                      onChange={(e) =>
                        setTwoFaCode(e.target.value.replace(/\D/g, "").slice(0, 6))
                      }
                      disabled={authLoading}
                      required
                      autoFocus
                    />
                  </div>
                </div>

                <div className="modal-footer">
                  <button
                    type="button"
                    className="btn btn-outline btn-sm"
                    onClick={() => {
                      setAuthStep("credentials");
                      setAuthError(null);
                    }}
                    disabled={authLoading}
                  >
                    Back
                  </button>
                  <button
                    type="submit"
                    className="btn btn-primary btn-sm"
                    disabled={authLoading || twoFaCode.length < 6}
                    style={{ display: "inline-flex", gap: "0.4rem", alignItems: "center" }}
                  >
                    {authLoading && <RefreshCw size={14} className="spin-icon" />}
                    <span>
                      {authLoading
                        ? STRINGS.device.auth.verifying
                        : STRINGS.device.auth.verifyBtn}
                    </span>
                  </button>
                </div>
              </form>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
