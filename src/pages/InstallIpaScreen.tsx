// Copyright (C) 2026 WinIPA Contributors
// SPDX-License-Identifier: GPL-3.0-only

import React, { useState, useEffect, useCallback } from "react";
import { STRINGS } from "../strings";
import {
  IpaMetadata,
  ErrorDetail,
  DeviceInfo,
  AppleSessionInfo,
  PipelineStatus,
  PipelineResult,
} from "../types";
import { inspectIpaPackage, pickIpaFile } from "../api/ipa";
import { getCurrentWebviewWindow } from "@tauri-apps/api/webviewWindow";
import { getConnectedDevices } from "../api/device";
import { appleGetSession, appleLogout, appleSetTeamId } from "../api/apple";
import {
  startInstallationPipeline,
  cancelInstallationPipeline,
  listenToPipelineStatus,
} from "../api/pipeline";
import { getRedactedDiagnostics } from "../api/diagnostics";
import { openUrl } from "@tauri-apps/plugin-opener";
import {
  ArrowLeft,
  UploadCloud,
  Package,
  AlertTriangle,
  CheckCircle2,
  RefreshCw,
  FileCode,
  Smartphone,
  User,
  ShieldCheck,
  ShieldAlert,
  XCircle,
  Copy,
  Check,
  Info,
  LogOut,
  ExternalLink,
} from "lucide-react";

interface InstallIpaScreenProps {
  onNavigate: (view: "home" | "install" | "device-account") => void;
  appleSession?: AppleSessionInfo | null;
  onSessionRefresh?: () => void;
  onLogout?: () => void;
}

export const InstallIpaScreen: React.FC<InstallIpaScreenProps> = ({
  onNavigate,
  appleSession: propAppleSession,
  onSessionRefresh,
  onLogout,
}) => {
  const [isDragging, setIsDragging] = useState<boolean>(false);
  const [isInspecting, setIsInspecting] = useState<boolean>(false);
  const [metadata, setMetadata] = useState<IpaMetadata | null>(null);
  const [iconError, setIconError] = useState<boolean>(false);
  const [errorDetail, setErrorDetail] = useState<ErrorDetail | null>(null);
  const [manualPath, setManualPath] = useState<string>("");

  // Device & Account prerequisites
  const [devices, setDevices] = useState<DeviceInfo[]>([]);
  const [selectedUdid, setSelectedUdid] = useState<string>("");
  const [appleSession, setAppleSession] = useState<AppleSessionInfo | null>(
    propAppleSession || null
  );
  const [customBundleId, setCustomBundleId] = useState<string>("");

  useEffect(() => {
    if (propAppleSession !== undefined) {
      setAppleSession(propAppleSession);
    }
  }, [propAppleSession]);

  const handleLogout = async () => {
    try {
      await appleLogout();
      setAppleSession(null);
      onLogout?.();
      onSessionRefresh?.();
    } catch (err) {
      console.error("Failed to log out:", err);
    }
  };

  // Pipeline execution state
  const [isPipelineRunning, setIsPipelineRunning] = useState<boolean>(false);
  const [pipelineStatus, setPipelineStatus] = useState<PipelineStatus>({
    step: "Idle",
    progress: 0,
    message: "",
  });
  const [pipelineResult, setPipelineResult] = useState<PipelineResult | null>(null);
  const [pipelineError, setPipelineError] = useState<string | null>(null);
  const [copiedDiagnostics, setCopiedDiagnostics] = useState<boolean>(false);
  const [manualDevModeConfirmed, setManualDevModeConfirmed] = useState<boolean>(false);

  // Team ID Prompt State for Error 3050 / Free Personal Team
  const [teamIdInput, setTeamIdInput] = useState<string>("");
  const [teamIdSaving, setTeamIdSaving] = useState<boolean>(false);
  const [teamIdError, setTeamIdError] = useState<string | null>(null);

  const handleSaveTeamIdAndRetry = async () => {
    const clean = teamIdInput.trim().toUpperCase();
    if (clean.length !== 10 || !/^[A-Z0-9]{10}$/.test(clean)) {
      setTeamIdError("Team ID must be exactly 10 alphanumeric characters (e.g. 7X8Y9Z1A2B).");
      return;
    }
    setTeamIdSaving(true);
    setTeamIdError(null);
    try {
      const updated = await appleSetTeamId(clean);
      setAppleSession(updated);
      onSessionRefresh?.();
      setPipelineError(null);
      setTeamIdInput("");
      handleStartInstallation();
    } catch (err: any) {
      setTeamIdError(typeof err === "string" ? err : err?.message || "Failed to update Team ID");
    } finally {
      setTeamIdSaving(false);
    }
  };

  // Load prerequisites on mount
  const refreshPrerequisites = useCallback(async () => {
    try {
      const devs = await getConnectedDevices();
      setDevices(devs);
      if (devs.length > 0 && !selectedUdid) {
        setSelectedUdid(devs[0].udid);
      }
      const session = await appleGetSession();
      setAppleSession(session);
    } catch (err) {
      console.error("Failed to load prerequisites:", err);
    }
  }, [selectedUdid]);

  useEffect(() => {
    refreshPrerequisites();
  }, [refreshPrerequisites]);

  // Subscribe to pipeline progress events
  useEffect(() => {
    let unlisten: (() => void) | undefined;
    listenToPipelineStatus((status) => {
      setPipelineStatus(status);
    }).then((unsub) => {
      unlisten = unsub;
    });

    return () => {
      unlisten?.();
    };
  }, []);

  useEffect(() => {
    let unlisten: (() => void) | undefined;
    getCurrentWebviewWindow()
      .onDragDropEvent((event) => {
        if (event.payload.type === "drop") {
          const paths = event.payload.paths;
          if (paths && paths.length > 0) {
            setManualPath(paths[0]);
            handleInspect(paths[0]);
          }
        }
      })
      .then((unsub) => {
        unlisten = unsub;
      })
      .catch((err) => {
        console.warn("Native drag-drop listener error:", err);
      });

    return () => {
      unlisten?.();
    };
  }, []);

  const handleInspect = async (filePath: string) => {
    setIsInspecting(true);
    setErrorDetail(null);
    setMetadata(null);
    setIconError(false);
    setPipelineResult(null);
    setPipelineError(null);

    try {
      const meta = await inspectIpaPackage(filePath);
      setMetadata(meta);
      await refreshPrerequisites();
    } catch (err: unknown) {
      const errorObj = err as ErrorDetail;
      if (errorObj && errorObj.title && errorObj.message) {
        setErrorDetail(errorObj);
      } else {
        setErrorDetail({
          code: "InspectionError",
          title: "Inspection Failed",
          message: String(err),
          remedy: "Verify the file is a valid, readable iOS .ipa archive.",
        });
      }
    } finally {
      setIsInspecting(false);
    }
  };

  const handleStartInstallation = async () => {
    if (!metadata || !selectedUdid) return;

    setIsPipelineRunning(true);
    setPipelineError(null);
    setPipelineResult(null);
    setPipelineStatus({
      step: "Inspecting",
      progress: 5.0,
      message: "Starting installation pipeline...",
    });

    try {
      const res = await startInstallationPipeline({
        ipa_path: metadata.file_path,
        target_udid: selectedUdid,
        custom_bundle_id: customBundleId.trim() || undefined,
      });
      setPipelineResult(res);
      setPipelineStatus({
        step: "Completed",
        progress: 100.0,
        message: "Installation complete!",
      });
    } catch (err: unknown) {
      const msg = typeof err === "string" ? err : (err as Error)?.message || "Installation pipeline failed";
      setPipelineError(msg);
      setPipelineStatus({
        step: "Failed",
        progress: 0.0,
        message: msg,
      });
    } finally {
      setIsPipelineRunning(false);
    }
  };

  const handleCancelPipeline = async () => {
    try {
      await cancelInstallationPipeline();
    } catch (err) {
      console.error("Failed to cancel pipeline:", err);
    }
  };

  const handleCopyDiagnostics = async () => {
    try {
      const fullSystemReport = await getRedactedDiagnostics();
      const diagnostics = `=== WINIPA PIPELINE ERROR DIAGNOSTICS ===
Step: ${pipelineStatus.step}
Message: ${pipelineStatus.message}
Error: ${pipelineError || errorDetail?.message || "None"}
App: ${metadata?.app_name || "None"} (${metadata?.bundle_id || "None"})
Timestamp: ${new Date().toISOString()}

${fullSystemReport}`;
      await navigator.clipboard.writeText(diagnostics);
    } catch {
      const fallback = `Error: ${pipelineError || errorDetail?.message || "None"}\nStep: ${pipelineStatus.step}\nTime: ${new Date().toISOString()}`;
      await navigator.clipboard.writeText(fallback);
    }
    setCopiedDiagnostics(true);
    setTimeout(() => setCopiedDiagnostics(false), 2500);
  };

  const handleBrowseFile = async () => {
    try {
      const picked = await pickIpaFile();
      if (picked) {
        setManualPath(picked);
        handleInspect(picked);
      }
    } catch (err) {
      console.error("Failed to pick file:", err);
    }
  };

  const onDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(true);
  };

  const onDragLeave = () => {
    setIsDragging(false);
  };

  const onDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);

    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      const file = e.dataTransfer.files[0];
      const filePath = (file as unknown as { path?: string }).path || file.name;
      setManualPath(filePath);
      handleInspect(filePath);
    }
  };

  const loadFixture = (fixtureName: string) => {
    const path = `tests/fixtures/${fixtureName}`;
    setManualPath(path);
    handleInspect(path);
  };

  const activeDevice = devices.find((d) => d.udid === selectedUdid) || (devices.length > 0 ? devices[0] : null);

  // Check if free account will strip entitlements
  const restrictedEntitlements = [
    "aps-environment",
    "com.apple.developer.associated-domains",
    "com.apple.developer.in-app-payments",
    "com.apple.developer.siri",
    "com.apple.security.application-groups",
  ];
  const detectedStripped = metadata?.original_entitlements.filter((e) =>
    restrictedEntitlements.some((r) => e.includes(r))
  ) || [];

  return (
    <div className="install-ipa-screen">
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
          <h2 className="page-title">{STRINGS.installFlow.title}</h2>
        </div>

        {metadata && !isPipelineRunning && (
          <button
            type="button"
            className="btn btn-outline btn-sm"
            onClick={() => {
              setMetadata(null);
              setErrorDetail(null);
              setPipelineResult(null);
              setPipelineError(null);
            }}
          >
            Select Different IPA
          </button>
        )}
      </div>

      {/* Step 1: File Dropzone (if no IPA picked) */}
      {!metadata && !errorDetail && (
        <>
          <div
            className={`dropzone-container ${isDragging ? "dropzone-active" : ""}`}
            onDragOver={onDragOver}
            onDragLeave={onDragLeave}
            onDrop={onDrop}
            onClick={handleBrowseFile}
          >
            {isInspecting ? (
              <div className="inspecting-state">
                <RefreshCw size={44} className="spin-icon text-accent mb-3" />
                <h3 className="dropzone-title">Inspecting IPA Package...</h3>
                <p className="dropzone-subtitle">Reading Info.plist and scanning Mach-O binaries</p>
              </div>
            ) : (
              <>
                <UploadCloud size={48} className="dropzone-icon" />
                <h3 className="dropzone-title">{STRINGS.installFlow.dropPrompt}</h3>
                <p className="dropzone-subtitle">{STRINGS.installFlow.supportedFormat}</p>
                <button
                  type="button"
                  className="btn btn-primary mt-3"
                  onClick={(e) => {
                    e.stopPropagation();
                    handleBrowseFile();
                  }}
                >
                  Browse .ipa File
                </button>
              </>
            )}
          </div>

          {/* Quick Test Fixtures bar */}
          <div className="fixtures-bar mt-4">
            <span className="fixtures-label">
              <FileCode size={14} style={{ display: "inline", marginRight: 4 }} />
              Quick Test Fixtures:
            </span>
            <div className="fixtures-buttons">
              <button
                type="button"
                className="btn btn-outline btn-sm"
                onClick={() => loadFixture("valid.ipa")}
              >
                Valid IPA
              </button>
              <button
                type="button"
                className="btn btn-outline btn-sm"
                onClick={() => loadFixture("encrypted.ipa")}
              >
                Encrypted DRM IPA
              </button>
              <button
                type="button"
                className="btn btn-outline btn-sm"
                onClick={() => loadFixture("no_plist.ipa")}
              >
                Missing Info.plist
              </button>
              <button
                type="button"
                className="btn btn-outline btn-sm"
                onClick={() => loadFixture("invalid.ipa")}
              >
                Corrupted IPA
              </button>
            </div>
          </div>

          {/* Manual Path input */}
          <div className="manual-path-box mt-3">
            <input
              type="text"
              className="path-input"
              placeholder="Or enter path to .ipa (e.g. C:\Users\User\Downloads\App.ipa)..."
              value={manualPath}
              onChange={(e) => setManualPath(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter" && manualPath.trim()) {
                  handleInspect(manualPath.trim());
                }
              }}
            />
            <button
              type="button"
              className="btn btn-primary btn-sm"
              disabled={!manualPath.trim() || isInspecting}
              onClick={() => handleInspect(manualPath.trim())}
            >
              Inspect
            </button>
          </div>
        </>
      )}

      {/* Error state presentation */}
      {errorDetail && (
        <div className="inspection-error-card mt-4">
          <div className="error-header-row">
            <AlertTriangle size={28} className="text-danger shrink-0" />
            <div>
              <h3 className="error-card-title">{errorDetail.title}</h3>
              <span className="error-code-badge">Error Code: {errorDetail.code}</span>
            </div>
          </div>

          <div className="error-card-body">
            <p className="error-message-text">{errorDetail.message}</p>
            <div className="error-remedy-box">
              <strong>Next Step:</strong>
              <p className="mt-1">{errorDetail.remedy}</p>
            </div>
          </div>

          <div className="error-card-actions">
            <button
              type="button"
              className="btn btn-primary btn-sm"
              onClick={() => setErrorDetail(null)}
            >
              Try Another IPA
            </button>
          </div>
        </div>
      )}

      {/* Pipeline Active Progress View */}
      {isPipelineRunning && (
        <div className="pipeline-card mt-4">
          <div className="pipeline-header">
            <div>
              <h3 className="text-lg font-bold">{STRINGS.installFlow.pipelineTitle}</h3>
              <p className="text-sm text-muted mt-0.5">{pipelineStatus.message}</p>
            </div>
            <button
              type="button"
              className="btn btn-outline btn-sm"
              onClick={handleCancelPipeline}
              style={{ display: "inline-flex", gap: "0.4rem", alignItems: "center" }}
            >
              <XCircle size={14} className="text-danger" />
              <span>{STRINGS.installFlow.cancelBtn}</span>
            </button>
          </div>

          <div className="progress-track">
            <div
              className="progress-fill"
              style={{ width: `${Math.min(100, Math.max(5, pipelineStatus.progress))}%` }}
            />
          </div>

          <div className="pipeline-steps-list">
            <div className="pipeline-step-row">
              <div
                className={`pipeline-step-icon ${
                  pipelineStatus.progress >= 20 ? "completed" : "active"
                }`}
              >
                {pipelineStatus.progress >= 20 ? <Check size={14} /> : "1"}
              </div>
              <span>Package Inspection & Metadata Extraction</span>
            </div>

            <div className="pipeline-step-row">
              <div
                className={`pipeline-step-icon ${
                  pipelineStatus.progress >= 40
                    ? "completed"
                    : pipelineStatus.progress >= 20
                    ? "active"
                    : "pending"
                }`}
              >
                {pipelineStatus.progress >= 40 ? <Check size={14} /> : "2"}
              </div>
              <span>Device USB Handshake & Developer Mode Verification</span>
            </div>

            <div className="pipeline-step-row">
              <div
                className={`pipeline-step-icon ${
                  pipelineStatus.progress >= 60
                    ? "completed"
                    : pipelineStatus.progress >= 40
                    ? "active"
                    : "pending"
                }`}
              >
                {pipelineStatus.progress >= 60 ? <Check size={14} /> : "3"}
              </div>
              <span>Developer Certificate & Provisioning Profile Issuance</span>
            </div>

            <div className="pipeline-step-row">
              <div
                className={`pipeline-step-icon ${
                  pipelineStatus.progress >= 70
                    ? "completed"
                    : pipelineStatus.progress >= 60
                    ? "active"
                    : "pending"
                }`}
              >
                {pipelineStatus.progress >= 70 ? <Check size={14} /> : "4"}
              </div>
              <span>Local Entitlement Sanitization & Code Re-signing</span>
            </div>

            <div className="pipeline-step-row">
              <div
                className={`pipeline-step-icon ${
                  pipelineStatus.progress >= 100
                    ? "completed"
                    : pipelineStatus.progress >= 70
                    ? "active"
                    : "pending"
                }`}
              >
                {pipelineStatus.progress >= 100 ? <Check size={14} /> : "5"}
              </div>
              <span>USB Installation & SpringBoard App Registration</span>
            </div>
          </div>
        </div>
      )}

      {/* Result: Success View */}
      {pipelineResult && !isPipelineRunning && (
        <div className="success-card mt-4">
          <CheckCircle2 size={48} className="text-success mb-1" />
          <h3 className="text-xl font-bold">{STRINGS.installFlow.successTitle}</h3>
          <p className="text-sm text-muted">{STRINGS.installFlow.successSub}</p>

          <div className="trust-guide-box">
            <h4 className="trust-guide-title">
              <ShieldCheck size={18} className="text-accent" />
              <span>{STRINGS.installFlow.firstTimeTrustTitle}</span>
            </h4>
            <ol className="trust-steps-list">
              <li>{STRINGS.installFlow.firstTimeTrustStep1}</li>
              <li>{STRINGS.installFlow.firstTimeTrustStep2}</li>
              <li>{STRINGS.installFlow.firstTimeTrustStep3}</li>
              <li>{STRINGS.installFlow.firstTimeTrustStep4}</li>
            </ol>
            <div className="limits-item mt-3">
              <Info size={14} className="text-accent shrink-0 mt-0.5" />
              <span>{STRINGS.installFlow.devModeReminder}</span>
            </div>
          </div>

          {pipelineResult.stripped_entitlements.length > 0 && (
            <div className="stripped-entitlements-box text-left w-full max-w-xl">
              <strong>{STRINGS.installFlow.entitlementsNoticeTitle}</strong>
              <p className="mt-1">{STRINGS.installFlow.entitlementsNoticeDesc}</p>
              <div className="mt-2">
                {pipelineResult.stripped_entitlements.map((ent) => (
                  <span key={ent} className="entitlement-pill">
                    {ent}
                  </span>
                ))}
              </div>
            </div>
          )}

          <div style={{ display: "flex", gap: "1rem", marginTop: "1rem" }}>
            <button
              type="button"
              className="btn btn-outline btn-sm"
              onClick={() => onNavigate("device-account")}
            >
              View Installed Apps
            </button>
            <button
              type="button"
              className="btn btn-primary btn-sm"
              onClick={() => {
                setMetadata(null);
                setPipelineResult(null);
              }}
            >
              {STRINGS.installFlow.installAnotherBtn}
            </button>
          </div>
        </div>
      )}

      {/* Result: Pipeline Failure View */}
      {pipelineError && !isPipelineRunning && (
        <div className="inspection-error-card mt-4">
          <div className="error-header-row">
            <AlertTriangle size={28} className="text-danger shrink-0" />
            <div>
              <h3 className="error-card-title">Installation Failed</h3>
              <span className="error-code-badge">Pipeline Error</span>
            </div>
          </div>

          <div className="error-card-body">
            <p className="error-message-text">{pipelineError}</p>

            {pipelineError &&
              (pipelineError.includes("3050") ||
                pipelineError.toLowerCase().includes("team")) && (
                <div
                  className="team-id-fix-box mt-3 p-3 rounded"
                  style={{
                    background: "rgba(245, 158, 11, 0.08)",
                    border: "1px solid rgba(245, 158, 11, 0.3)",
                    borderRadius: "8px",
                    padding: "1rem",
                  }}
                >
                  <h4
                    style={{
                      fontWeight: 600,
                      fontSize: "0.95rem",
                      color: "var(--warning)",
                      marginBottom: "0.4rem",
                    }}
                  >
                    Enter Personal Team ID
                  </h4>
                  <p
                    style={{
                      fontSize: "0.85rem",
                      opacity: 0.9,
                      marginBottom: "0.6rem",
                      lineHeight: 1.4,
                    }}
                  >
                    Because this free Apple ID is not enrolled in the paid Developer Program, Apple's API does not list teams automatically. Since you previously used this Apple ID on a Mac, your 10-character Team ID already exists:
                  </p>
                  <ul
                    style={{
                      fontSize: "0.8rem",
                      opacity: 0.85,
                      marginBottom: "0.75rem",
                      paddingLeft: "1.2rem",
                      lineHeight: 1.5,
                    }}
                  >
                    <li>
                      <strong>Xcode on Mac:</strong> Xcode Settings &gt; Accounts &gt; select your Apple ID &gt; Personal Team ID.
                    </li>
                    <li>
                      <strong>Keychain Access on Mac:</strong> Search your Apple ID &gt; look for the 10 characters in parentheses in your certificate name <code>Apple Development: ... (XXXXXXXXXX)</code>.
                    </li>
                    <li>
                      <strong>Xcode Project:</strong> Look for <code>DEVELOPMENT_TEAM = XXXXXXXXXX;</code> in <code>project.pbxproj</code>.
                    </li>
                  </ul>
                  <div
                    style={{
                      display: "flex",
                      gap: "0.5rem",
                      alignItems: "center",
                      flexWrap: "wrap",
                    }}
                  >
                    <input
                      type="text"
                      className="input font-mono uppercase"
                      placeholder="e.g. 7A8B9C1D2E"
                      maxLength={10}
                      value={teamIdInput}
                      onChange={(e) => {
                        setTeamIdInput(e.target.value.toUpperCase());
                        setTeamIdError(null);
                      }}
                      style={{
                        width: "160px",
                        padding: "0.4rem 0.6rem",
                        fontSize: "0.9rem",
                        textTransform: "uppercase",
                      }}
                    />
                    <button
                      type="button"
                      className="btn btn-primary btn-sm"
                      disabled={teamIdSaving || teamIdInput.trim().length !== 10}
                      onClick={handleSaveTeamIdAndRetry}
                    >
                      {teamIdSaving ? "Saving..." : "Save Team ID & Install"}
                    </button>
                  </div>
                  {teamIdError && (
                    <p
                      style={{
                        color: "var(--danger)",
                        fontSize: "0.8rem",
                        marginTop: "0.5rem",
                      }}
                    >
                      {teamIdError}
                    </p>
                  )}
                </div>
              )}

            {pipelineError &&
              (pipelineError.includes("3018") ||
                pipelineError.includes("Xcode 7.3") ||
                pipelineError.toLowerCase().includes("two-factor")) && (
                <div
                  className="twofa-refresh-box mt-3 p-3 rounded"
                  style={{
                    background: "rgba(59, 130, 246, 0.08)",
                    border: "1px solid rgba(59, 130, 246, 0.3)",
                    borderRadius: "8px",
                    padding: "1rem",
                  }}
                >
                  <h4
                    style={{
                      fontWeight: 600,
                      fontSize: "0.95rem",
                      color: "var(--accent)",
                      marginBottom: "0.4rem",
                    }}
                  >
                    Apple 2FA Authentication Refresh Required
                  </h4>
                  <p
                    style={{
                      fontSize: "0.85rem",
                      opacity: 0.9,
                      marginBottom: "0.8rem",
                      lineHeight: 1.4,
                    }}
                  >
                    Apple Developer Services requires an active two-factor authentication session token to generate certificates and provisioning profiles. Click below to re-authenticate with your 6-digit 2FA code. Your Personal Team ID (H2834KURW4) is preserved automatically.
                  </p>
                  <button
                    type="button"
                    className="btn btn-primary btn-sm"
                    onClick={async () => {
                      await handleLogout();
                      onNavigate("device-account");
                    }}
                    style={{ display: "inline-flex", gap: "0.4rem", alignItems: "center" }}
                  >
                    <LogOut size={14} />
                    <span>Log Out &amp; Sign In Again</span>
                  </button>
                </div>
              )}
          </div>

          <div className="error-card-actions">
            {pipelineError && pipelineError.includes("developer.apple.com") && (
              <button
                type="button"
                className="btn btn-outline btn-sm"
                onClick={() => {
                  openUrl("https://developer.apple.com/account").catch(() => {
                    window.open("https://developer.apple.com/account", "_blank");
                  });
                }}
                style={{ display: "inline-flex", gap: "0.4rem", alignItems: "center" }}
              >
                <ExternalLink size={14} />
                <span>Open Apple Developer Portal</span>
              </button>
            )}
            <button
              type="button"
              className="btn btn-outline btn-sm"
              onClick={handleCopyDiagnostics}
              style={{ display: "inline-flex", gap: "0.4rem", alignItems: "center" }}
            >
              {copiedDiagnostics ? <Check size={14} className="text-success" /> : <Copy size={14} />}
              <span>
                {copiedDiagnostics
                  ? STRINGS.installFlow.diagnosticsCopied
                  : STRINGS.installFlow.copyDiagnosticsBtn}
              </span>
            </button>
            <button
              type="button"
              className="btn btn-primary btn-sm"
              onClick={() => {
                setPipelineError(null);
                handleStartInstallation();
              }}
            >
              Try Again
            </button>
          </div>
        </div>
      )}

      {/* Valid Inspection result: Preparation & Launch Step */}
      {metadata && !isPipelineRunning && !pipelineResult && !pipelineError && (
        <div className="inspection-result-card mt-4">
          <div className="result-header">
            <div className="app-icon-container">
              {metadata.icon_base64 && !iconError ? (
                <img
                  src={metadata.icon_base64}
                  alt=""
                  className="app-icon-img"
                  onError={() => setIconError(true)}
                />
              ) : (
                <div className="app-icon-placeholder">
                  <Package size={36} />
                </div>
              )}
            </div>

            <div className="app-identity">
              <h3 className="app-display-name">{metadata.app_name}</h3>
              <p className="app-bundle-id font-mono">{metadata.bundle_id}</p>
              <div className="app-badges-row">
                <span className="badge-tag">v{metadata.version} ({metadata.build_number})</span>
                <span className="badge-tag">Min iOS {metadata.min_ios_version}+</span>
                <span
                  className={`status-pill ${
                    metadata.is_already_signed ? "pill-info" : "pill-warning"
                  }`}
                >
                  {metadata.is_already_signed ? "Already Signed" : "Unsigned / Developer Build"}
                </span>
                <span className="status-pill pill-success">
                  <CheckCircle2 size={12} style={{ display: "inline", marginRight: 4 }} />
                  Unencrypted (Sideloadable)
                </span>
              </div>
            </div>
          </div>

          {/* Device & Account Prerequisites Grid */}
          <div className="install-prep-grid">
            {/* Device Box */}
            <div className="prep-card">
              <div className="prep-card-title">
                <Smartphone size={16} />
                <span>{STRINGS.installFlow.deviceSectionTitle}</span>
              </div>
              <div className="prep-card-content">
                {activeDevice ? (
                  <div>
                    <strong>{activeDevice.name}</strong> ({activeDevice.model})
                    <div className="text-xs text-muted mt-1">iOS {activeDevice.ios_version}</div>
                    <div className="mt-2">
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
                      <span
                        className={`status-pill ml-2 ${
                          activeDevice.developer_mode_enabled || manualDevModeConfirmed
                            ? "pill-success"
                            : "pill-warning"
                        }`}
                        style={{ marginLeft: "0.5rem" }}
                      >
                        DevMode:{" "}
                        {activeDevice.developer_mode_enabled || manualDevModeConfirmed
                          ? "On"
                          : "Unverified"}
                      </span>
                      {!activeDevice.developer_mode_enabled && !manualDevModeConfirmed && (
                        <button
                          type="button"
                          className="btn btn-outline btn-sm text-accent"
                          onClick={() => setManualDevModeConfirmed(true)}
                          style={{
                            marginLeft: "0.5rem",
                            padding: "0.1rem 0.4rem",
                            fontSize: "0.7rem",
                          }}
                          title="Click if you turned Developer Mode ON in iPhone Settings"
                        >
                          Mark as ON
                        </button>
                      )}
                    </div>
                  </div>
                ) : (
                  <div className="text-danger text-sm">
                    {STRINGS.installFlow.noDevicePrompt}
                  </div>
                )}
              </div>
            </div>

            {/* Apple ID Account Box */}
            <div className="prep-card">
              <div className="prep-card-title">
                <User size={16} />
                <span>{STRINGS.installFlow.accountSectionTitle}</span>
              </div>
              <div className="prep-card-content">
                {appleSession ? (
                  <div>
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                      <strong className="font-mono">{appleSession.apple_id}</strong>
                      <button
                        type="button"
                        className="btn btn-outline btn-sm text-danger"
                        onClick={handleLogout}
                        style={{
                          display: "inline-flex",
                          gap: "0.3rem",
                          alignItems: "center",
                          padding: "0.15rem 0.45rem",
                          fontSize: "0.75rem",
                        }}
                        title="Log out of Apple account"
                      >
                        <LogOut size={12} />
                        <span>Log Out</span>
                      </button>
                    </div>
                    <div className="text-xs text-muted mt-1">
                      Team: {appleSession.team_name}
                    </div>
                    <div className="mt-2">
                      <span
                        className={`tier-badge ${
                          appleSession.account_type === "Paid" ? "paid" : "free"
                        }`}
                      >
                        {appleSession.account_type} Tier
                      </span>
                    </div>
                  </div>
                ) : (
                  <div>
                    <p className="text-warning text-sm">
                      {STRINGS.installFlow.noAccountPrompt}
                    </p>
                    <button
                      type="button"
                      className="btn btn-outline btn-sm mt-2"
                      onClick={() => onNavigate("device-account")}
                    >
                      Sign In Now
                    </button>
                  </div>
                )}
              </div>
            </div>
          </div>

          {/* Entitlements Warning if Free Account */}
          {appleSession?.account_type === "Free" && detectedStripped.length > 0 && (
            <div className="stripped-entitlements-box">
              <div style={{ display: "flex", gap: "0.5rem", alignItems: "flex-start" }}>
                <ShieldAlert size={16} className="text-warning shrink-0 mt-0.5" />
                <div>
                  <strong>{STRINGS.installFlow.entitlementsNoticeTitle}</strong>
                  <p className="mt-0.5">{STRINGS.installFlow.entitlementsNoticeDesc}</p>
                  <div className="mt-2">
                    {detectedStripped.map((ent) => (
                      <span key={ent} className="entitlement-pill">
                        {ent}
                      </span>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* Optional Custom Bundle ID */}
          <div className="form-group mt-3">
            <label className="form-label" htmlFor="custom-bundle-id">
              {STRINGS.installFlow.customBundleIdLabel}
            </label>
            <input
              id="custom-bundle-id"
              type="text"
              className="form-input text-xs font-mono"
              placeholder={metadata.bundle_id}
              value={customBundleId}
              onChange={(e) => setCustomBundleId(e.target.value)}
            />
          </div>

          <div className="result-card-footer mt-4">
            <div className="step-indicator">
              <span className="step-label">{STRINGS.installFlow.readyToInstall}</span>
              <span className="step-desc">
                {activeDevice && appleSession
                  ? "Device and signing identity ready"
                  : "Resolve device or account requirements above"}
              </span>
            </div>

            <button
              type="button"
              className="btn btn-primary"
              disabled={!activeDevice || !activeDevice.is_trusted || !appleSession}
              onClick={handleStartInstallation}
              style={{ display: "flex", gap: "0.5rem", alignItems: "center" }}
            >
              <span>{STRINGS.installFlow.installBtn}</span>
            </button>
          </div>
        </div>
      )}
    </div>
  );
};
