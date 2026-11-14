// Copyright (C) 2026 WinIPA Contributors
// SPDX-License-Identifier: GPL-3.0-only

import React, { useState, useRef } from "react";
import { STRINGS } from "../strings";
import { IpaMetadata, ErrorDetail } from "../types";
import { inspectIpaPackage } from "../api/ipa";
import {
  ArrowLeft,
  UploadCloud,
  Package,
  AlertTriangle,
  CheckCircle2,
  ArrowRight,
  RefreshCw,
  FileCode,
} from "lucide-react";

interface InstallIpaScreenProps {
  onNavigate: (view: "home" | "install" | "device-account") => void;
}

export const InstallIpaScreen: React.FC<InstallIpaScreenProps> = ({ onNavigate }) => {
  const [isDragging, setIsDragging] = useState<boolean>(false);
  const [isInspecting, setIsInspecting] = useState<boolean>(false);
  const [metadata, setMetadata] = useState<IpaMetadata | null>(null);
  const [errorDetail, setErrorDetail] = useState<ErrorDetail | null>(null);
  const [manualPath, setManualPath] = useState<string>("");
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleInspect = async (filePath: string) => {
    setIsInspecting(true);
    setErrorDetail(null);
    setMetadata(null);

    try {
      const meta = await inspectIpaPackage(filePath);
      setMetadata(meta);
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

  const onFileInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      const file = e.target.files[0];
      const filePath = (file as unknown as { path?: string }).path || file.name;
      setManualPath(filePath);
      handleInspect(filePath);
    }
  };

  const loadFixture = (fixtureName: string) => {
    // Relative path to generated fixture
    const path = `tests/fixtures/${fixtureName}`;
    setManualPath(path);
    handleInspect(path);
  };

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

        {metadata && (
          <button
            type="button"
            className="btn btn-outline btn-sm"
            onClick={() => {
              setMetadata(null);
              setErrorDetail(null);
            }}
          >
            Select Different IPA
          </button>
        )}
      </div>

      {!metadata && !errorDetail && (
        <>
          <div
            className={`dropzone-container ${isDragging ? "dropzone-active" : ""}`}
            onDragOver={onDragOver}
            onDragLeave={onDragLeave}
            onDrop={onDrop}
            onClick={() => fileInputRef.current?.click()}
          >
            <input
              type="file"
              ref={fileInputRef}
              accept=".ipa"
              style={{ display: "none" }}
              onChange={onFileInputChange}
            />

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
                <button type="button" className="btn btn-primary mt-3">
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
              placeholder="Or enter absolute path to an .ipa file (e.g. C:\Users\User\Downloads\App.ipa)..."
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

      {/* Valid Inspection result presentation */}
      {metadata && (
        <div className="inspection-result-card mt-4">
          <div className="result-header">
            <div className="app-icon-container">
              {metadata.icon_base64 ? (
                <img
                  src={metadata.icon_base64}
                  alt={metadata.app_name}
                  className="app-icon-img"
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

          <div className="result-metadata-grid">
            <div className="meta-item">
              <span className="meta-label">File Path:</span>
              <span className="meta-value font-mono text-xs">{metadata.file_path}</span>
            </div>
            <div className="meta-item">
              <span className="meta-label">FairPlay DRM:</span>
              <span className="meta-value text-success">None detected (`cryptid = 0`)</span>
            </div>
          </div>

          <div className="result-card-footer">
            <div className="step-indicator">
              <span className="step-label">Step 2 Complete</span>
              <span className="step-desc">Package inspected successfully</span>
            </div>
            <button
              type="button"
              className="btn btn-primary"
              onClick={() => onNavigate("device-account")}
              style={{ display: "flex", gap: "0.5rem", alignItems: "center" }}
            >
              <span>Next: Select Device & Account</span>
              <ArrowRight size={16} />
            </button>
          </div>
        </div>
      )}
    </div>
  );
};
