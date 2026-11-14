// Copyright (C) 2026 WinIPA Contributors
// SPDX-License-Identifier: GPL-3.0-only

import React, { useState } from "react";
import { STRINGS } from "../strings";
import { ArrowLeft, UploadCloud, Info, AlertOctagon } from "lucide-react";

interface InstallIpaScreenProps {
  onNavigate: (view: "home" | "install" | "device-account") => void;
}

export const InstallIpaScreen: React.FC<InstallIpaScreenProps> = ({ onNavigate }) => {
  const [selectedFile, setSelectedFile] = useState<string | null>(null);

  const handleSelectFile = () => {
    // Simulated selection placeholder for M0; real picker wired in M2
    setSelectedFile("sample_app.ipa");
  };

  return (
    <div className="install-ipa-screen">
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
        <h2 className="page-title">{STRINGS.installFlow.title}</h2>
      </div>

      <div className="dropzone-container" onClick={handleSelectFile}>
        <UploadCloud size={48} className="dropzone-icon" />
        <h3 className="dropzone-title">{STRINGS.installFlow.dropPrompt}</h3>
        <p className="dropzone-subtitle">{STRINGS.installFlow.supportedFormat}</p>
        <button type="button" className="btn btn-primary mt-3">
          Select IPA File
        </button>
      </div>

      {selectedFile && (
        <div className="selected-file-banner mt-3" style={{ display: "flex", gap: "0.5rem", alignItems: "center" }}>
          <Info size={18} />
          <span>Selected: {selectedFile}</span>
        </div>
      )}

      <div className="alert-card alert-warning mt-4">
        <AlertOctagon size={20} className="shrink-0" />
        <div>
          <strong>Important Ground Truth:</strong>
          <p className="mt-1 text-sm">
            {STRINGS.installFlow.groundTruthNote} Please make sure your IPA is an unsigned or developer-signed build, not an App Store export.
          </p>
        </div>
      </div>
    </div>
  );
};
