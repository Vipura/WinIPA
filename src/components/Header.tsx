// Copyright (C) 2026 WinIPA Contributors
// SPDX-License-Identifier: GPL-3.0-only

import React, { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { STRINGS } from "../strings";
import { Smartphone, Moon, Sun, ShieldCheck, User, LogOut } from "lucide-react";
import { AppleSessionInfo } from "../types";

interface HeaderProps {
  currentView: "home" | "install" | "device-account";
  onNavigate: (view: "home" | "install" | "device-account") => void;
  isDarkMode: boolean;
  onToggleTheme: () => void;
  appleSession?: AppleSessionInfo | null;
  onLogout?: () => void;
}

export const Header: React.FC<HeaderProps> = ({
  currentView,
  onNavigate,
  isDarkMode,
  onToggleTheme,
  appleSession,
  onLogout,
}) => {
  const [version, setVersion] = useState<string>(STRINGS.app.version);

  useEffect(() => {
    invoke<string>("get_app_version")
      .then((ver) => {
        if (ver) {
          setVersion(ver.startsWith("v") ? ver : `v${ver}`);
        }
      })
      .catch(() => {});
  }, []);

  return (
    <header className="header">
      <div className="header-left" onClick={() => onNavigate("home")} style={{ cursor: "pointer" }}>
        <div className="logo-icon">
          <Smartphone size={22} className="text-accent" />
        </div>
        <div className="title-group">
          <h1 className="header-title">{STRINGS.app.title}</h1>
          <span className="badge-tag">{version}</span>
        </div>
      </div>

      <div className="header-right">
        {appleSession && (
          <div className="header-account-pill" title={`Apple ID: ${appleSession.apple_id}`}>
            <User size={13} className="text-accent shrink-0" />
            <span className="header-account-email">{appleSession.apple_id}</span>
            {onLogout && (
              <button
                type="button"
                className="header-logout-btn"
                onClick={onLogout}
                title="Log out of Apple account"
                aria-label="Log out of Apple account"
              >
                <LogOut size={12} />
                <span>Log Out</span>
              </button>
            )}
          </div>
        )}

        <div className="gpl-tag" title={STRINGS.app.gplNotice}>
          <ShieldCheck size={14} />
          <span>GPL-3.0</span>
        </div>

        <nav className="header-nav">
          <button
            type="button"
            className={`nav-link ${currentView === "home" ? "active" : ""}`}
            onClick={() => onNavigate("home")}
          >
            {STRINGS.nav.home}
          </button>
          <button
            type="button"
            className={`nav-link ${currentView === "device-account" ? "active" : ""}`}
            onClick={() => onNavigate("device-account")}
          >
            {STRINGS.nav.deviceAndAccount}
          </button>
        </nav>

        <button
          type="button"
          className="theme-toggle-btn"
          onClick={onToggleTheme}
          aria-label={STRINGS.nav.toggleTheme}
          title={STRINGS.nav.toggleTheme}
        >
          {isDarkMode ? <Sun size={18} /> : <Moon size={18} />}
        </button>
      </div>
    </header>
  );
};
