// Copyright (C) 2026 WinIPA Contributors
// SPDX-License-Identifier: GPL-3.0-only

import React from "react";
import { STRINGS } from "../strings";
import { Smartphone, Moon, Sun, ShieldCheck } from "lucide-react";

interface HeaderProps {
  currentView: "home" | "install" | "device-account";
  onNavigate: (view: "home" | "install" | "device-account") => void;
  isDarkMode: boolean;
  onToggleTheme: () => void;
}

export const Header: React.FC<HeaderProps> = ({
  currentView,
  onNavigate,
  isDarkMode,
  onToggleTheme,
}) => {
  return (
    <header className="header">
      <div className="header-left" onClick={() => onNavigate("home")} style={{ cursor: "pointer" }}>
        <div className="logo-icon">
          <Smartphone size={22} className="text-accent" />
        </div>
        <div className="title-group">
          <h1 className="header-title">{STRINGS.app.title}</h1>
          <span className="badge-tag">{STRINGS.app.version}</span>
        </div>
      </div>

      <div className="header-right">
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
