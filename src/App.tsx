// Copyright (C) 2026 WinIPA Contributors
// SPDX-License-Identifier: GPL-3.0-only

import React, { useState, useEffect, useCallback } from "react";
import { Header } from "./components/Header";
import { HomeScreen } from "./pages/HomeScreen";
import { DeviceAccountScreen } from "./pages/DeviceAccountScreen";
import { InstallIpaScreen } from "./pages/InstallIpaScreen";
import { appleGetSession, appleLogout } from "./api/apple";
import { AppleSessionInfo } from "./types";
import "./App.css";

export const App: React.FC = () => {
  const [currentView, setCurrentView] = useState<"home" | "install" | "device-account">("home");
  const [appleSession, setAppleSession] = useState<AppleSessionInfo | null>(null);
  const [isDarkMode, setIsDarkMode] = useState<boolean>(() => {
    return window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches;
  });

  const refreshSession = useCallback(async () => {
    try {
      const session = await appleGetSession();
      setAppleSession(session);
    } catch (e) {
      console.warn("Failed to check Apple session:", e);
    }
  }, []);

  useEffect(() => {
    refreshSession();
  }, [refreshSession]);

  useEffect(() => {
    document.documentElement.setAttribute("data-theme", isDarkMode ? "dark" : "light");
  }, [isDarkMode]);

  const toggleTheme = () => {
    setIsDarkMode((prev) => !prev);
  };

  const handleLogout = async () => {
    try {
      await appleLogout();
      setAppleSession(null);
    } catch (err) {
      console.error("Failed to log out:", err);
    }
  };

  return (
    <div className="app-shell">
      <Header
        currentView={currentView}
        onNavigate={setCurrentView}
        isDarkMode={isDarkMode}
        onToggleTheme={toggleTheme}
        appleSession={appleSession}
        onLogout={handleLogout}
      />

      <main className="main-content">
        {currentView === "home" && <HomeScreen onNavigate={setCurrentView} />}
        {currentView === "install" && (
          <InstallIpaScreen
            onNavigate={setCurrentView}
            appleSession={appleSession}
            onSessionRefresh={refreshSession}
            onLogout={handleLogout}
          />
        )}
        {currentView === "device-account" && (
          <DeviceAccountScreen
            onNavigate={setCurrentView}
            appleSession={appleSession}
            onSessionChange={setAppleSession}
          />
        )}
      </main>

      <footer className="app-footer">
        <span>WinIPA &copy; 2026 WinIPA Contributors &bull; Licensed under GNU GPL-3.0</span>
        <span className="privacy-badge">100% Local Signing &bull; Zero Telemetry</span>
      </footer>
    </div>
  );
};

export default App;
