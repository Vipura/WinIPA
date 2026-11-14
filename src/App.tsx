// Copyright (C) 2026 WinIPA Contributors
// SPDX-License-Identifier: GPL-3.0-only

import React, { useState, useEffect } from "react";
import { Header } from "./components/Header";
import { HomeScreen } from "./pages/HomeScreen";
import { DeviceAccountScreen } from "./pages/DeviceAccountScreen";
import { InstallIpaScreen } from "./pages/InstallIpaScreen";
import "./App.css";

export const App: React.FC = () => {
  const [currentView, setCurrentView] = useState<"home" | "install" | "device-account">("home");
  const [isDarkMode, setIsDarkMode] = useState<boolean>(() => {
    return window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches;
  });

  useEffect(() => {
    document.documentElement.setAttribute("data-theme", isDarkMode ? "dark" : "light");
  }, [isDarkMode]);

  const toggleTheme = () => {
    setIsDarkMode((prev) => !prev);
  };

  return (
    <div className="app-shell">
      <Header
        currentView={currentView}
        onNavigate={setCurrentView}
        isDarkMode={isDarkMode}
        onToggleTheme={toggleTheme}
      />

      <main className="main-content">
        {currentView === "home" && <HomeScreen onNavigate={setCurrentView} />}
        {currentView === "install" && <InstallIpaScreen onNavigate={setCurrentView} />}
        {currentView === "device-account" && <DeviceAccountScreen onNavigate={setCurrentView} />}
      </main>

      <footer className="app-footer">
        <span>WinIPA &copy; 2026 WinIPA Contributors &bull; Licensed under GNU GPL-3.0</span>
        <span className="privacy-badge">100% Local Signing &bull; Zero Telemetry</span>
      </footer>
    </div>
  );
};

export default App;
