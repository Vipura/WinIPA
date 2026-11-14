// Copyright (C) 2026 WinIPA Contributors
// SPDX-License-Identifier: GPL-3.0-only

export const STRINGS = {
  app: {
    title: "WinIPA",
    tagline: "Test your iOS apps on your iPhone from Windows without a Mac",
    version: "v0.1.0",
    gplNotice: "Open source under GNU GPL v3.0. No telemetry.",
  },
  nav: {
    home: "Home",
    deviceAndAccount: "Device & Account",
    backToHome: "Back to Home",
    toggleTheme: "Toggle dark/light mode",
  },
  home: {
    welcome: "Welcome to WinIPA",
    subtitle: "Select an option below to test apps on your connected iPhone.",
    cards: {
      installIpa: {
        title: "Install IPA",
        desc: "Inspect, locally re-sign with your Apple ID, and install a pre-built .ipa package over USB.",
        action: "Select or Drop IPA",
        badge: "Phase 1 Ready",
      },
      githubRelease: {
        title: "From GitHub Release",
        desc: "Download and install pre-built IPAs directly from public GitHub release assets.",
        action: "Download & Install",
        badge: "Coming soon",
      },
      buildRepo: {
        title: "Build from Repo / Folder",
        desc: "Trigger build on your own GitHub Actions macOS runner or local SwiftPM toolchain.",
        action: "Configure Build",
        badge: "Coming soon",
      },
      deviceAccount: {
        title: "Device & Account",
        desc: "View connected iPhone status, Apple ID sessions, development certificates, and installed apps.",
        action: "Manage Device & Account",
        badge: "Phase 1 Ready",
      },
    },
  },
  device: {
    title: "Device & Account Management",
    deviceSection: "Connected iPhone",
    noDeviceTitle: "No iPhone Connected",
    noDeviceMsg: "Connect your iPhone via a USB cable, unlock the screen, and tap 'Trust This Computer' if prompted.",
    driverMissingTitle: "Apple USB Driver Missing",
    driverMissingMsg: "WinIPA requires Apple Mobile Device Service. Please install 'Apple Devices' or 'iTunes' from the Microsoft Store.",
    developerModeTitle: "Developer Mode Required",
    developerModeMsg: "On iOS 16+, enable Developer Mode in iPhone Settings > Privacy & Security > Developer Mode, then restart.",
    accountSection: "Apple ID & Signing Identity",
    notLoggedIn: "No Apple ID session active. Log in to generate development signing certificates.",
    loginBtn: "Sign in with Apple ID",
    logoutBtn: "Sign Out",
    appsSection: "Installed Sideloaded Apps",
    noApps: "No sideloaded apps tracked in WinIPA yet. Apps installed with WinIPA will show expiration countdowns here.",
  },
  installFlow: {
    title: "Install IPA Package",
    dropPrompt: "Drag & drop an .ipa file here, or click to browse",
    supportedFormat: "Supported format: Standard iOS Application Archive (.ipa)",
    groundTruthNote: "App Store IPAs are FairPlay encrypted and cannot be sideloaded.",
  },
} as const;

export type Strings = typeof STRINGS;
