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
    refreshBtn: "Refresh Devices",
    refreshing: "Scanning USB...",
    noDeviceTitle: "No iPhone Connected",
    noDeviceMsg: "Connect your iPhone using a working USB cable, unlock the screen, and ensure the phone is powered on.",
    driverMissingTitle: "Apple USB Driver Missing",
    driverMissingMsg: "WinIPA requires Apple Mobile Device Service to communicate over USB. Please install 'Apple Devices' or 'iTunes' from the Microsoft Store.",
    serviceStoppedTitle: "Apple Mobile Device Service Not Running",
    serviceStoppedMsg: "Apple software was detected, but the mobile device service is not active. Please launch iTunes or Apple Devices on Windows, or start Apple Mobile Device Service in Services.",
    driverInstalledSource: "Detected software source: ",
    microsoftStoreGuide: "Get 'Apple Devices' from Microsoft Store",
    lockedOrUntrustedTitle: "iPhone is Passcode Locked or Untrusted",
    lockedOrUntrustedMsg: "Unlock your iPhone using your passcode and tap 'Trust This Computer' on the alert dialog.",
    developerModeTitle: "Developer Mode is Disabled",
    developerModeMsg: "iOS 16 and later requires Developer Mode enabled before sideloaded apps will run. Go to Settings > Privacy & Security > Developer Mode on your iPhone, turn it ON, and restart.",
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
