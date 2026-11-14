# WinIPA

> **Test your iOS apps on your iPhone from Windows without a Mac.**
> Works with Flutter, React Native, Swift, and native iOS builds.

WinIPA is an open-source Windows desktop application licensed under the **GNU General Public License v3.0 (GPL-3.0)** that enables Windows developers to inspect, re-sign, and install iOS applications (`.ipa`) directly to an iPhone over USB.

---

## Project Status

> **Status: Milestones 0, 1, 2, 3 & 4 Completed**

### What Works Now
- **Desktop UI Shell**: Modern desktop interface with clean dark and light themes, keyboard navigation, and centralized localizable strings.
- **Home Navigation**: 4-card dashboard laying out the user workflows:
  - *Install IPA* (Fully implemented 8-step flow)
  - *From GitHub Release* (Coming soon badge)
  - *Build from repo/folder* (Coming soon badge)
  - *Device & Account* (Device info, Apple ID status, cert expiry, installed apps table)
- **USB Device Layer (M1)**: Detects Apple Mobile Device Service (AMDS) and USB driver presence, monitors device connection/disconnection via `usbmuxd`, reads device name, iOS version, trust state, and Developer Mode state.
- **IPA Inspector (M2)**: Unzips IPAs, parses `Payload/*.app/Info.plist`, extracts app icon to data URI, checks minimum iOS version compatibility, and inspects Mach-O binaries for FairPlay DRM encryption (`cryptid != 0`).
- **Apple ID & Provisioning (M3)**: Secure local authentication with Apple ID & 2FA, development certificate issuance (2048-bit RSA CSR generation), device registration, App ID provisioning, and Windows Credential Manager session persistence.
- **Signer, Installer & Pipeline (M4)**: 
  - Local offline code re-signing via bundled `zsign` executable.
  - Entitlements sanitization (strips unsupported free-tier entitlements such as `aps-environment` and `application-groups`).
  - USB file upload over Apple File Conduit (AFC) protocol framing.
  - App installation and SpringBoard registration via `com.apple.mobile.installation_proxy`.
  - Full 8-step pipeline with live progress streaming, cancellation support, and local app store persistence (`installed_apps.json`).
- **Typed Error System**: Full Rust typed error hierarchy (`WinIpaError`) with user-friendly titles, plain-language causes, and actionable remedies.
- **Security & Redaction**: Built-in redaction engine for logs and diagnostics covering Apple IDs, UDIDs, 2FA codes, and session secrets.
- **Continuous Integration**: GitHub Actions workflow running formatting, clippy, strict TypeScript checks, frontend build, and 37 Rust unit/integration tests.

### What is Untested on Physical Hardware
- Real physical iPhone USB deployment testing depends on physical device availability (verified with comprehensive mock USB/lockdown test suites).

---

## Ground Truths & Design Principles

1. **No Compilation on Windows**: Compiling iOS apps for Flutter or React Native requires macOS and Xcode. WinIPA operates on pre-built `.ipa` files.
2. **Local Signing Only**: Your Apple ID credentials, certificates, and private keys reside strictly on your PC. They are never sent anywhere except to Apple's own servers.
3. **No Apple Driver Redistribution**: WinIPA does not bundle Apple's proprietary USB drivers. If missing, it guides you to install "Apple Devices" or iTunes from the Microsoft Store.
4. **App Store DRM IPAs Cannot Be Sideloaded**: Apps exported directly from the App Store are FairPlay encrypted (`cryptid != 0`). WinIPA detects and explains this clearly.
5. **Free Apple ID Limits**:
   - Certificates are valid for 7 days.
   - Maximum 3 active sideloaded apps per device.
   - ~10 App IDs generated per week.
   - Restricted entitlements (Push Notifications, App Groups, etc. are not available for free accounts and will be stripped/adjusted).
6. **iOS 16+ Developer Mode**: Requires Developer Mode enabled on the iPhone (*Settings > Privacy & Security > Developer Mode*).
7. **Zero Telemetry**: No analytics, tracking, or network calls other than direct communication with Apple.

---

## Documentation
- [Architecture & Library Decisions](docs/ARCHITECTURE.md)
- [Setup & Developer Guide](docs/SETUP.md)
- [Third-Party Licenses](THIRD_PARTY_LICENSES.md)

---

## License
WinIPA is distributed under the terms of the **GNU General Public License v3.0**. See [LICENSE](LICENSE) for details.
