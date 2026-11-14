# WinIPA

> **Test your iOS apps on your iPhone from Windows without a Mac.**
> Works with Flutter, React Native, Swift, and native iOS builds.

WinIPA is an open-source Windows desktop application licensed under the **GNU General Public License v3.0 (GPL-3.0)** that enables Windows developers to inspect, re-sign, and install iOS applications (`.ipa`) directly to an iPhone over USB.

---

## Project Status

> **Status: Early Development (Phase 1 / Milestone 0 Completed)**

### What Works Now
- **Desktop UI Shell**: Modern desktop interface with clean dark and light themes, keyboard navigation, and centralized localizable strings.
- **Home Navigation**: 4-card dashboard laying out the user workflows:
  - *Install IPA* (Active entry point)
  - *From GitHub Release* (Coming soon)
  - *Build from repo/folder* (Coming soon)
  - *Device & Account* (Active entry point)
- **Typed Error System**: Full Rust typed error hierarchy (`WinIpaError`) with user-friendly titles, plain-language causes, and actionable remedies.
- **Security & Redaction**: Built-in redaction engine for logs and diagnostics covering Apple IDs, UDIDs, 2FA codes, and session secrets.
- **Continuous Integration**: GitHub Actions workflow running formatting, clippy, strict TypeScript checks, frontend build, and Rust tests.

### What is In Progress / Untested
- **USB Device Layer (M1)**: Live communication with Apple Mobile Device Service via `idevice` / `usbmuxd`.
- **IPA Inspector (M2)**: Unzipping, parsing `Info.plist`, extracting app icons, and detecting FairPlay encryption.
- **Apple ID & Provisioning (M3)**: Direct authentication with Apple GrandSlam/Anisette and Developer Portal.
- **Signer & Installer Pipeline (M4)**: Local offline re-signing via `zsign` and USB deployment.

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
