# WinIPA Architecture & Technical Design

## 1. Project Overview & Scope

**WinIPA** is a Windows desktop application (licensed under **GNU General Public License v3.0**) designed to allow Windows users without a Mac to inspect, sign, and install iOS applications (`.ipa`) directly to their own iPhone over USB.

### Ground Truths & Constraints
1. **No Compilation on Windows**: Compiling iOS apps for Flutter or React Native requires macOS and Xcode. WinIPA does not compile or spoof Xcode. Phase 1 operates purely on pre-built `.ipa` packages.
2. **Local Signing Only**: All Apple ID credentials, certificates, and private keys reside strictly on the user's PC. They are never sent to any third-party server—only to Apple's official authentication and provisioning endpoints.
3. **No Apple Driver Redistribution**: WinIPA does not bundle Apple proprietary USB drivers. It detects the presence of Apple Mobile Device Service (AMDS) and guides the user to install "Apple Devices" from the Microsoft Store or iTunes.
4. **DRM / FairPlay Detection**: App Store IPAs are encrypted with Apple FairPlay DRM and cannot be sideloaded. WinIPA detects encrypted binaries in Mach-O headers and explains why they cannot be installed.
5. **Free Apple ID Limitations**: 
   - 7-day certificate validity.
   - 3 active sideloaded apps maximum per device.
   - ~10 App IDs generated per 7 days.
   - Restricted entitlements (no Push Notifications, App Groups, Network Extensions, etc.).
   - Entitlements that the account cannot fulfill are automatically stripped or sanitized, with full user notification.
6. **iOS 16+ Developer Mode**: iOS 16 and later requires Developer Mode enabled on the iPhone before sideloaded apps will launch. WinIPA detects and guides the user.
7. **Offline Capability & Zero Telemetry**: Except for communicating directly with Apple servers during authentication and provisioning, WinIPA operates entirely offline. No analytics, tracking, or telemetry.

---

## 2. Technology Stack & Component Selection

| Component | Selected Technology | Upstream License | GPL-3.0 Compatible? | Rationale & Trade-offs |
|---|---|---|---|---|
| **App Framework** | **Tauri 2** (Rust + React + Vite) | MIT / Apache-2.0 | Yes | Tauri provides a minimal binary size (~10–15 MB vs 150+ MB for Electron), direct Rust performance and safety, Windows WebView2 integration, and strict capability-based IPC. |
| **Frontend UI** | **React 19 + TypeScript + Vite + Tailwind CSS** | MIT | Yes | Type-safe UI layer with component isolation, dark/light theme support, and responsive status/progress reporting. |
| **USB Device Communication** | **`idevice` crate** (Rust) | MIT | Yes | Pure Rust client connecting to `usbmuxd` (Apple Mobile Device Service) over Windows Named Pipes (`\\.\pipe\USBMuxd`). Avoids bundling heavy Python runtimes (`pymobiledevice3`) or fragile C DLL bindings (`libimobiledevice`). |
| **IPA Code Signer** | **`zsign` sidecar** | MIT | Yes | Fast, cross-platform Mach-O / IPA code signing utility that operates entirely offline given a certificate and mobileprovision profile. Embeds entitlements and regenerates code directories and CMS signatures. |
| **Apple Auth & Provisioning** | **Apple Developer Session (`apple/` module)** | GPL-3.0 / MIT | Yes | Communicates directly with Apple GrandSlam/Anisette endpoints and Developer Portal APIs (`developer.apple.com`). Handles 2FA, development certificate issuance, device registration, App ID registration, and provisioning profile downloads. |
| **IPA & Plist Parsing** | **`zip`** and **`plist`** crates | MIT / Apache-2.0 | Yes | Pure-Rust zip extraction and Apple Property List parser (supports both XML and binary plist formats). No regex or external tools required. |
| **Mach-O Inspection** | **`goblin`** / **`mach_object`** crate | MIT / Apache-2.0 | Yes | Inspects Mach-O load commands (`LC_ENCRYPTION_INFO` and `LC_ENCRYPTION_INFO_64`) to reliably detect FairPlay DRM (`cryptid != 0`). |
| **Credential Storage** | **`keyring` crate** | MIT / Apache-2.0 | Yes | Interacts directly with Windows Credential Manager (`wincred`). Apple ID passwords and session tokens are never saved to plaintext files or application logs. |

---

## 3. Module Architecture (`src-tauri/src/`)

```
src-tauri/src/
├── main.rs              # Application entry point and Tauri setup
├── lib.rs               # Module exports and Tauri command registrations
├── device/              # Device management & usbmuxd communication
│   ├── mod.rs           # Device listing, monitoring, and state queries
│   ├── usbmux.rs        # Named pipe connection to Apple Mobile Device Service
│   └── lockdown.rs      # Lockdown protocol handshake, UDID, device info, DevMode
├── ipa/                 # IPA inspection and packaging
│   ├── mod.rs           # High-level inspect & repack interface
│   ├── reader.rs        # Unzip Payload/*.app, extract Info.plist & AppIcon
│   ├── macho.rs         # Mach-O header inspection for FairPlay encryption
│   └── bundle.rs        # Bundle ID rewriting, entitlement extraction & sanitization
├── apple/               # Apple ID authentication & provisioning service
│   ├── mod.rs           # Unified AppleService trait & state management
│   ├── auth.rs          # GrandSlam / Anisette authentication & 2FA handling
│   ├── developer.rs     # Developer portal API: certificates, devices, App IDs
│   └── session.rs       # Secure session persistence via Windows Credential Manager
├── signer/              # IPA code signing orchestration
│   ├── mod.rs           # Re-sign interface wrapping zsign sidecar
│   └── entitlements.rs  # Entitlements sanitization for free vs paid accounts
├── installer/           # Device installation service
│   ├── mod.rs           # Push signed IPA over afc / installation_proxy
│   └── progress.rs      # Streaming byte/percent progress reporter
├── pipeline/            # End-to-end installation coordinator
│   ├── mod.rs           # inspect -> auth -> sign -> install pipeline
│   └── cancellation.rs  # Cooperative task cancellation and temp cleanup
├── store/               # Local SQLite / file persistence
│   ├── mod.rs           # Installed apps, expiry dates, user preferences
│   └── redaction.rs     # Redacting UDIDs, Apple IDs, and tokens in diagnostics
└── errors/              # Typed error definitions
    └── mod.rs           # WinIpaError enum with user-facing titles and remedies
```

---

## 4. Security & Privacy Architecture

1. **Windows Credential Manager**:
   - Secrets (Apple ID passwords, auth tokens, session cookies) are stored exclusively in Windows Credential Manager under the target name `WinIPA:AppleID:<account>`.
   - Never written to config files, temp folders, or logs.
2. **Log Sanitization & Redaction**:
   - Any log output presented to the user or written to `%TEMP%\WinIPA\diagnostics.log` undergoes strict regex redaction for:
     - Apple ID email addresses (`***@domain.com`)
     - Device UDIDs (`[REDACTED_UDID]`)
     - Passwords, 2FA codes, and auth session tokens (`[REDACTED_SECRET]`)
3. **Sandbox & Temp Directory Isolation**:
   - All extraction and signing happens in `%TEMP%\WinIPA\<uuid>\`.
   - On completion, error, or cancellation, the directory is aggressively removed.
4. **Network Boundaries**:
   - Network calls are strictly restricted to Apple domains (`*.apple.com`, `gsa.apple.com`, `idmsa.apple.com`, `developer.apple.com`).
   - No external analytics, telemetry, or remote crash reporters.

---

## 5. Error Classification Matrix

Every error implements `WinIpaError` and provides:
1. `code`: Machine-readable error code.
2. `title`: Human-readable title.
3. `message`: Plain-language explanation of what went wrong.
4. `remedy`: Step-by-step guidance for the user to resolve the issue.

| Error Code | Human Title | Description & Root Cause | Recommended User Action |
|---|---|---|---|
| `NoDevice` | No iPhone Connected | No device detected on USB bus via usbmuxd. | Connect iPhone via USB cable and unlock screen. |
| `DeviceLocked` | iPhone is Locked | Device cannot communicate while passcode locked. | Unlock your iPhone using your passcode. |
| `DeviceNotTrusted` | Trust Prompt Not Accepted | Computer is not paired or trusted by device. | Unlock iPhone and tap "Trust This Computer". |
| `DriverMissing` | Apple USB Driver Missing | Apple Mobile Device Service is not running or installed. | Install "Apple Devices" or iTunes from the Microsoft Store. |
| `DeveloperModeOff` | Developer Mode Disabled | iOS 16+ requires Developer Mode to run sideloaded apps. | Enable Developer Mode in Settings > Privacy & Security > Developer Mode. |
| `IosTooOld` | iOS Version Too Low | App requires a higher iOS version than the connected iPhone. | Update iOS on your iPhone or select a compatible IPA. |
| `InvalidIpa` | Invalid IPA Package | Archive missing Payload directory or valid Info.plist. | Verify the IPA file is not corrupted. |
| `EncryptedIpa` | App Store DRM Encrypted | App binary contains FairPlay DRM (`cryptid != 0`). | Download an unencrypted/developer build; App Store binaries cannot be sideloaded. |
| `AppleAuthFailed` | Apple ID Login Failed | Incorrect Apple ID email or password. | Check your credentials and try again. |
| `TwoFactorFailed` | 2FA Code Incorrect | The 6-digit verification code was rejected or expired. | Request a new verification code and enter it promptly. |
| `AppleRateLimited` | Apple Server Rate Limit | Apple has temporarily blocked requests from this IP/account. | Wait 1–2 hours before attempting to sign again. |
| `AccountLimitReached` | Sideload App Limit Reached | Free Apple ID limit reached (3 active apps or 10 App IDs/week). | Remove unused sideloaded apps or wait for weekly quota reset. |
| `CertificateFailed` | Certificate Generation Failed | Failed to generate or download development certificate. | Check Apple Developer portal status or revoke unused certs. |
| `ProfileFailed` | Provisioning Profile Failed | Failed to generate provisioning profile for bundle ID. | Verify device is registered to account. |
| `SigningFailed` | IPA Signing Failed | `zsign` exited with an error during code signing. | Review diagnostics for signing log details. |
| `InstallFailed` | App Installation Failed | Device rejected installation (e.g. storage full, invalid signature). | Check iPhone storage space and developer profile trust. |
| `ToolMissing` | Helper Tool Missing | Required sidecar tool (e.g., zsign) was not found. | Reinstall WinIPA or verify antivirus didn't quarantine binary. |
| `Timeout` | Operation Timed Out | Device or Apple server did not respond in time. | Check USB cable connection and internet connectivity. |
| `Cancelled` | Operation Cancelled | User cancelled the ongoing operation. | Ready for next task. |
