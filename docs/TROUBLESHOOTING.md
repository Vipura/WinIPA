# WinIPA Troubleshooting Guide

This guide covers common issues, root causes, and step-by-step resolutions when inspecting, signing, or sideloading iOS applications using WinIPA on Windows 10/11.

---

## Table of Contents
1. [Apple USB Driver & Mobile Device Service](#1-apple-usb-driver--mobile-device-service)
2. [Device Connection, Lock Screen & Trust State](#2-device-connection-lock-screen--trust-state)
3. [Developer Mode (iOS 16, 17, 18+)](#3-developer-mode-ios-16-17-18)
4. [App Store DRM Encryption (FairPlay)](#4-app-store-drm-encryption-fairplay)
5. [Apple ID Authentication & 2FA](#5-apple-id-authentication--2fa)
6. [Free Account Limits & Provisioning Quotas](#6-free-account-limits--provisioning-quotas)
7. [First-Time Launch: Untrusted Developer Profile](#7-first-time-launch-untrusted-developer-profile)
8. [USB Installation & Installation Proxy Errors](#8-usb-installation--installation-proxy-errors)
9. [Diagnostic Logs & Reporting Issues](#9-diagnostic-logs--reporting-issues)

---

## 1. Apple USB Driver & Mobile Device Service

### Symptom
WinIPA displays an alert banner: **"Apple USB Driver Missing"** or **"Apple Mobile Device Service Stopped"**.

### Cause
WinIPA communicates with iOS devices via `usbmuxd` through the Windows named pipe `\\.\pipe\USBMuxd` managed by Apple's official **Apple Mobile Device Service (AMDS)**. If neither iTunes nor Apple Devices is installed, or if the background Windows service is paused, USB communication cannot occur.

### Resolution
1. **Install Apple Devices or iTunes**:
   - **Recommended (Windows 10/11)**: Install [Apple Devices from Microsoft Store](ms-windows-store://pdp/?productid=9NP83LWLPZ9K).
   - **Alternative**: Download and install [iTunes for Windows](https://www.apple.com/itunes/).
2. **Start Apple Mobile Device Service**:
   - Press `Win + R`, type `services.msc`, and press `Enter`.
   - Scroll to **Apple Mobile Device Service**.
   - If its status is not *Running*, right-click and select **Start** (or **Restart**).
   - Alternatively, run PowerShell as Administrator:
     ```powershell
     Get-Service "Apple Mobile Device Service" | Start-Service
     ```
3. Click the **Refresh** button in WinIPA.

---

## 2. Device Connection, Lock Screen & Trust State

### Symptom
- WinIPA shows **"No iPhone Connected"**.
- WinIPA shows **"iPhone is Locked"** or **"Untrusted"**.

### Causes & Resolutions
1. **Device is Locked**:
   - The iOS lockdown protocol strictly blocks file transfers and service requests while the lock screen is active.
   - **Fix**: Unlock your iPhone with your passcode or Face ID / Touch ID.
2. **"Trust This Computer" Prompt Not Accepted**:
   - When plugging an iPhone into a PC for the first time, iOS prompts: *"Trust This Computer?"*.
   - **Fix**: Tap **Trust** on your iPhone and enter your device passcode.
3. **Trust Prompt Does Not Appear**:
   - Disconnect the USB cable, wait 5 seconds, and reconnect.
   - Avoid unpowered USB hubs; connect directly to a motherboard USB 3.0 / USB-C port.
   - If previously selected "Don't Trust", go to your iPhone:
     *Settings > General > Transfer or Reset iPhone > Reset > Reset Location & Privacy*.

---

## 3. Developer Mode (iOS 16, 17, 18+)

### Symptom
The app installs successfully over USB, but tapping its icon produces an alert:
> *"Developer Mode Required: Developer Mode is required to run sideloaded apps on iOS 16 and later."*

### Cause
Starting in iOS 16, Apple requires an explicit developer opt-in switch on the device to execute unsigned or personal-team signed code.

### Resolution
1. On your iPhone, open **Settings**.
2. Navigate to **Privacy & Security** (scroll down towards the bottom).
3. Scroll to the bottom of Privacy & Security and tap **Developer Mode**.
4. Toggle the switch to **On**.
5. Tap **Restart** when prompted.
6. After your iPhone reboots, unlock it. A confirmation dialog will appear: tap **Turn On** and enter your passcode.

---

## 4. App Store DRM Encryption (FairPlay)

### Symptom
When inspecting an IPA, WinIPA stops with:
> *"App Store DRM Encrypted: This IPA contains encrypted Mach-O binaries (FairPlay DRM). Encrypted apps from the App Store cannot be re-signed or sideloaded."*

### Cause
Every app distributed through the official Apple App Store has its executable code encrypted using Apple's FairPlay DRM system. When examined, the Mach-O load command `LC_ENCRYPTION_INFO` has `cryptid = 1`. A non-jailbroken device or local code signing utility cannot decrypt or re-sign these binaries.

### Resolution
- Only sideload **unencrypted builds** (developer builds, ad-hoc builds, or builds exported from Xcode / CI).
- For Flutter developers: build with `flutter build ipa --no-codesign`.
- For React Native developers: generate a `.xcarchive` or unsigned `.ipa` via `xcodebuild`.

---

## 5. Apple ID Authentication & 2FA

### Symptom
- **Apple ID Login Failed**: "Incorrect password or Apple ID".
- **Two-Factor Code Rejected**: "Verification code invalid or expired".

### Resolutions
1. **Password Verification**:
   - Confirm your Apple ID and password at [appleid.apple.com](https://appleid.apple.com).
   - Credentials are sent **strictly** to Apple's authentication servers (`gsa.apple.com` / `idmsa.apple.com`) and stored securely in the native **Windows Credential Manager**. They are never transmitted elsewhere.
2. **Obtaining a 2FA Verification Code**:
   - Apple displays the 6-digit code on your trusted Apple devices (iPhone, iPad, Mac).
   - If the popup does not appear, go to your iPhone:
     *Settings > [Your Name] > Sign-In & Security > Two-Factor Authentication > Get Verification Code*.
   - Enter the 6-digit code into WinIPA before it expires (usually 30–60 seconds).
3. **Session Refresh**:
   - If your session expires after 30 days, click **Log Out** in the *Device & Account* tab and sign in again.

---

## 6. Free Account Limits & Provisioning Quotas

### Ground Truth Limits for Free (Personal) Apple Accounts
| Resource | Free Apple ID Limit | Paid Apple Developer Account ($99/yr) |
|---|---|---|
| **Certificate Validity** | **7 Days** | **365 Days** |
| **Active Sideloaded Apps** | **3 Apps Maximum** | **Unlimited** |
| **New App IDs / Week** | **~10 App IDs** | **Unlimited** |
| **Push Notifications** | **Not Available** (Stripped) | **Supported** |
| **Application Groups** | **Not Available** (Stripped) | **Supported** |
| **Network Extensions** | **Not Available** (Stripped) | **Supported** |

### Common Free Account Errors
1. **"Maximum number of apps for free development profile reached"**:
   - Apple enforces a maximum of 3 concurrent sideloaded apps signed with a free account per device.
   - **Fix**: Long-press and delete an unused sideloaded app from your iPhone's home screen, then re-run the install pipeline.
2. **"Certificate Expired" (after 7 days)**:
   - Sideloaded apps stop opening after 7 days on free accounts.
   - **Fix**: Open WinIPA, navigate to **Device & Account**, check the days remaining, or go to **Install IPA** and re-sign/re-install your app to renew the 7-day period.

---

## 7. First-Time Launch: Untrusted Developer Profile

### Symptom
When opening the newly sideloaded app on your iPhone, you see:
> *"Untrusted Developer: Your device management settings do not allow using an app from developer..."*

### Cause
This is a standard iOS security feature for apps installed outside the App Store. The certificate must be trusted once per developer account.

### Resolution
1. Connect your iPhone to an active **Wi-Fi or cellular network** (required for Apple's OCSP certificate verification).
2. Open **Settings** on your iPhone.
3. Tap **General** > **VPN & Device Management** (on older iOS versions: *Device Management* or *Profiles & Device Management*).
4. Under **Developer App**, tap your Apple ID email.
5. Tap **Trust "[Your Apple ID]"** and confirm.
6. You can now launch your app from the home screen!

---

## 8. USB Installation & Installation Proxy Errors

### Common Installation Proxy Errors
- **`ApplicationVerificationFailed`**:
  - The provisioning profile does not match the device's UDID or the certificate used for code signing.
  - **Fix**: Ensure your device was connected during signing so its UDID is included in the provisioning profile.
- **`APIInternalError`**:
  - The iOS installation daemon was busy or encountered a locked file.
  - **Fix**: Unplug the USB cable, reconnect, and try again.
- **`MismatchedApplicationIdentifierEntitlement`**:
  - The bundle ID in the signed binary conflicts with another app on the device.
  - **Fix**: Enter a unique suffix in the *Custom Bundle Identifier* field in WinIPA before signing.
- **`DeviceStorageFull`**:
  - Your iPhone has insufficient free storage space to extract and install the application.
  - **Fix**: Free up storage space in *Settings > General > iPhone Storage*.

---

## 9. Diagnostic Logs & Reporting Issues

WinIPA operates entirely offline and includes **no telemetry, tracking, or remote error reporting**. If you encounter a bug, you can generate a redacted diagnostics export:

1. Open WinIPA and navigate to **Device & Account**.
2. Click **Export Diagnostics** in the top header.
3. WinIPA will save a complete system diagnostics report to `%APPDATA%\WinIPA\diagnostics.txt` and automatically copy the redacted report to your clipboard.
4. **All sensitive personal data is strictly redacted**:
   - Apple ID emails: `[REDACTED_EMAIL]`
   - Device UDIDs: `[REDACTED_UDID]`
   - Passwords and auth tokens: `[REDACTED_SECRET]`
5. Paste the diagnostics into a [GitHub Issue](https://github.com/WinIPA/WinIPA/issues).

### Temporary Working Directories
- **Temporary Extraction & Signing**: `%TEMP%\WinIPA\<uuid>\` (cleaned automatically).
- **Persistent Local Store**: `%APPDATA%\WinIPA\installed_apps.json`.
- **Windows Credential Manager Target**: `WinIPA:AppleID:<account>`.
