# Third-Party Licenses

WinIPA is released under the **GNU General Public License v3.0 (GPL-3.0)**. 
Below is a list of the third-party open-source components, crates, and libraries used by WinIPA, along with their respective licenses. All dependencies have been verified to be compatible with GPL-3.0.

---

## 1. Rust Crates (Backend)

| Crate | Purpose | Upstream License | Repository / Home |
|---|---|---|---|
| `tauri` | Desktop application framework (v2) | MIT OR Apache-2.0 | https://github.com/tauri-apps/tauri |
| `tauri-build` | Tauri build script helper | MIT OR Apache-2.0 | https://github.com/tauri-apps/tauri |
| `serde`, `serde_json` | Data serialization / deserialization | MIT OR Apache-2.0 | https://github.com/serde-rs/serde |
| `tokio` | Asynchronous runtime | MIT | https://github.com/tokio-rs/tokio |
| `plist` | Apple Property List parser (binary & XML) | MIT | https://github.com/ebarnard/rust-plist |
| `zip` | Zip archive creation and extraction | MIT | https://github.com/zip-rs/zip2 |
| `keyring` | Windows Credential Manager integration | MIT OR Apache-2.0 | https://github.com/hwchen/keyring-rs |
| `goblin` | Mach-O binary parsing and encryption flag detection | MIT | https://github.com/m4b/goblin |
| `reqwest` | HTTP client for Apple Developer Portal and Anisette communication | MIT OR Apache-2.0 | https://github.com/seanmonstar/reqwest |
| `thiserror` | Structured typed error derive macro | MIT OR Apache-2.0 | https://github.com/dtolnay/thiserror |
| `uuid` | Unique identifier generation for temp directories | MIT OR Apache-2.0 | https://github.com/uuid-rs/uuid |
| `regex` | Diagnostic log sanitization and redaction | MIT OR Apache-2.0 | https://github.com/rust-lang/regex |
| `tracing`, `tracing-subscriber` | Structured logging | MIT | https://github.com/tokio-rs/tracing |
| `idevice` | Pure-Rust usbmuxd and lockdown client for iOS | MIT | https://github.com/jkcoxson/idevice |

---

## 2. Helper Binaries & Sidecars

| Binary | Purpose | Upstream License | Notes |
|---|---|---|---|
| `zsign` | Re-signing iOS Mach-O binaries and updating entitlements | MIT | Standalone C++ sidecar executable compiled for Windows x64. |

---

## 3. Frontend Dependencies (npm)

| Package | Purpose | Upstream License | Repository |
|---|---|---|---|
| `react`, `react-dom` | UI component library | MIT | https://github.com/facebook/react |
| `@tauri-apps/api` | Tauri client-side IPC bridge | MIT OR Apache-2.0 | https://github.com/tauri-apps/tauri |
| `lucide-react` | Clean icon set | ISC | https://github.com/lucide-icons/lucide |
| `vite` | Frontend build tool and bundler | MIT | https://github.com/vitejs/vite |
| `typescript` | Static type checker | Apache-2.0 | https://github.com/microsoft/TypeScript |
| `tailwindcss` | Utility-first CSS framework | MIT | https://github.com/tailwindlabs/tailwindcss |
| `clsx`, `tailwind-merge` | Utility for conditional CSS class joining | MIT | https://github.com/lukeed/clsx |

---

## GPL-3.0 Compatibility Notice
All above licenses (MIT, Apache-2.0, ISC) are permissive licenses compatible with distribution under the terms of the GNU General Public License version 3.0.
