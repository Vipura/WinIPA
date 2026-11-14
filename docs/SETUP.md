# WinIPA Setup & Developer Guide

## System Requirements
- **OS**: Windows 10 (1809+) or Windows 11 (64-bit x86_64).
- **Node.js**: v18+ or v20+ (LTS recommended) and npm.
- **Rust**: 1.78+ with `x86_64-pc-windows-msvc` target.
- **Visual Studio Build Tools**: 2022 with C++ Build Tools and Windows 10/11 SDK.
- **Apple Mobile Device Service**: Installed via "Apple Devices" app (Microsoft Store) or iTunes.

## Initial Setup

1. **Install Prerequisites**:
   ```powershell
   # Install Rustup if not installed
   winget install --id Rustlang.Rustup -e
   # Ensure MSVC toolchain is default
   rustup default stable-x86_64-pc-windows-msvc
   ```

2. **Install Node Dependencies**:
   ```powershell
   npm install
   ```

3. **Run Development Server**:
   ```powershell
   npm run tauri dev
   ```

4. **Run Unit Tests & Linters**:
   ```powershell
   # Run frontend lint and type check
   npm run lint
   npm run typecheck

   # Run Rust cargo tests and clippy
   cargo test --manifest-path src-tauri/Cargo.toml
   cargo clippy --manifest-path src-tauri/Cargo.toml -- -D warnings
   ```
