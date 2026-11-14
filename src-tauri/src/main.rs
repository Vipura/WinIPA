// Copyright (C) 2026 WinIPA Contributors
// SPDX-License-Identifier: GPL-3.0-only

// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    std::panic::set_hook(Box::new(|panic_info| {
        let msg = format!("{panic_info}");
        if let Ok(appdata) = std::env::var("APPDATA") {
            let log_dir = std::path::PathBuf::from(appdata).join("WinIPA");
            let _ = std::fs::create_dir_all(&log_dir);
            let _ = std::fs::write(log_dir.join("crash.log"), &msg);
        }
        eprintln!("{msg}");
    }));

    winipa_lib::run();
}
