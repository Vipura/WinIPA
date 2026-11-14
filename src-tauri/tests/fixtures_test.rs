// Copyright (C) 2026 WinIPA Contributors
// SPDX-License-Identifier: GPL-3.0-only

use std::fs::{create_dir_all, File};
use std::io::Write;
use std::path::Path;
use winipa_lib::ipa::inspect_ipa;
use winipa_lib::ipa::macho::create_test_macho;
use zip::write::SimpleFileOptions;
use zip::ZipWriter;

fn generate_fixture(path: &Path, has_payload: bool, has_plist: bool, encrypted_binary: bool) {
    if let Some(parent) = path.parent() {
        create_dir_all(parent).unwrap();
    }
    let file = File::create(path).expect("create test ipa");
    let mut zip = ZipWriter::new(file);
    let options = SimpleFileOptions::default();

    if has_payload {
        if has_plist {
            zip.start_file("Payload/TestApp.app/Info.plist", options)
                .unwrap();
            let plist = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleDisplayName</key>
    <string>Fixture Test App</string>
    <key>CFBundleIdentifier</key>
    <string>io.winipa.fixtureapp</string>
    <key>CFBundleShortVersionString</key>
    <string>1.0.0</string>
    <key>CFBundleVersion</key>
    <string>1</string>
    <key>MinimumOSVersion</key>
    <string>15.0</string>
    <key>CFBundleExecutable</key>
    <string>TestApp</string>
</dict>
</plist>"#;
            zip.write_all(plist.as_bytes()).unwrap();

            zip.start_file("Payload/TestApp.app/TestApp", options)
                .unwrap();
            let macho = create_test_macho(encrypted_binary, false);
            zip.write_all(&macho).unwrap();

            // Minimal valid 1x1 png
            zip.start_file("Payload/TestApp.app/AppIcon60x60@2x.png", options)
                .unwrap();
            let dummy_png = [
                0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x48,
                0x44, 0x52, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0x00, 0x00,
                0x00, 0x1F, 0x15, 0xC4, 0x89, 0x00, 0x00, 0x00, 0x0A, 0x49, 0x44, 0x41, 0x54, 0x78,
                0x9C, 0x63, 0x00, 0x01, 0x00, 0x00, 0x05, 0x00, 0x01, 0x0D, 0x0A, 0x2D, 0xB4, 0x00,
                0x00, 0x00, 0x00, 0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82,
            ];
            zip.write_all(&dummy_png).unwrap();
        } else {
            zip.start_file("Payload/TestApp.app/empty.txt", options)
                .unwrap();
            zip.write_all(b"Missing info plist").unwrap();
        }
    } else {
        zip.start_file("InvalidFolder/dummy.txt", options).unwrap();
        zip.write_all(b"Corrupted archive").unwrap();
    }

    zip.finish().unwrap();
}

#[test]
fn test_fixture_directory_and_inspection() {
    let fixtures_dir = Path::new("../tests/fixtures");
    create_dir_all(fixtures_dir).unwrap();

    let valid_path = fixtures_dir.join("valid.ipa");
    let encrypted_path = fixtures_dir.join("encrypted.ipa");
    let no_plist_path = fixtures_dir.join("no_plist.ipa");
    let invalid_path = fixtures_dir.join("invalid.ipa");

    generate_fixture(&valid_path, true, true, false);
    generate_fixture(&encrypted_path, true, true, true);
    generate_fixture(&no_plist_path, true, false, false);
    generate_fixture(&invalid_path, false, false, false);

    // Verify valid fixture
    let valid_meta = inspect_ipa(&valid_path).expect("valid fixture should inspect");
    assert_eq!(valid_meta.app_name, "Fixture Test App");
    assert_eq!(valid_meta.bundle_id, "io.winipa.fixtureapp");
    assert_eq!(valid_meta.min_ios_version, "15.0");
    assert!(!valid_meta.is_encrypted);

    // Verify encrypted fixture
    let enc_err = inspect_ipa(&encrypted_path).expect_err("encrypted fixture must fail");
    assert_eq!(enc_err, winipa_lib::errors::WinIpaError::EncryptedIpa);

    // Verify no_plist fixture
    let plist_err = inspect_ipa(&no_plist_path).expect_err("no plist fixture must fail");
    assert!(matches!(
        plist_err,
        winipa_lib::errors::WinIpaError::InvalidIpa(_)
    ));

    // Verify invalid fixture
    let inv_err = inspect_ipa(&invalid_path).expect_err("invalid fixture must fail");
    assert!(matches!(
        inv_err,
        winipa_lib::errors::WinIpaError::InvalidIpa(_)
    ));
}
