// Copyright (C) 2026 WinIPA Contributors
// SPDX-License-Identifier: GPL-3.0-only

pub mod entitlements;
pub mod zsign;

use crate::errors::WinIpaError;
use crate::ipa::inspect_ipa;
use entitlements::{
    extract_profile_entitlements, sanitize_entitlements, serialize_entitlements_xml,
};
use plist::{Dictionary, Value};
use serde::{Deserialize, Serialize};
use std::fs::{create_dir_all, remove_dir_all, write};
use std::path::{Path, PathBuf};
use zsign::{run_zsign, ZsignInvocation};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigningOptions {
    pub input_ipa: String,
    pub output_ipa: String,
    pub certificate_pem: String,
    pub private_key_pem: String,
    pub mobileprovision_data: Vec<u8>,
    pub team_id: String,
    pub new_bundle_id: Option<String>,
    pub is_free_account: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigningResult {
    pub signed_ipa_path: String,
    pub stripped_entitlements: Vec<String>,
}

/// Orchestrates the IPA re-signing procedure:
/// 1. Extracts profile entitlements and determines Team ID
/// 2. Inspects original IPA for existing entitlements
/// 3. Sanitizes entitlements (stripping unsupported free-tier entitlements)
/// 4. Writes temporary credentials and profile to a scoped temp directory
/// 5. Invokes zsign to re-sign the app and embedded frameworks/dylibs
/// 6. Deletes temporary credential files immediately
/// 7. Returns SigningResult with stripped entitlements report
pub async fn sign_ipa(options: SigningOptions) -> Result<SigningResult, WinIpaError> {
    let input_path = Path::new(&options.input_ipa);
    if !input_path.exists() {
        return Err(WinIpaError::InvalidIpa(format!(
            "Input IPA file not found: {}",
            options.input_ipa
        )));
    }

    let output_path = PathBuf::from(&options.output_ipa);
    if let Some(parent) = output_path.parent() {
        create_dir_all(parent).map_err(|e| {
            WinIpaError::SigningFailed(format!("Failed to create output directory: {e}"))
        })?;
    }

    // 1. Extract granted entitlements from the mobileprovision profile
    let profile_entitlements = extract_profile_entitlements(&options.mobileprovision_data)?;

    // 2. Read app metadata and original entitlements from the input IPA
    let metadata = inspect_ipa(input_path)?;
    let target_bundle_id = options.new_bundle_id.clone().unwrap_or(metadata.bundle_id);

    // Convert string original_entitlements to dictionary format if present
    let mut app_ent_dict = Dictionary::new();
    for ent in &metadata.original_entitlements {
        app_ent_dict.insert(ent.clone(), Value::Boolean(true));
    }
    let app_ent_ref = if app_ent_dict.is_empty() {
        None
    } else {
        Some(&app_ent_dict)
    };

    // 3. Sanitize entitlements (strip restricted entitlements for free account)
    let (sanitized_dict, stripped_entitlements) = sanitize_entitlements(
        app_ent_ref,
        &profile_entitlements,
        &options.team_id,
        &target_bundle_id,
        options.is_free_account,
    );

    let entitlements_xml = serialize_entitlements_xml(&sanitized_dict)?;

    // 4. Create isolated temp directory for signing artifacts
    let session_id = uuid::Uuid::new_v4().to_string();
    let temp_root = std::env::temp_dir()
        .join("WinIPA")
        .join(format!("sign_{session_id}"));
    create_dir_all(&temp_root).map_err(|e| {
        WinIpaError::SigningFailed(format!("Failed to create temporary signing folder: {e}"))
    })?;

    let cert_file = temp_root.join("cert.pem");
    let key_file = temp_root.join("key.pem");
    let prov_file = temp_root.join("embedded.mobileprovision");
    let ent_file = temp_root.join("entitlements.plist");
    let zsign_temp = temp_root.join("zsign_work");
    create_dir_all(&zsign_temp).map_err(|e| {
        WinIpaError::SigningFailed(format!("Failed to create zsign work folder: {e}"))
    })?;

    // Write temp files
    let write_res = (|| -> Result<(), WinIpaError> {
        write(&cert_file, options.certificate_pem.as_bytes()).map_err(|e| {
            WinIpaError::SigningFailed(format!("Failed to write certificate file: {e}"))
        })?;
        write(&key_file, options.private_key_pem.as_bytes()).map_err(|e| {
            WinIpaError::SigningFailed(format!("Failed to write private key file: {e}"))
        })?;
        write(&prov_file, &options.mobileprovision_data).map_err(|e| {
            WinIpaError::SigningFailed(format!("Failed to write mobileprovision file: {e}"))
        })?;
        write(&ent_file, entitlements_xml.as_bytes()).map_err(|e| {
            WinIpaError::SigningFailed(format!("Failed to write entitlements plist: {e}"))
        })?;
        Ok(())
    })();

    if let Err(e) = write_res {
        let _ = remove_dir_all(&temp_root);
        return Err(e);
    }

    // 5. Run zsign
    let zsign_res = run_zsign(ZsignInvocation {
        input_ipa: input_path,
        output_ipa: &output_path,
        cert_path: &cert_file,
        key_path: &key_file,
        prov_path: &prov_file,
        entitlements_path: Some(&ent_file),
        new_bundle_id: options.new_bundle_id.as_deref(),
        temp_dir: &zsign_temp,
    })
    .await;

    // 6. Aggressively clean up temp files (especially private key!)
    let _ = remove_dir_all(&temp_root);

    zsign_res?;

    Ok(SigningResult {
        signed_ipa_path: options.output_ipa,
        stripped_entitlements,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::apple::crypto::generate_dev_csr;
    use crate::ipa::macho::create_signable_test_macho;
    use std::fs::File;
    use std::io::Write;
    use zip::write::SimpleFileOptions;
    use zip::ZipWriter;

    fn build_signable_fixture(ipa_path: &Path) {
        let file = File::create(ipa_path).expect("create test ipa");
        let mut zip = ZipWriter::new(file);
        let options = SimpleFileOptions::default();

        zip.start_file("Payload/SignableApp.app/Info.plist", options)
            .unwrap();
        let plist = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleDisplayName</key>
    <string>Signable App</string>
    <key>CFBundleIdentifier</key>
    <string>io.winipa.signable</string>
    <key>CFBundleShortVersionString</key>
    <string>1.0.0</string>
    <key>CFBundleVersion</key>
    <string>1</string>
    <key>MinimumOSVersion</key>
    <string>15.0</string>
    <key>CFBundleExecutable</key>
    <string>SignableApp</string>
</dict>
</plist>"#;
        zip.write_all(plist.as_bytes()).unwrap();

        zip.start_file("Payload/SignableApp.app/SignableApp", options)
            .unwrap();
        let macho = create_signable_test_macho();
        zip.write_all(&macho).unwrap();

        zip.finish().unwrap();
    }

    #[tokio::test]
    async fn test_sign_ipa_workflow() {
        let temp_dir = std::env::temp_dir().join(format!("winipa_test_{}", uuid::Uuid::new_v4()));
        create_dir_all(&temp_dir).unwrap();

        let input_ipa = temp_dir.join("input.ipa");
        let output_ipa = temp_dir.join("output.ipa");
        build_signable_fixture(&input_ipa);

        // Generate valid self-signed certificate and RSA keypair using rcgen
        let mut params = rcgen::CertificateParams::default();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "Apple Development: Tester");
        params
            .distinguished_name
            .push(rcgen::DnType::OrganizationalUnitName, "TEAM123456");
        // Create a simulated Apple WWDR G3 CA to issue the developer certificate
        let mut ca_params = rcgen::CertificateParams::default();
        ca_params.distinguished_name.push(
            rcgen::DnType::CommonName,
            "Apple Worldwide Developer Relations Certification Authority",
        );
        ca_params
            .distinguished_name
            .push(rcgen::DnType::OrganizationalUnitName, "G3");
        ca_params
            .distinguished_name
            .push(rcgen::DnType::OrganizationName, "Apple Inc.");
        ca_params
            .distinguished_name
            .push(rcgen::DnType::CountryName, "US");
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let issuer = rcgen::Issuer::from_params(&ca_params, &ca_key);

        // Developer certificate signed by Apple WWDR CA
        let mut dev_params = rcgen::CertificateParams::default();
        dev_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "Apple Development: Tester");
        dev_params
            .distinguished_name
            .push(rcgen::DnType::OrganizationalUnitName, "TEAM123456");

        let kp = generate_dev_csr("Apple Development: Tester", "TEAM123456").unwrap();
        let key_pair = rcgen::KeyPair::from_pem(&kp.private_key_pem).unwrap();
        let cert = dev_params.signed_by(&key_pair, &issuer).unwrap();
        let cert_pem = cert.pem();
        let key_pem = kp.private_key_pem;

        // Valid CMS-wrapped mobileprovision
        let prov_xml = br#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Name</key>
    <string>Test Profile</string>
    <key>TeamIdentifier</key>
    <array>
        <string>TEAM123456</string>
    </array>
    <key>Entitlements</key>
    <dict>
        <key>application-identifier</key>
        <string>TEAM123456.*</string>
        <key>get-task-allow</key>
        <true/>
    </dict>
</dict>
</plist>"#;
        let prov_cms = crate::apple::crypto::wrap_in_cms_content_info(prov_xml);

        let options = SigningOptions {
            input_ipa: input_ipa.to_string_lossy().to_string(),
            output_ipa: output_ipa.to_string_lossy().to_string(),
            certificate_pem: cert_pem,
            private_key_pem: key_pem,
            mobileprovision_data: prov_cms,
            team_id: "TEAM123456".to_string(),
            new_bundle_id: Some("io.winipa.resigned".to_string()),
            is_free_account: true,
        };

        let result = sign_ipa(options).await;
        // Verify signing execution
        assert!(result.is_ok(), "sign_ipa should succeed: {:?}", result);
        assert!(output_ipa.exists(), "Output IPA should exist");

        let _ = remove_dir_all(&temp_dir);
    }
}
