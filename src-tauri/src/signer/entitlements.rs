// Copyright (C) 2026 WinIPA Contributors
// SPDX-License-Identifier: GPL-3.0-only

use crate::errors::WinIpaError;
use plist::{Dictionary, Value};
use std::io::Cursor;

/// List of entitlement keys restricted or forbidden for free Apple Developer accounts.
pub const RESTRICTED_FREE_ENTITLEMENTS: &[&str] = &[
    "aps-environment",
    "com.apple.developer.associated-domains",
    "com.apple.developer.in-app-payments",
    "com.apple.developer.siri",
    "com.apple.security.application-groups",
    "com.apple.developer.networking.wifi-info",
    "com.apple.developer.networking.networkextension",
    "com.apple.developer.icloud-container-identifiers",
    "com.apple.developer.ubiquity-kvstore-identifier",
    "com.apple.developer.healthkit",
    "com.apple.developer.homekit",
    "com.apple.developer.pass-type-identifiers",
    "com.apple.developer.default-data-protection",
];

/// Extracts the embedded XML plist from a signed Apple `.mobileprovision` file.
pub fn extract_mobileprovision_plist(data: &[u8]) -> Result<Dictionary, WinIpaError> {
    let start_needle = b"<?xml";
    let end_needle = b"</plist>";

    let start_pos = data
        .windows(start_needle.len())
        .position(|window| window == start_needle)
        .ok_or_else(|| {
            WinIpaError::ProfileFailed("Invalid provisioning profile: missing XML header".into())
        })?;

    let end_pos = data[start_pos..]
        .windows(end_needle.len())
        .position(|window| window == end_needle)
        .map(|pos| start_pos + pos + end_needle.len())
        .ok_or_else(|| {
            WinIpaError::ProfileFailed("Invalid provisioning profile: missing </plist> tag".into())
        })?;

    let xml_slice = &data[start_pos..end_pos];
    let value = Value::from_reader_xml(Cursor::new(xml_slice)).map_err(|e| {
        WinIpaError::ProfileFailed(format!(
            "Failed to parse XML within provisioning profile: {e}"
        ))
    })?;

    value.into_dictionary().ok_or_else(|| {
        WinIpaError::ProfileFailed("Provisioning profile root is not a dictionary".into())
    })
}

/// Extracts the `<key>Entitlements</key>` dictionary from a provisioning profile.
pub fn extract_profile_entitlements(data: &[u8]) -> Result<Dictionary, WinIpaError> {
    let root = extract_mobileprovision_plist(data)?;
    root.get("Entitlements")
        .and_then(|v| v.as_dictionary())
        .cloned()
        .ok_or_else(|| {
            WinIpaError::ProfileFailed(
                "Provisioning profile does not contain an Entitlements dictionary".into(),
            )
        })
}

/// Sanitizes entitlements for an IPA being signed.
/// Strips unsupported entitlements, aligns team/app identifiers, and ensures `get-task-allow`.
pub fn sanitize_entitlements(
    app_entitlements: Option<&Dictionary>,
    profile_entitlements: &Dictionary,
    team_id: &str,
    bundle_id: &str,
    is_free_account: bool,
) -> (Dictionary, Vec<String>) {
    let mut sanitized = Dictionary::new();
    let mut stripped = Vec::new();

    // 1. Copy over base granted entitlements from the provisioning profile
    for (k, v) in profile_entitlements {
        sanitized.insert(k.clone(), v.clone());
    }

    // 2. Align application-identifier
    let full_app_id = format!("{team_id}.{bundle_id}");
    sanitized.insert("application-identifier".into(), Value::String(full_app_id));

    // 3. Ensure get-task-allow is boolean true for development signing
    sanitized.insert("get-task-allow".into(), Value::Boolean(true));

    // 4. If the original app requested entitlements, examine them
    if let Some(requested) = app_entitlements {
        for (key, val) in requested {
            if is_free_account && RESTRICTED_FREE_ENTITLEMENTS.contains(&key.as_str()) {
                stripped.push(key.clone());
                continue;
            }

            // If profile does not grant this key and it's not a standard runtime key, strip it
            if !profile_entitlements.contains_key(key)
                && key != "get-task-allow"
                && key != "application-identifier"
            {
                if is_free_account {
                    stripped.push(key.clone());
                } else {
                    // Paid accounts: keep if requested
                    sanitized.insert(key.clone(), val.clone());
                }
            } else if !sanitized.contains_key(key) {
                sanitized.insert(key.clone(), val.clone());
            }
        }
    }

    (sanitized, stripped)
}

/// Serializes an entitlements dictionary to a clean XML plist string.
pub fn serialize_entitlements_xml(dict: &Dictionary) -> Result<String, WinIpaError> {
    let mut buf = Vec::new();
    plist::to_writer_xml(&mut buf, &Value::Dictionary(dict.clone())).map_err(|e| {
        WinIpaError::SigningFailed(format!("Failed to serialize entitlements XML plist: {e}"))
    })?;
    String::from_utf8(buf).map_err(|e| {
        WinIpaError::SigningFailed(format!("Serialized entitlements is invalid UTF-8: {e}"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_mobileprovision_plist() {
        let dummy_prov = b"CMS_HEADER_DATA_12345<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">
<plist version=\"1.0\">
<dict>
    <key>Name</key>
    <string>Test Profile</string>
    <key>TeamIdentifier</key>
    <array>
        <string>ABC123XYZ</string>
    </array>
    <key>Entitlements</key>
    <dict>
        <key>application-identifier</key>
        <string>ABC123XYZ.*</string>
        <key>get-task-allow</key>
        <true/>
    </dict>
</dict>
</plist>CMS_TRAILER_SIGNATURE_6789";

        let plist_dict =
            extract_mobileprovision_plist(dummy_prov).expect("Should extract embedded XML plist");
        assert_eq!(
            plist_dict.get("Name").and_then(|v| v.as_string()),
            Some("Test Profile")
        );

        let entitlements =
            extract_profile_entitlements(dummy_prov).expect("Should extract entitlements");
        assert_eq!(
            entitlements
                .get("application-identifier")
                .and_then(|v| v.as_string()),
            Some("ABC123XYZ.*")
        );
    }

    #[test]
    fn test_sanitize_entitlements_strips_restricted_for_free_account() {
        let mut profile_entitlements = Dictionary::new();
        profile_entitlements.insert(
            "application-identifier".into(),
            Value::String("TEAM123.*".into()),
        );
        profile_entitlements.insert("get-task-allow".into(), Value::Boolean(true));

        let mut app_requested = Dictionary::new();
        app_requested.insert(
            "aps-environment".into(),
            Value::String("development".into()),
        );
        app_requested.insert(
            "com.apple.security.application-groups".into(),
            Value::Array(vec![Value::String("group.mytest".into())]),
        );
        app_requested.insert(
            "com.apple.developer.associated-domains".into(),
            Value::Array(vec![]),
        );

        let (sanitized, stripped) = sanitize_entitlements(
            Some(&app_requested),
            &profile_entitlements,
            "TEAM123",
            "io.winipa.demo",
            true, // is_free_account
        );

        // Verify restricted entitlements were stripped
        assert!(!sanitized.contains_key("aps-environment"));
        assert!(!sanitized.contains_key("com.apple.security.application-groups"));
        assert!(!sanitized.contains_key("com.apple.developer.associated-domains"));

        assert!(stripped.contains(&"aps-environment".to_string()));
        assert!(stripped.contains(&"com.apple.security.application-groups".to_string()));
        assert!(stripped.contains(&"com.apple.developer.associated-domains".to_string()));

        // Verify application-identifier and get-task-allow were correctly set
        assert_eq!(
            sanitized
                .get("application-identifier")
                .and_then(|v| v.as_string()),
            Some("TEAM123.io.winipa.demo")
        );
        assert_eq!(
            sanitized.get("get-task-allow").and_then(|v| v.as_boolean()),
            Some(true)
        );

        let xml = serialize_entitlements_xml(&sanitized).expect("Should serialize XML");
        assert!(xml.contains("<string>TEAM123.io.winipa.demo</string>"));
        assert!(xml.contains("<true/>"));
    }
}
