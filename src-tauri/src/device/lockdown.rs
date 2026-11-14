// Copyright (C) 2026 WinIPA Contributors
// SPDX-License-Identifier: GPL-3.0-only

use crate::device::DeviceInfo;
use crate::errors::WinIpaError;
use plist::Value;
use std::io::Cursor;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Sends a lockdown framed packet: 4-byte big-endian length prefix followed by XML plist.
pub async fn send_lockdown_message(stream: &mut TcpStream, xml: &str) -> Result<(), WinIpaError> {
    let bytes = xml.as_bytes();
    let len = bytes.len() as u32;

    stream
        .write_all(&len.to_be_bytes())
        .await
        .map_err(|e| WinIpaError::Unknown {
            message: format!("Failed to write lockdown length prefix: {e}"),
            diagnostics: None,
        })?;

    stream
        .write_all(bytes)
        .await
        .map_err(|e| WinIpaError::Unknown {
            message: format!("Failed to write lockdown payload: {e}"),
            diagnostics: None,
        })?;

    stream.flush().await.map_err(|e| WinIpaError::Unknown {
        message: format!("Failed to flush lockdown stream: {e}"),
        diagnostics: None,
    })?;

    Ok(())
}

/// Reads a lockdown response packet.
pub async fn read_lockdown_message(stream: &mut TcpStream) -> Result<Value, WinIpaError> {
    let mut len_buf = [0u8; 4];
    stream
        .read_exact(&mut len_buf)
        .await
        .map_err(|e| WinIpaError::Unknown {
            message: format!("Failed to read lockdown message length: {e}"),
            diagnostics: None,
        })?;

    let len = u32::from_be_bytes(len_buf) as usize;
    if len > 10 * 1024 * 1024 {
        // Guard against runaway memory allocation
        return Err(WinIpaError::Unknown {
            message: format!("Lockdown packet exceeds 10MB safety limit: {len}"),
            diagnostics: None,
        });
    }

    let mut body = vec![0u8; len];
    stream
        .read_exact(&mut body)
        .await
        .map_err(|e| WinIpaError::Unknown {
            message: format!("Failed to read lockdown message body: {e}"),
            diagnostics: None,
        })?;

    let val = Value::from_reader_xml(Cursor::new(&body)).map_err(|e| WinIpaError::Unknown {
        message: format!("Failed to parse lockdown XML plist: {e}"),
        diagnostics: None,
    })?;

    Ok(val)
}

/// Parses the lockdown GetValue response into a DeviceInfo struct.
pub fn parse_device_info_response(udid_hint: &str, resp: &Value) -> DeviceInfo {
    let dict = match resp.as_dictionary() {
        Some(d) => d,
        None => {
            return DeviceInfo {
                udid: udid_hint.to_string(),
                name: "iPhone".to_string(),
                ios_version: "Unknown".to_string(),
                model: "iPhone".to_string(),
                is_trusted: false,
                is_locked: false,
                developer_mode_enabled: false,
            }
        }
    };

    // Check for explicit error responses from lockdown
    if let Some(err) = dict.get("Error").and_then(|v| v.as_string()) {
        let is_locked = err.eq_ignore_ascii_case("PasswordProtected")
            || err.eq_ignore_ascii_case("DeviceLocked");
        let is_trusted = !err.eq_ignore_ascii_case("InvalidHostID")
            && !err.eq_ignore_ascii_case("PairingDialogResponsePending")
            && !is_locked;

        return DeviceInfo {
            udid: udid_hint.to_string(),
            name: "iPhone (Passcode Locked / Untrusted)".to_string(),
            ios_version: "Unknown".to_string(),
            model: "iPhone".to_string(),
            is_trusted,
            is_locked,
            developer_mode_enabled: false,
        };
    }

    // Get the root Value dictionary or dict itself
    let values = dict
        .get("Value")
        .and_then(|v| v.as_dictionary())
        .unwrap_or(dict);

    let name = values
        .get("DeviceName")
        .and_then(|v| v.as_string())
        .unwrap_or("iPhone")
        .to_string();

    let ios_version = values
        .get("ProductVersion")
        .and_then(|v| v.as_string())
        .unwrap_or("Unknown")
        .to_string();

    let model = values
        .get("ProductType")
        .and_then(|v| v.as_string())
        .unwrap_or("iPhone")
        .to_string();

    let udid = values
        .get("UniqueDeviceID")
        .and_then(|v| v.as_string())
        .unwrap_or(udid_hint)
        .to_string();

    // If we obtained valid device properties without a lockdown error, device is unlocked & trusted
    DeviceInfo {
        udid,
        name,
        ios_version,
        model,
        is_trusted: true,
        is_locked: false,
        developer_mode_enabled: true, // Will be refined by query_developer_mode_status
    }
}

/// Parses the DeveloperModeStatus response from the AMFI domain.
pub fn parse_developer_mode_response(resp: &Value, ios_version: &str) -> bool {
    // If iOS version is less than 16, Developer Mode does not exist and is not required
    if let Some(major_str) = ios_version.split('.').next() {
        if let Ok(major) = major_str.parse::<u32>() {
            if major < 16 {
                return true;
            }
        }
    }

    if let Some(dict) = resp.as_dictionary() {
        if let Some(val) = dict.get("Value") {
            if let Some(b) = val.as_boolean() {
                return b;
            }
            if let Some(i) = val.as_signed_integer() {
                return i != 0;
            }
        }
    }

    false
}

/// Queries all device properties from an active lockdown TCP stream.
pub async fn query_device_info(
    stream: &mut TcpStream,
    udid_hint: &str,
) -> Result<DeviceInfo, WinIpaError> {
    // 1. Send QueryType
    let query_type_xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Request</key>
    <string>QueryType</string>
    <key>Label</key>
    <string>WinIPA</string>
</dict>
</plist>"#;

    send_lockdown_message(stream, query_type_xml).await?;
    let _type_resp = read_lockdown_message(stream).await?;

    // 2. Query GetValue
    let get_value_xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Request</key>
    <string>GetValue</string>
    <key>Label</key>
    <string>WinIPA</string>
</dict>
</plist>"#;

    send_lockdown_message(stream, get_value_xml).await?;
    let value_resp = read_lockdown_message(stream).await?;

    let mut device_info = parse_device_info_response(udid_hint, &value_resp);

    // If device is locked or untrusted, we cannot query Developer Mode
    if !device_info.is_trusted || device_info.is_locked {
        return Ok(device_info);
    }

    // 3. Query DeveloperModeStatus via AMFI domain
    let dev_mode_xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Request</key>
    <string>GetValue</string>
    <key>Domain</key>
    <string>com.apple.security.mac.amfi</string>
    <key>Key</key>
    <string>DeveloperModeStatus</string>
    <key>Label</key>
    <string>WinIPA</string>
</dict>
</plist>"#;

    if send_lockdown_message(stream, dev_mode_xml).await.is_ok() {
        if let Ok(dev_mode_resp) = read_lockdown_message(stream).await {
            device_info.developer_mode_enabled =
                parse_developer_mode_response(&dev_mode_resp, &device_info.ios_version);
        }
    }

    Ok(device_info)
}

/// Starts an isolated lockdown service (such as com.apple.afc or com.apple.mobile.installation_proxy)
/// and returns the allocated port number on the device.
pub async fn start_lockdown_service(
    stream: &mut TcpStream,
    service_name: &str,
) -> Result<u16, WinIpaError> {
    let xml = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Request</key>
    <string>StartService</string>
    <key>Service</key>
    <string>{service_name}</string>
    <key>Label</key>
    <string>WinIPA</string>
</dict>
</plist>"#
    );

    send_lockdown_message(stream, &xml).await?;
    let resp = read_lockdown_message(stream).await?;

    if let Some(dict) = resp.as_dictionary() {
        if let Some(err) = dict.get("Error").and_then(|v| v.as_string()) {
            return Err(WinIpaError::InstallFailed(format!(
                "Failed to start service {service_name}: {err}"
            )));
        }
        if let Some(port) = dict.get("Port").and_then(|v| v.as_signed_integer()) {
            return Ok(port as u16);
        }
    }

    Err(WinIpaError::InstallFailed(format!(
        "Invalid response starting service {service_name}"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_device_info_success() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Value</key>
    <dict>
        <key>DeviceName</key>
        <string>Alex's iPhone</string>
        <key>ProductVersion</key>
        <string>17.4.1</string>
        <key>ProductType</key>
        <string>iPhone15,2</string>
        <key>UniqueDeviceID</key>
        <string>00008110-001234567890ABCD</string>
    </dict>
</dict>
</plist>"#;

        let val = Value::from_reader_xml(Cursor::new(xml.as_bytes())).unwrap();
        let info = parse_device_info_response("00008110-001234567890ABCD", &val);

        assert_eq!(info.name, "Alex's iPhone");
        assert_eq!(info.ios_version, "17.4.1");
        assert_eq!(info.model, "iPhone15,2");
        assert_eq!(info.udid, "00008110-001234567890ABCD");
        assert!(info.is_trusted);
        assert!(!info.is_locked);
    }

    #[test]
    fn test_parse_device_info_password_protected() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Error</key>
    <string>PasswordProtected</string>
</dict>
</plist>"#;

        let val = Value::from_reader_xml(Cursor::new(xml.as_bytes())).unwrap();
        let info = parse_device_info_response("fake-udid", &val);

        assert!(info.is_locked);
        assert!(!info.is_trusted);
    }

    #[test]
    fn test_developer_mode_parsing() {
        // iOS 17 with DeveloperModeStatus = true
        let xml_true = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Value</key>
    <true/>
</dict>
</plist>"#;
        let val_true = Value::from_reader_xml(Cursor::new(xml_true.as_bytes())).unwrap();
        assert!(parse_developer_mode_response(&val_true, "17.4.1"));

        // iOS 17 with DeveloperModeStatus = false
        let xml_false = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Value</key>
    <false/>
</dict>
</plist>"#;
        let val_false = Value::from_reader_xml(Cursor::new(xml_false.as_bytes())).unwrap();
        assert!(!parse_developer_mode_response(&val_false, "17.4.1"));

        // iOS 15 (older iOS where Developer Mode did not exist)
        assert!(parse_developer_mode_response(&val_false, "15.7"));
    }
}
