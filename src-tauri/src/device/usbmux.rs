// Copyright (C) 2026 WinIPA Contributors
// SPDX-License-Identifier: GPL-3.0-only

use crate::device::driver::{check_service_running, USBMUXD_TCP_PORT};
use crate::errors::WinIpaError;
use plist::Value;
use std::io::Cursor;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

pub const USBMUX_VERSION: u32 = 1;
pub const USBMUX_MSG_PLIST: u32 = 8;
pub const LOCKDOWN_PORT: u16 = 62078;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsbmuxHeader {
    pub length: u32,
    pub version: u32,
    pub message: u32,
    pub tag: u32,
}

impl UsbmuxHeader {
    pub fn new(payload_len: usize, tag: u32) -> Self {
        Self {
            length: (16 + payload_len) as u32,
            version: USBMUX_VERSION,
            message: USBMUX_MSG_PLIST,
            tag,
        }
    }

    pub fn to_bytes(&self) -> [u8; 16] {
        let mut buf = [0u8; 16];
        buf[0..4].copy_from_slice(&self.length.to_le_bytes());
        buf[4..8].copy_from_slice(&self.version.to_le_bytes());
        buf[8..12].copy_from_slice(&self.message.to_le_bytes());
        buf[12..16].copy_from_slice(&self.tag.to_le_bytes());
        buf
    }

    pub fn from_bytes(bytes: &[u8; 16]) -> Self {
        Self {
            length: u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
            version: u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
            message: u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]),
            tag: u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]),
        }
    }
}

#[derive(Debug, Clone)]
pub struct DiscoveredDevice {
    pub device_id: u32,
    pub udid: String,
    pub connection_type: String,
}

#[derive(Debug, Clone)]
pub enum UsbmuxEvent {
    Result { number: i64 },
    Attached(DiscoveredDevice),
    Detached { device_id: u32 },
}

/// Connects to the local usbmuxd service.
pub async fn connect_usbmuxd() -> Result<TcpStream, WinIpaError> {
    if !check_service_running().await {
        return Err(WinIpaError::DriverMissing);
    }

    let addr: SocketAddr = ([127, 0, 0, 1], USBMUXD_TCP_PORT).into();
    let stream = timeout(Duration::from_secs(2), TcpStream::connect(addr))
        .await
        .map_err(|_| WinIpaError::Timeout("Connecting to usbmuxd".into()))?
        .map_err(|_| WinIpaError::DriverMissing)?;

    Ok(stream)
}

/// Sends a plist payload to a usbmuxd connection.
pub async fn send_usbmux_message(
    stream: &mut TcpStream,
    tag: u32,
    payload: &str,
) -> Result<(), WinIpaError> {
    let payload_bytes = payload.as_bytes();
    let header = UsbmuxHeader::new(payload_bytes.len(), tag);

    stream
        .write_all(&header.to_bytes())
        .await
        .map_err(|e| WinIpaError::Unknown {
            message: format!("Failed to write usbmux header: {e}"),
            diagnostics: None,
        })?;

    stream
        .write_all(payload_bytes)
        .await
        .map_err(|e| WinIpaError::Unknown {
            message: format!("Failed to write usbmux payload: {e}"),
            diagnostics: None,
        })?;

    stream.flush().await.map_err(|e| WinIpaError::Unknown {
        message: format!("Failed to flush usbmux stream: {e}"),
        diagnostics: None,
    })?;

    Ok(())
}

/// Reads the next usbmux packet from the connection.
pub async fn read_usbmux_packet(
    stream: &mut TcpStream,
) -> Result<(UsbmuxHeader, Value), WinIpaError> {
    let mut header_buf = [0u8; 16];
    stream
        .read_exact(&mut header_buf)
        .await
        .map_err(|e| WinIpaError::Unknown {
            message: format!("Failed to read usbmux packet header: {e}"),
            diagnostics: None,
        })?;

    let header = UsbmuxHeader::from_bytes(&header_buf);
    if header.length < 16 {
        return Err(WinIpaError::Unknown {
            message: format!("Invalid usbmux packet length: {}", header.length),
            diagnostics: None,
        });
    }

    let payload_len = (header.length - 16) as usize;
    let mut payload_buf = vec![0u8; payload_len];
    stream
        .read_exact(&mut payload_buf)
        .await
        .map_err(|e| WinIpaError::Unknown {
            message: format!("Failed to read usbmux packet body: {e}"),
            diagnostics: None,
        })?;

    let value =
        Value::from_reader_xml(Cursor::new(&payload_buf)).map_err(|e| WinIpaError::Unknown {
            message: format!("Failed to parse usbmux XML plist: {e}"),
            diagnostics: None,
        })?;

    Ok((header, value))
}

/// Parses a plist Value into a structured UsbmuxEvent.
pub fn parse_usbmux_event(plist_val: &Value) -> Option<UsbmuxEvent> {
    let dict = plist_val.as_dictionary()?;
    let msg_type = dict.get("MessageType")?.as_string()?;

    match msg_type {
        "Result" => {
            let number = dict.get("Number")?.as_signed_integer()?;
            Some(UsbmuxEvent::Result { number })
        }
        "Attached" => {
            let device_id = dict.get("DeviceID")?.as_signed_integer()? as u32;
            let props = dict.get("Properties")?.as_dictionary()?;
            let udid = props.get("SerialNumber")?.as_string()?.to_string();
            let connection_type = props
                .get("ConnectionType")
                .and_then(|v| v.as_string())
                .unwrap_or("USB")
                .to_string();

            Some(UsbmuxEvent::Attached(DiscoveredDevice {
                device_id,
                udid,
                connection_type,
            }))
        }
        "Detached" => {
            let device_id = dict.get("DeviceID")?.as_signed_integer()? as u32;
            Some(UsbmuxEvent::Detached { device_id })
        }
        _ => None,
    }
}

/// Starts listening for device attach/detach events on a new usbmux connection.
pub async fn send_listen_request(stream: &mut TcpStream, tag: u32) -> Result<(), WinIpaError> {
    let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>MessageType</key>
    <string>Listen</string>
    <key>ClientVersionString</key>
    <string>WinIPA</string>
    <key>ProgName</key>
    <string>WinIPA</string>
</dict>
</plist>"#;

    send_usbmux_message(stream, tag, xml).await
}

/// Connects a stream through usbmuxd to a port on the target device (e.g. lockdown on 62078).
pub async fn connect_to_device_port(device_id: u32, port: u16) -> Result<TcpStream, WinIpaError> {
    let mut stream = connect_usbmuxd().await?;

    // Port number must be in network byte order (big-endian) in the usbmux plist
    let port_network_order = ((port >> 8) & 0xFF) | ((port & 0xFF) << 8);

    let xml = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>MessageType</key>
    <string>Connect</string>
    <key>ClientVersionString</key>
    <string>WinIPA</string>
    <key>ProgName</key>
    <string>WinIPA</string>
    <key>DeviceID</key>
    <integer>{device_id}</integer>
    <key>PortNumber</key>
    <integer>{port_network_order}</integer>
</dict>
</plist>"#
    );

    send_usbmux_message(&mut stream, 1, &xml).await?;

    let (_header, resp) = read_usbmux_packet(&mut stream).await?;
    if let Some(UsbmuxEvent::Result { number }) = parse_usbmux_event(&resp) {
        if number != 0 {
            return Err(WinIpaError::InstallFailed(format!(
                "usbmux connect rejected with error code {number}"
            )));
        }
    } else {
        return Err(WinIpaError::Unknown {
            message: "Unexpected response from usbmux connect request".into(),
            diagnostics: None,
        });
    }

    Ok(stream)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_usbmux_header_serialization() {
        let header = UsbmuxHeader::new(100, 42);
        assert_eq!(header.length, 116);
        assert_eq!(header.version, 1);
        assert_eq!(header.message, 8);
        assert_eq!(header.tag, 42);

        let bytes = header.to_bytes();
        let parsed = UsbmuxHeader::from_bytes(&bytes);
        assert_eq!(header, parsed);
    }

    #[test]
    fn test_parse_attached_event() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>MessageType</key>
    <string>Attached</string>
    <key>DeviceID</key>
    <integer>5</integer>
    <key>Properties</key>
    <dict>
        <key>ConnectionType</key>
        <string>USB</string>
        <key>DeviceID</key>
        <integer>5</integer>
        <key>ProductID</key>
        <integer>4776</integer>
        <key>SerialNumber</key>
        <string>00008030-001234567890ABCD</string>
    </dict>
</dict>
</plist>"#;

        let val = Value::from_reader_xml(Cursor::new(xml.as_bytes())).expect("valid plist");
        let event = parse_usbmux_event(&val).expect("valid event");

        match event {
            UsbmuxEvent::Attached(dev) => {
                assert_eq!(dev.device_id, 5);
                assert_eq!(dev.udid, "00008030-001234567890ABCD");
                assert_eq!(dev.connection_type, "USB");
            }
            _ => panic!("Expected Attached event"),
        }
    }

    #[test]
    fn test_parse_detached_event() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>MessageType</key>
    <string>Detached</string>
    <key>DeviceID</key>
    <integer>5</integer>
</dict>
</plist>"#;

        let val = Value::from_reader_xml(Cursor::new(xml.as_bytes())).expect("valid plist");
        let event = parse_usbmux_event(&val).expect("valid event");

        match event {
            UsbmuxEvent::Detached { device_id } => {
                assert_eq!(device_id, 5);
            }
            _ => panic!("Expected Detached event"),
        }
    }
}
