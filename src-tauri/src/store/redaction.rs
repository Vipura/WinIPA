// Copyright (C) 2026 WinIPA Contributors
// SPDX-License-Identifier: GPL-3.0-only

use regex::Regex;
use std::sync::OnceLock;

static REDACTION_RULES: OnceLock<Vec<(Regex, &'static str)>> = OnceLock::new();

fn get_rules() -> &'static [(Regex, &'static str)] {
    REDACTION_RULES.get_or_init(|| {
        vec![
            // Email address: redact user portion, keep domain
            (
                Regex::new(r"(?i)\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
                    .expect("valid regex"),
                "[REDACTED_EMAIL]",
            ),
            // UDID (40 hex chars or 25 chars with hyphen)
            (
                Regex::new(r"\b[0-9a-fA-F]{40}\b").expect("valid regex"),
                "[REDACTED_UDID]",
            ),
            (
                Regex::new(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{16}\b").expect("valid regex"),
                "[REDACTED_UDID]",
            ),
            // Password / token keys in json: "password": "..." -> "password": "[REDACTED_SECRET]"
            (
                Regex::new(
                    r#"(?i)"(password|token|secret|authKey|appleIdSessionToken)"\s*:\s*"[^"]*""#,
                )
                .expect("valid regex"),
                r#""$1": "[REDACTED_SECRET]""#,
            ),
            // Password / token keys in key=value or unquoted: password=... -> password=[REDACTED_SECRET]
            (
                Regex::new(
                    r#"(?i)\b(password|token|secret|authKey|appleIdSessionToken)\s*=\s*[^\s,]+"#,
                )
                .expect("valid regex"),
                "$1=[REDACTED_SECRET]",
            ),
            // 6-digit 2FA code
            (
                Regex::new(r"\b\d{6}\b").expect("valid regex"),
                "[REDACTED_CODE]",
            ),
        ]
    })
}

/// Redacts sensitive personal information (Apple IDs, UDIDs, secrets, passwords)
/// from any string before it is shown in UI or written to logs.
pub fn redact_sensitive_info(input: &str) -> String {
    let mut sanitized = input.to_string();
    for (regex, replacement) in get_rules() {
        sanitized = regex.replace_all(&sanitized, *replacement).to_string();
    }
    sanitized
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_redact_email() {
        let text = "User test.developer@example.com logged in";
        assert_eq!(
            redact_sensitive_info(text),
            "User [REDACTED_EMAIL] logged in"
        );
    }

    #[test]
    fn test_redact_udid() {
        let text = "Device with UDID 1234567890abcdef1234567890abcdef12345678 connected";
        assert_eq!(
            redact_sensitive_info(text),
            "Device with UDID [REDACTED_UDID] connected"
        );

        let modern_udid = "00008030-001234567890ABCD";
        assert_eq!(redact_sensitive_info(modern_udid), "[REDACTED_UDID]");
    }

    #[test]
    fn test_redact_password() {
        let text = r#"{"password": "SuperSecretPassword123!"}"#;
        assert_eq!(
            redact_sensitive_info(text),
            r#"{"password": "[REDACTED_SECRET]"}"#
        );

        let cli_text = "Connecting with token=secretToken12345 to Apple";
        assert_eq!(
            redact_sensitive_info(cli_text),
            "Connecting with token=[REDACTED_SECRET] to Apple"
        );
    }
}
