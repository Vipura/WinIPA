// Copyright (C) 2026 WinIPA Contributors
// SPDX-License-Identifier: GPL-3.0-only

use super::crypto::generate_dev_csr;
use super::service::{AppleService, DevelopmentCertificate, LoginResult, ProvisioningProfile};
use super::{AppleAccountType, AppleSessionInfo};
use crate::errors::WinIpaError;
use async_trait::async_trait;

#[derive(Debug, Default)]
pub struct MockAppleService {
    pub session: Option<AppleSessionInfo>,
    pub force_wrong_password: bool,
    pub force_rate_limit: bool,
    pub force_account_limit: bool,
    pub force_2fa: bool,
    pub force_invalid_2fa: bool,
}

#[async_trait]
impl AppleService for MockAppleService {
    async fn login(&mut self, apple_id: &str, password: &str) -> Result<LoginResult, WinIpaError> {
        if self.force_rate_limit {
            return Err(WinIpaError::AppleRateLimited);
        }

        if self.force_wrong_password || password == "wrong_password" {
            return Err(WinIpaError::AppleAuthFailed(
                "Your Apple ID or password was entered incorrectly.".into(),
            ));
        }

        if self.force_account_limit {
            return Err(WinIpaError::AccountLimitReached(
                "Maximum number of free apps (3) already active on this device.".into(),
            ));
        }

        if self.force_2fa || password == "needs_2fa" {
            return Ok(LoginResult::TwoFactorRequired {
                phone_numbers: vec!["Trusted Devices / SMS".into()],
            });
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let session = AppleSessionInfo {
            apple_id: apple_id.to_string(),
            team_id: "TEAMMOCK12".into(),
            team_name: format!("{apple_id} (Personal Team)"),
            account_type: AppleAccountType::Free,
            cert_expires_at: Some(now + 7 * 86400),
        };

        self.session = Some(session.clone());
        Ok(LoginResult::Success(session))
    }

    async fn submit_2fa(&mut self, code: &str) -> Result<AppleSessionInfo, WinIpaError> {
        if self.force_invalid_2fa || code != "123456" {
            return Err(WinIpaError::TwoFactorFailed(
                "Incorrect 2FA verification code.".into(),
            ));
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let session = AppleSessionInfo {
            apple_id: "test.developer@example.com".into(),
            team_id: "TEAMMOCK12".into(),
            team_name: "Mock Developer (Personal Team)".into(),
            account_type: AppleAccountType::Free,
            cert_expires_at: Some(now + 7 * 86400),
        };

        self.session = Some(session.clone());
        Ok(session)
    }

    async fn get_active_session(&self) -> Result<Option<AppleSessionInfo>, WinIpaError> {
        Ok(self.session.clone())
    }

    async fn logout(&mut self) -> Result<(), WinIpaError> {
        self.session = None;
        Ok(())
    }

    async fn register_device(&self, udid: &str, _name: &str) -> Result<String, WinIpaError> {
        if self.force_account_limit {
            return Err(WinIpaError::AccountLimitReached(
                "Maximum registered device limit reached.".into(),
            ));
        }
        Ok(format!("DEV_{udid}"))
    }

    async fn get_or_create_app_id(
        &self,
        bundle_id: &str,
        _name: &str,
    ) -> Result<String, WinIpaError> {
        if self.force_account_limit {
            return Err(WinIpaError::AccountLimitReached(
                "Weekly App ID limit reached (~10 per week for free accounts).".into(),
            ));
        }
        Ok(format!("APPID_{bundle_id}"))
    }

    async fn request_development_certificate(&self) -> Result<DevelopmentCertificate, WinIpaError> {
        let keypair = generate_dev_csr("Apple Development: Mock User", "TEAMMOCK12")?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Ok(DevelopmentCertificate {
            cert_id: "MOCK_CERT_ID_123".into(),
            certificate_data: b"MOCK_CERTIFICATE_BYTES".to_vec(),
            private_key_pem: keypair.private_key_pem,
            expires_at: now + 7 * 86400,
        })
    }

    async fn request_provisioning_profile(
        &self,
        app_id_id: &str,
        device_id: &str,
        cert_id: &str,
    ) -> Result<ProvisioningProfile, WinIpaError> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Ok(ProvisioningProfile {
            profile_id: format!("PROF_{app_id_id}_{device_id}_{cert_id}"),
            profile_name: "iOS Team Provisioning Profile: com.mock.app".into(),
            profile_data: b"MOCK_PROVISIONING_PROFILE_DATA".to_vec(),
            expires_at: now + 7 * 86400,
        })
    }

    async fn set_team_id(&mut self, team_id: &str) -> Result<AppleSessionInfo, WinIpaError> {
        let team_id_clean = team_id.trim().to_uppercase();
        if team_id_clean.len() != 10 || !team_id_clean.chars().all(|c| c.is_ascii_alphanumeric()) {
            return Err(WinIpaError::AppleAuthFailed(
                "Team ID must be exactly 10 alphanumeric characters (e.g. 7X8Y9Z1A2B)".into(),
            ));
        }

        if let Some(ref mut session) = self.session {
            session.team_id = team_id_clean.clone();
            session.team_name = format!("{} (Personal Team)", session.apple_id);
            return Ok(session.clone());
        }

        Err(WinIpaError::AppleAuthFailed(
            "No active session to update Team ID".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_mock_login_success() {
        let mut service = MockAppleService::default();
        let res = service
            .login("developer@example.com", "valid_password")
            .await
            .unwrap();

        match res {
            LoginResult::Success(s) => {
                assert_eq!(s.apple_id, "developer@example.com");
                assert_eq!(s.account_type, AppleAccountType::Free);
            }
            _ => panic!("Expected login success"),
        }
    }

    #[tokio::test]
    async fn test_mock_login_wrong_password() {
        let mut service = MockAppleService::default();
        let err = service
            .login("developer@example.com", "wrong_password")
            .await
            .unwrap_err();

        match err {
            WinIpaError::AppleAuthFailed(msg) => {
                assert!(msg.contains("incorrectly"));
            }
            _ => panic!("Expected AppleAuthFailed error"),
        }
    }

    #[tokio::test]
    async fn test_mock_login_2fa_flow() {
        let mut service = MockAppleService::default();
        let res = service
            .login("developer@example.com", "needs_2fa")
            .await
            .unwrap();

        match res {
            LoginResult::TwoFactorRequired { phone_numbers } => {
                assert!(!phone_numbers.is_empty());
            }
            _ => panic!("Expected TwoFactorRequired"),
        }

        // Test invalid 2fa code
        let fail_2fa = service.submit_2fa("000000").await.unwrap_err();
        match fail_2fa {
            WinIpaError::TwoFactorFailed(_) => {}
            _ => panic!("Expected TwoFactorFailed error"),
        }

        // Test valid 2fa code
        let session = service.submit_2fa("123456").await.unwrap();
        assert_eq!(session.apple_id, "test.developer@example.com");
    }

    #[tokio::test]
    async fn test_mock_rate_limit() {
        let mut service = MockAppleService {
            force_rate_limit: true,
            ..Default::default()
        };
        let err = service
            .login("developer@example.com", "password")
            .await
            .unwrap_err();
        assert_eq!(err, WinIpaError::AppleRateLimited);
    }

    #[tokio::test]
    async fn test_mock_account_limit() {
        let mut service = MockAppleService {
            force_account_limit: true,
            ..Default::default()
        };
        let err = service
            .login("developer@example.com", "password")
            .await
            .unwrap_err();
        match err {
            WinIpaError::AccountLimitReached(_) => {}
            _ => panic!("Expected AccountLimitReached"),
        }
    }

    #[tokio::test]
    async fn test_mock_certificate_and_profile_generation() {
        let service = MockAppleService::default();
        let cert = service.request_development_certificate().await.unwrap();
        assert!(cert
            .private_key_pem
            .starts_with("-----BEGIN PRIVATE KEY-----"));
        assert!(!cert.certificate_data.is_empty());

        let prof = service
            .request_provisioning_profile("APP_1", "DEV_1", &cert.cert_id)
            .await
            .unwrap();
        assert!(!prof.profile_data.is_empty());
        assert_eq!(
            prof.profile_name,
            "iOS Team Provisioning Profile: com.mock.app"
        );
    }

    #[tokio::test]
    async fn test_mock_set_team_id() {
        let mut service = MockAppleService::default();
        let _ = service
            .login("developer@example.com", "valid_password")
            .await
            .unwrap();

        // Invalid length
        let err = service.set_team_id("TOO_SHORT").await.unwrap_err();
        match err {
            WinIpaError::AppleAuthFailed(_) => {}
            _ => panic!("Expected AppleAuthFailed for invalid team ID"),
        }

        // Valid 10-char team ID
        let updated = service.set_team_id("abc1234xyz").await.unwrap();
        assert_eq!(updated.team_id, "ABC1234XYZ");
    }
}
