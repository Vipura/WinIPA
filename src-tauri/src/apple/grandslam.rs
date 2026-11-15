// Copyright (C) 2026 WinIPA Contributors
// SPDX-License-Identifier: GPL-3.0-only

use std::io::Cursor;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::UNIX_EPOCH;

use async_trait::async_trait;
use isideload::auth::apple_account::{TwoFactorCallbackParams, TwoFactorCallbackResponse};
use isideload::auth::builder::AppleAccountBuilder;
use isideload::dev::app_ids::{AppId, AppIdsApi};
use isideload::dev::developer_session::DeveloperSession;
use isideload::dev::device_type::DeveloperDeviceType;
use isideload::dev::devices::DevicesApi;
use isideload::dev::teams::{DeveloperTeam, TeamsApi};
use isideload::sideload::builder::MaxCertsBehavior;
use isideload::sideload::cert_identity::CertificateIdentity;
use isideload::util::fs_storage::FsStorage;
use rootcause::Report;
use rsa::pkcs8::EncodePrivateKey;
use tokio::sync::Mutex as TokioMutex;
use x509_cert::der::Encode;

use super::service::{AppleService, DevelopmentCertificate, LoginResult, ProvisioningProfile};
use super::{AppleAccountType, AppleSessionInfo};
use crate::errors::WinIpaError;
use crate::store::{delete_secret, get_app_dir, get_secret, store_secret};

#[allow(dead_code)]
fn dummy_max_certs_callback(
    _certs: Vec<isideload::dev::certificates::DevelopmentCertificate>,
) -> std::future::Ready<Result<Option<Vec<String>>, Report>> {
    std::future::ready(Ok(None))
}

struct Pending2FASession {
    #[allow(dead_code)]
    apple_id: String,
    code_tx: tokio::sync::oneshot::Sender<String>,
    result_rx: tokio::sync::oneshot::Receiver<Result<AppleSessionInfo, WinIpaError>>,
}

pub struct GrandSlamAppleClient {
    active_apple_id: StdMutex<Option<String>>,
    session_info: StdMutex<Option<AppleSessionInfo>>,
    dev_session: TokioMutex<Option<DeveloperSession>>,
    pending_2fa: TokioMutex<Option<Pending2FASession>>,
}

impl Default for GrandSlamAppleClient {
    fn default() -> Self {
        Self::new()
    }
}

impl GrandSlamAppleClient {
    pub fn new() -> Self {
        Self {
            active_apple_id: StdMutex::new(None),
            session_info: StdMutex::new(None),
            dev_session: TokioMutex::new(None),
            pending_2fa: TokioMutex::new(None),
        }
    }

    async fn get_or_create_dev_session(&self) -> Result<DeveloperSession, WinIpaError> {
        let mut guard = self.dev_session.lock().await;
        if let Some(ref ds) = *guard {
            return Ok(ds.clone());
        }

        let apple_id = get_secret("active_apple_id")
            .ok()
            .flatten()
            .or_else(|| self.active_apple_id.lock().unwrap().clone())
            .ok_or_else(|| {
                WinIpaError::AppleAuthFailed(
                    "No active Apple account found. Please sign in via Device & Account.".into(),
                )
            })?;

        // 1. Check if SPD is stored in vault
        let spd_xml = get_secret(&format!("spd:{apple_id}")).ok().flatten();

        if let Some(spd_str) = spd_xml {
            let spd_val: plist::Value = plist::Value::from_reader(Cursor::new(spd_str.as_bytes()))
                .map_err(|e| {
                    WinIpaError::AppleAuthFailed(format!(
                        "Failed to parse stored Apple credentials: {e}"
                    ))
                })?;

            let account_builder = AppleAccountBuilder::new(&apple_id);
            let mut account = account_builder.build().await.map_err(|e| {
                WinIpaError::AppleAuthFailed(format!(
                    "Failed to initialize Apple account client: {e}"
                ))
            })?;
            account.spd = spd_val.into_dictionary();

            let ds = DeveloperSession::from_account(&mut account).await.map_err(|e| {
                WinIpaError::AppleAuthFailed(format!(
                    "Apple Developer session expired ({e}). Please click 'Log Out & Sign In Again' to authenticate."
                ))
            })?;

            *guard = Some(ds.clone());
            return Ok(ds);
        }

        Err(WinIpaError::AppleAuthFailed(
            "Your Apple Developer session requires authentication. Please click 'Log Out & Sign In Again' to authenticate with your 6-digit 2FA code.".into(),
        ))
    }

    async fn get_current_team(
        &self,
        dev_session: &mut DeveloperSession,
    ) -> Result<DeveloperTeam, WinIpaError> {
        let teams = dev_session.list_teams().await.map_err(|e| {
            WinIpaError::AppleAuthFailed(format!("Failed to list Apple Developer teams: {e}"))
        })?;

        if teams.is_empty() {
            return Err(WinIpaError::AppleAuthFailed(
                "No Developer Team found for this Apple ID. Please accept the Apple Developer Agreement at developer.apple.com.".into(),
            ));
        }

        // Match by saved team if available
        let saved_team_id =
            self.session_info
                .lock()
                .unwrap()
                .as_ref()
                .map(|s| s.team_id.clone())
                .or_else(|| {
                    get_secret("active_apple_id").ok().flatten().and_then(|id| {
                        get_secret(&format!("saved_team:{id}"))
                            .ok()
                            .flatten()
                            .or_else(|| {
                                get_secret(&format!("info:{id}")).ok().flatten().and_then(
                                    |info_str| {
                                        serde_json::from_str::<AppleSessionInfo>(&info_str)
                                            .ok()
                                            .map(|s| s.team_id)
                                    },
                                )
                            })
                    })
                });

        if let Some(target_id) = saved_team_id {
            if let Some(t) = teams.iter().find(|t| t.team_id == target_id) {
                return Ok(t.clone());
            }
        }

        // Default to personal team or first team
        let personal = teams.iter().find(|t| {
            t.r#type.as_deref() == Some("Personal")
                || t.name.as_deref().unwrap_or("").contains("Personal")
        });

        if let Some(t) = personal {
            Ok(t.clone())
        } else {
            Ok(teams[0].clone())
        }
    }
}

#[async_trait]
impl AppleService for GrandSlamAppleClient {
    async fn login(&mut self, apple_id: &str, password: &str) -> Result<LoginResult, WinIpaError> {
        // Clear any previous pending 2FA state
        *self.pending_2fa.lock().await = None;

        let (code_tx, code_rx) = tokio::sync::oneshot::channel::<String>();
        let (initial_res_tx, initial_res_rx) =
            tokio::sync::oneshot::channel::<Result<LoginResult, WinIpaError>>();
        let (final_res_tx, final_res_rx) =
            tokio::sync::oneshot::channel::<Result<AppleSessionInfo, WinIpaError>>();

        let apple_id_owned = apple_id.trim().to_string();
        let password_owned = password.to_string();

        tokio::spawn(async move {
            let account_builder = AppleAccountBuilder::new(&apple_id_owned);
            let mut account = match account_builder.build().await {
                Ok(acc) => acc,
                Err(e) => {
                    let _ = initial_res_tx.send(Err(WinIpaError::AppleAuthFailed(format!(
                        "Failed to initialize Apple account: {e}"
                    ))));
                    return;
                }
            };

            let initial_tx_cell = Arc::new(tokio::sync::Mutex::new(Some(initial_res_tx)));
            let code_rx_cell = Arc::new(tokio::sync::Mutex::new(Some(code_rx)));

            let initial_tx_for_cb = initial_tx_cell.clone();
            let code_rx_for_cb = code_rx_cell.clone();

            let login_res = account
                .login(&password_owned, move |params: TwoFactorCallbackParams| {
                    let initial_tx = initial_tx_for_cb.clone();
                    let code_rx = code_rx_for_cb.clone();
                    async move {
                        // Signal apple_login command that 2FA code is needed
                        if let Some(tx) = initial_tx.lock().await.take() {
                            let phone_numbers = params
                                .numbers
                                .into_iter()
                                .map(|n| n.number_with_dial_code)
                                .collect();
                            let _ = tx.send(Ok(LoginResult::TwoFactorRequired { phone_numbers }));
                        }

                        // Wait for the 2FA code delivered via apple_submit_2fa
                        let mut guard = code_rx.lock().await;
                        if let Some(rx) = guard.take() {
                            match rx.await {
                                Ok(code) => Ok(TwoFactorCallbackResponse::SubmitCode(code)),
                                Err(_) => Ok(TwoFactorCallbackResponse::Abort),
                            }
                        } else {
                            Ok(TwoFactorCallbackResponse::Abort)
                        }
                    }
                })
                .await;

            match login_res {
                Ok(()) => {
                    // Create developer session with modern Xcode GrandSlam token
                    let dev_session_res = DeveloperSession::from_account(&mut account).await;
                    let mut dev_session = match dev_session_res {
                        Ok(ds) => ds,
                        Err(e) => {
                            let err = WinIpaError::AppleAuthFailed(format!(
                                "Failed to establish Developer session: {e}"
                            ));
                            if let Some(tx) = initial_tx_cell.lock().await.take() {
                                let _ = tx.send(Err(err));
                            } else {
                                let _ = final_res_tx.send(Err(err));
                            }
                            return;
                        }
                    };

                    // Query available teams
                    let teams = dev_session.list_teams().await.unwrap_or_default();
                    let (team_id, team_name, is_free) = if let Some(t) = teams.first() {
                        let is_free = t.r#type.as_deref() == Some("Personal")
                            || t.name.as_deref().unwrap_or("").contains("Personal");
                        (
                            t.team_id.clone(),
                            t.name.clone().unwrap_or_else(|| "Personal Team".into()),
                            is_free,
                        )
                    } else {
                        ("".into(), "Personal Team".into(), true)
                    };

                    let now_secs = std::time::SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();

                    let session_info = AppleSessionInfo {
                        apple_id: apple_id_owned.clone(),
                        team_id,
                        team_name,
                        account_type: if is_free {
                            AppleAccountType::Free
                        } else {
                            AppleAccountType::Paid
                        },
                        cert_expires_at: Some(now_secs + 7 * 86400),
                    };

                    // Persist credentials & GrandSlam SPD to vault
                    let _ = store_secret("active_apple_id", &apple_id_owned);
                    let _ = store_secret(&format!("auth:{apple_id_owned}"), &password_owned);
                    if let Ok(info_str) = serde_json::to_string(&session_info) {
                        let _ = store_secret(&format!("info:{apple_id_owned}"), &info_str);
                    }
                    if let Some(ref spd) = account.spd {
                        let mut spd_bytes = Vec::new();
                        if plist::to_writer_xml(
                            &mut spd_bytes,
                            &plist::Value::Dictionary(spd.clone()),
                        )
                        .is_ok()
                        {
                            if let Ok(spd_xml) = String::from_utf8(spd_bytes) {
                                let _ = store_secret(&format!("spd:{apple_id_owned}"), &spd_xml);
                            }
                        }
                    }

                    // If 2FA was not prompted, finish initial_res_tx
                    if let Some(tx) = initial_tx_cell.lock().await.take() {
                        let _ = tx.send(Ok(LoginResult::Success(session_info)));
                    } else {
                        let _ = final_res_tx.send(Ok(session_info));
                    }
                }
                Err(e) => {
                    let err = WinIpaError::AppleAuthFailed(format!("{e}"));
                    if let Some(tx) = initial_tx_cell.lock().await.take() {
                        let _ = tx.send(Err(err));
                    } else {
                        let _ = final_res_tx.send(Err(err));
                    }
                }
            }
        });

        // Await initial response (either Success or TwoFactorRequired)
        match initial_res_rx.await {
            Ok(Ok(LoginResult::TwoFactorRequired { phone_numbers })) => {
                *self.pending_2fa.lock().await = Some(Pending2FASession {
                    apple_id: apple_id.to_string(),
                    code_tx,
                    result_rx: final_res_rx,
                });
                Ok(LoginResult::TwoFactorRequired { phone_numbers })
            }
            Ok(Ok(LoginResult::Success(info))) => {
                *self.active_apple_id.lock().unwrap() = Some(info.apple_id.clone());
                *self.session_info.lock().unwrap() = Some(info.clone());
                *self.dev_session.lock().await = None;
                Ok(LoginResult::Success(info))
            }
            Ok(Err(e)) => Err(e),
            Err(_) => Err(WinIpaError::AppleAuthFailed(
                "Apple sign-in task aborted unexpectedly".into(),
            )),
        }
    }

    async fn submit_2fa(&mut self, code: &str) -> Result<AppleSessionInfo, WinIpaError> {
        let pending = self.pending_2fa.lock().await.take().ok_or_else(|| {
            WinIpaError::TwoFactorFailed("No pending two-factor authentication session".into())
        })?;

        // Forward code to waiting callback
        if pending.code_tx.send(code.trim().to_string()).is_err() {
            return Err(WinIpaError::TwoFactorFailed(
                "2FA authentication handler was closed".into(),
            ));
        }

        // Await final session result
        match pending.result_rx.await {
            Ok(Ok(info)) => {
                *self.active_apple_id.lock().unwrap() = Some(info.apple_id.clone());
                *self.session_info.lock().unwrap() = Some(info.clone());
                // Invalidate dev_session in memory so fresh SPD is loaded
                *self.dev_session.lock().await = None;
                Ok(info)
            }
            Ok(Err(e)) => Err(e),
            Err(_) => Err(WinIpaError::TwoFactorFailed(
                "2FA verification timed out or was cancelled".into(),
            )),
        }
    }

    async fn get_active_session(&self) -> Result<Option<AppleSessionInfo>, WinIpaError> {
        if let Some(ref info) = *self.session_info.lock().unwrap() {
            return Ok(Some(info.clone()));
        }

        if let Ok(Some(apple_id)) = get_secret("active_apple_id") {
            if let Ok(Some(info_str)) = get_secret(&format!("info:{apple_id}")) {
                if let Ok(info) = serde_json::from_str::<AppleSessionInfo>(&info_str) {
                    *self.active_apple_id.lock().unwrap() = Some(apple_id);
                    *self.session_info.lock().unwrap() = Some(info.clone());
                    return Ok(Some(info));
                }
            }
        }

        Ok(None)
    }

    async fn logout(&mut self) -> Result<(), WinIpaError> {
        if let Some(ref apple_id) = *self.active_apple_id.lock().unwrap() {
            let _ = delete_secret(&format!("spd:{apple_id}"));
            let _ = delete_secret(&format!("auth:{apple_id}"));
            let _ = delete_secret(&format!("info:{apple_id}"));
            let _ = delete_secret(&format!("session:{apple_id}"));
            let _ = delete_secret(&format!("saved_team:{apple_id}"));
        }
        let _ = delete_secret("active_apple_id");
        *self.active_apple_id.lock().unwrap() = None;
        *self.session_info.lock().unwrap() = None;
        *self.dev_session.lock().await = None;
        *self.pending_2fa.lock().await = None;
        Ok(())
    }

    async fn register_device(&self, udid: &str, name: &str) -> Result<String, WinIpaError> {
        let mut dev_session = self.get_or_create_dev_session().await?;
        let team = self.get_current_team(&mut dev_session).await?;

        // Ensure device is registered with Apple Developer Services
        let _ = dev_session
            .ensure_device_registered(&team, name, udid, DeveloperDeviceType::Ios)
            .await;

        let devices = dev_session
            .list_devices(&team, DeveloperDeviceType::Ios)
            .await
            .map_err(|e| WinIpaError::Unknown {
                message: format!("Failed to list devices: {e}"),
                diagnostics: None,
            })?;

        let dev = devices
            .into_iter()
            .find(|d| d.device_number.eq_ignore_ascii_case(udid));

        let device_id = dev
            .and_then(|d| d.device_id)
            .unwrap_or_else(|| udid.to_string());

        Ok(device_id)
    }

    async fn get_or_create_app_id(
        &self,
        bundle_id: &str,
        name: &str,
    ) -> Result<String, WinIpaError> {
        let mut dev_session = self.get_or_create_dev_session().await?;
        let team = self.get_current_team(&mut dev_session).await?;

        // Check if App ID already exists
        if let Ok(list) = dev_session
            .list_app_ids(&team, DeveloperDeviceType::Ios)
            .await
        {
            let target_id_suffix = format!("{bundle_id}.{}", team.team_id);
            for app in list.app_ids {
                if app.identifier == bundle_id || app.identifier == target_id_suffix {
                    return Ok(app.app_id_id);
                }
            }
        }

        // Register App ID
        let app_id = dev_session
            .add_app_id(&team, name, bundle_id, DeveloperDeviceType::Ios)
            .await
            .map_err(|e| WinIpaError::Unknown {
                message: format!("Failed to register App ID '{bundle_id}': {e}"),
                diagnostics: None,
            })?;

        Ok(app_id.app_id_id)
    }

    async fn request_development_certificate(&self) -> Result<DevelopmentCertificate, WinIpaError> {
        let mut dev_session = self.get_or_create_dev_session().await?;
        let team = self.get_current_team(&mut dev_session).await?;

        let apple_id = self
            .active_apple_id
            .lock()
            .unwrap()
            .clone()
            .or_else(|| get_secret("active_apple_id").ok().flatten())
            .unwrap_or_else(|| "WinIPA User".into());

        let keys_dir = get_app_dir().join("keys");
        let _ = std::fs::create_dir_all(&keys_dir);
        let storage = FsStorage::new(keys_dir);

        let max_certs: MaxCertsBehavior<
            fn(
                Vec<isideload::dev::certificates::DevelopmentCertificate>,
            ) -> std::future::Ready<Result<Option<Vec<String>>, Report>>,
        > = MaxCertsBehavior::Revoke;

        let cert_identity = CertificateIdentity::retrieve(
            "WinIPA",
            &apple_id,
            &mut dev_session,
            &team,
            &storage,
            &max_certs,
        )
        .await
        .map_err(|e| WinIpaError::Unknown {
            message: format!("Failed to retrieve or generate development certificate: {e}"),
            diagnostics: None,
        })?;

        let cert_der = cert_identity
            .certificate
            .to_der()
            .map_err(|e| WinIpaError::Unknown {
                message: format!("Failed to encode certificate DER: {e}"),
                diagnostics: None,
            })?;

        let priv_pem = cert_identity
            .private_key
            .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
            .map_err(|e| WinIpaError::Unknown {
                message: format!("Failed to encode private key PEM: {e}"),
                diagnostics: None,
            })?;

        let cert_id = cert_identity.get_serial_number();
        let now_secs = std::time::SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Ok(DevelopmentCertificate {
            cert_id,
            certificate_data: cert_der,
            private_key_pem: priv_pem.to_string(),
            expires_at: now_secs + 7 * 86400,
        })
    }

    async fn request_provisioning_profile(
        &self,
        app_id_id: &str,
        _device_id: &str,
        _cert_id: &str,
    ) -> Result<ProvisioningProfile, WinIpaError> {
        let mut dev_session = self.get_or_create_dev_session().await?;
        let team = self.get_current_team(&mut dev_session).await?;

        let dummy_app = AppId {
            app_id_id: app_id_id.to_string(),
            identifier: "".into(),
            name: "".into(),
            features: plist::Dictionary::new(),
            expiration_date: None,
        };

        let profile = dev_session
            .download_team_provisioning_profile(&team, &dummy_app, DeveloperDeviceType::Ios)
            .await
            .map_err(|e| WinIpaError::Unknown {
                message: format!("Failed to download provisioning profile: {e}"),
                diagnostics: None,
            })?;

        let sys_time: std::time::SystemTime = profile.date_expire.into();
        let expires_at = sys_time
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Ok(ProvisioningProfile {
            profile_id: profile.provisioning_profile_id,
            profile_name: profile.name,
            profile_data: profile.encoded_profile.as_ref().to_vec(),
            expires_at,
        })
    }

    async fn set_team_id(&mut self, team_id: &str) -> Result<AppleSessionInfo, WinIpaError> {
        if let Some(ref mut info) = *self.session_info.lock().unwrap() {
            info.team_id = team_id.to_string();
            if let Ok(info_str) = serde_json::to_string(info) {
                let _ = store_secret(&format!("info:{}", info.apple_id), &info_str);
            }
            let _ = store_secret(&format!("saved_team:{}", info.apple_id), team_id);
            return Ok(info.clone());
        }

        if let Ok(Some(apple_id)) = get_secret("active_apple_id") {
            if let Ok(Some(info_str)) = get_secret(&format!("info:{apple_id}")) {
                if let Ok(mut info) = serde_json::from_str::<AppleSessionInfo>(&info_str) {
                    info.team_id = team_id.to_string();
                    let _ = store_secret(
                        &format!("info:{apple_id}"),
                        &serde_json::to_string(&info).unwrap_or_default(),
                    );
                    let _ = store_secret(&format!("saved_team:{apple_id}"), team_id);
                    *self.session_info.lock().unwrap() = Some(info.clone());
                    return Ok(info);
                }
            }
        }

        Err(WinIpaError::AppleAuthFailed(
            "No active Apple session found".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_grandslam_client_init_and_get_session() {
        let client = GrandSlamAppleClient::new();
        let session = client.get_active_session().await;
        assert!(session.is_ok());
    }

    #[tokio::test]
    async fn test_grandslam_client_logout_clears_state() {
        let mut client = GrandSlamAppleClient::new();
        let res = client.logout().await;
        assert!(res.is_ok());
        assert!(client.active_apple_id.lock().unwrap().is_none());
        assert!(client.session_info.lock().unwrap().is_none());
    }
}
