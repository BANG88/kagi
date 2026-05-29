use crate::domain::error::DomainError;
use crate::domain::sync::envelope::{RequestPlaintext, ResponseEnvelope, verify_response_mac};
use crate::domain::sync::remote_config::ServerKeyResponse;
use crate::infrastructure::remote_envelope::{decrypt_response, encrypt_request, parse_recipient};
use age::x25519;
use base64::Engine;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;

pub struct RemoteClient {
    client: Client,
    remote_url: String,
    server_recipient: x25519::Recipient,
    server_key_id: String,
    fingerprint: String,
}

fn is_localhost_url(url: &str) -> bool {
    let parsed = match Url::parse(url) {
        Ok(u) => u,
        Err(_) => return false,
    };
    if parsed.scheme() != "http" {
        return false;
    }
    match parsed.host() {
        Some(url::Host::Domain("localhost")) => true,
        Some(url::Host::Ipv4(ip)) if ip.is_loopback() => true,
        Some(url::Host::Ipv6(ip)) if ip.is_loopback() => true,
        _ => false,
    }
}

#[derive(Error, Debug)]
pub enum ClientError {
    #[error("invalid token")]
    InvalidToken,
    #[error("project not found")]
    ProjectNotFound,
    #[error("project state conflict")]
    ProjectStateConflict,
    #[error("request failed: {0}")]
    RequestFailed(String),
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MemberJoinRequest {
    pub member_id: String,
    pub name: String,
    pub recipient: String,
}

#[derive(Deserialize, Debug, Clone)]
pub struct JoinResponse {}

#[derive(Deserialize, Debug, Clone)]
pub struct TokenIssueResponse {
    pub token_id: String,
    pub project_token: String,
    #[allow(dead_code)]
    pub status: String,
}

pub fn validate_http_transport(remote_url: &str, allow_insecure: bool) -> Result<(), DomainError> {
    if remote_url.starts_with("http://") && !is_localhost_url(remote_url) && !allow_insecure {
        let env_override = std::env::var("KAGI_ALLOW_INSECURE_HTTP")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        if !env_override {
            return Err(DomainError::StoreCorrupted(
                "HTTP remotes are only allowed for localhost. Use HTTPS or pass --allow-insecure-http for local testing.".into(),
            ));
        }
    }
    Ok(())
}

impl RemoteClient {
    pub async fn new(remote_url: String, allow_insecure: bool) -> Result<Self, DomainError> {
        validate_http_transport(&remote_url, allow_insecure)?;
        let client = if is_localhost_url(&remote_url) {
            Client::builder().no_proxy().build().map_err(|e| {
                DomainError::StoreCorrupted(format!("failed to build HTTP client: {}", e))
            })?
        } else {
            Client::new()
        };
        let url = format!("{}/v1/server-key", remote_url.trim_end_matches('/'));
        let server_key: ServerKeyResponse = client
            .get(&url)
            .send()
            .await
            .map_err(|e| DomainError::StoreCorrupted(format!("failed to fetch server key: {}", e)))?
            .json()
            .await
            .map_err(|e| {
                DomainError::StoreCorrupted(format!("invalid server key response: {}", e))
            })?;

        let server_recipient = parse_recipient(&server_key.recipient)?;
        Ok(Self {
            client,
            remote_url,
            server_recipient,
            server_key_id: server_key.server_key_id,
            fingerprint: server_key.fingerprint,
        })
    }

    pub async fn new_pinned(
        remote_url: String,
        expected_fingerprint: &str,
        allow_insecure: bool,
    ) -> Result<Self, DomainError> {
        let remote = Self::new(remote_url, allow_insecure).await?;
        if remote.fingerprint != expected_fingerprint {
            return Err(DomainError::StoreCorrupted(format!(
                "server fingerprint mismatch: expected {}, got {}",
                expected_fingerprint, remote.fingerprint
            )));
        }
        Ok(remote)
    }

    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    pub fn server_key_id(&self) -> &str {
        &self.server_key_id
    }

    pub async fn send_request(
        &self,
        plaintext: &RequestPlaintext,
        local_identity: &x25519::Identity,
    ) -> Result<serde_json::Value, DomainError> {
        let local_recipient = local_identity.to_public();
        let mut envelope = encrypt_request(plaintext, &self.server_recipient, &local_recipient)?;
        envelope.server_key_id = self.server_key_id.clone();

        let url = format!(
            "{}{}",
            self.remote_url.trim_end_matches('/'),
            plaintext.path
        );
        let response = self
            .client
            .post(&url)
            .json(&envelope)
            .send()
            .await
            .map_err(|e| DomainError::StoreCorrupted(format!("request failed: {}", e)))?;

        let response_text = response
            .text()
            .await
            .map_err(|e| DomainError::StoreCorrupted(format!("invalid response body: {}", e)))?;
        let response_envelope: ResponseEnvelope =
            serde_json::from_str(&response_text).map_err(|e| {
                DomainError::StoreCorrupted(format!(
                    "invalid response: {} | raw: {}",
                    e, response_text
                ))
            })?;

        if response_envelope.request_id != plaintext.request_id {
            return Err(DomainError::StoreCorrupted(
                "response request_id mismatch".into(),
            ));
        }
        let mac_key = plaintext
            .token
            .as_deref()
            .or(plaintext.claim_secret.as_deref());
        if let Some(key) = mac_key {
            let mac = response_envelope.mac.as_deref().ok_or_else(|| {
                DomainError::StoreCorrupted("missing response authentication mac".into())
            })?;
            if !verify_response_mac(
                key,
                &plaintext.request_id,
                &response_envelope.ciphertext,
                mac,
            ) {
                return Err(DomainError::StoreCorrupted(
                    "invalid response authentication mac".into(),
                ));
            }
        }

        let ciphertext = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&response_envelope.ciphertext)
            .map_err(|e| DomainError::DecryptFailed(e.to_string()))?;
        let decrypted = decrypt_response(&ciphertext, local_identity)?;
        if decrypted.get("request_id").and_then(|v| v.as_str())
            != Some(plaintext.request_id.as_str())
        {
            return Err(DomainError::StoreCorrupted(
                "decrypted response request_id mismatch".into(),
            ));
        }

        if !decrypted
            .get("ok")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        {
            let error = decrypted.get("error").cloned().unwrap_or_default();
            let code = error
                .get("code")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            let message = error
                .get("message")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown error");
            return Err(DomainError::RemoteRejected {
                code: code.to_string(),
                message: message.to_string(),
            });
        }

        Ok(decrypted.get("data").cloned().unwrap_or_default())
    }

    fn map_request_error(e: DomainError) -> ClientError {
        if let DomainError::RemoteRejected { ref code, .. } = e {
            if code == "auth_failed" {
                return ClientError::InvalidToken;
            }
            if code == "not_found" {
                return ClientError::ProjectNotFound;
            }
            if code == "conflict" {
                return ClientError::ProjectStateConflict;
            }
        }
        ClientError::RequestFailed(e.to_string())
    }

    pub async fn get_token_from_claim_secret(
        &self,
        project_id: &str,
        member_id: &str,
        claim_secret: &str,
        identity: &x25519::Identity,
    ) -> Result<String, DomainError> {
        let request_id = format!("kgr_{}", nanoid::nanoid!(12));
        let plaintext = RequestPlaintext {
            version: 1,
            request_id: request_id.clone(),
            issued_at: time::OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap(),
            operation: "pull".into(),
            method: "POST".into(),
            path: format!("/v1/projects/{}/pull", project_id),
            project_id: Some(project_id.to_string()),
            token: None,
            claim_secret: Some(claim_secret.to_string()),
            payload: serde_json::json!({
                "member_id": member_id,
            }),
        };
        let data = self.send_request(&plaintext, identity).await?;
        if let Some(wrapped_b64) = data.get("wrapped_project_token").and_then(|v| v.as_str()) {
            let wrapped = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(wrapped_b64)
                .map_err(|e| {
                    DomainError::StoreCorrupted(format!("invalid wrapped token: {}", e))
                })?;
            let decrypted = crate::infrastructure::remote_envelope::decrypt_bytes(
                &wrapped, identity,
            )
            .map_err(|e| {
                DomainError::StoreCorrupted(format!("failed to decrypt wrapped token: {}", e))
            })?;
            String::from_utf8(decrypted)
                .map_err(|e| DomainError::StoreCorrupted(format!("invalid token: {}", e)))
        } else {
            Err(DomainError::ProjectTokenUnavailable(
                "no project token available; ask an active member/admin to approve this member, then run `kagi pull`"
                    .into(),
            ))
        }
    }

    pub async fn send_member_join_request(
        &self,
        project_id: &str,
        token: &str,
        join_request: &MemberJoinRequest,
        identity: &x25519::Identity,
    ) -> Result<JoinResponse, ClientError> {
        let request_id = format!("kgr_{}", nanoid::nanoid!(12));
        let plaintext = RequestPlaintext {
            version: 1,
            request_id: request_id.clone(),
            issued_at: time::OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap(),
            operation: "join".into(),
            method: "POST".into(),
            path: format!("/v1/projects/{}/join", project_id),
            project_id: Some(project_id.to_string()),
            token: Some(token.to_string()),
            claim_secret: None,
            payload: serde_json::json!({
                "join_request": {
                    "member_id": join_request.member_id,
                    "name": join_request.name,
                    "recipient": join_request.recipient,
                }
            }),
        };
        let data = self
            .send_request(&plaintext, identity)
            .await
            .map_err(Self::map_request_error)?;
        serde_json::from_value(data).map_err(|e| ClientError::RequestFailed(e.to_string()))
    }

    pub async fn send_member_token_issue(
        &self,
        project_id: &str,
        token: &str,
        member_id: &str,
        identity: &x25519::Identity,
    ) -> Result<TokenIssueResponse, ClientError> {
        let request_id = format!("kgr_{}", nanoid::nanoid!(12));
        let plaintext = RequestPlaintext {
            version: 1,
            request_id: request_id.clone(),
            issued_at: time::OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap(),
            operation: "token_issue".into(),
            method: "POST".into(),
            path: format!("/v1/projects/{}/tokens/issue", project_id),
            project_id: Some(project_id.to_string()),
            token: Some(token.to_string()),
            claim_secret: None,
            payload: serde_json::json!({
                "member_id": member_id,
                "capabilities": ["pull", "push"],
            }),
        };
        let data = self
            .send_request(&plaintext, identity)
            .await
            .map_err(Self::map_request_error)?;
        serde_json::from_value(data).map_err(|e| ClientError::RequestFailed(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    struct EnvVarGuard {
        key: &'static str,
        previous: Option<OsString>,
    }

    impl EnvVarGuard {
        fn set(key: &'static str, value: &str) -> Self {
            let previous = std::env::var_os(key);
            unsafe {
                std::env::set_var(key, value);
            }
            Self { key, previous }
        }

        fn unset(key: &'static str) -> Self {
            let previous = std::env::var_os(key);
            unsafe {
                std::env::remove_var(key);
            }
            Self { key, previous }
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            unsafe {
                if let Some(previous) = &self.previous {
                    std::env::set_var(self.key, previous);
                } else {
                    std::env::remove_var(self.key);
                }
            }
        }
    }

    #[test]
    fn test_is_localhost_url_localhost() {
        assert!(is_localhost_url("http://localhost:13816"));
        assert!(is_localhost_url("http://localhost:8787"));
    }

    #[test]
    fn test_is_localhost_url_127_0_0_1() {
        assert!(is_localhost_url("http://127.0.0.1:13816"));
        assert!(is_localhost_url("http://127.0.0.1:8787"));
    }

    #[test]
    fn test_is_localhost_url_ipv6_loopback() {
        assert!(is_localhost_url("http://[::1]:13816"));
    }

    #[test]
    fn test_is_localhost_url_rejects_non_loopback() {
        assert!(!is_localhost_url("http://example.com"));
        assert!(!is_localhost_url("http://192.168.1.1:13816"));
        assert!(!is_localhost_url("http://10.0.0.1:13816"));
    }

    #[test]
    fn test_is_localhost_url_rejects_https() {
        assert!(!is_localhost_url("https://localhost:13816"));
        assert!(!is_localhost_url("https://127.0.0.1:13816"));
    }

    #[test]
    fn test_validate_http_transport_blocks_non_localhost_http() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _env = EnvVarGuard::unset("KAGI_ALLOW_INSECURE_HTTP");
        let result = validate_http_transport("http://example.com", false);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("HTTP remotes are only allowed for localhost")
        );
    }

    #[test]
    fn test_validate_http_transport_allows_localhost_http() {
        assert!(validate_http_transport("http://127.0.0.1:13816", false).is_ok());
        assert!(validate_http_transport("http://localhost:13816", false).is_ok());
    }

    #[test]
    fn test_validate_http_transport_allows_https_anywhere() {
        assert!(validate_http_transport("https://example.com", false).is_ok());
        assert!(validate_http_transport("https://kagi.example.com", false).is_ok());
    }

    #[test]
    fn test_validate_http_transport_allows_insecure_with_flag() {
        assert!(validate_http_transport("http://example.com", true).is_ok());
    }

    #[test]
    fn test_validate_http_transport_allows_insecure_with_env() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _env = EnvVarGuard::set("KAGI_ALLOW_INSECURE_HTTP", "1");
        assert!(validate_http_transport("http://example.com", false).is_ok());
    }
}
