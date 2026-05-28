use crate::domain::error::DomainError;
use crate::domain::sync::envelope::{RequestPlaintext, ResponseEnvelope, verify_response_mac};
use crate::domain::sync::remote_config::ServerKeyResponse;
use crate::infrastructure::remote_envelope::{decrypt_response, encrypt_request, parse_recipient};
use age::x25519;
use base64::Engine;
use reqwest::Client;

pub struct RemoteClient {
    client: Client,
    remote_url: String,
    server_recipient: x25519::Recipient,
    server_key_id: String,
    fingerprint: String,
}

impl RemoteClient {
    pub async fn new(remote_url: String) -> Result<Self, DomainError> {
        let client = Client::new();
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
    ) -> Result<Self, DomainError> {
        let remote = Self::new(remote_url).await?;
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
            return Err(DomainError::StoreCorrupted(format!(
                "{}: {}",
                code, message
            )));
        }

        Ok(decrypted.get("data").cloned().unwrap_or_default())
    }
}
