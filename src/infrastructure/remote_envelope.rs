use crate::domain::error::DomainError;
#[cfg(feature = "server")]
use crate::domain::sync::envelope::SuccessResponse;
use crate::domain::sync::envelope::{RequestEnvelope, RequestPlaintext};
use age::{Decryptor, Encryptor, x25519};
use base64::{Engine as _, engine::general_purpose};
use std::io::{Read, Write};
use std::str::FromStr;

pub fn encrypt_request(
    plaintext: &RequestPlaintext,
    server_recipient: &x25519::Recipient,
    response_recipient: &x25519::Recipient,
) -> Result<RequestEnvelope, DomainError> {
    let mut plaintext_value = serde_json::to_value(plaintext)?;
    let response_recipient = response_recipient.to_string();
    let object = plaintext_value.as_object_mut().ok_or_else(|| {
        DomainError::EncryptFailed("request plaintext must serialize to an object".into())
    })?;
    object.insert(
        "response_recipient".to_string(),
        serde_json::Value::String(response_recipient.clone()),
    );
    let plaintext_json = serde_json::to_vec(&plaintext_value)?;
    let ciphertext = encrypt_age(&plaintext_json, server_recipient)?;
    Ok(RequestEnvelope {
        version: 1,
        request_id: plaintext.request_id.clone(),
        server_key_id: "kgs_placeholder".to_string(),
        response_recipient,
        ciphertext: general_purpose::STANDARD.encode(&ciphertext),
    })
}

#[cfg(feature = "server")]
pub fn decrypt_request(
    envelope: &RequestEnvelope,
    server_identity: &x25519::Identity,
) -> Result<RequestPlaintext, DomainError> {
    let ciphertext = general_purpose::STANDARD
        .decode(&envelope.ciphertext)
        .map_err(|e| DomainError::DecryptFailed(e.to_string()))?;
    let plaintext_bytes = decrypt_age(&ciphertext, server_identity)?;
    let plaintext: RequestPlaintext = serde_json::from_slice(&plaintext_bytes)
        .map_err(|e| DomainError::DecryptFailed(e.to_string()))?;
    Ok(plaintext)
}

#[cfg(feature = "server")]
pub fn encrypt_response(
    data: &SuccessResponse,
    recipient: &x25519::Recipient,
) -> Result<Vec<u8>, DomainError> {
    let plaintext = serde_json::to_vec(data)?;
    encrypt_age(&plaintext, recipient)
}

pub fn decrypt_response(
    ciphertext: &[u8],
    identity: &x25519::Identity,
) -> Result<serde_json::Value, DomainError> {
    let plaintext = decrypt_age(ciphertext, identity)?;
    let value: serde_json::Value = serde_json::from_slice(&plaintext)
        .map_err(|e| DomainError::DecryptFailed(e.to_string()))?;
    Ok(value)
}

pub fn encrypt_bytes(
    plaintext: &[u8],
    recipient: &x25519::Recipient,
) -> Result<Vec<u8>, DomainError> {
    encrypt_age(plaintext, recipient)
}

pub fn decrypt_bytes(
    ciphertext: &[u8],
    identity: &x25519::Identity,
) -> Result<Vec<u8>, DomainError> {
    decrypt_age(ciphertext, identity)
}

fn encrypt_age(plaintext: &[u8], recipient: &x25519::Recipient) -> Result<Vec<u8>, DomainError> {
    let encryptor = Encryptor::with_recipients(std::iter::once(recipient as _))
        .map_err(|e| DomainError::EncryptFailed(e.to_string()))?;
    let mut encrypted = Vec::new();
    let mut writer = encryptor
        .wrap_output(&mut encrypted)
        .map_err(|e| DomainError::EncryptFailed(e.to_string()))?;
    writer
        .write_all(plaintext)
        .map_err(|e| DomainError::EncryptFailed(e.to_string()))?;
    writer
        .finish()
        .map_err(|e| DomainError::EncryptFailed(e.to_string()))?;
    Ok(encrypted)
}

fn decrypt_age(encrypted: &[u8], identity: &x25519::Identity) -> Result<Vec<u8>, DomainError> {
    let decryptor =
        Decryptor::new(encrypted).map_err(|e| DomainError::DecryptFailed(e.to_string()))?;
    let mut reader = decryptor
        .decrypt(std::iter::once(identity as &dyn age::Identity))
        .map_err(|e| DomainError::DecryptFailed(e.to_string()))?;
    let mut decrypted = Vec::new();
    reader
        .read_to_end(&mut decrypted)
        .map_err(|e| DomainError::DecryptFailed(e.to_string()))?;
    Ok(decrypted)
}

pub fn parse_recipient(s: &str) -> Result<x25519::Recipient, DomainError> {
    x25519::Recipient::from_str(s)
        .map_err(|e| DomainError::StoreCorrupted(format!("invalid recipient: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "server")]
    use crate::domain::sync::envelope::RequestPlaintext;
    use age::x25519;

    #[cfg(feature = "server")]
    fn test_identities() -> (x25519::Identity, x25519::Recipient) {
        let identity = x25519::Identity::generate();
        let recipient = identity.to_public();
        (identity, recipient)
    }

    #[test]
    #[cfg(feature = "server")]
    fn test_encrypt_decrypt_request_roundtrip() {
        let (server_identity, server_recipient) = test_identities();
        let (_client_identity, client_recipient) = test_identities();

        let plaintext = RequestPlaintext {
            version: 1,
            request_id: "kgr_test".into(),
            issued_at: "2026-01-01T00:00:00Z".into(),
            operation: "push".into(),
            method: "POST".into(),
            path: "/v1/projects/kgp_test/push".into(),
            project_id: Some("kgp_test".into()),
            token: Some("test_token".into()),
            claim_secret: None,
            payload: serde_json::json!({"base_revision": 0}),
        };

        let envelope = encrypt_request(&plaintext, &server_recipient, &client_recipient).unwrap();
        assert_eq!(envelope.request_id, "kgr_test");
        assert_eq!(envelope.server_key_id, "kgs_placeholder");
        assert!(!envelope.ciphertext.is_empty());

        let decrypted = decrypt_request(&envelope, &server_identity).unwrap();
        assert_eq!(decrypted.request_id, plaintext.request_id);
        assert_eq!(decrypted.path, plaintext.path);
        assert_eq!(decrypted.method, plaintext.method);
    }

    #[test]
    #[cfg(feature = "server")]
    fn test_encrypt_decrypt_response_roundtrip() {
        let (client_identity, client_recipient) = test_identities();

        let response = SuccessResponse {
            ok: true,
            request_id: "kgr_test".into(),
            data: serde_json::json!({"revision": 42}),
        };

        let ciphertext = encrypt_response(&response, &client_recipient).unwrap();
        assert!(!ciphertext.is_empty());

        let decrypted = decrypt_response(&ciphertext, &client_identity).unwrap();
        assert_eq!(decrypted["ok"], true);
        assert_eq!(decrypted["request_id"], "kgr_test");
        assert_eq!(decrypted["data"]["revision"], 42);
    }

    #[test]
    #[cfg(feature = "server")]
    fn test_decrypt_with_wrong_identity_fails() {
        let (server_identity, server_recipient) = test_identities();
        let (_wrong_identity, wrong_recipient) = test_identities();

        let plaintext = RequestPlaintext {
            version: 1,
            request_id: "kgr_test".into(),
            issued_at: "2026-01-01T00:00:00Z".into(),
            operation: "test".into(),
            method: "POST".into(),
            path: "/v1/test".into(),
            project_id: None,
            token: None,
            claim_secret: None,
            payload: serde_json::json!({}),
        };

        let envelope = encrypt_request(&plaintext, &server_recipient, &wrong_recipient).unwrap();
        assert!(decrypt_request(&envelope, &server_identity).is_ok());

        // But encrypting for wrong recipient and decrypting with wrong identity should fail
        let (_other_identity, other_recipient) = test_identities();
        let envelope2 = encrypt_request(&plaintext, &other_recipient, &wrong_recipient).unwrap();
        assert!(decrypt_request(&envelope2, &server_identity).is_err());
    }

    #[test]
    fn test_parse_recipient_valid() {
        let identity = x25519::Identity::generate();
        let recipient = identity.to_public().to_string();
        assert!(parse_recipient(&recipient).is_ok());
    }

    #[test]
    fn test_parse_recipient_invalid() {
        assert!(parse_recipient("not_a_recipient").is_err());
    }
}
