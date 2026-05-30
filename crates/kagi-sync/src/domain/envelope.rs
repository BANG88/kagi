use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RequestEnvelope {
    pub version: u8,
    pub request_id: String,
    pub server_key_id: String,
    pub response_recipient: String,
    pub ciphertext: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ResponseEnvelope {
    pub version: u8,
    pub request_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mac: Option<String>,
    pub ciphertext: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RequestPlaintext {
    pub version: u8,
    pub request_id: String,
    pub issued_at: String,
    pub operation: String,
    pub method: String,
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub project_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claim_secret: Option<String>,
    #[serde(flatten)]
    pub payload: serde_json::Value,
}

#[cfg(feature = "server")]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SuccessResponse {
    pub ok: bool,
    pub request_id: String,
    pub data: serde_json::Value,
}

pub fn response_mac(key: &str, request_id: &str, ciphertext: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(key.as_bytes()).expect("HMAC accepts any key size");
    mac.update(b"kagi-response-v1");
    mac.update(request_id.as_bytes());
    mac.update(ciphertext.as_bytes());
    let result = mac.finalize().into_bytes();
    base64_url_encode(&result)
}

pub fn verify_response_mac(key: &str, request_id: &str, ciphertext: &str, mac: &str) -> bool {
    let Ok(expected) = base64_url_decode(mac) else {
        return false;
    };
    let mut verifier =
        HmacSha256::new_from_slice(key.as_bytes()).expect("HMAC accepts any key size");
    verifier.update(b"kagi-response-v1");
    verifier.update(request_id.as_bytes());
    verifier.update(ciphertext.as_bytes());
    verifier.verify_slice(&expected).is_ok()
}

fn base64_url_encode(input: &[u8]) -> String {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    URL_SAFE_NO_PAD.encode(input)
}

fn base64_url_decode(input: &str) -> Result<Vec<u8>, base64::DecodeError> {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    URL_SAFE_NO_PAD.decode(input)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn response_mac_roundtrip() {
        let token = "kagi_proj_v1_test.secret";
        let request_id = "kgr_test";
        let ciphertext = "ciphertext";
        let mac = response_mac(token, request_id, ciphertext);
        assert!(verify_response_mac(token, request_id, ciphertext, &mac));
    }

    #[test]
    fn response_mac_rejects_tampered_ciphertext() {
        let token = "kagi_proj_v1_test.secret";
        let request_id = "kgr_test";
        let mac = response_mac(token, request_id, "ciphertext");
        assert!(!verify_response_mac(token, request_id, "other", &mac));
    }

    #[test]
    fn response_mac_rejects_wrong_token() {
        let mac = response_mac("token-a", "kgr_test", "ciphertext");
        assert!(!verify_response_mac(
            "token-b",
            "kgr_test",
            "ciphertext",
            &mac
        ));
    }
}
