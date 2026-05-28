use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AdminRemoteConfig {
    pub version: u8,
    pub remote: String,
    pub server_fingerprint: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ServerKeyResponse {
    pub version: u8,
    pub server_key_id: String,
    pub recipient: String,
    pub fingerprint: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RemoteMetadata {
    pub version: u8,
    pub project_id: String,
    pub remote: String,
    pub server_key_id: String,
    pub server_fingerprint: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local_revision: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_pulled_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_pushed_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_manifest_hash: Option<String>,
}
