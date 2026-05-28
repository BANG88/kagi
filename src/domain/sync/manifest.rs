use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Serialize, Deserialize, Debug, Clone)]
#[allow(dead_code)]
pub struct ProjectStateManifest {
    pub version: i64,
    pub project_id: String,
    pub revision: i64,
    pub previous_manifest_hash: Option<String>,
    pub kagi_json_hash: String,
    pub access_json_hash: String,
    pub file_hashes: Vec<FileHash>,
    pub timestamp: String,
    pub signer_member_id: String,
    pub signer_public_key: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[allow(dead_code)]
pub struct FileHash {
    pub path: String,
    pub sha256: String,
}

impl ProjectStateManifest {
    #[allow(dead_code)]
    pub fn compute_hash(&self) -> String {
        let canonical = serde_json::to_string(self).unwrap_or_default();
        let mut hasher = Sha256::new();
        hasher.update(canonical.as_bytes());
        hex::encode(hasher.finalize())
    }
}

#[allow(dead_code)]
pub fn hash_json(json: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(json.as_bytes());
    hex::encode(hasher.finalize())
}
